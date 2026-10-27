"""Measure one pre-sanitized driver against one target line."""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from src.core.llvm_cov import ReplayCrash
from src.driver_qualification.runtime import (
    FuzzProcessExited,
    FuzzProcessFailure,
    PersistentFuzzSession,
)

from .progress import Progress, probe
from .stall import STALLED, StallDetector


@dataclass(frozen=True)
class RuntimeBuild:
    source: str
    binary: str


BuildRuntime = Callable[[str], Optional[RuntimeBuild]]
BuildBinary = Callable[[str], Optional[str]]
OnEvent = Callable[..., None]

STALL_PATIENCE = 3


class QualificationPhase(str, Enum):
    """Observable phases of the reach-only qualification state machine."""

    BUILDING = "BUILDING"
    FUZZING = "FUZZING"
    MEASURING = "MEASURING"


@dataclass(frozen=True)
class QualificationPhaseEvent:
    """Structured progress emitted at long-running state boundaries."""

    phase: QualificationPhase
    total_rounds: int = 0
    candidate_round: int = 0
    target_reached: bool = False
    progress: Optional[Progress] = None
    detail: str = ""


OnPhase = Callable[[QualificationPhaseEvent], None]


class _RuntimeBuildFailed(RuntimeError):
    pass


class _CoverageBuildFailed(RuntimeError):
    pass


class ReachabilityOutcome(Enum):
    REACHED = "reached"
    GAVE_UP = "gave_up"
    BUILD_FAILED = "build_failed"
    MEASURE_FAILED = "measure_failed"
    TARGET_SOURCE_UNLINKED = "target_source_unlinked"
    COVERAGE_SOURCE_UNAVAILABLE = "coverage_source_unavailable"
    RUNTIME_FAILED = "runtime_failed"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass
class ReachabilityResult:
    outcome: ReachabilityOutcome
    driver: str
    rounds: int
    last: Optional[Progress] = None
    failure: Optional[FuzzProcessFailure] = None
    coverage_binary: Optional[str] = None
    corpus_snapshot: Optional[str] = None
    reaching_input: Optional[str] = None
    target_marker_path: Optional[str] = None


class ReachabilityMonitor:
    """Run reachability measurement without SAN repair or source refinement."""

    def __init__(
        self,
        driver: str,
        target: str,
        chain,
        *,
        build_runtime: BuildRuntime,
        build_cov: BuildBinary,
        coverage_workdir: str,
        fuzz_session: PersistentFuzzSession,
        max_rounds: Optional[int] = None,
        measurement_timeout_seconds: int = 600,
        coverage_rss_limit_mb: int | None = None,
        coverage_source_root: str | None = None,
        coverage_resolution_path: str | None = None,
        target_marker_path: str | None = None,
        require_exact_witness: bool = False,
        on_event: Optional[OnEvent] = None,
        on_phase: Optional[OnPhase] = None,
    ):
        self.driver = driver
        self.target = target
        self.chain = list(chain)
        self.build_runtime = build_runtime
        self.build_cov = build_cov
        self.coverage_workdir = coverage_workdir
        self.fuzz_session = fuzz_session
        self.max_rounds = max_rounds
        self.measurement_timeout_seconds = measurement_timeout_seconds
        self.coverage_rss_limit_mb = coverage_rss_limit_mb
        self.coverage_source_root = coverage_source_root
        self.coverage_resolution_path = coverage_resolution_path
        self.target_marker_path = target_marker_path
        self.require_exact_witness = require_exact_witness
        self.detector = StallDetector(STALL_PATIENCE)
        self.on_event = on_event or (lambda *args, **kwargs: None)
        self.on_phase = on_phase or (lambda event: None)
        self._coverage_binary: Optional[str] = None
        self._corpus_snapshot: Optional[str] = None
        self._reaching_input: Optional[str] = None
        self._previous_snapshot_files: frozenset[str] = frozenset()

    def _phase(
        self,
        phase: QualificationPhase,
        *,
        total_rounds: int = 0,
        candidate_round: int = 0,
        target_reached: bool = False,
        progress: Optional[Progress] = None,
        detail: str = "",
    ) -> None:
        self.on_phase(
            QualificationPhaseEvent(
                phase=phase,
                total_rounds=total_rounds,
                candidate_round=candidate_round,
                target_reached=target_reached,
                progress=progress,
                detail=detail,
            )
        )

    def run(self) -> ReachabilityResult:
        """Run the monitor and always reap its active process group."""
        self._coverage_binary = None
        self._corpus_snapshot = None
        self._reaching_input = None
        self._previous_snapshot_files = frozenset()
        try:
            result = self._run()
        except BaseException:
            try:
                self.fuzz_session.stop()
            except FuzzProcessExited:
                pass
            raise
        try:
            self.fuzz_session.stop()
        except FuzzProcessExited as exc:
            if result.outcome != ReachabilityOutcome.RUNTIME_FAILED:
                return self._result(
                    ReachabilityOutcome.RUNTIME_FAILED,
                    result.driver,
                    result.rounds,
                    result.last,
                    exc.failure,
                )
        return result

    def _result(
        self,
        outcome: ReachabilityOutcome,
        driver: str,
        rounds: int,
        last: Optional[Progress],
        failure: Optional[FuzzProcessFailure] = None,
    ) -> ReachabilityResult:
        return ReachabilityResult(
            outcome=outcome,
            driver=driver,
            rounds=rounds,
            last=last,
            failure=failure,
            coverage_binary=self._coverage_binary,
            corpus_snapshot=self._corpus_snapshot,
            reaching_input=self._reaching_input,
            target_marker_path=self.target_marker_path,
        )

    def _build_epoch(self, driver: str) -> tuple[str, str, str]:
        runtime = self.build_runtime(driver)
        if runtime is None:
            raise _RuntimeBuildFailed(driver)
        coverage_binary = self.build_cov(runtime.source)
        if not coverage_binary:
            raise _CoverageBuildFailed(runtime.source)
        self._coverage_binary = coverage_binary
        return runtime.source, runtime.binary, coverage_binary

    def _probe(self, coverage_binary: str, corpus_dir: str) -> Progress | ReplayCrash | None:
        return probe(
            coverage_binary,
            corpus_dir,
            self.target,
            self.chain,
            workdir=self.coverage_workdir,
            timeout=self.measurement_timeout_seconds,
            rss_limit_mb=self.coverage_rss_limit_mb,
            source_root=self.coverage_source_root,
            resolution_audit_path=self.coverage_resolution_path,
            target_marker_path=self.target_marker_path,
        )

    def _stop_failure(self) -> Optional[FuzzProcessFailure]:
        try:
            self.fuzz_session.stop()
        except FuzzProcessExited as exc:
            return exc.failure
        return None

    @staticmethod
    def _snapshot_inputs(snapshot_dir: str) -> list[Path]:
        """Return the regular files in one immutable checkpoint, deterministically."""

        snapshot = Path(snapshot_dir).resolve(strict=True)
        if not snapshot.is_dir():
            raise NotADirectoryError(
                f"qualification corpus snapshot is not a directory: {snapshot}"
            )
        inputs: list[Path] = []
        with os.scandir(snapshot) as entries:
            for entry in entries:
                if entry.is_symlink():
                    raise ValueError(
                        f"qualification corpus snapshot contains a symlink: "
                        f"{entry.path}"
                    )
                if entry.is_file(follow_symlinks=False):
                    inputs.append(Path(entry.path).resolve(strict=True))
        return sorted(inputs, key=lambda path: path.name)

    def _probe_input_group(
        self,
        coverage_binary: str,
        inputs: list[Path],
    ) -> Progress | ReplayCrash | None:
        """Measure an isolated subset without mutating its source snapshot."""

        workdir = Path(self.coverage_workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="exact-reaching-",
            dir=str(workdir),
        ) as temporary:
            corpus = Path(temporary)
            for index, source in enumerate(inputs):
                destination = corpus / f"{index:08d}-{source.name}"
                try:
                    os.link(source, destination)
                except OSError:
                    shutil.copyfile(source, destination)
            return self._probe(coverage_binary, str(corpus))

    def _search_reaching_group(
        self,
        coverage_binary: str,
        inputs: list[Path],
        *,
        known_reaching: bool,
    ) -> Optional[Path]:
        """Find one independently reaching input by recursively splitting groups."""

        pending: list[tuple[list[Path], bool]] = [(inputs, known_reaching)]
        while pending:
            group, group_reaches = pending.pop()
            if not group:
                continue
            if not group_reaches:
                measurement = self._probe_input_group(coverage_binary, group)
                if isinstance(measurement, Progress):
                    if not measurement.reached:
                        continue
                    group_reaches = True
                elif len(group) == 1:
                    # A crashing or unmeasurable singleton cannot establish the
                    # target-reachability witness required by this qualification.
                    continue
                else:
                    # One bad input may mask another reaching input in a group.
                    # Split the group instead of discarding all of its members.
                    midpoint = len(group) // 2
                    pending.append((group[midpoint:], False))
                    pending.append((group[:midpoint], False))
                    continue

            if len(group) == 1:
                return group[0]

            midpoint = len(group) // 2
            # LIFO ordering checks the lexicographically earlier half first.
            pending.append((group[midpoint:], False))
            pending.append((group[:midpoint], False))
        return None

    def _find_reaching_input(
        self,
        coverage_binary: str,
        snapshot_dir: str,
    ) -> Optional[str]:
        """Locate one file whose isolated replay reaches the target."""

        inputs = self._snapshot_inputs(snapshot_dir)
        if not inputs:
            return None

        # After a previous miss, a deterministic reaching witness normally lies
        # in the newly added checkpoint entries.  Search that small delta first,
        # then fall back to the whole snapshot whose aggregate hit is known.
        if self._previous_snapshot_files:
            new_inputs = [
                path
                for path in inputs
                if path.name not in self._previous_snapshot_files
            ]
            witness = self._search_reaching_group(
                coverage_binary,
                new_inputs,
                known_reaching=False,
            )
            if witness is not None:
                return str(witness)

        witness = self._search_reaching_group(
            coverage_binary,
            inputs,
            known_reaching=True,
        )
        return str(witness) if witness is not None else None

    def _run(self) -> ReachabilityResult:
        self._phase(QualificationPhase.BUILDING, detail="initial candidate")
        try:
            driver, runtime_binary, coverage_binary = self._build_epoch(self.driver)
        except _RuntimeBuildFailed:
            return self._result(
                ReachabilityOutcome.BUILD_FAILED, self.driver, 0, None
            )
        except _CoverageBuildFailed:
            return self._result(
                ReachabilityOutcome.MEASURE_FAILED, self.driver, 0, None
            )

        rounds = 0
        last: Optional[Progress] = None
        while True:
            self._phase(
                QualificationPhase.FUZZING,
                total_rounds=rounds,
                candidate_round=rounds + 1,
                progress=last,
                detail="collecting next corpus checkpoint",
            )
            try:
                checkpoint = self.fuzz_session.checkpoint(runtime_binary)
            except FuzzProcessExited as exc:
                return self._result(
                    ReachabilityOutcome.RUNTIME_FAILED,
                    driver,
                    rounds,
                    last,
                    exc.failure,
                )
            self._corpus_snapshot = checkpoint.snapshot_dir

            self._phase(
                QualificationPhase.MEASURING,
                total_rounds=rounds,
                candidate_round=rounds + 1,
                progress=last,
                detail="measuring target reachability",
            )
            measurement = self._probe(coverage_binary, checkpoint.snapshot_dir)
            if isinstance(measurement, ReplayCrash):
                failure = FuzzProcessFailure(
                    command=measurement.command,
                    returncode=measurement.returncode,
                    output="\n".join((
                        "Crash observed while replaying the corpus over the coverage binary.",
                        measurement.stdout,
                        measurement.stderr,
                    )),
                    artifacts=(measurement.input_path,),
                    work_dir=checkpoint.snapshot_dir,
                )
                rounds += 1
                self.on_event(rounds, last, "RUNTIME_FAILED")
                return self._result(
                    ReachabilityOutcome.RUNTIME_FAILED,
                    driver,
                    rounds,
                    last,
                    failure,
                )
            last = measurement
            try:
                self.fuzz_session.assert_running()
            except FuzzProcessExited as exc:
                return self._result(
                    ReachabilityOutcome.RUNTIME_FAILED,
                    driver,
                    rounds,
                    last,
                    exc.failure,
                )

            rounds += 1
            if last is None:
                self.on_event(rounds, None, "MEASURE_FAILED")
                failure = self._stop_failure()
                if failure is not None:
                    return self._result(
                        ReachabilityOutcome.RUNTIME_FAILED,
                        driver,
                        rounds,
                        None,
                        failure,
                    )
                return self._result(
                    ReachabilityOutcome.MEASURE_FAILED,
                    driver,
                    rounds,
                    None,
                )

            status = self.detector.update(last)
            if last.reached:
                failure = self._stop_failure()
                if failure is not None:
                    return self._result(
                        ReachabilityOutcome.RUNTIME_FAILED,
                        driver,
                        rounds,
                        last,
                        failure,
                    )
                if self.require_exact_witness:
                    self._phase(
                        QualificationPhase.MEASURING,
                        total_rounds=rounds,
                        candidate_round=rounds,
                        target_reached=True,
                        progress=last,
                        detail="isolating one exact reaching input",
                    )
                    self._reaching_input = self._find_reaching_input(
                        coverage_binary,
                        checkpoint.snapshot_dir,
                    )
                    if self._reaching_input is None:
                        self.on_event(rounds, last, "MEASURE_FAILED")
                        return self._result(
                            ReachabilityOutcome.MEASURE_FAILED,
                            driver,
                            rounds,
                            last,
                        )
                self.on_event(rounds, last, status)
                return self._result(
                    ReachabilityOutcome.REACHED,
                    driver,
                    rounds,
                    last,
                )

            self.on_event(rounds, last, status)
            self._previous_snapshot_files = frozenset(
                path.name
                for path in self._snapshot_inputs(checkpoint.snapshot_dir)
            )

            if status == STALLED:
                failure = self._stop_failure()
                if failure is not None:
                    return self._result(
                        ReachabilityOutcome.RUNTIME_FAILED,
                        driver,
                        rounds,
                        last,
                        failure,
                    )
                return self._result(
                    ReachabilityOutcome.GAVE_UP,
                    driver,
                    rounds,
                    last,
                )

            if self.max_rounds is not None and rounds >= self.max_rounds:
                failure = self._stop_failure()
                if failure is not None:
                    return self._result(
                        ReachabilityOutcome.RUNTIME_FAILED,
                        driver,
                        rounds,
                        last,
                        failure,
                    )
                return self._result(
                    ReachabilityOutcome.BUDGET_EXHAUSTED,
                    driver,
                    rounds,
                    last,
                )
