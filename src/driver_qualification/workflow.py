"""Batch target-reach qualification for pre-sanitized drivers."""

from __future__ import annotations

import hashlib
import math
import os
import shlex
import signal
import sys
import threading
import time
from datetime import datetime
from multiprocessing import get_context
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.core import (
    get_project_root,
    load_library_config,
)
from src.experiment import RunArtifactStore
from src.llm import driver_agent_usage_summary
from src.driver_qualification.runtime import (
    ASAN_OPTIONS,
    FUZZ_INPUT_TIMEOUT_SECONDS,
    FUZZ_RSS_LIMIT_MB,
    UBSAN_OPTIONS,
)
from src.driver_qualification.config import get_qualification_seconds
from src.driver_qualification.contracts import (
    DriverQualificationRecord,
    DriverQualificationResult,
    DriverQualificationSpec,
)
from src.driver_qualification.parsers import parse_fuzzer_log
from src.driver_qualification.dashboard import run_qualification_dashboard
from src.driver_qualification.store import DriverQualificationStore
from src.driver_qualification.reachability import (
    STALL_PATIENCE,
    QualificationPhaseEvent,
    ReachabilityOutcome,
    ReachabilityMonitor,
    RuntimeBuild,
    chain_step_fn,
    log_phase,
    log_result,
    make_adapters,
    make_event_logger,
    prepare_assert_target_marker,
    resolve_target,
)
from src.driver_qualification.reachability.diagnose import make_region_diagnose
from src.driver_qualification.reachability.source_diagnostics import (
    classify_source_resolution_failure,
)
from src.driver_qualification.reachability.audit import decision_fields, progress_fields

REACHABILITY_STAGE = "target_reachability"
INFRASTRUCTURE_OUTCOMES = frozenset(
    {
        "build_failed",
        "measure_failed",
        "infrastructure_failed",
        "worker_failed",
        "error",
        "coverage_source_unavailable",
    }
)
NONRETRYABLE_INFRASTRUCTURE_OUTCOMES = frozenset(
    {"coverage_source_unavailable"}
)
# Workers and their status manager start from a fresh interpreter, not a fork of this
# multithreaded process: a fork inherits any file another thread holds open for writing
# at that moment (a driver binary being copied into place), and running that binary
# then fails with ETXTBSY for as long as the forked worker lives.
_PROCESS_CONTEXT = get_context("spawn")


def _update_status(status_dict: dict, index: int, **values: Any) -> None:
    info = dict(status_dict.get(index, {}))
    info.update(values)
    status_dict[index] = info


def _update_phase_status(
    status_dict: dict,
    index: int,
    event: QualificationPhaseEvent,
    max_rounds: Optional[int],
) -> None:
    values: Dict[str, Any] = {
        "phase": event.phase.value,
        "phase_started_at": time.time(),
        "phase_detail": event.detail,
        "rounds": event.total_rounds,
        "candidate_round": event.candidate_round,
        "max_rounds": max_rounds,
        "target_reached": event.target_reached,
    }
    if event.progress is not None:
        values.update(progress_fields(event.progress))
    _update_status(status_dict, index, **values)


def _append_log(log_file: str, line: str = "") -> None:
    with open(log_file, "a", encoding="utf-8") as log_handle:
        log_handle.write(line + "\n")


def _redirect_worker_console(path: str) -> None:
    """Make the controller the only process that writes to the terminal."""
    sys.stdout.flush()
    sys.stderr.flush()
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        os.dup2(descriptor, sys.stdout.fileno())
        os.dup2(descriptor, sys.stderr.fileno())
    finally:
        os.close(descriptor)


def _ensure_qualification_corpus(corpus_dir: str) -> str:
    corpus = Path(corpus_dir)
    corpus.mkdir(parents=True, exist_ok=True)
    with os.scandir(corpus) as entries:
        if any(entry.is_file() for entry in entries):
            return str(corpus)

    (corpus / "seed-empty").write_bytes(b"")
    return str(corpus)


def _persistent_fuzzer_args(command_args: Sequence[str]) -> tuple[str, ...]:
    """Keep runtime limits while leaving duration and artifacts to the session."""
    excluded = ("-artifact_prefix=", "-max_total_time=", "-print_final_stats=", "-seed=")
    return tuple(
        arg
        for arg in command_args[1:]
        if arg.startswith("-") and not arg.startswith(excluded)
    )


def _qualification_seed(driver_id: str) -> int:
    """Return a stable libFuzzer seed for one generated driver."""
    digest = hashlib.sha256(driver_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], byteorder="big")


def _reachability_exit_code(outcome: ReachabilityOutcome) -> int:
    research_outcomes = {
        ReachabilityOutcome.REACHED,
        ReachabilityOutcome.GAVE_UP,
        ReachabilityOutcome.RUNTIME_FAILED,
        ReachabilityOutcome.BUDGET_EXHAUSTED,
        ReachabilityOutcome.TARGET_SOURCE_UNLINKED,
    }
    return 0 if outcome in research_outcomes else 1


def _format_chain(chain: Sequence[Any]) -> str:
    names = [chain_step_fn(step) for step in chain]
    return " -> ".join(name for name in names if name)


def _validate_worker_result_path(
    store: RunArtifactStore,
    path: Path,
    driver_id: str,
) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    payload = store.read_json(path)
    if not isinstance(payload, dict) or payload.get("name") != driver_id:
        raise ValueError(f"invalid qualification worker result: {path}")
    if payload.get("status") not in {"DONE", "ERROR"}:
        raise ValueError(f"non-terminal qualification worker result: {path}")
    return payload


def _new_qualification_attempt(stage_dir: Path) -> Path:
    attempts_dir = stage_dir / "attempts"
    attempts_dir.mkdir(parents=True, exist_ok=True)
    numbers = [
        int(path.name.removeprefix("attempt-"))
        for path in attempts_dir.iterdir()
        if path.is_dir()
        and path.name.startswith("attempt-")
        and path.name.removeprefix("attempt-").isdigit()
    ]
    attempt_dir = attempts_dir / f"attempt-{max(numbers, default=0) + 1:03d}"
    attempt_dir.mkdir(exist_ok=False)
    return attempt_dir


def _run_driver_qualification(
    library: str,
    spec: DriverQualificationSpec,
    target: str,
    chain: Sequence[Any],
    target_origin: str,
    run_id: str,
    chunk_seconds: int,
    max_rounds: int,
    status_dict: dict,
    index: int,
    assigned_attempt_dir: str,
) -> None:
    """Measure target reachability for one compiled driver in its assigned attempt."""
    started = datetime.now()
    run_store = RunArtifactStore.from_environment(get_project_root(), library)
    driver_dir = run_store.stage_dir(REACHABILITY_STAGE, spec.name)
    attempt_dir = Path(assigned_attempt_dir).resolve(strict=True)
    attempts_dir = (driver_dir / "attempts").resolve(strict=True)
    if attempt_dir.parent != attempts_dir or not attempt_dir.is_dir():
        raise ValueError(
            f"invalid assigned qualification attempt for {spec.name}: "
            f"{attempt_dir}"
        )
    logs_dir = run_store.attempt_logs_dir(REACHABILITY_STAGE, spec.name, attempt_dir)
    log_file = str(logs_dir / "qualification.log")
    worker_console_log = str(logs_dir / "worker-console.log")

    _update_status(
        status_dict,
        index,
        name=spec.name,
        status="RUNNING",
        phase="STARTING",
        phase_started_at=started.timestamp(),
        start_time=time.time(),
        elapsed=0,
        rounds=0,
        candidate_round=0,
        max_rounds=max_rounds,
        reachability_outcome=None,
        attempt_dir=str(attempt_dir),
    )

    run_jsonl = str(attempt_dir / "run.jsonl")
    workdir = str(attempt_dir / "work")
    coverage_source_root = str(get_project_root() / "test_lib" / library)
    coverage_resolution_path = str(
        Path(workdir) / "coverage-source-resolution.json"
    )
    command = (
        f"reachability-monitor {shlex.quote(library)} {shlex.quote(spec.name)} "
        f"--chunk-seconds={chunk_seconds}"
    )
    if max_rounds is not None:
        command += f" --max-rounds={max_rounds}"

    with open(log_file, "x", encoding="utf-8") as log_handle:
        log_handle.write(f"Command: {command}\n")
        log_handle.write(f"Started at: {started.isoformat(sep=' ')}\n")
        log_handle.write(f"Run id: {run_id}\n")
        log_handle.write("Mode: target_reachability\n")
        log_handle.write(f"Target: {target} (from {target_origin})\n")
        log_handle.write(f"Chain: {_format_chain(chain)}\n")
        log_handle.write(f"libFuzzer seed: {_qualification_seed(spec.name)}\n")
        log_handle.write(
            f"Policy: patience={STALL_PATIENCE}, "
            f"max_rounds={max_rounds}, precondition=COMPILED\n"
        )
        log_handle.write(f"Qualification attempt: {attempt_dir}\n")
        log_handle.write(f"Worker console: {worker_console_log}\n")
        log_handle.write("=" * 80 + "\n\n")
    Path(worker_console_log).touch(exist_ok=False)
    _redirect_worker_console(worker_console_log)

    exit_code = 0
    final_driver = spec.source_path
    final_binary = spec.binary_path
    outcome = "error"
    rounds = 0
    qualification_error: Optional[str] = None
    crash: Optional[Dict[str, Any]] = None
    reach_report: Optional[str] = None
    coverage_binary: Optional[str] = None
    corpus_snapshot: Optional[str] = None
    reaching_input: Optional[str] = None
    target_marker_path: Optional[str] = None
    try:
        corpus = _ensure_qualification_corpus(spec.corpus_dir)

        def on_fuzzer_start(pid: int) -> None:
            _update_status(status_dict, index, popen_pid=pid)

        def on_fuzzer_stop() -> None:
            _update_status(status_dict, index, popen_pid=0)

        runtime_env = os.environ.copy()
        runtime_env.update(spec.env)
        target_marker = prepare_assert_target_marker(
            library,
            target,
            workdir,
        )
        target_marker_path = (
            str(target_marker.hit_path) if target_marker else None
        )
        build_cov, fuzz_session = make_adapters(
            library,
            corpus_dir=corpus,
            workdir=workdir,
            chunk_seconds=chunk_seconds,
            replacement_objects=(
                [str(target_marker.object_path)] if target_marker else []
            ),
            artifact_dir=spec.artifact_dir,
            output_path=log_file,
            runtime_env=runtime_env,
            fuzzer_args=(
                *_persistent_fuzzer_args(spec.command_args),
                f"-seed={_qualification_seed(spec.name)}",
            ),
            on_fuzzer_start=on_fuzzer_start,
            on_fuzzer_stop=on_fuzzer_stop,
        )
        log_event = make_event_logger(run_jsonl)

        def on_phase(event: QualificationPhaseEvent) -> None:
            _append_log(
                log_file,
                f"[phase {event.phase.value} rounds={event.total_rounds} "
                f"candidate_round={event.candidate_round}] {event.detail}",
            )
            log_phase(run_jsonl, event)
            _update_phase_status(status_dict, index, event, max_rounds)

        def build_runtime(driver_src: str) -> Optional[RuntimeBuild]:
            if Path(driver_src).resolve() != Path(spec.source_path).resolve():
                return None
            if not Path(spec.binary_path).is_file():
                return None
            return RuntimeBuild(spec.source_path, spec.binary_path)

        def on_event(rnd, progress, status):
            decision = monitor.detector.last_decision if progress is not None else None
            fields = progress_fields(progress)
            policy_fields = decision_fields(decision)
            detail = (
                f"depth={progress.depth}/{progress.chain_len} hit={progress.hit} "
                f"frontier={progress.frontier_fn} "
                f"local_branches={fields['covered_branch_outcomes']} "
                f"branches_available={fields['branch_coverage_available']} "
                f"new_branches={policy_fields['new_branch_outcomes']} "
                f"reason={policy_fields['progress_reason']} "
                f"stale_checks={policy_fields['stale_checks']}"
                if progress else "measure-failed"
            )
            _append_log(
                log_file,
                f"[round {rnd}] {detail} -> {status}",
            )
            log_event(rnd, progress, status, decision=decision)
            _update_status(
                status_dict,
                index,
                rounds=rnd,
                reachability_status=status,
                elapsed=int(time.time() - started.timestamp()),
                **fields,
                **policy_fields,
            )

        monitor = ReachabilityMonitor(
            driver=spec.source_path,
            target=target,
            chain=chain,
            build_runtime=build_runtime,
            build_cov=build_cov,
            coverage_workdir=workdir,
            fuzz_session=fuzz_session,
            max_rounds=max_rounds,
            measurement_timeout_seconds=chunk_seconds * max_rounds,
            coverage_rss_limit_mb=FUZZ_RSS_LIMIT_MB,
            coverage_source_root=coverage_source_root,
            coverage_resolution_path=coverage_resolution_path,
            target_marker_path=target_marker_path,
            require_exact_witness=True,
            on_event=on_event,
            on_phase=on_phase,
        )
        result = monitor.run()
        if result.outcome == ReachabilityOutcome.MEASURE_FAILED:
            coverage_library = Path(
                load_library_config(library)["compile_config"]["coverage_library"]
            )
            if not coverage_library.is_absolute():
                coverage_library = get_project_root() / coverage_library
            classified = classify_source_resolution_failure(
                Path(workdir) / "measurement-failure.json",
                coverage_library,
                target,
            )
            if classified is not None:
                kind, qualification_error = classified
                result.outcome = ReachabilityOutcome(kind)
                if result.outcome == ReachabilityOutcome.TARGET_SOURCE_UNLINKED:
                    reach_report = qualification_error
                _append_log(log_file, f"Measurement diagnosis: {qualification_error}")
        final_driver = result.driver
        final_binary = spec.binary_path
        outcome = result.outcome.value
        rounds = result.rounds
        coverage_binary = result.coverage_binary
        corpus_snapshot = result.corpus_snapshot
        reaching_input = result.reaching_input
        target_marker_path = result.target_marker_path
        log_result(run_jsonl, result)
        if result.outcome in {
            ReachabilityOutcome.GAVE_UP,
            ReachabilityOutcome.BUDGET_EXHAUSTED,
        }:
            reach_report = make_region_diagnose(
                library,
                target,
                chain,
                build_cov,
                corpus_snapshot or corpus,
                workdir=workdir,
                source_root=coverage_source_root,
            )(result.driver, result.last)
        if result.failure is not None:
            crash = result.failure.to_dict()
            _append_log(log_file, "\nRuntime crash:")
            _append_log(log_file, result.failure.failure_context())
        exit_code = _reachability_exit_code(result.outcome)
    except Exception as exc:
        exit_code = 1
        outcome = "error"
        final_driver = spec.source_path
        qualification_error = str(exc)
        _append_log(log_file, f"\nError: {exc}")
    finally:
        finished = datetime.now()
        _append_log(log_file)
        _append_log(log_file, f"Reachability outcome: {outcome}")
        _append_log(log_file, f"Final driver: {final_driver}")
        _append_log(log_file, f"Final binary: {final_binary}")
        _append_log(log_file, f"Coverage binary: {coverage_binary}")
        _append_log(log_file, f"Corpus snapshot: {corpus_snapshot}")
        _append_log(log_file, f"Reaching input: {reaching_input}")
        _append_log(log_file, f"Target marker path: {target_marker_path}")
        _append_log(log_file, f"Reachability rounds: {rounds}")
        _append_log(log_file, f"Finished at: {finished.isoformat(sep=' ')}")
        _append_log(log_file, f"Exit code: {exit_code}")
        terminal = dict(status_dict.get(index, {}))
        last_phase = terminal.get("phase")
        terminal.update({
            "name": spec.name,
            "status": "DONE" if exit_code == 0 else "ERROR",
            "phase": "DONE" if exit_code == 0 else "ERROR",
            "last_phase": last_phase,
            "target_reached": outcome == ReachabilityOutcome.REACHED.value,
            "phase_started_at": finished.timestamp(),
            "popen_pid": 0,
            "final_driver": final_driver,
            "final_binary": final_binary,
            "coverage_binary": coverage_binary,
            "corpus_snapshot": corpus_snapshot,
            "reaching_input": reaching_input,
            "target_marker_path": target_marker_path,
            "reachability_outcome": outcome,
            "reachability_rounds": rounds,
            "qualification_error": qualification_error,
            "crash": crash,
            "reach_report": reach_report,
            "log_file": log_file,
            "worker_console_log": worker_console_log,
            "start_time": started.timestamp(),
            "elapsed": int((finished - started).total_seconds()),
            "attempt_dir": str(attempt_dir),
        })
        run_store.write_json(
            attempt_dir / "worker-result.json",
            terminal,
        )
        _update_status(status_dict, index, **terminal)


class DriverQualificationWorkflow:
    """Measure target reachability for SAN-smoke-passed drivers."""

    def __init__(self, library_name: str):
        self.library = library_name
        self.config = load_library_config(library_name)
        self.check_interval_seconds = get_qualification_seconds(
            self.config, "chunk_seconds"
        )
        self.qualification_budget_seconds = get_qualification_seconds(
            self.config, "max_total_time"
        )
        self.store = DriverQualificationStore(library_name)
        self._compiled_drivers: Dict[str, Tuple[str, str]] = {}
        self._preflight_failures: Dict[str, Dict[str, Any]] = {}

        self.project_root = self.store.project_root
        self.workspace_base = self.store.workspace_base
        self.qualification_base = self.store.qualification_base

    def build_runtime_command(
        self,
        binary_path: str,
        driver_id: Optional[str] = None,
        *,
        seed_runtime_corpus: bool = True,
    ) -> Tuple[List[str], Dict[str, str]]:
        """Build the libFuzzer command line and runtime environment."""
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = ASAN_OPTIONS
        env["UBSAN_OPTIONS"] = UBSAN_OPTIONS

        driver_id = driver_id or Path(binary_path).stem
        driver_corpus = self.store.driver_path(driver_id, "corpus")
        driver_corpus.mkdir(parents=True, exist_ok=True)
        if seed_runtime_corpus:
            self._copy_runtime_corpus(driver_id, driver_corpus)

        cmd_parts = [
            os.path.abspath(binary_path),
            f"-rss_limit_mb={FUZZ_RSS_LIMIT_MB}",
            f"-timeout={FUZZ_INPUT_TIMEOUT_SECONDS}",
        ]
        cmd_parts.append(str(driver_corpus))
        return cmd_parts, env

    def run_artifact_candidate(
        self,
        driver_id: str,
        source_path: str,
        binary_path: str,
        *,
        show_progress: bool = False,
    ) -> DriverQualificationResult:
        """Measure the exact source/binary pair in a new reachability attempt."""
        source = Path(source_path).resolve(strict=True)
        binary = Path(binary_path).resolve(strict=True)
        self._compiled_drivers = {str(binary): (driver_id, str(source))}
        specs = self._build_run_specs([str(binary)])
        status = self._execute_specs(
            specs,
            self.store.run_store.run_id,
            show_progress=show_progress,
        )
        self._apply_qualification_results(specs, status)
        qualification = dict(status.get(0, {}))
        payload = self._execution_payload(specs[0], qualification)
        for field in (
            "depth",
            "chain_len",
            "hit",
            "frontier",
            "rounds",
            "last_phase",
            "attempt_dir",
            "worker_console_log",
            "crash",
            "reach_report",
            "branch_coverage_available",
            "covered_branch_outcomes",
            "progress_reason",
            "new_branch_outcomes",
            "stale_checks",
            "target_reached",
            "elapsed",
            "qualification_error",
            "coverage_binary",
            "corpus_snapshot",
            "reaching_input",
            "target_marker_path",
        ):
            if field in qualification:
                payload[field] = qualification[field]
        return DriverQualificationResult(
            total=1,
            completed=int(payload.get("status") == "DONE"),
            infrastructure_failed=int(payload.get("status") != "DONE"),
            drivers={driver_id: payload},
        )

    def _max_rounds(self) -> int:
        return math.ceil(self.qualification_budget_seconds / self.check_interval_seconds)

    def _reachability_command(
        self,
        spec: DriverQualificationSpec,
        *,
        max_rounds: Optional[int] = None,
    ) -> str:
        parts = [
            "reachability-monitor",
            self.library,
            spec.name,
            f"--chunk-seconds={self.check_interval_seconds}",
        ]
        effective_max_rounds = self._max_rounds() if max_rounds is None else max_rounds
        if effective_max_rounds <= 0:
            raise ValueError("max_rounds must be a positive integer")
        parts.append(f"--max-rounds={effective_max_rounds}")
        return " ".join(shlex.quote(part) for part in parts)

    def _resolve_qualification_target(self, spec: DriverQualificationSpec) -> Tuple[Optional[str], Optional[List[Any]], Optional[str]]:
        if not spec.source_path or not Path(spec.source_path).is_file():
            return None, None, None

        resolved = resolve_target(self.library, spec.name)
        if resolved:
            return resolved[0], resolved[1], "candidate_plan.json"
        return None, None, None

    def _apply_qualification_results(self, specs: List[DriverQualificationSpec], qualification_status: Dict[int, Dict[str, Any]]) -> None:
        for index, spec in enumerate(specs):
            info = qualification_status.get(index, {})
            if not info.get("reachability_outcome"):
                continue
            spec.command = self._reachability_command(spec)
            spec.command_args = []
            log_file = info.get("log_file")
            if isinstance(log_file, str) and os.path.isfile(log_file):
                spec.log_file = log_file
            if info.get("status") != "DONE":
                continue
            try:
                if not isinstance(log_file, str) or not os.path.isfile(log_file):
                    raise FileNotFoundError(
                        f"qualification returned no log for {spec.name}: {log_file}"
                    )
                final_driver = info.get("final_driver")
                final_binary = info.get("final_binary")
                coverage_binary = info.get("coverage_binary")
                if not isinstance(final_driver, str) or not os.path.isfile(final_driver):
                    raise FileNotFoundError(
                        f"qualification returned no final source for {spec.name}: "
                        f"{final_driver}"
                    )
                if not isinstance(final_binary, str) or not os.path.isfile(final_binary):
                    raise FileNotFoundError(
                        f"qualification returned no final binary for {spec.name}: "
                        f"{final_binary}"
                    )
                if not isinstance(coverage_binary, str):
                    raise FileNotFoundError(
                        f"qualification returned no coverage binary for {spec.name}: "
                        f"{coverage_binary}"
                    )
                attempt_value = info.get("attempt_dir")
                if not isinstance(attempt_value, str):
                    raise ValueError(
                        f"qualification returned no attempt directory for {spec.name}"
                    )
                attempt_dir = Path(attempt_value).resolve(strict=True)
                attempts_dir = (
                    self.store.run_store.stage_dir(REACHABILITY_STAGE, spec.name)
                    / "attempts"
                ).resolve(strict=True)
                if attempt_dir.parent != attempts_dir or not attempt_dir.is_dir():
                    raise ValueError(
                        f"qualification attempt is not assigned to {spec.name} in "
                        f"the current run: {attempt_dir}"
                    )
                work_dir = (attempt_dir / "work").resolve(strict=True)
                coverage_binary_path = Path(coverage_binary).resolve(strict=True)
                if not coverage_binary_path.is_file():
                    raise FileNotFoundError(
                        f"qualification coverage binary is not a file: "
                        f"{coverage_binary_path}"
                    )
                try:
                    coverage_binary_path.relative_to(work_dir)
                except ValueError as exc:
                    raise ValueError(
                        f"qualification coverage binary is outside the assigned "
                        f"attempt: {coverage_binary_path}"
                    ) from exc
                snapshots_dir = (attempt_dir / "work" / "snapshots").resolve()
                corpus_snapshot_value = info.get("corpus_snapshot")
                corpus_snapshot: Optional[Path] = None
                if corpus_snapshot_value is None:
                    if int(info.get("reachability_rounds") or 0) > 0:
                        raise ValueError(
                            f"qualification returned no corpus snapshot for "
                            f"{spec.name} after a completed round"
                        )
                else:
                    if not isinstance(corpus_snapshot_value, str):
                        raise ValueError(
                            f"qualification returned an invalid corpus snapshot for "
                            f"{spec.name}: {corpus_snapshot_value!r}"
                        )
                    corpus_snapshot = Path(corpus_snapshot_value).resolve(strict=True)
                    if not corpus_snapshot.is_dir():
                        raise NotADirectoryError(
                            f"qualification corpus snapshot is not a directory: "
                            f"{corpus_snapshot}"
                        )
                    try:
                        corpus_snapshot.relative_to(snapshots_dir)
                    except ValueError as exc:
                        raise ValueError(
                            f"qualification corpus snapshot is outside the assigned "
                            f"attempt: {corpus_snapshot}"
                        ) from exc
                reaching_input_value = info.get("reaching_input")
                reaching_input: Optional[Path] = None
                if info.get("reachability_outcome") == ReachabilityOutcome.REACHED.value:
                    if not isinstance(reaching_input_value, str):
                        raise ValueError(
                            f"qualification returned no exact reaching input for "
                            f"{spec.name}"
                        )
                    if corpus_snapshot is None:
                        raise ValueError(
                            f"qualification returned a reaching input without a "
                            f"corpus snapshot for {spec.name}"
                        )
                    reaching_input = Path(reaching_input_value).resolve(strict=True)
                    if not reaching_input.is_file():
                        raise FileNotFoundError(
                            f"qualification reaching input is not a file: "
                            f"{reaching_input}"
                        )
                    if reaching_input.parent != corpus_snapshot:
                        raise ValueError(
                            f"qualification reaching input is outside its exact "
                            f"snapshot: {reaching_input}"
                        )
                elif reaching_input_value is not None:
                    raise ValueError(
                        f"non-reaching qualification returned a reaching input for "
                        f"{spec.name}: {reaching_input_value!r}"
                    )

                marker_value = info.get("target_marker_path")
                target_marker_path: Optional[Path] = None
                if marker_value is not None:
                    if not isinstance(marker_value, str):
                        raise ValueError(
                            f"qualification returned an invalid target marker path "
                            f"for {spec.name}: {marker_value!r}"
                        )
                    supplied_marker = Path(marker_value)
                    expected_marker = attempt_dir / "work" / "assert-target-marker" / "hit"
                    if (
                        supplied_marker.name != "hit"
                        or supplied_marker.parent.resolve(strict=True)
                        != expected_marker.parent.resolve(strict=True)
                        or supplied_marker.is_symlink()
                    ):
                        raise ValueError(
                            f"qualification target marker is outside the assigned "
                            f"attempt: {supplied_marker}"
                        )
                    target_marker_path = expected_marker
                    if (
                        info.get("reachability_outcome")
                        == ReachabilityOutcome.REACHED.value
                        and not target_marker_path.is_file()
                    ):
                        raise FileNotFoundError(
                            f"qualification target marker did not record the exact "
                            f"witness: {target_marker_path}"
                        )
                source_snapshot = self.store.run_store.copy_file_or_validate(
                    final_driver,
                    attempt_dir / "final" / "qualification-final.cc",
                )
                binary_snapshot = self.store.run_store.copy_file_or_validate(
                    final_binary,
                    attempt_dir / "final" / "qualification-final.out",
                )
                coverage_snapshot = self.store.run_store.copy_file_or_validate(
                    coverage_binary_path,
                    attempt_dir / "final" / "qualification-coverage.out",
                )
                reaching_snapshot = (
                    self.store.run_store.copy_file_or_validate(
                        reaching_input,
                        attempt_dir / "final" / "qualification-reaching-input",
                    )
                    if reaching_input is not None
                    else None
                )
            except (OSError, ValueError) as exc:
                info.update(
                    {
                        "status": "ERROR",
                        "reachability_outcome": "infrastructure_failed",
                        "qualification_error": f"final artifact snapshot failed: {exc}",
                    }
                )
                qualification_status[index] = info
                continue
            spec.source_path = str(source_snapshot)
            spec.binary_path = str(binary_snapshot)
            info["coverage_binary"] = str(coverage_snapshot)
            info["corpus_snapshot"] = (
                str(corpus_snapshot) if corpus_snapshot is not None else None
            )
            info["reaching_input"] = (
                str(reaching_snapshot) if reaching_snapshot is not None else None
            )
            info["target_marker_path"] = (
                str(target_marker_path) if target_marker_path is not None else None
            )
            qualification_status[index] = info

    def _build_run_specs(
        self,
        binaries: List[str],
        *,
        seed_runtime_corpus: bool = True,
    ) -> List[DriverQualificationSpec]:
        """Build the manifest entries for the selected drivers."""
        specs: List[DriverQualificationSpec] = []
        for binary_path in binaries:
            resolved_binary = str(Path(binary_path).resolve())
            compiled = self._compiled_drivers.get(resolved_binary)
            driver_id = compiled[0] if compiled else Path(binary_path).stem
            if compiled is None:
                raise KeyError(f"binary is absent from current compile result: {binary_path}")
            source_path = compiled[1]
            command_args, env = self.build_runtime_command(
                binary_path,
                driver_id,
                seed_runtime_corpus=seed_runtime_corpus,
            )
            command = " ".join(shlex.quote(part) for part in command_args)
            specs.append(
                DriverQualificationSpec(
                    name=driver_id,
                    binary_path=os.path.abspath(binary_path),
                    source_path=source_path,
                    log_file=str(
                        self.store.run_store.logs_dir(
                            REACHABILITY_STAGE, driver_id
                        )
                        / "qualification.log"
                    ),
                    corpus_dir=str(self.store.driver_path(driver_id, "corpus")),
                    artifact_dir=str(self.store.driver_path(driver_id, "artifacts")),
                    command=command,
                    command_args=command_args,
                    env={
                        "ASAN_OPTIONS": env.get("ASAN_OPTIONS", ""),
                        "UBSAN_OPTIONS": env.get("UBSAN_OPTIONS", ""),
                    },
                )
            )
        return specs

    def _copy_runtime_corpus(self, driver_id: str, driver_corpus: Path) -> None:
        """Seed the fuzz corpus with runtime test cases when available."""
        runtime_corpus = self.workspace_base / "runtime_test" / "corpus" / driver_id
        if not runtime_corpus.exists():
            return

        import shutil

        for corpus_file in runtime_corpus.iterdir():
            if corpus_file.is_file():
                shutil.copy2(corpus_file, driver_corpus / corpus_file.name)

    def _execute_specs(
        self,
        specs: List[DriverQualificationSpec],
        run_id: str,
        *,
        show_progress: bool = True,
    ) -> Dict[int, Dict[str, Any]]:
        """Run each driver qualification in its own process and new attempt.

        Callers pass one driver per probe; driver_rounds bounds how many probes run at once.
        """
        if not specs:
            return {}

        pending: List[Tuple[int, DriverQualificationSpec]] = list(enumerate(specs))
        manager = _PROCESS_CONTEXT.Manager()
        status_dict = manager.dict()
        processes: List[BaseProcess] = []
        processes_by_index: Dict[int, BaseProcess] = {}
        attempt_dirs: Dict[int, Path] = {}
        qualification_status: Dict[int, Dict[str, Any]] = {}
        for index, spec in pending:
            status_dict[index] = {
                "name": spec.name,
                "status": "WAITING",
                "phase": "WAITING",
                "phase_started_at": 0,
                "start_time": 0,
                "elapsed": 0,
            }

        stop_display = threading.Event()
        display_thread: Optional[threading.Thread] = None
        if show_progress:
            display_thread = threading.Thread(
                target=run_qualification_dashboard,
                args=(
                    self.library,
                    run_id,
                    [spec.name for spec in specs],
                    status_dict,
                    stop_display,
                ),
                daemon=True,
            )
            display_thread.start()

        try:
            running: List[Tuple[BaseProcess, int]] = []
            while pending or running:
                while pending:
                    index, spec = pending.pop(0)
                    try:
                        attempt_dirs[index] = _new_qualification_attempt(
                            self.store.run_store.stage_dir(REACHABILITY_STAGE, spec.name)
                        )
                        process = self._start_process(
                            spec,
                            status_dict,
                            index,
                            run_id,
                            assigned_attempt_dir=str(attempt_dirs[index]),
                        )
                    except Exception as exc:
                        _update_status(
                            status_dict,
                            index,
                            status="ERROR",
                            phase="ERROR",
                            phase_started_at=time.time(),
                            reachability_outcome="infrastructure_failed",
                            qualification_error=str(exc),
                            popen_pid=0,
                        )
                        continue
                    processes.append(process)
                    processes_by_index[index] = process
                    running.append((process, index))
                    time.sleep(0.2)

                time.sleep(0.5)
                for item in running[:]:
                    process, index = item
                    if process.is_alive():
                        continue
                    process.join()
                    completed = _validate_worker_result_path(
                        self.store.run_store,
                        attempt_dirs[index] / "worker-result.json",
                        specs[index].name,
                    )
                    if completed is not None:
                        status_dict[index] = completed
                    else:
                        self._handle_worker_exit(
                            status_dict,
                            index,
                            process.exitcode,
                        )
                    running.remove(item)

        except KeyboardInterrupt:
            print("\n\nStopping driver qualification...")
            for process in processes:
                if process.is_alive():
                    process.terminate()
            for process in processes:
                process.join(timeout=2)
            self._terminate_child_fuzzers(status_dict)
            raise
        finally:
            for process in processes_by_index.values():
                process.join(timeout=2)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=2)
                if process.is_alive():
                    process.kill()
                    process.join()
            self._terminate_child_fuzzers(status_dict)
            if display_thread is not None:
                stop_display.set()
                display_thread.join(timeout=2)
            qualification_status = {
                int(index): dict(info)
                for index, info in list(status_dict.items())
            }
            manager.shutdown()

        return qualification_status

    @staticmethod
    def _terminate_process_group(pid: int) -> None:
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            return

        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            try:
                os.killpg(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)

        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    @classmethod
    def _handle_worker_exit(
        cls,
        status_dict: dict,
        index: int,
        exitcode: Optional[int],
    ) -> None:
        info = dict(status_dict.get(index, {}))
        if exitcode == 0 and info.get("status") in {"DONE", "ERROR"}:
            return
        cls._terminate_child_fuzzer(status_dict, index)
        _update_status(
            status_dict,
            index,
            status="ERROR",
            phase="ERROR",
            phase_started_at=time.time(),
            popen_pid=0,
            reachability_outcome="worker_failed",
            qualification_error=(
                f"qualification worker exited with code {exitcode} "
                "before recording a final result"
            ),
        )

    @classmethod
    def _terminate_child_fuzzer(cls, status_dict: dict, index: int) -> None:
        pid = int(dict(status_dict.get(index, {})).get("popen_pid") or 0)
        if pid > 0:
            cls._terminate_process_group(pid)
            _update_status(status_dict, index, popen_pid=0)

    @classmethod
    def _terminate_child_fuzzers(cls, status_dict: dict) -> None:
        """Terminate libFuzzer process groups started by worker processes."""
        for index in list(status_dict.keys()):
            cls._terminate_child_fuzzer(status_dict, index)

    def _start_process(
        self,
        spec: DriverQualificationSpec,
        status_dict: dict,
        index: int,
        run_id: str,
        *,
        assigned_attempt_dir: str,
    ) -> BaseProcess:
        """Create and start the worker process for one spec."""
        target, chain, origin = self._resolve_qualification_target(spec)
        if not target or not chain or not origin:
            raise ValueError(
                f"driver {spec.name} has no candidate-plan target mapping"
            )
        process = _PROCESS_CONTEXT.Process(
            target=_run_driver_qualification,
            args=(
                self.library,
                spec,
                target,
                chain,
                origin,
                run_id,
                self.check_interval_seconds,
                self._max_rounds(),
                status_dict,
                index,
                assigned_attempt_dir,
            ),
        )
        process.start()
        return process

    def _execution_payload(
        self,
        spec: DriverQualificationSpec,
        qualification: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build the persisted execution payload for one completed attempt."""
        stats = parse_fuzzer_log(spec.log_file)
        status = str(qualification.get("status") or stats["status"])
        exit_code = stats["exit_code"]
        if exit_code is None and status in {"DONE", "ERROR"}:
            exit_code = 0 if status == "DONE" else 1
        record = DriverQualificationRecord(
            name=spec.name,
            command=spec.command,
            log_file=spec.log_file,
            binary_path=spec.binary_path,
            source_path=spec.source_path,
            status=status,
            exit_code=exit_code,
            started_at=stats["started_at"],
            finished_at=stats["finished_at"],
            total_runs=int(stats["total_runs"] or 0),
            runtime_seconds=int(stats["runtime_seconds"] or 0),
            exec_per_sec=int(stats["exec_per_sec"] or 0),
            corpus_size=self._count_corpus_files(spec.corpus_dir),
            fuzz_time_seconds=int(stats["fuzz_time_seconds"] or 0),
            error=(
                qualification.get("qualification_error")
                or stats.get("error")
            ),
            reachability_outcome=qualification.get("reachability_outcome"),
            reachability_rounds=int(
                qualification.get("reachability_rounds") or 0
            ),
            crash=qualification.get("crash"),
            coverage_binary=qualification.get("coverage_binary"),
            corpus_snapshot=qualification.get("corpus_snapshot"),
            reaching_input=qualification.get("reaching_input"),
            target_marker_path=qualification.get("target_marker_path"),
        )
        payload = record.to_dict()
        payload["agent_usage"] = driver_agent_usage_summary(
            self.store.run_store,
            spec.name,
        )
        return payload

    def _count_corpus_files(self, corpus_dir: str) -> int:
        if not os.path.isdir(corpus_dir):
            return 0
        with os.scandir(corpus_dir) as entries:
            return sum(1 for entry in entries if entry.is_file())
