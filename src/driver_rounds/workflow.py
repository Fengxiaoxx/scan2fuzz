"""Target-centric, resumable driver orchestration."""

from __future__ import annotations

import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping

from src.compile_repair.workflow import compile_repair_candidate_once
from src.core import build_compile_flags, load_library_config, normalize_language
from src.core.sanitizer_report import attribute_sanitizer_report
from src.driver_generation.inputs import load_candidate_plan, work_item
from src.driver_generation.workflow import (
    generate_candidate,
    load_generation_record,
)
from src.driver_qualification.runtime import FuzzProcessFailure
from src.driver_qualification.workflow import (
    INFRASTRUCTURE_OUTCOMES,
    NONRETRYABLE_INFRASTRUCTURE_OUTCOMES,
)
from src.driver_refinement import refine_candidate_once
from src.experiment import RunArtifactStore
from src.target_reachability import TargetReachabilityWorkflow
from src.tools.compiler import (
    compile_driver,
    compile_driver_signature,
    file_sha256,
    sanitizer_library_path,
)

from .state import (
    CRASH,
    EXHAUSTED,
    INFRASTRUCTURE_FAILED,
    READY_COMPILE,
    READY_GENERATE,
    READY_REACH,
    READY_REFINE,
    READY_TRIAGE,
    REACHED,
    TARGET_STATES,
    TERMINAL_STATES,
    UNRESOLVED_STATIC,
    apply_compile_action,
    apply_generation_result,
    apply_infrastructure_retry,
    apply_refine_action,
    eliminate_candidate,
    initial_target_state,
    mark_ready_refine,
    mark_reached,
    request_triage,
    validate_target_state,
)


_ACTION_STATES = {
    READY_GENERATE,
    READY_COMPILE,
    READY_REACH,
    READY_TRIAGE,
    READY_REFINE,
}
_NOT_REACHED_OUTCOMES = {
    "gave_up",
    "budget_exhausted",
    "target_source_unlinked",
}


class DriverRoundWorkflow:
    """Run one independent durable state machine per static-analysis target."""

    def __init__(
        self,
        library: str,
        store: RunArtifactStore,
        *,
        max_generation_failures: int = 5,
        max_infrastructure_retries: int = 5,
        max_repair_attempts: int = 5,
        max_refine_attempts: int = 5,
        concurrency: int,
        fuzz_concurrency: int,
    ) -> None:
        if max_generation_failures <= 0:
            raise ValueError("max_generation_failures must be positive")
        if max_infrastructure_retries <= 0:
            raise ValueError("max_infrastructure_retries must be positive")
        if max_repair_attempts <= 0:
            raise ValueError("max_repair_attempts must be positive")
        if max_refine_attempts <= 0:
            raise ValueError("max_refine_attempts must be positive")
        if concurrency <= 0:
            raise ValueError("concurrency must be positive")
        if fuzz_concurrency <= 0:
            raise ValueError("fuzz_concurrency must be positive")
        self.library = library
        self.store = store
        self.language = normalize_language(load_library_config(library)["language"])
        self.concurrency = concurrency
        self.fuzz_concurrency = fuzz_concurrency
        self.max_generation_failures = max_generation_failures
        self.max_infrastructure_retries = max_infrastructure_retries
        self.max_repair_attempts = max_repair_attempts
        self.max_refine_attempts = max_refine_attempts
        self.root = store.safe_path("stages/driver_rounds")

    def run(
        self,
        *,
        candidate_rejections: Mapping[str, int] | None = None,
    ) -> Dict[str, Any]:
        plan = load_candidate_plan(self.library, self.store)
        targets = {
            str(target["marker"]): target for target in plan["targets"]
        }
        if len(targets) != len(plan["targets"]):
            raise ValueError("candidate plan contains duplicate target markers")
        self._write_state_manifest(plan)
        states = self._restore_states(targets)
        self._apply_candidate_rejections(
            states,
            targets,
            candidate_rejections or {},
        )
        retry_not_before: dict[str, float] = {}
        infrastructure_retries: Counter[tuple[str, str]] = Counter()
        paused_targets: dict[str, str] = {}
        running: dict[Future[dict[str, Any]], str] = {}

        # Reachability fuzzing is CPU work; every other action may hold an LLM session.
        # Separate pools keep a running fuzzer from occupying an LLM slot and keep LLM
        # sessions within --concurrency, the bound the API keys set.
        with ThreadPoolExecutor(
            max_workers=self.concurrency
        ) as llm_pool, ThreadPoolExecutor(
            max_workers=self.fuzz_concurrency
        ) as fuzz_pool:
            while True:
                if all(
                    state["state"] in TERMINAL_STATES
                    for state in states.values()
                ):
                    break

                now = time.monotonic()
                active_markers = set(running.values())
                for marker in sorted(states):
                    state = states[marker]
                    if (
                        state["state"] not in _ACTION_STATES
                        or marker in active_markers
                        or marker in paused_targets
                        or retry_not_before.get(marker, 0.0) > now
                    ):
                        continue
                    snapshot = deepcopy(state)
                    pool = fuzz_pool if state["state"] == READY_REACH else llm_pool
                    running[
                        pool.submit(
                            self._execute_action,
                            snapshot,
                            targets[marker],
                        )
                    ] = marker

                if not running:
                    delayed = [
                        deadline
                        for marker, deadline in retry_not_before.items()
                        if (
                            states[marker]["state"] in _ACTION_STATES
                            and marker not in paused_targets
                        )
                    ]
                    if not delayed:
                        if paused_targets:
                            details = "; ".join(
                                f"{marker}: {error}"
                                for marker, error in sorted(paused_targets.items())
                            )
                            raise RuntimeError(
                                "infrastructure retry limit reached; target states "
                                f"were preserved for a later run: {details}"
                            )
                        waiting = {
                            marker: state["state"]
                            for marker, state in states.items()
                            if state["state"] not in TERMINAL_STATES
                        }
                        raise RuntimeError(
                            f"target scheduler has no runnable action: {waiting}"
                        )
                    time.sleep(min(max(0.0, min(delayed) - now), 1.0))
                    continue

                done, _ = wait(running, return_when=FIRST_COMPLETED)
                for future in done:
                    marker = running.pop(future)
                    action = future.result()
                    updated, event = self._apply_action(
                        states[marker],
                        targets[marker],
                        action,
                    )
                    states[marker] = updated
                    self._persist_state(marker, event, updated, action)
                    if event == "infrastructure_retry":
                        phase = str(action["phase"])
                        key = (marker, phase)
                        retries = infrastructure_retries[key]
                        nonretryable = phase == "runtime_relink" or (
                            action["record"].get("reachability_outcome")
                            in NONRETRYABLE_INFRASTRUCTURE_OUTCOMES
                        )
                        if nonretryable or retries >= self.max_infrastructure_retries:
                            error = str(
                                action["record"].get("qualification_error")
                                or action["record"].get("error")
                                or updated.get("last_infrastructure_error")
                                or f"{phase} infrastructure failure"
                            )
                            paused_targets[marker] = (
                                f"{phase} cannot proceed: {error}"
                                if nonretryable
                                else f"{phase} failed after {retries} retries: {error}"
                            )
                            retry_not_before.pop(marker, None)
                        else:
                            retries += 1
                            infrastructure_retries[key] = retries
                            retry_not_before[marker] = (
                                time.monotonic()
                                + self._infrastructure_retry_delay(retries)
                            )
                    else:
                        infrastructure_retries.pop(
                            (marker, str(action["phase"])),
                            None,
                        )
                        retry_not_before.pop(marker, None)

        result = self._final_result(plan, states)
        self.store.write_json(self.store.stage_result_path("driver_rounds"), result)
        return result

    def _apply_candidate_rejections(
        self,
        states: Dict[str, Dict[str, Any]],
        targets: Mapping[str, Mapping[str, Any]],
        rejections: Mapping[str, int],
    ) -> None:
        """Durably reject exact current candidates before normal scheduling."""
        unknown = sorted(set(rejections) - set(targets))
        if unknown:
            raise KeyError(
                "unknown target marker(s) in candidate rejection: "
                + ", ".join(unknown)
            )
        for marker in sorted(rejections):
            rejected_index = rejections[marker]
            if isinstance(rejected_index, bool) or not isinstance(
                rejected_index, int
            ):
                raise ValueError(f"invalid candidate rejection index: {marker}")
            target = targets[marker]
            candidate_count = len(target.get("candidates", []))
            if rejected_index < 0 or rejected_index >= candidate_count:
                raise ValueError(
                    f"candidate rejection is out of range: "
                    f"{marker}={rejected_index + 1}/{candidate_count}"
                )
            state = states[marker]
            current_index = state.get("candidate_index")
            if current_index is None:
                raise ValueError(f"{marker} has no candidate to reject")
            current_index = int(current_index)
            if current_index > rejected_index:
                continue
            if current_index != rejected_index:
                raise ValueError(
                    f"{marker} currently uses candidate {current_index + 1}; "
                    f"cannot reject candidate {rejected_index + 1}"
                )
            if state["state"] in TERMINAL_STATES:
                raise ValueError(
                    f"{marker} is already terminal in state {state['state']}"
                )

            previous_driver = str(state["active_driver_id"])
            updated, event = eliminate_candidate(
                state,
                reason="manually_confirmed_static_false_positive",
                details={"operator_rejected": True},
                next_driver_id=self._next_driver_id(state, target),
            )
            action = {
                "phase": "operator_candidate_rejection",
                "record": {
                    "driver_id": previous_driver,
                    "status": "eliminated",
                    "outcome": "manually_confirmed_static_false_positive",
                },
                "previous_candidate_index": current_index,
                "next_candidate_index": updated.get("candidate_index"),
            }
            states[marker] = updated
            self._persist_state(marker, event, updated, action)

    def _execute_action(
        self,
        state: Mapping[str, Any],
        target: Mapping[str, Any],
    ) -> dict[str, Any]:
        validate_target_state(state)
        item = work_item(target, int(state["candidate_index"]))
        if item["driver_id"] != state["active_driver_id"]:
            raise ValueError(
                f"active driver mismatch for {state['marker']}: "
                f"{state['active_driver_id']} != {item['driver_id']}"
            )

        if state["state"] == READY_GENERATE:
            record = generate_candidate(
                item,
                self.library,
                self.language,
                self.store,
                persist_infrastructure_failure=False,
                persist_candidate_failure=False,
                retry_feedback=str(state.get("generation_feedback") or ""),
                quiet=True,
            )
            return {"phase": "driver_generation", "record": record}

        generation = load_generation_record(self.store, item)
        if generation is None or generation.get("success") is not True:
            raise ValueError(
                f"{state['state']} requires successful generation for "
                f"{item['driver_id']}"
            )

        # READY_TRIAGE runs the same single Repair with the pending crash: the Agent
        # first judges driver fault vs library bug and edits only for a driver fault.
        if state["state"] in (READY_COMPILE, READY_TRIAGE):
            record = compile_repair_candidate_once(
                self.store,
                self.library,
                self.language,
                generation,
                source_path=str(
                    state["source_path"] or generation["generated_source"]
                ),
                repair_attempts=dict(state["repair_attempts"]),
                max_repair_attempts=self.max_repair_attempts,
                failed_attempts=list(state["repair_history"]),
                repair_request=dict(state["repair_request"]),
                quiet=True,
            )
            return {"phase": "compile_repair", "record": record}

        if state["state"] == READY_REACH:
            try:
                needs_relink = self._needs_runtime_relink(state)
            except Exception as exc:
                return {
                    "phase": "runtime_relink",
                    "record": {
                        "driver_id": item["driver_id"],
                        "status": "ERROR",
                        "error": f"cannot verify sanitizer binary provenance: {exc}",
                    },
                }
            if needs_relink:
                return {
                    "phase": "runtime_relink",
                    "record": self._relink_runtime_binary(state, item),
                }
            batch = TargetReachabilityWorkflow(
                self.library
            ).run_artifact_candidate(
                item["driver_id"],
                str(state["source_path"]),
                str(state["binary_path"]),
                show_progress=False,
            )
            record = batch.drivers.get(item["driver_id"])
            if record is None:
                record = {
                    "status": "ERROR",
                    "reachability_outcome": INFRASTRUCTURE_FAILED,
                    "error": "reachability worker returned no driver result",
                }
            if record.get("reachability_outcome") == "runtime_failed":
                # Recorded for later comparison with the Agent's verdict; it routes nothing.
                record = {
                    **record,
                    "attribution": attribute_sanitizer_report(
                        record["crash"]["output"],
                        target_function=self._target_function(item),
                    ),
                }
            return {"phase": "target_reachability", "record": record}

        if state["state"] == READY_REFINE:
            if int(state["refine_attempts"]) >= self.max_refine_attempts:
                return {
                    "phase": "driver_refinement",
                    "record": {
                        "driver_id": item["driver_id"],
                        "status": "refine_exhausted",
                        "edited": False,
                    },
                }
            record = refine_candidate_once(
                self.store,
                self.library,
                self.language,
                item,
                source_path=str(
                    state["stable_source_path"] or state["source_path"]
                ),
                reach_feedback=dict(state["reach_feedback"]),
                refine_attempts=int(state["refine_attempts"]),
                refine_history=list(state["refine_history"]),
            )
            return {"phase": "driver_refinement", "record": record}

        raise ValueError(f"no action for target state {state['state']}")

    def _apply_action(
        self,
        state: Mapping[str, Any],
        target: Mapping[str, Any],
        action: Mapping[str, Any],
    ) -> tuple[dict[str, Any], str]:
        phase = str(action["phase"])
        record = action["record"]
        if not isinstance(record, Mapping):
            raise ValueError(f"{phase} result must be an object")

        if phase == "driver_generation":
            return apply_generation_result(
                state,
                record,
                max_failures=self.max_generation_failures,
                next_driver_id=self._next_driver_id(state, target),
            )

        if phase == "compile_repair":
            return apply_compile_action(
                state,
                record,
                max_repairs=self.max_repair_attempts,
                max_refinements=self.max_refine_attempts,
                next_driver_id=self._next_driver_id(state, target),
            )

        if phase == "driver_refinement":
            return apply_refine_action(
                state,
                record,
                max_refinements=self.max_refine_attempts,
                next_driver_id=self._next_driver_id(state, target),
            )

        if phase == "runtime_relink":
            if record.get("status") == "DONE" and record.get("success") is True:
                binary_path = str(record.get("binary_path") or "")
                provenance = record.get("binary_provenance")
                if (
                    record.get("driver_id") != state["active_driver_id"]
                    or not binary_path
                    or not Path(binary_path).is_file()
                    or not isinstance(provenance, dict)
                    or provenance.get("binary_path") != binary_path
                ):
                    raise ValueError("runtime relink returned invalid binary provenance")
                updated = deepcopy(dict(state))
                updated["binary_path"] = binary_path
                updated["binary_provenance"] = dict(provenance)
                updated["last_infrastructure_error"] = ""
                validate_target_state(updated)
                return updated, "runtime_binary_relinked"
            return (
                apply_infrastructure_retry(
                    state,
                    "runtime_relink",
                    str(record.get("error") or "sanitizer binary relink failed"),
                ),
                "infrastructure_retry",
            )

        if phase != "target_reachability":
            raise ValueError(f"unknown target action phase: {phase}")
        reach_outcome = str(record.get("reachability_outcome") or "")
        if (
            record.get("status") != "DONE"
            or reach_outcome in INFRASTRUCTURE_OUTCOMES
        ):
            error = str(
                record.get("qualification_error")
                or record.get("error")
                or "target reachability infrastructure failure"
            )
            return (
                apply_infrastructure_retry(
                    state,
                    "target_reachability",
                    error,
                ),
                "infrastructure_retry",
            )
        if record.get("status") == "DONE" and reach_outcome == "reached":
            return (
                mark_reached(
                    state,
                    self._reach_details(record),
                ),
                "target_reached",
            )
        if record.get("status") == "DONE" and reach_outcome == "runtime_failed":
            return request_triage(
                state,
                self._triage_request(record),
                max_repairs=self.max_repair_attempts,
                max_refinements=self.max_refine_attempts,
                next_driver_id=self._next_driver_id(state, target),
            )
        if record.get("status") == "DONE" and reach_outcome in _NOT_REACHED_OUTCOMES:
            return (
                mark_ready_refine(
                    state,
                    self._reach_details(record),
                ),
                "target_not_reached",
            )
        raise RuntimeError(
            str(
                record.get("error")
                or f"reachability could not decide target state: "
                f"{reach_outcome or 'unknown'}"
            )
        )

    def _needs_runtime_relink(self, state: Mapping[str, Any]) -> bool:
        """Require exact provenance before fuzzing a saved sanitizer binary."""
        provenance = state.get("binary_provenance")
        if not isinstance(provenance, Mapping) or not provenance:
            # Legacy target events have no build fingerprint. A timestamp cannot
            # establish that their binary used the current sanitizer archive.
            return True
        source = Path(str(state["source_path"]))
        binary = Path(str(state["binary_path"]))
        if not source.is_file() or not binary.is_file():
            return True
        library = sanitizer_library_path(self.library)
        expected = {
            "binary_path": str(binary),
            "binary_sha256": file_sha256(binary),
            "source_sha256": file_sha256(source),
            "sanitizer_library": str(library),
            "sanitizer_sha256": file_sha256(library),
            "compile_flags": build_compile_flags(self.library),
            "compiler_signature": compile_driver_signature(str(source), self.library),
        }
        return any(provenance.get(key) != value for key, value in expected.items())

    def _relink_runtime_binary(
        self,
        state: Mapping[str, Any],
        item: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Compile the saved source into an append-only run artifact."""
        marker = str(state["marker"])
        relinks = self.store.safe_path(
            Path("stages/driver_rounds/targets") / marker / "relinks"
        )
        relinks.mkdir(parents=True, exist_ok=True)
        numbers = [
            int(path.name.removeprefix("attempt-"))
            for path in relinks.glob("attempt-[0-9][0-9][0-9]")
            if path.is_dir()
        ]
        attempt = relinks / f"attempt-{max(numbers, default=0) + 1:03d}"
        attempt.mkdir(exist_ok=False)
        output = attempt / "sanitized.out"
        try:
            compiled = compile_driver(
                str(state["source_path"]),
                self.library,
                output_path=str(output),
            )
            if compiled.get("success") is not True:
                diagnostic = str(
                    compiled.get("stderr")
                    or compiled.get("stdout")
                    or "compiler returned nonzero without diagnostics"
                ).strip()
                raise RuntimeError(
                    "saved driver could not be linked with the current "
                    f"sanitizer library: {diagnostic}"
                )
            provenance = compiled.get("binary_provenance")
            if not isinstance(provenance, dict) or not provenance:
                raise RuntimeError("compiler returned no binary provenance")
            candidate_state = {
                **state,
                "binary_path": str(output),
                "binary_provenance": provenance,
            }
            if self._needs_runtime_relink(candidate_state):
                raise RuntimeError(
                    "relinked binary does not match its source or current "
                    "sanitizer library"
                )
            record = {
                "driver_id": item["driver_id"],
                "status": "DONE",
                "success": True,
                "source_path": str(state["source_path"]),
                "binary_path": str(output),
                "binary_provenance": provenance,
                "compile_command": compiled.get("compile_command"),
            }
        except Exception as exc:
            record = {
                "driver_id": item["driver_id"],
                "status": "ERROR",
                "success": False,
                "source_path": str(state["source_path"]),
                "error": f"sanitizer binary relink failed: {exc}",
            }
        self.store.write_json(attempt / "result.json", record)
        return record

    def _restore_states(
        self,
        targets: Mapping[str, Mapping[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        states: Dict[str, Dict[str, Any]] = {}
        for marker, target in targets.items():
            event_paths = sorted(
                self._target_events_dir(marker).glob(
                    "event-[0-9][0-9][0-9][0-9][0-9][0-9].json"
                )
            )
            if event_paths:
                for expected, path in enumerate(event_paths, 1):
                    number = int(path.stem.removeprefix("event-"))
                    if number != expected:
                        raise ValueError(
                            f"target state events are not contiguous: {path}"
                        )
                payload = self.store.read_json(event_paths[-1])
                state = payload.get("target_state")
                if not isinstance(state, dict):
                    raise ValueError(f"invalid target state event: {event_paths[-1]}")
                validate_target_state(state)
            else:
                state = initial_target_state(target)
                self._persist_state(marker, "initialized", state, {})
            self._validate_state_target(state, target)
            states[marker] = state
        return states

    def _persist_state(
        self,
        marker: str,
        event: str,
        state: Mapping[str, Any],
        action: Mapping[str, Any],
    ) -> None:
        validate_target_state(state)
        events_dir = self._target_events_dir(marker)
        events_dir.mkdir(parents=True, exist_ok=True)
        numbers = [
            int(path.stem.removeprefix("event-"))
            for path in events_dir.glob(
                "event-[0-9][0-9][0-9][0-9][0-9][0-9].json"
            )
        ]
        number = max(numbers, default=0) + 1
        self.store.write_json(
            events_dir / f"event-{number:06d}.json",
            {
                "schema_version": 1,
                "event_number": number,
                "event": event,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": self._action_summary(action),
                "target_state": dict(state),
            },
        )

    def _write_state_manifest(self, plan: Mapping[str, Any]) -> None:
        payload = {
            "schema_version": 1,
            "library": self.library,
            "candidate_plan_schema_version": plan["schema_version"],
            "targets": [
                {
                    "target_id": target["target_id"],
                    "marker": target["marker"],
                    "candidate_count": len(target.get("candidates", [])),
                }
                for target in plan["targets"]
            ],
        }
        self.store.write_json_or_validate(
            self.root / "state-manifest.json",
            payload,
        )

    def _final_result(
        self,
        plan: Mapping[str, Any],
        states: Mapping[str, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        targets = [dict(states[str(item["marker"])]) for item in plan["targets"]]
        counts = Counter(target["state"] for target in targets)
        candidate_results = [
            result
            for target in targets
            for result in target["candidate_results"]
        ]
        return {
            "schema_version": 2,
            "library": self.library,
            "status": "completed",
            "success": True,
            "policy": plan["policy"],
            "states": sorted(TARGET_STATES),
            "summary": {
                "targets": len(targets),
                "reached": counts[REACHED],
                "crashed": counts[CRASH],
                "exhausted": counts[EXHAUSTED],
                "unresolved_static": counts[UNRESOLVED_STATIC],
                "drivers_evaluated": len(candidate_results),
                "later_candidates_evaluated": sum(
                    int(item["candidate_index"]) > 0
                    for item in candidate_results
                ),
                "infrastructure_attempts": sum(
                    sum(target["infrastructure_retries"].values())
                    for target in targets
                ),
                "candidate_outcomes": dict(
                    sorted(
                        Counter(
                            item["outcome"] for item in candidate_results
                        ).items()
                    )
                ),
            },
            "targets": targets,
        }

    @staticmethod
    def _next_driver_id(
        state: Mapping[str, Any],
        target: Mapping[str, Any],
    ) -> str | None:
        next_index = int(state["candidate_index"]) + 1
        if next_index >= int(state["candidate_count"]):
            return None
        return str(work_item(dict(target), next_index)["driver_id"])

    @staticmethod
    def _reach_details(record: Mapping[str, Any]) -> Dict[str, Any]:
        details: Dict[str, Any] = {
            "reachability_outcome": str(
                record.get("reachability_outcome") or ""
            ),
            "reachability_rounds": int(
                record.get("reachability_rounds") or 0
            ),
        }
        for field in (
            "depth",
            "chain_len",
            "hit",
            "frontier",
            "log_file",
            "source_path",
            "binary_path",
            "attempt_dir",
            "worker_console_log",
            "error",
            "crash",
            "attribution",
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
        ):
            if field in record:
                details[field] = record[field]
        return details

    @staticmethod
    def _target_function(item: Mapping[str, Any]) -> str:
        """The function enclosing the target line: the last hop of the candidate chain."""
        return str(item["target"]["chain"][-1]["fn"])

    @classmethod
    def _triage_request(cls, record: Mapping[str, Any]) -> Dict[str, Any]:
        crash = record["crash"]
        failure = FuzzProcessFailure(
            command=tuple(crash["command"]),
            returncode=int(crash["returncode"]),
            output=str(crash["output"]),
            artifacts=tuple(crash["artifacts"]),
            work_dir=str(crash["work_dir"]),
        )
        return {
            "kind": "runtime",
            "error": failure.failure_context(),
            "artifact_paths": list(failure.artifacts),
            # Kept for the CRASH record should the Agent judge this a library bug.
            "reach_details": cls._reach_details(record),
        }

    @staticmethod
    def _validate_state_target(
        state: Mapping[str, Any],
        target: Mapping[str, Any],
    ) -> None:
        expected = {
            "target_id": str(target["target_id"]),
            "marker": str(target["marker"]),
            "candidate_count": len(target.get("candidates", [])),
        }
        for field, value in expected.items():
            if state.get(field) != value:
                raise ValueError(
                    f"target state {field} mismatch: {state.get(field)!r} != {value!r}"
                )
        index = state.get("candidate_index")
        if index is not None:
            item = work_item(dict(target), int(index))
            if state.get("active_driver_id") != item["driver_id"]:
                raise ValueError(
                    f"target state active driver mismatch for {state['marker']}"
                )

    @staticmethod
    def _action_summary(action: Mapping[str, Any]) -> Dict[str, Any]:
        summary: Dict[str, Any] = {"phase": str(action.get("phase") or "")}
        record = action.get("record")
        if isinstance(record, Mapping):
            for field in (
                "driver_id",
                "success",
                "failure_kind",
                "outcome",
                "status",
                "passed",
                "reachability_outcome",
                "attribution",
                "verdict",
                "error",
            ):
                if field in record:
                    summary[field] = record[field]
        for field in ("previous_candidate_index", "next_candidate_index"):
            if field in action:
                summary[field] = action[field]
        return summary

    def _target_events_dir(self, marker: str) -> Path:
        return self.root / "targets" / marker / "events"

    @staticmethod
    def _infrastructure_retry_delay(retries: int) -> float:
        return float(min(60, 2 ** min(max(retries - 1, 0), 6)))
