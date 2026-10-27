"""Persistent target states and deterministic state transitions."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping


READY_GENERATE = "READY_GENERATE"
READY_COMPILE = "READY_COMPILE"
READY_REACH = "READY_REACH"
READY_TRIAGE = "READY_TRIAGE"
REACHED = "REACHED"
CRASH = "CRASH"
READY_REFINE = "READY_REFINE"
EXHAUSTED = "EXHAUSTED"
UNRESOLVED_STATIC = "UNRESOLVED_STATIC"

TARGET_STATES = frozenset(
    {
        READY_GENERATE,
        READY_COMPILE,
        READY_REACH,
        READY_TRIAGE,
        REACHED,
        CRASH,
        READY_REFINE,
        EXHAUSTED,
        UNRESOLVED_STATIC,
    }
)
TERMINAL_STATES = frozenset(
    {REACHED, CRASH, EXHAUSTED, UNRESOLVED_STATIC}
)

GENERATION_FAILED = "generation_failed"
COMPILE_FAILED = "compile_failed"
RUNTIME_FAILED = "runtime_failed"
INFRASTRUCTURE_FAILED = "infrastructure_failed"
REPAIR_KINDS = ("compile", "runtime")


def empty_repair_attempts() -> dict[str, int]:
    return {kind: 0 for kind in REPAIR_KINDS}


def validate_repair_attempts(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != set(REPAIR_KINDS):
        raise ValueError("repair_attempts must contain compile and runtime")
    result = {}
    for kind in REPAIR_KINDS:
        attempts = value[kind]
        if isinstance(attempts, bool) or not isinstance(attempts, int):
            raise ValueError(f"invalid {kind} repair attempt count")
        if attempts < 0:
            raise ValueError(f"invalid {kind} repair attempt count")
        result[kind] = attempts
    return result


def initial_target_state(target: Mapping[str, Any]) -> dict[str, Any]:
    """Build the first durable state for one immutable candidate-plan target."""
    candidates = target.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError(f"target has invalid candidates: {target.get('marker')}")
    marker = str(target["marker"])
    state = {
        "schema_version": 1,
        "target_id": str(target["target_id"]),
        "marker": marker,
        "state": READY_GENERATE if candidates else UNRESOLVED_STATIC,
        "candidate_count": len(candidates),
        "candidate_index": 0 if candidates else None,
        "active_driver_id": (
            str(candidates[0]["driver_id"]) if candidates else None
        ),
        "selected_candidate_index": None,
        "selected_driver_id": None,
        "generation_failures": 0,
        "generation_feedback": "",
        "source_path": "",
        "binary_path": "",
        "binary_provenance": {},
        "repair_attempts": empty_repair_attempts(),
        "repair_history": [],
        "repair_request": {},
        "refine_attempts": 0,
        "refine_history": [],
        "stable_source_path": "",
        "stable_binary_path": "",
        "pending_refinement": False,
        "reach_feedback": {},
        "infrastructure_retries": {},
        "last_infrastructure_error": "",
        "candidate_results": [],
    }
    validate_target_state(state)
    return state


def validate_target_state(state: Mapping[str, Any]) -> None:
    """Reject a state snapshot that cannot be resumed deterministically."""
    value = state.get("state")
    if value not in TARGET_STATES:
        raise ValueError(f"invalid target state: {value!r}")
    count = state.get("candidate_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError(f"invalid candidate_count: {count!r}")
    index = state.get("candidate_index")
    if value == UNRESOLVED_STATIC:
        if count != 0 or index is not None:
            raise ValueError("UNRESOLVED_STATIC must have no candidate")
    elif count == 0:
        raise ValueError(f"{value} cannot have zero candidates")
    elif (
        isinstance(index, bool)
        or not isinstance(index, int)
        or not 0 <= index < count
    ):
        raise ValueError(f"invalid candidate_index: {index!r}/{count}")
    failures = state.get("generation_failures")
    if isinstance(failures, bool) or not isinstance(failures, int) or failures < 0:
        raise ValueError(f"invalid generation_failures: {failures!r}")
    if not isinstance(state.get("generation_feedback"), str):
        raise ValueError("generation_feedback must be a string")
    if not isinstance(state.get("source_path"), str):
        raise ValueError("source_path must be a string")
    if not isinstance(state.get("binary_path"), str):
        raise ValueError("binary_path must be a string")
    if not isinstance(state.get("binary_provenance", {}), dict):
        raise ValueError("binary_provenance must be an object")
    validate_repair_attempts(state.get("repair_attempts"))
    repair_history = state.get("repair_history")
    if not isinstance(repair_history, list) or any(
        not isinstance(entry, dict) for entry in repair_history
    ):
        raise ValueError("invalid repair_history")
    repair_request = state.get("repair_request")
    if not isinstance(repair_request, dict):
        raise ValueError("repair_request must be an object")
    if repair_request and repair_request.get("kind") != "runtime":
        raise ValueError("repair_request has invalid kind")
    # A runtime failure waits in READY_TRIAGE; it never rides along into a compile.
    if value == READY_TRIAGE and not repair_request:
        raise ValueError("READY_TRIAGE requires a runtime repair_request")
    if value == READY_COMPILE and repair_request:
        raise ValueError("READY_COMPILE cannot carry a runtime repair_request")
    refine_attempts = state.get("refine_attempts")
    if (
        isinstance(refine_attempts, bool)
        or not isinstance(refine_attempts, int)
        or refine_attempts < 0
    ):
        raise ValueError("invalid refine_attempts")
    refine_history = state.get("refine_history")
    if not isinstance(refine_history, list) or any(
        not isinstance(entry, dict) for entry in refine_history
    ):
        raise ValueError("invalid refine_history")
    for field in ("stable_source_path", "stable_binary_path"):
        if not isinstance(state.get(field), str):
            raise ValueError(f"{field} must be a string")
    if not isinstance(state.get("pending_refinement"), bool):
        raise ValueError("pending_refinement must be a boolean")
    if not isinstance(state.get("reach_feedback"), dict):
        raise ValueError("reach_feedback must be an object")
    retries = state.get("infrastructure_retries")
    if not isinstance(retries, dict) or any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in retries.values()
    ):
        raise ValueError("invalid infrastructure_retries")
    results = state.get("candidate_results")
    if not isinstance(results, list):
        raise ValueError("candidate_results must be a list")


def apply_generation_result(
    state: Mapping[str, Any],
    record: Mapping[str, Any],
    *,
    max_failures: int = 5,
    next_driver_id: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Apply one Generator action without conflating failures and states."""
    if isinstance(max_failures, bool) or not isinstance(max_failures, int):
        raise ValueError("max_failures must be an integer")
    if max_failures <= 0:
        raise ValueError("max_failures must be positive")
    validate_target_state(state)
    if state["state"] != READY_GENERATE:
        raise ValueError(f"Generator cannot run from {state['state']}")

    updated = deepcopy(dict(state))
    expected_driver = updated["active_driver_id"]
    if record.get("driver_id") != expected_driver:
        raise ValueError(
            "generation result driver mismatch: "
            f"{record.get('driver_id')!r} != {expected_driver!r}"
        )

    if record.get("success") is True:
        updated["state"] = READY_COMPILE
        updated["generation_failures"] = 0
        updated["generation_feedback"] = ""
        updated["source_path"] = str(record.get("generated_source") or "")
        updated["binary_path"] = ""
        updated["binary_provenance"] = {}
        updated["repair_attempts"] = empty_repair_attempts()
        updated["repair_history"] = []
        updated["repair_request"] = {}
        updated["refine_attempts"] = 0
        updated["refine_history"] = []
        updated["stable_source_path"] = ""
        updated["stable_binary_path"] = ""
        updated["pending_refinement"] = False
        updated["reach_feedback"] = {}
        updated["last_infrastructure_error"] = ""
        validate_target_state(updated)
        return updated, "generated"

    failure_kind = str(record.get("failure_kind") or "")
    if failure_kind == INFRASTRUCTURE_FAILED:
        retries = dict(updated["infrastructure_retries"])
        retries["driver_generation"] = retries.get("driver_generation", 0) + 1
        updated["infrastructure_retries"] = retries
        updated["last_infrastructure_error"] = str(
            record.get("error") or "driver generation infrastructure failure"
        )
        validate_target_state(updated)
        return updated, "infrastructure_retry"

    failures = int(updated["generation_failures"]) + 1
    updated["generation_failures"] = failures
    updated["generation_feedback"] = str(record.get("retry_feedback") or "")
    if failures >= max_failures:
        updated, event = eliminate_candidate(
            updated,
            reason=GENERATION_FAILED,
            details={
                "generation_failures": failures,
                "error": str(record.get("error") or "driver generation failed"),
            },
            next_driver_id=next_driver_id,
        )
    else:
        event = "generation_retry"
    validate_target_state(updated)
    return updated, event


def apply_compile_action(
    state: Mapping[str, Any],
    record: Mapping[str, Any],
    *,
    max_repairs: int = 5,
    max_refinements: int = 5,
    next_driver_id: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Apply one Repair action: a compile in READY_COMPILE, a runtime triage in READY_TRIAGE."""
    if isinstance(max_repairs, bool) or not isinstance(max_repairs, int):
        raise ValueError("max_repairs must be an integer")
    if max_repairs <= 0:
        raise ValueError("max_repairs must be positive")
    validate_target_state(state)
    if state["state"] not in (READY_COMPILE, READY_TRIAGE):
        raise ValueError(f"Repair cannot run from {state['state']}")

    updated = deepcopy(dict(state))
    expected_driver = updated["active_driver_id"]
    if record.get("driver_id") != expected_driver:
        raise ValueError(
            "compile result driver mismatch: "
            f"{record.get('driver_id')!r} != {expected_driver!r}"
        )

    if record.get("outcome") == INFRASTRUCTURE_FAILED:
        return (
            apply_infrastructure_retry(
                updated,
                "compile_repair",
                str(record.get("error") or "compile infrastructure failure"),
            ),
            "infrastructure_retry",
        )

    if record.get("action") != "compile_repair":
        action = str(record.get("action") or "")
        raise ValueError(f"invalid compile action: {action!r}")
    current_attempts = validate_repair_attempts(updated["repair_attempts"])
    returned_attempts = validate_repair_attempts(record.get("repair_attempts"))
    if any(value > max_repairs for value in returned_attempts.values()):
        raise ValueError(f"repair attempt count exceeds {max_repairs}")
    history = record.get("repair_history", updated["repair_history"])
    if not isinstance(history, list) or any(
        not isinstance(entry, dict) for entry in history
    ):
        raise ValueError("compile action returned invalid repair_history")
    updated["repair_attempts"] = returned_attempts
    updated["repair_history"] = list(history)
    updated["source_path"] = str(record.get("source_path") or updated["source_path"])
    updated["binary_path"] = str(record.get("binary_path") or "")
    updated["binary_provenance"] = dict(record.get("binary_provenance") or {})
    repair_request = record.get("repair_request", updated["repair_request"])
    if not isinstance(repair_request, dict):
        raise ValueError("compile action returned invalid repair_request")
    updated["repair_request"] = dict(repair_request)
    updated["last_infrastructure_error"] = ""

    outcome = str(record.get("outcome") or "")
    if record.get("success") is True:
        if state["state"] != READY_COMPILE:
            raise ValueError("a runtime triage cannot end as a compile success")
        if returned_attempts != current_attempts:
            raise ValueError("successful compile changed Repair counters")
        updated["state"] = READY_REACH
        updated["repair_request"] = {}
        validate_target_state(updated)
        return updated, "compiled"

    failure_origin = str(record.get("failure_origin") or "compile")
    if failure_origin not in REPAIR_KINDS:
        raise ValueError(f"invalid Repair origin: {failure_origin!r}")
    if (failure_origin == "runtime") != (state["state"] == READY_TRIAGE):
        raise ValueError(
            f"{failure_origin} Repair result does not belong to {state['state']}"
        )
    changed = [
        kind
        for kind in REPAIR_KINDS
        if returned_attempts[kind] != current_attempts[kind]
    ]
    consumed_one = (
        changed == [failure_origin]
        and returned_attempts[failure_origin]
        == current_attempts[failure_origin] + 1
    )

    if outcome == "library_bug":
        if failure_origin != "runtime" or not consumed_one:
            raise ValueError("library_bug must come from one runtime triage")
        details = {
            **dict(updated["repair_request"].get("reach_details") or {}),
            "verdict": "library_bug",
            "evidence": str(record.get("evidence") or ""),
        }
        return mark_crashed(updated, details), "library_crash_confirmed"

    if outcome == "repair_applied":
        if not consumed_one:
            raise ValueError("repair_applied did not consume exactly one attempt")
        if not updated["source_path"]:
            raise ValueError("repair_applied requires source_path")
        updated["repair_request"] = {}
        updated["state"] = READY_COMPILE
        validate_target_state(updated)
        return updated, "candidate_repaired"

    if outcome == "repair_failed":
        if not consumed_one:
            raise ValueError("repair_failed did not consume exactly one attempt")
        if (
            returned_attempts[failure_origin] < max_repairs
            and record.get("terminal") is not True
        ):
            validate_target_state(updated)
            return updated, "repair_retry"
    elif outcome not in {COMPILE_FAILED, "repair_exhausted"}:
        raise ValueError(f"invalid compile action outcome: {outcome!r}")

    error = str(
        record.get("error")
        or record.get("compile_error")
        or "compile repair exhausted"
    )
    if outcome in {COMPILE_FAILED, "repair_exhausted"}:
        canonical_compile_sync = (
            outcome == COMPILE_FAILED
            and returned_attempts["runtime"] == current_attempts["runtime"]
            and returned_attempts["compile"] >= current_attempts["compile"]
        )
        if changed and not consumed_one and not canonical_compile_sync:
            raise ValueError("terminal Repair result changed invalid counters")
        reason = RUNTIME_FAILED if failure_origin == "runtime" else COMPILE_FAILED
        if updated["pending_refinement"]:
            updated = rollback_refinement(updated, error)
            if int(updated["refine_attempts"]) < max_refinements:
                updated["state"] = READY_REFINE
                validate_target_state(updated)
                return updated, "refinement_validation_failed"
        updated, event = eliminate_candidate(
            updated,
            reason=reason,
            details={
                "repair_attempts": dict(returned_attempts),
                "error": error,
            },
            next_driver_id=next_driver_id,
        )
        validate_target_state(updated)
        return updated, event
    raise ValueError(f"non-terminal compile action ended as {outcome!r}")


def apply_infrastructure_retry(
    state: Mapping[str, Any],
    phase: str,
    error: str,
) -> dict[str, Any]:
    """Record a retryable execution failure without changing target state."""
    validate_target_state(state)
    if state["state"] in TERMINAL_STATES:
        raise ValueError(
            f"terminal state cannot retry infrastructure: {state['state']}"
        )
    if not phase:
        raise ValueError("infrastructure retry requires a phase")
    updated = deepcopy(dict(state))
    retries = dict(updated["infrastructure_retries"])
    retries[phase] = retries.get(phase, 0) + 1
    updated["infrastructure_retries"] = retries
    updated["last_infrastructure_error"] = error
    validate_target_state(updated)
    return updated


def eliminate_candidate(
    state: Mapping[str, Any],
    *,
    reason: str,
    details: Mapping[str, Any] | None = None,
    next_driver_id: str | None,
) -> tuple[dict[str, Any], str]:
    """Atomically mark the current candidate and activate the next unmarked one."""
    validate_target_state(state)
    updated = deepcopy(dict(state))
    result = {
        "candidate_index": updated["candidate_index"],
        "driver_id": updated["active_driver_id"],
        "status": "eliminated",
        "reason": reason,
        "outcome": reason,
    }
    if details:
        result.update(dict(details))
    updated["candidate_results"].append(result)
    next_index = int(updated["candidate_index"]) + 1
    updated["generation_failures"] = 0
    updated["generation_feedback"] = ""
    updated["source_path"] = ""
    updated["binary_path"] = ""
    updated["binary_provenance"] = {}
    updated["repair_attempts"] = empty_repair_attempts()
    updated["repair_history"] = []
    updated["repair_request"] = {}
    updated["refine_attempts"] = 0
    updated["refine_history"] = []
    updated["stable_source_path"] = ""
    updated["stable_binary_path"] = ""
    updated["pending_refinement"] = False
    updated["reach_feedback"] = {}
    updated["last_infrastructure_error"] = ""
    if next_index >= int(updated["candidate_count"]):
        if next_driver_id is not None:
            raise ValueError("exhausted target cannot have a next driver")
        updated["state"] = EXHAUSTED
        event = "candidates_exhausted"
    else:
        if not next_driver_id:
            raise ValueError("next candidate must have a driver identity")
        updated["candidate_index"] = next_index
        updated["active_driver_id"] = next_driver_id
        updated["state"] = READY_GENERATE
        event = "candidate_activated"
    validate_target_state(updated)
    return updated, event


def _probe_completed(state: Mapping[str, Any]) -> dict[str, Any]:
    """A reachability probe that ran to completion validates the current driver."""
    updated = deepcopy(dict(state))
    updated["stable_source_path"] = updated["source_path"]
    updated["stable_binary_path"] = updated["binary_path"]
    updated["pending_refinement"] = False
    return updated


def mark_reached(
    state: Mapping[str, Any],
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Select the current candidate as the target's successful driver."""
    validate_target_state(state)
    if state["state"] != READY_REACH:
        raise ValueError(f"target cannot be reached from {state['state']}")
    updated = _probe_completed(state)
    record = {
        "candidate_index": updated["candidate_index"],
        "driver_id": updated["active_driver_id"],
        "status": "selected",
        "outcome": "reached",
    }
    if details:
        record.update(dict(details))
    updated["candidate_results"].append(record)
    updated["reach_feedback"] = dict(details or {})
    updated["state"] = REACHED
    updated["selected_candidate_index"] = updated["candidate_index"]
    updated["selected_driver_id"] = updated["active_driver_id"]
    validate_target_state(updated)
    return updated


def mark_crashed(
    state: Mapping[str, Any],
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Stop the target once triage confirms its crash is a library bug."""
    validate_target_state(state)
    if state["state"] != READY_TRIAGE:
        raise ValueError(f"target cannot crash from {state['state']}")
    updated = deepcopy(dict(state))
    record = {
        "candidate_index": updated["candidate_index"],
        "driver_id": updated["active_driver_id"],
        "status": "crashed",
        "outcome": "crash",
    }
    if details:
        record.update(dict(details))
    updated["candidate_results"].append(record)
    updated["reach_feedback"] = dict(details or {})
    updated["state"] = CRASH
    validate_target_state(updated)
    return updated


def request_triage(
    state: Mapping[str, Any],
    repair_request: Mapping[str, Any],
    *,
    max_repairs: int = 5,
    max_refinements: int = 5,
    next_driver_id: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Send a reachability crash to the Repair Agent, which judges it before any edit."""
    validate_target_state(state)
    if state["state"] != READY_REACH:
        raise ValueError(f"crash cannot be triaged from {state['state']}")
    if repair_request.get("kind") != "runtime":
        raise ValueError("crash triage requires a runtime repair_request")
    updated = deepcopy(dict(state))
    attempts = validate_repair_attempts(updated["repair_attempts"])
    if attempts["runtime"] >= max_repairs:
        error = str(repair_request["error"])
        if updated["pending_refinement"]:
            updated = rollback_refinement(updated, error)
            if int(updated["refine_attempts"]) < max_refinements:
                updated["state"] = READY_REFINE
                validate_target_state(updated)
                return updated, "refinement_validation_failed"
        return eliminate_candidate(
            updated,
            reason=RUNTIME_FAILED,
            details={
                "repair_attempts": dict(attempts),
                "error": error,
            },
            next_driver_id=next_driver_id,
        )
    updated["repair_request"] = dict(repair_request)
    updated["state"] = READY_TRIAGE
    validate_target_state(updated)
    return updated, "triage_requested"


def mark_ready_refine(
    state: Mapping[str, Any],
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Record a completed reach miss that is ready for refinement."""
    validate_target_state(state)
    if state["state"] != READY_REACH:
        raise ValueError(f"target cannot be marked not reached from {state['state']}")
    updated = _probe_completed(state)
    updated["reach_feedback"] = dict(details or {})
    updated["state"] = READY_REFINE
    validate_target_state(updated)
    return updated


def apply_refine_action(
    state: Mapping[str, Any],
    record: Mapping[str, Any],
    *,
    max_refinements: int = 5,
    next_driver_id: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Apply one Refiner response without compiling or running its edit."""
    if max_refinements <= 0:
        raise ValueError("max_refinements must be positive")
    validate_target_state(state)
    if state["state"] != READY_REFINE:
        raise ValueError(f"Refiner cannot run from {state['state']}")
    updated = deepcopy(dict(state))
    if record.get("driver_id") != updated["active_driver_id"]:
        raise ValueError("Refiner result driver mismatch")

    if record.get("status") == INFRASTRUCTURE_FAILED:
        return (
            apply_infrastructure_retry(
                updated,
                "driver_refinement",
                str(record.get("error") or "Refiner infrastructure failure"),
            ),
            "infrastructure_retry",
        )

    if record.get("status") == "refine_exhausted":
        if int(updated["refine_attempts"]) < max_refinements:
            raise ValueError("Refiner cannot exhaust before consuming its budget")
        return eliminate_candidate(
            updated,
            reason="refine_exhausted",
            details={"refine_attempts": int(updated["refine_attempts"])},
            next_driver_id=next_driver_id,
        )

    expected_attempt = int(updated["refine_attempts"]) + 1
    if int(record.get("refine_attempt") or 0) != expected_attempt:
        raise ValueError("Refiner attempt result is stale")
    status = str(record.get("status") or "")
    if status not in {"edited", "no_edit", "unreachable"}:
        raise ValueError(f"invalid Refiner result status: {status!r}")

    updated["refine_attempts"] = expected_attempt
    updated["refine_history"].append(
        {
            "attempt": expected_attempt,
            "status": status,
            "source_path": str(record.get("source_path") or ""),
            "error": str(record.get("error") or ""),
            "agent_decision": str(record.get("agent_decision") or ""),
            "agent_evidence": str(record.get("agent_evidence") or ""),
            "agent_changes": str(record.get("agent_changes") or ""),
            "user_message_id": str(record.get("user_message_id") or ""),
        }
    )
    if status == "edited" and record.get("edited") is not True:
        raise ValueError("edited Refiner result must set edited=true")
    if record.get("edited") is True and status == "edited":
        source_path = str(record.get("source_path") or "")
        if not source_path:
            raise ValueError("edited Refiner result has no source")
        updated["source_path"] = source_path
        updated["binary_path"] = ""
        updated["binary_provenance"] = {}
        updated["pending_refinement"] = True
        updated["repair_attempts"] = empty_repair_attempts()
        updated["repair_history"] = []
        updated["repair_request"] = {}
        updated["state"] = READY_COMPILE
        validate_target_state(updated)
        return updated, "refined"

    if record.get("edited") is not False:
        raise ValueError("unchanged Refiner result must set edited=false")
    if status == "unreachable":
        evidence = str(record.get("agent_evidence") or "").strip()
        if not evidence:
            raise ValueError("unreachable Refiner result requires evidence")
        return eliminate_candidate(
            updated,
            reason="refiner_unreachable",
            details={"refine_attempts": expected_attempt, "evidence": evidence},
            next_driver_id=next_driver_id,
        )
    # A no-edit decision needs new fuzz/coverage evidence before asking the
    # same Agent again; the validated source and binary remain unchanged.
    # Even at the edit limit, one final measurement can establish reachability.
    updated["state"] = READY_REACH
    validate_target_state(updated)
    return updated, "continue_fuzz"


def rollback_refinement(
    state: Mapping[str, Any],
    error: str,
) -> dict[str, Any]:
    """Restore the last source whose reachability probe completed after a bad refined edit."""
    updated = deepcopy(dict(state))
    if not updated.get("stable_source_path"):
        raise ValueError("cannot roll back refinement without stable source")
    updated["refine_history"].append(
        {
            "attempt": int(updated["refine_attempts"]),
            "status": "validation_failed",
            "source_path": str(updated.get("source_path") or ""),
            "error": error,
        }
    )
    updated["source_path"] = str(updated["stable_source_path"])
    updated["binary_path"] = str(updated["stable_binary_path"])
    updated["binary_provenance"] = {}
    updated["pending_refinement"] = False
    updated["repair_attempts"] = empty_repair_attempts()
    updated["repair_history"] = []
    updated["repair_request"] = {}
    validate_target_state(updated)
    return updated
