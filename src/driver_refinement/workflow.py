"""Append-only orchestration for one reachability Refiner action."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Mapping

from src.core import resolve_driver_identity
from src.driver_generation.inputs import resolve_work_item
from src.experiment import RunArtifactStore, validate_driver_id
from src.experiment.edit_snapshots import EditSnapshots
from src.llm import driver_agent_usage_summary

from .agent import ReachabilityRefinerAgent, RefinerResult


def _refine_candidate_once_impl(
    store: RunArtifactStore,
    library: str,
    language: str,
    item: Mapping[str, Any],
    *,
    source_path: str,
    reach_feedback: Mapping[str, Any],
    refine_attempts: int,
    refine_history: list[dict[str, Any]],
) -> dict[str, Any]:
    """Run exactly one reachability Refiner action against a stable source."""
    driver_id = validate_driver_id(str(item["driver_id"]))
    # Establish the durable attempt directory before checking that the source
    # still exists.  A source removed between state restore and execution is a
    # retryable infrastructure failure and should not abort every target.
    source = Path(source_path).resolve()
    attempt_number = refine_attempts + 1
    if attempt_number <= 0:
        raise ValueError("invalid Refiner attempt number")
    attempt_dir = _next_attempt_dir(store, driver_id)
    candidate_path = attempt_dir / "candidate.cc"
    snapshots = EditSnapshots(store, attempt_dir)
    session_dir = store.session_path(driver_id, "refinement")
    session_work_dir = session_dir / "work"
    session_candidate = session_work_dir / f"{driver_id}.cc"
    coverage_evidence = _coverage_evidence_text(reach_feedback)
    rollback = bool(refine_history and refine_history[-1].get("status") == "validation_failed")
    validation_error = (
        str(refine_history[-1].get("error") or "No detailed diagnostic").strip()
        if rollback else ""
    )
    failed_message_id = _failed_turn_message_id(refine_history) if rollback else ""
    fresh_session = attempt_dir.name == "attempt-001" or (
        rollback and (refine_attempts == 1 or not failed_message_id)
    )
    fork_before_message_id = failed_message_id if rollback and not fresh_session else None
    request = {
        "schema_version": 2,
        "prompt_contract": "reachability_refiner_v25",
        "driver_id": driver_id,
        "candidate_index": int(item["candidate_index"]),
        "refine_attempt": attempt_number,
        "source_path": str(source),
        "candidate_path": str(session_candidate),
        "snapshot_path": str(candidate_path),
        "code_location": "",
        "entry_api": str(item["qualified_name"]),
        "reach_feedback": dict(reach_feedback),
        "coverage_evidence": coverage_evidence,
        "refine_history": list(refine_history),
        "session_rollback": "fork" if fork_before_message_id else "fresh" if rollback else "none",
    }
    request_path = attempt_dir / "request.json"
    request_written = False
    agent: ReachabilityRefinerAgent | None = None
    result = None
    failures: list[str] = []
    try:
        source = source.resolve(strict=True)
        request["source_path"] = str(source)
        snapshots.capture_before(source)
        driver_source = snapshots.before.read_text(encoding="utf-8")
        session_dir.mkdir(parents=True, exist_ok=True)
        session_work_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, session_candidate)
        # Freeze the run-scoped code location actually shown to the Agent.
        code_location = _refinement_hint(library, str(source))
        request["code_location"] = code_location
        store.write_json(request_path, request)
        request_written = True
        log_file = store.agent_log_path(
            "driver_refinement",
            driver_id,
            f"{attempt_dir.name}.log",
        )
        log_file.touch(exist_ok=False)
        call_index = _next_call_index(store, driver_id)
        agent = ReachabilityRefinerAgent(
            library,
            language,
            session_candidate,
            session_dir=session_dir,
            new_session=fresh_session,
        )
        result = agent.run(
            driver_id=driver_id,
            entry_api=str(item["qualified_name"]),
            code_location=code_location,
            coverage_evidence=coverage_evidence,
            driver_source=driver_source,
            log_file=log_file,
            call_index=call_index,
            fork_before_message_id=fork_before_message_id,
            validation_error=validation_error,
        )
        if result.error:
            failures.append(f"invalid Refiner result: {result.error}")
    except Exception as exc:
        failures.append(str(exc))
    finally:
        # Preserve any partial edit for audit, but never let snapshot/close
        # cleanup hide the primary failure or escape the infrastructure-retry
        # path.
        if snapshots.before.is_file() and session_candidate.is_file():
            try:
                snapshots.capture_after(session_candidate)
            except Exception as exc:
                failures.append(f"capture after edit failed: {exc}")
        elif snapshots.before.is_file() and not failures:
            failures.append("Driver Refiner candidate disappeared before snapshot")
        if agent is not None:
            try:
                agent.close()
            except Exception as exc:
                failures.append(f"closing Driver Refiner failed: {exc}")

    if result is None and not failures:
        failures.append("Driver Refiner completed without a result")

    if not failures:
        try:
            shutil.copyfile(session_candidate, candidate_path)
        except Exception as exc:
            failures.append(f"copying enhanced candidate failed: {exc}")

    if failures:
        if not request_written:
            request["setup_error"] = "; ".join(failures)
            try:
                store.write_json(request_path, request)
            except Exception as exc:
                failures.append(f"writing Refiner request failed: {exc}")

    try:
        usage_summary = driver_agent_usage_summary(store, driver_id)
        if not isinstance(usage_summary, Mapping):
            raise TypeError("Driver Refiner usage summary must be an object")
        agent_usage = dict(usage_summary)
    except Exception as exc:
        agent_usage = {}
        failures.append(f"collecting Driver Refiner usage failed: {exc}")

    if failures:
        record = _infrastructure_failure_record(
            driver_id=driver_id,
            attempt_number=attempt_number,
            source=source,
            candidate_path=candidate_path,
            attempt_dir=attempt_dir,
            failures=failures,
            agent_usage=agent_usage,
            agent_result=result,
        )
    else:
        record = {
            "schema_version": 2,
            "driver_id": driver_id,
            "refine_attempt": attempt_number,
            "status": result.decision,
            "edited": result.edited,
            "source_path": str(candidate_path),
            "attempt_dir": str(attempt_dir),
            "error": result.error,
            "agent_response": result.response_text,
            "agent_decision": result.decision,
            "agent_evidence": result.evidence,
            "agent_changes": result.changes,
            "user_message_id": result.user_message_id,
            "model": result.model,
            "tool_calls": result.tool_calls,
            "agent_usage": agent_usage,
        }
    return _persist_result_or_failure(
        store,
        attempt_dir / "result.json",
        record,
        driver_id=driver_id,
        attempt_number=attempt_number,
        source=source,
        candidate_path=candidate_path,
        attempt_dir=attempt_dir,
        agent_usage=agent_usage,
        agent_result=result,
    )


def refine_candidate_once(
    store: RunArtifactStore,
    library: str,
    language: str,
    item: Mapping[str, Any],
    *,
    source_path: str,
    reach_feedback: Mapping[str, Any],
    refine_attempts: int,
    refine_history: list[dict[str, Any]],
) -> dict[str, Any]:
    """Run one bounded reachability refinement action."""
    return _refine_candidate_once_impl(
        store,
        library,
        language,
        item,
        source_path=source_path,
        reach_feedback=reach_feedback,
        refine_attempts=refine_attempts,
        refine_history=refine_history,
    )


def _infrastructure_failure_record(
    *,
    driver_id: str,
    attempt_number: int,
    source: Path,
    candidate_path: Path,
    attempt_dir: Path,
    failures: list[str],
    agent_usage: dict[str, Any],
    agent_result: RefinerResult | None,
) -> dict[str, Any]:
    record = {
        "schema_version": 2,
        "driver_id": driver_id,
        "refine_attempt": attempt_number,
        "status": "infrastructure_failed",
        "edited": False,
        "source_path": str(source),
        "candidate_path": str(candidate_path),
        "attempt_dir": str(attempt_dir),
        "error": "; ".join(failures),
        "agent_usage": agent_usage,
        "agent_completed": agent_result is not None,
    }
    if agent_result is not None:
        record.update(
            {
                "agent_response": agent_result.response_text,
                "agent_decision": agent_result.decision,
                "agent_evidence": agent_result.evidence,
                "agent_changes": agent_result.changes,
                "user_message_id": agent_result.user_message_id,
                "model": agent_result.model,
                "tool_calls": agent_result.tool_calls,
            }
        )
    return record


def _persist_result_or_failure(
    store: RunArtifactStore,
    result_path: Path,
    record: dict[str, Any],
    *,
    driver_id: str,
    attempt_number: int,
    source: Path,
    candidate_path: Path,
    attempt_dir: Path,
    agent_usage: dict[str, Any],
    agent_result: RefinerResult | None,
) -> dict[str, Any]:
    """Persist a result without allowing artifact I/O to abort driver rounds."""
    try:
        store.write_json(result_path, record)
        return record
    except Exception as exc:
        if _persisted_record_matches(store, result_path, record):
            return record
        persistence_error = f"writing Refiner result failed: {exc}"

    failures = []
    if record.get("status") == "infrastructure_failed":
        existing_error = str(record.get("error") or "")
        if existing_error:
            failures.append(existing_error)
    failures.append(persistence_error)
    failed_record = _infrastructure_failure_record(
        driver_id=driver_id,
        attempt_number=attempt_number,
        source=source,
        candidate_path=candidate_path,
        attempt_dir=attempt_dir,
        failures=failures,
        agent_usage=agent_usage,
        agent_result=agent_result,
    )
    retry_record = {**failed_record, "result_persisted": True}
    try:
        store.write_json(result_path, retry_record)
        return retry_record
    except Exception as exc:
        if _persisted_record_matches(store, result_path, retry_record):
            return retry_record
        failed_record["result_persisted"] = False
        failed_record["error"] += (
            f"; writing infrastructure failure result failed: {exc}"
        )
        return failed_record


def _persisted_record_matches(
    store: RunArtifactStore,
    result_path: Path,
    record: Mapping[str, Any],
) -> bool:
    try:
        return result_path.is_file() and store.read_json(result_path) == record
    except Exception:
        return False


def _next_attempt_dir(store: RunArtifactStore, driver_id: str) -> Path:
    attempts = (
        store.stage_dir("driver_refinement", driver_id)
        / "attempts"
    )
    attempts.mkdir(parents=True, exist_ok=True)
    numbers = [
        int(path.name.removeprefix("attempt-"))
        for path in attempts.iterdir()
        if path.is_dir()
        and path.name.startswith("attempt-")
        and path.name.removeprefix("attempt-").isdigit()
    ]
    path = attempts / f"attempt-{max(numbers, default=0) + 1:03d}"
    path.mkdir(exist_ok=False)
    return path


def _next_call_index(store: RunArtifactStore, driver_id: str) -> int:
    path = store.usage_path("driver_refinement", driver_id)
    maximum = 0
    if path.is_file():
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"invalid Agent usage JSONL at {path}:{line_number}"
                    ) from exc
                if (
                    record.get("agent") in {
                        "reachability_refiner",
                        "driver_refiner",
                    }
                    and record.get("stage") == "driver_refinement"
                ):
                    maximum = max(maximum, int(record["call_index"]))
    return maximum + 1


def _coverage_evidence_text(feedback: Mapping[str, Any]) -> str:
    """Keep the observed coverage evidence, not the report's repeated status line."""
    progress = []
    for key, label in (
        ("reachability_rounds", "bounded rounds"),
        ("depth", "observed call-chain depth"),
        ("chain_len", "call-chain length"),
        ("covered_branch_outcomes", "covered branch outcomes"),
        ("new_branch_outcomes", "new branch outcomes"),
        ("stale_checks", "consecutive checks without progress"),
    ):
        value = feedback.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            progress.append(f"{label}: {value}")
    for key, label in (("progress_reason", "progress reason"), ("frontier", "observed frontier")):
        value = feedback.get(key)
        if isinstance(value, str) and value.strip():
            progress.append(f"{label}: {value.strip()[:160]}")
    prefix = "Probe progress (this bounded run): " + "; ".join(progress) if progress else ""
    report = feedback.get("reach_report")
    if isinstance(report, str) and report.strip():
        first, separator, evidence = report.strip().partition("\n")
        if (
            first.startswith("Specified code line ")
            and first.endswith(": not covered in this bounded run.")
        ) or (
            first.startswith("指定代码行 ")
            and first.endswith("：本次有界运行未覆盖。")
        ):
            report = evidence if separator else ""
        if report.startswith("Crash observed while replaying the corpus"):
            evidence = "Coverage replay crashed; reliable line-by-line coverage information is not yet available."
            return f"{prefix}\n{evidence}" if prefix else evidence
        if report.strip():
            return f"{prefix}\n{report.strip()}" if prefix else report.strip()
    evidence = "Reliable line-by-line coverage information is not yet available."
    return f"{prefix}\n{evidence}" if prefix else evidence


def _refinement_hint(library: str, driver_file: str) -> str:
    """Return only the code location, never finding prose or vulnerability type."""
    api_id, marker = resolve_driver_identity(library, driver_file)
    if not marker:
        raise ValueError(f"driver has no code-line marker: {driver_file}")
    item = resolve_work_item(library, api_id, marker)
    code_line = item["target"]
    return f"{code_line['file']}:{code_line['line']}"


def _failed_turn_message_id(history: list[dict[str, Any]]) -> str:
    """Find the Refiner turn whose edit the latest rollback rejected."""
    failed_attempt = history[-1].get("attempt")
    for entry in reversed(history[:-1]):
        if entry.get("attempt") == failed_attempt and entry.get("status") == "edited":
            return str(entry.get("user_message_id") or "")
    return ""
