"""Reusable driver-generation operations for active API-target candidates."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict

from src.core import make_driver_id
from src.driver_generation.driver_generation_agent import DriverGenerationAgent
from src.driver_generation.inputs import load_api_document
from src.experiment import RunArtifactStore
from src.llm import driver_agent_usage_summary


_ATTEMPT_RE = re.compile(r"attempt-(\d{3})", re.ASCII)


def driver_id_for(item: Dict[str, Any]) -> str:
    computed = make_driver_id(item["api_id"], item["marker"], item["api"])
    planned = item.get("driver_id")
    if planned is not None and planned != computed:
        raise ValueError(
            f"candidate-plan driver identity mismatch: {planned!r} != {computed!r}"
        )
    return computed


def _validate_record(
    store: RunArtifactStore,
    item: Dict[str, Any],
    record: Any,
) -> Dict[str, Any]:
    driver_id = driver_id_for(item)
    if not isinstance(record, dict):
        raise ValueError(f"generation result must be an object for {driver_id}")
    expected = {
        "driver_id": driver_id,
        "api_id": item["api_id"],
        "api": item["api"],
        "abi_symbol": item["abi_symbol"],
        "marker": item["marker"],
        "target_key": item["target_key"],
        "candidate_index": item["candidate_index"],
    }
    for field, value in expected.items():
        if record.get(field) != value:
            raise ValueError(
                f"generation result {field} mismatch for {driver_id}: "
                f"{record.get(field)!r} != {value!r}"
            )
    if not isinstance(record.get("success"), bool):
        raise ValueError(f"generation result has invalid success state for {driver_id}")
    if record["success"]:
        source = Path(str(record.get("generated_source") or "")).resolve()
        expected_source = store.source_path(driver_id, "generated.cc").resolve()
        if source != expected_source or not source.is_file():
            raise ValueError(f"generated source is incomplete for {driver_id}: {source}")
    return record


def load_generation_record(
    store: RunArtifactStore,
    item: Dict[str, Any],
) -> Dict[str, Any] | None:
    """Load and validate one immutable successful or terminal result."""
    result_path = store.stage_result_path(
        "driver_generation", driver_id_for(item)
    )
    if not result_path.is_file():
        return None
    return _validate_record(store, item, store.read_json(result_path))


def _next_attempt_dir(stage_dir: Path) -> Path:
    attempts_dir = stage_dir / "attempts"
    attempts_dir.mkdir(parents=True, exist_ok=True)
    numbers = []
    for path in attempts_dir.iterdir():
        match = _ATTEMPT_RE.fullmatch(path.name)
        if path.is_dir() and match:
            numbers.append(int(match.group(1)))
    attempt_dir = attempts_dir / f"attempt-{max(numbers, default=0) + 1:03d}"
    attempt_dir.mkdir(exist_ok=False)
    return attempt_dir


def _generation_call_offset(store: RunArtifactStore, driver_id: str) -> int:
    calls_path = store.usage_path("driver_generation", driver_id)
    if not calls_path.is_file():
        return 0
    maximum = 0
    with calls_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid Agent usage JSONL at {calls_path}:{line_number}"
                ) from exc
            if (
                record.get("stage") == "driver_generation"
                and record.get("agent") == "driver_generation"
            ):
                maximum = max(maximum, int(record["call_index"]))
    return maximum


def generate_candidate(
    item: Dict[str, Any],
    library: str,
    language: str,
    store: RunArtifactStore,
    *,
    persist_infrastructure_failure: bool = True,
    persist_candidate_failure: bool = True,
    retry_feedback: str = "",
    quiet: bool = False,
) -> Dict[str, Any]:
    """Generate one immutable driver for one exact candidate-plan entry."""
    api_id = item["api_id"]
    driver_id = driver_id_for(item)
    existing = load_generation_record(store, item)
    if existing is not None:
        existing["agent_usage"] = driver_agent_usage_summary(store, driver_id)
        return existing
    record: Dict[str, Any] = {
        "driver_id": driver_id,
        "api_id": api_id,
        "api": item["api"],
        "abi_symbol": item["abi_symbol"],
        "marker": item["marker"],
        "target_key": item["target_key"],
        "candidate_index": item["candidate_index"],
        "candidate_count": item["candidate_count"],
        "candidate_layer": item["candidate_layer"],
        "success": False,
        "failure_kind": "",
        "error": "",
        "generated_source": "",
        "working_source": "",
    }
    try:
        snapshot = store.source_path(driver_id, "generated.cc")
        if snapshot.is_file():
            code = snapshot.read_text(encoding="utf-8")
            if "LLVMFuzzerTestOneInput" not in code:
                raise ValueError(f"incomplete generated source: {snapshot}")
            working_source = snapshot
        else:
            attempt_dir = _next_attempt_dir(
                store.stage_dir("driver_generation", driver_id)
            )
            agent_log = store.agent_log_path("driver_generation", driver_id, f"{attempt_dir.name}.log")
            agent = DriverGenerationAgent(
                item["qualified_name"],
                load_api_document(library, api_id, store),
                [item["target"]],
                library,
                language,
                api_id=api_id,
                quiet=quiet,
                vulnerability_type=str(item.get("vulnerability_type") or ""),
            )
            try:
                result = agent.run(
                    log_file=str(agent_log),
                    call_index_offset=_generation_call_offset(store, driver_id),
                    retry_feedback=retry_feedback,
                )
            finally:
                agent.close()
            if not result["success"]:
                record["failure_kind"] = str(
                    result.get("failure_kind") or "candidate_failed"
                )
                record["retry_feedback"] = str(
                    result.get("retry_feedback") or retry_feedback
                )
                raise RuntimeError(result.get("error") or "driver generation failed")

            working_source = attempt_dir / "generated.cc"
            with working_source.open("x", encoding="utf-8") as handle:
                handle.write(result["code"])
            snapshot = store.copy_source(working_source, driver_id, "generated.cc")
        record.update(
            success=True,
            generated_source=str(snapshot.resolve()),
            working_source=str(working_source.resolve()),
        )
    except Exception as exc:
        record["error"] = str(exc)
        if not record["failure_kind"]:
            record["failure_kind"] = "infrastructure_failed"
    record["agent_usage"] = driver_agent_usage_summary(store, driver_id)
    failure_kind = record.get("failure_kind")
    if (
        record["success"]
        or (failure_kind == "infrastructure_failed" and persist_infrastructure_failure)
        or (failure_kind != "infrastructure_failed" and persist_candidate_failure)
    ):
        store.write_json(
            store.stage_result_path("driver_generation", driver_id),
            record,
        )
    return record
