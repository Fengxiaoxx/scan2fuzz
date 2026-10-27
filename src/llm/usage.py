"""Strict, run-scoped Agent token and tool telemetry."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from src.core import get_project_root
from src.experiment.store import RunArtifactStore, validate_driver_id, artifact_driver_id


TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
)

MODEL_USAGE_TOKEN_FIELDS = {
    "input_tokens": "inputTokens",
    "output_tokens": "outputTokens",
    "cache_read_input_tokens": "cacheReadInputTokens",
}

TOOL_COUNT_FIELDS = ("total_calls", "succeeded", "failed", "missing_result")


def _safe_subject_component(subject_id: str) -> str:
    if not isinstance(subject_id, str) or not subject_id:
        raise ValueError("subject_id must be a non-empty string")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", subject_id).strip("._") or "subject"
    if safe == subject_id and safe not in {".", ".."}:
        return safe
    digest = hashlib.sha256(subject_id.encode("utf-8")).hexdigest()[:12]
    return f"{safe}__{digest}"


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _mapping_or_none(value: Any, field: str) -> Optional[dict[str, Any]]:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object or null")
    return dict(value)


def _normalize_configured_tools(configured_tools: Sequence[str]) -> list[str]:
    if isinstance(configured_tools, (str, bytes)) or not isinstance(
        configured_tools, Sequence
    ):
        raise ValueError("configured_tools must be a sequence of tool names")
    normalized = list(configured_tools)
    if any(not isinstance(name, str) or not name for name in normalized):
        raise ValueError("configured_tools must contain non-empty strings")
    if len(set(normalized)) != len(normalized):
        raise ValueError("configured_tools must not contain duplicates")
    return normalized


def _sanitize_model_usage(
    model_usage: Optional[Mapping[str, Any]],
) -> Optional[dict[str, dict[str, Any]]]:
    if model_usage is None:
        return None
    sanitized: dict[str, dict[str, Any]] = {}
    for model_name, raw_details in model_usage.items():
        if not isinstance(model_name, str) or not model_name:
            raise ValueError("model_usage keys must be non-empty model names")
        if not isinstance(raw_details, Mapping):
            raise ValueError(f"model_usage[{model_name!r}] must be an object")
        sanitized[model_name] = {
            key: value
            for key, value in raw_details.items()
            if key not in {"costUSD", "cost_usd", "total_cost_usd"}
        }
    return sanitized


def _normalize_model_tokens(
    model_usage: Optional[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    if model_usage is None:
        return normalized
    for model_name, raw_details in model_usage.items():
        tokens: dict[str, Optional[int]] = {}
        for field, raw_field in MODEL_USAGE_TOKEN_FIELDS.items():
            raw_value = raw_details.get(raw_field)
            tokens[field] = (
                None
                if raw_value is None
                else _nonnegative_int(raw_value, f"model_usage.{model_name}.{raw_field}")
            )
        normalized[model_name] = {"tokens": tokens}
    return normalized


def _sum_model_tokens(
    model_tokens: Mapping[str, Mapping[str, Any]],
) -> dict[str, Optional[int]]:
    totals: dict[str, Optional[int]] = {}
    for field in TOKEN_FIELDS:
        values = [
            details.get("tokens", {}).get(field)
            for details in model_tokens.values()
            if details.get("tokens", {}).get(field) is not None
        ]
        totals[field] = sum(values) if values else None
    return totals


def _missing_tool_counts(configured_tools: Sequence[str]) -> dict[str, Any]:
    return {
        **{field: None for field in TOOL_COUNT_FIELDS},
        "by_tool": {
            name: {field: None for field in TOOL_COUNT_FIELDS}
            for name in configured_tools
        },
    }


def _normalize_tool_counts(
    result: Any,
    configured_tools: Sequence[str],
) -> tuple[str, dict[str, Any]]:
    if result is None:
        return "missing", _missing_tool_counts(configured_tools)
    if not isinstance(result.result_message_received, bool):
        raise ValueError("result_message_received must be a boolean")
    if not result.result_message_received:
        return "missing", _missing_tool_counts(configured_tools)
    if not isinstance(result.transcript, list):
        raise ValueError("result.transcript must be a list")

    by_tool = {
        name: {field: 0 for field in TOOL_COUNT_FIELDS}
        for name in configured_tools
    }
    totals = {field: 0 for field in TOOL_COUNT_FIELDS}
    seen_ids: set[str] = set()

    for index, entry in enumerate(result.transcript):
        if not isinstance(entry, Mapping):
            raise ValueError(f"transcript[{index}] must be an object")
        if entry.get("type") != "tool_call":
            continue
        call_id = entry.get("id")
        name = entry.get("name")
        turn_index = entry.get("turn_index")
        result_received = entry.get("result_received")
        is_error = entry.get("is_error")
        if not isinstance(call_id, str) or not call_id:
            raise ValueError(f"transcript[{index}] has no tool call id")
        if call_id in seen_ids:
            raise ValueError(f"duplicate tool call id: {call_id}")
        seen_ids.add(call_id)
        if isinstance(turn_index, bool) or not isinstance(turn_index, int) or turn_index < 1:
            raise ValueError(f"transcript[{index}] has an invalid turn_index")
        if not isinstance(result_received, bool) or not isinstance(is_error, bool):
            raise ValueError(f"transcript[{index}] has invalid tool result state")

        if name not in by_tool:
            continue

        totals["total_calls"] += 1
        by_tool[name]["total_calls"] += 1
        if not result_received:
            outcome = "missing_result"
        elif is_error:
            outcome = "failed"
        else:
            outcome = "succeeded"
        totals[outcome] += 1
        by_tool[name][outcome] += 1

    return "reported", {**totals, "by_tool": by_tool}


def _driver_from_artifact_path(
    store: RunArtifactStore,
    artifact_path: Optional[str],
) -> Optional[str]:
    if not artifact_path:
        return None
    return artifact_driver_id(store.run_dir, Path(artifact_path))


def record_agent_call(
    library_name: str,
    *,
    agent: str,
    stage: str,
    model: str,
    call_index: int,
    configured_tools: Sequence[str],
    result: Any = None,
    error: str = "",
    artifact_path: Optional[str] = None,
    driver_id: Optional[str] = None,
    subject_id: Optional[str] = None,
    subject_kind: Optional[str] = None,
    call_id: Optional[str] = None,
) -> dict[str, Any]:
    """Persist one SDK call without estimating fields absent from its result."""
    if not agent or not stage or not model:
        raise ValueError("agent, stage, and model are required")
    call_index = _nonnegative_int(call_index, "call_index")
    if call_index == 0:
        raise ValueError("call_index must be positive")
    from src.llm.opencode_query import (
        configured_tool_names_for_logs,
        normalize_tool_names_for_logs,
    )

    configured_tools = _normalize_configured_tools(configured_tools)
    if result is not None:
        normalize_tool_names_for_logs(result, configured_tools=configured_tools)
    # Resolve runtime aliases before converting the configuration to display names.
    configured_tools = _normalize_configured_tools(
        configured_tool_names_for_logs(configured_tools)
    )

    store = RunArtifactStore.from_environment(get_project_root(), library_name)
    inferred_driver = _driver_from_artifact_path(store, artifact_path)
    if driver_id is not None:
        driver_id = validate_driver_id(driver_id)
        if inferred_driver is not None and inferred_driver != driver_id:
            raise ValueError(
                f"driver_id {driver_id!r} does not match artifact path driver "
                f"{inferred_driver!r}"
            )
    else:
        driver_id = inferred_driver

    if driver_id is None and subject_id is None:
        raise ValueError("a driver artifact path, driver_id, or subject_id is required")
    if driver_id is None and not subject_kind:
        raise ValueError("subject_kind is required for non-driver usage")

    usage = _mapping_or_none(getattr(result, "usage", None), "usage")
    model_usage = _sanitize_model_usage(
        _mapping_or_none(getattr(result, "model_usage", None), "model_usage")
    )
    model_tokens = _normalize_model_tokens(model_usage)
    token_counts: dict[str, Optional[int]] = {}
    for field in TOKEN_FIELDS:
        raw_value = usage.get(field) if usage is not None else None
        token_counts[field] = (
            None if raw_value is None else _nonnegative_int(raw_value, field)
        )

    tool_telemetry_status, tool_counts = _normalize_tool_counts(
        result, configured_tools
    )
    if result is None:
        duration_ms = None
        result_is_error = True
        result_message_received = False
    else:
        duration_ms = _nonnegative_int(result.duration_ms, "duration_ms")
        result_is_error = bool(result.is_error)
        result_message_received = result.result_message_received

    record = {
        "schema_version": 4,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "agent": agent,
        "stage": stage,
        "model": model,
        "call_index": call_index,
        "call_id": call_id or getattr(result, "call_id", ""),
        "session_id": getattr(result, "session_id", ""),
        "message_usage": getattr(result, "message_usage", []),
        "driver_id": driver_id,
        "subject_id": subject_id,
        "subject_kind": subject_kind,
        "usage_status": "reported" if usage is not None else "missing",
        "tool_telemetry_status": tool_telemetry_status,
        "result_message_received": result_message_received,
        "result_is_error": result_is_error,
        "error": str(error or ""),
        "configured_tools": configured_tools,
        "tools": tool_counts,
        "tokens": token_counts,
        "all_model_tokens": _sum_model_tokens(model_tokens),
        "model_tokens": model_tokens,
        "usage": usage,
        "model_usage": model_usage,
        "duration_ms": duration_ms,
    }

    if getattr(result, "key_events", None):
        record["key_events"] = result.key_events

    relative_path = store.usage_path(stage, driver_id, _safe_subject_component(subject_id or "subject"))
    from src.llm.journal import append_record
    append_record(relative_path, record, unique_key="call_id")
    return record


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.endswith("\n"):
                raise ValueError(f"invalid Agent usage JSONL at {path}:{line_number}")
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(
                    f"invalid Agent usage record at {path}:{line_number}: expected object"
                )
            records.append(value)
    return records


def _sum_optional(records: Iterable[Mapping[str, Any]], field: str) -> tuple[Any, int]:
    values = [record.get(field) for record in records if record.get(field) is not None]
    return (sum(values), len(values)) if values else (None, 0)


def _summarize_tools(calls: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    reported = [
        record
        for record in calls
        if record.get("tool_telemetry_status") == "reported"
    ]
    configured_tools = sorted(
        {
            name
            for record in calls
            for name in record.get("configured_tools", [])
        }
    )
    totals = {
        field: (
            sum(record["tools"][field] for record in reported)
            if reported
            else None
        )
        for field in TOOL_COUNT_FIELDS
    }
    by_tool: dict[str, Any] = {}
    for name in configured_tools:
        configured_calls = [
            record for record in calls if name in record.get("configured_tools", [])
        ]
        tool_reported = [
            record
            for record in configured_calls
            if record.get("tool_telemetry_status") == "reported"
        ]
        by_tool[name] = {
            "configured_calls": len(configured_calls),
            "telemetry_reported_calls": len(tool_reported),
            "telemetry_missing_calls": len(configured_calls) - len(tool_reported),
            **{
                field: (
                    sum(record["tools"]["by_tool"][name][field] for record in tool_reported)
                    if tool_reported
                    else None
                )
                for field in TOOL_COUNT_FIELDS
            },
        }
    return {
        "configured_tools": configured_tools,
        "telemetry_reported_calls": len(reported),
        "telemetry_missing_calls": len(calls) - len(reported),
        **totals,
        "by_tool": by_tool,
    }


def summarize_agent_calls(
    records: Iterable[Mapping[str, Any]],
    *,
    include_breakdowns: bool = True,
) -> dict[str, Any]:
    """Aggregate only mechanically reported values and expose coverage counts."""
    calls = [dict(record) for record in records]
    token_totals: dict[str, Optional[int]] = {}
    token_reported_calls: dict[str, int] = {}
    all_model_token_totals: dict[str, Optional[int]] = {}
    all_model_token_reported_calls: dict[str, int] = {}
    for field in TOKEN_FIELDS:
        values = [
            record.get("tokens", {}).get(field)
            for record in calls
            if record.get("tokens", {}).get(field) is not None
        ]
        token_totals[field] = sum(values) if values else None
        token_reported_calls[field] = len(values)
        model_values = [
            record.get("all_model_tokens", {}).get(field)
            for record in calls
            if record.get("all_model_tokens", {}).get(field) is not None
        ]
        all_model_token_totals[field] = sum(model_values) if model_values else None
        all_model_token_reported_calls[field] = len(model_values)

    duration_ms, duration_reported_calls = _sum_optional(calls, "duration_ms")
    summary: dict[str, Any] = {
        "call_count": len(calls),
        "usage_reported_calls": sum(
            record.get("usage_status") == "reported" for record in calls
        ),
        "usage_missing_calls": sum(
            record.get("usage_status") == "missing" for record in calls
        ),
        "tokens": token_totals,
        "token_reported_calls": token_reported_calls,
        "all_model_tokens": all_model_token_totals,
        "all_model_token_reported_calls": all_model_token_reported_calls,
        "tools": _summarize_tools(calls),
        "duration_ms": duration_ms,
        "duration_reported_calls": duration_reported_calls,
    }
    if include_breakdowns:
        for key, output_key in (("agent", "by_agent"), ("stage", "by_stage")):
            grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for record in calls:
                grouped[str(record.get(key) or "unknown")].append(record)
            summary[output_key] = {
                name: summarize_agent_calls(group, include_breakdowns=False)
                for name, group in sorted(grouped.items())
            }
        models: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in calls:
            for model_name, details in record.get("model_tokens", {}).items():
                models[model_name].append(details)
        summary["by_model"] = {
            model_name: _summarize_model_calls(model_calls)
            for model_name, model_calls in sorted(models.items())
        }
    return summary


def _summarize_model_calls(
    model_calls: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    calls = [dict(call) for call in model_calls]
    totals: dict[str, Optional[int]] = {}
    reported_calls: dict[str, int] = {}
    for field in TOKEN_FIELDS:
        values = [
            call.get("tokens", {}).get(field)
            for call in calls
            if call.get("tokens", {}).get(field) is not None
        ]
        totals[field] = sum(values) if values else None
        reported_calls[field] = len(values)
    return {
        "call_count": len(calls),
        "tokens": totals,
        "token_reported_calls": reported_calls,
    }


def driver_agent_usage_summary(
    store: RunArtifactStore,
    driver_id: str,
) -> dict[str, Any]:
    driver_id = validate_driver_id(driver_id)
    paths = _usage_paths(store, driver_id)
    records = [record for path in paths for record in _read_jsonl(path)]
    return summarize_agent_calls(records)


def _known_driver_subjects(store: RunArtifactStore) -> dict[str, str]:
    links: dict[str, str] = {}
    generation_path = store.stage_result_path("driver_generation")
    if not generation_path.is_file():
        return links
    generation = store.read_json(generation_path)
    for record in generation.get("drivers", []):
        driver_id = validate_driver_id(record["driver_id"])
        api = record.get("api")
        if isinstance(api, str) and api:
            links[driver_id] = api
    return links


def _usage_paths(store: RunArtifactStore, driver_id: Optional[str] = None) -> list[Path]:
    if driver_id is not None:
        return sorted(
            (store.run_dir / "stages").glob(
                f"*/{validate_driver_id(driver_id)}/logs/calls.jsonl"
            )
        )
    return sorted(
        [
            *(store.run_dir / "stages").glob("*/*/logs/calls.jsonl"),
            *(store.run_dir / "stages").glob("*/subjects/*/logs/calls.jsonl"),
        ]
    )


def collect_agent_usage_metrics(store: RunArtifactStore) -> dict[str, Any]:
    """Collect run totals plus direct driver and shared preprocess Agent usage."""
    all_records: list[dict[str, Any]] = []
    driver_records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    subject_records: dict[str, list[dict[str, Any]]] = defaultdict(list)

    usage_paths = _usage_paths(store)

    for path in sorted(usage_paths):
        records = _read_jsonl(path)
        all_records.extend(records)
        for record in records:
            driver_id = record.get("driver_id")
            if driver_id is not None:
                driver_records[validate_driver_id(driver_id)].append(record)
                continue
            subject_id = record.get("subject_id")
            if not isinstance(subject_id, str) or not subject_id:
                raise ValueError(f"non-driver Agent usage record has no subject_id: {path}")
            subject_records[subject_id].append(record)

    driver_subjects = _known_driver_subjects(store)
    drivers_root = store.stage_dir("driver_generation")
    known_driver_ids = set(driver_records) | set(driver_subjects)
    if drivers_root.is_dir():
        known_driver_ids.update(
            validate_driver_id(path.name)
            for path in drivers_root.iterdir()
            if path.is_dir() and path.name not in {"logs", "subjects"}
        )

    driver_summaries: dict[str, Any] = {}
    for driver_id in sorted(known_driver_ids):
        driver_summaries[driver_id] = summarize_agent_calls(
            driver_records.get(driver_id, [])
        )
        subject = driver_subjects.get(driver_id)
        driver_summaries[driver_id]["shared_preprocess_subjects"] = (
            [subject] if subject else []
        )

    return {
        "schema_version": 4,
        "run": summarize_agent_calls(all_records),
        "drivers": driver_summaries,
        "shared_preprocess": {
            subject: summarize_agent_calls(records)
            for subject, records in sorted(subject_records.items())
        },
    }
