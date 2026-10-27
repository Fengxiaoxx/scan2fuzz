"""Canonical experiment summaries shared by standalone and pipeline runs."""

from __future__ import annotations

from typing import Optional

from .store import RunArtifactStore


PIPELINE_STAGES = (
    "scan",
    "preprocess",
    "driver_rounds",
    "fuzz_run",
)


def collect_stage_statuses(store: RunArtifactStore) -> list[tuple[str, str]]:
    statuses = []
    for stage in PIPELINE_STAGES:
        path = store.stage_result_path(stage)
        if not path.is_file():
            continue
        result = store.read_json(path)
        status = result.get("status", "completed")
        if stage == "scan" and status == "completed" and result.get("target_count") == 0:
            status = "no_targets"
        statuses.append((stage, status))
    return statuses


def collect_metrics(store: RunArtifactStore) -> dict:
    from src.llm.usage import collect_agent_usage_metrics

    metrics = {}
    rounds_path = store.stage_result_path("driver_rounds")
    if rounds_path.is_file():
        metrics["driver_rounds"] = store.read_json(rounds_path).get("summary", {})
    metrics["agent_usage"] = collect_agent_usage_metrics(store)
    return metrics


def finalize_run(store: RunArtifactStore, status: Optional[str] = None) -> None:
    """Refresh the canonical summary from the current immutable stage results."""
    stages = collect_stage_statuses(store)
    if status is None:
        status = (
            "failed"
            if any(stage_status == "failed" for _, stage_status in stages)
            else "partial"
            if any(stage_status == "partial" for _, stage_status in stages)
            else "completed"
        )
    metrics = collect_metrics(store)
    store.replace_json("summary/metrics.json", metrics)
    store.replace_json("summary/result.json", {"status": status, "stages": stages})
