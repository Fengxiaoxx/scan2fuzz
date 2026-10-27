"""Concise structured audit trail for reachability monitor runs."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from .progress import Progress

if TYPE_CHECKING:
    from .monitor import QualificationPhaseEvent
    from .stall import StallDecision


def append(jsonl_path: str, record: dict) -> None:
    """Append one compact JSON line."""
    with open(jsonl_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def progress_fields(p: Optional[Progress]) -> dict:
    """JSON-safe measurement summaries; keep branch sets out of run logs."""
    branches = p.branch_coverage if p is not None else None
    return {
        "hit": p.hit if p is not None else None,
        "depth": p.depth if p is not None else None,
        "chain_len": p.chain_len if p is not None else None,
        "frontier": p.frontier_fn if p is not None else None,
        "branch_coverage_available": branches is not None,
        "covered_branch_outcomes": len(branches.covered) if branches is not None else None,
    }


def decision_fields(decision: Optional["StallDecision"]) -> dict:
    """Expose policy observations separately from coverage measurements."""
    return {
        "progress_reason": decision.reason if decision is not None else None,
        "new_branch_outcomes": decision.new_branch_outcomes if decision is not None else None,
        "stale_checks": decision.stale_checks if decision is not None else None,
    }


def _recorded_at() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_event_logger(jsonl_path: str):
    """Return an event callback that records each coverage probe."""
    def on_event(
        rnd: int,
        progress: Optional[Progress],
        status: str,
        *,
        decision: Optional["StallDecision"] = None,
    ) -> None:
        append(
            jsonl_path,
            {
                "event": "progress",
                "recorded_at": _recorded_at(),
                "round": rnd,
                "status": status,
                **progress_fields(progress),
                **decision_fields(decision),
            },
        )

    return on_event


def log_phase(jsonl_path: str, event: "QualificationPhaseEvent") -> None:
    """Append one observable monitor phase transition."""
    append(
        jsonl_path,
        {
            "event": "phase",
            "recorded_at": _recorded_at(),
            "phase": event.phase.value,
            "total_rounds": event.total_rounds,
            "candidate_round": event.candidate_round,
            "target_reached": event.target_reached,
            "detail": event.detail,
            **progress_fields(event.progress),
        },
    )


def log_result(jsonl_path: str, result) -> None:
    """Append the final structured result line."""
    last = result.last
    record = {
        "event": "result",
        "recorded_at": _recorded_at(),
        "outcome": result.outcome.value,
        "rounds": result.rounds,
        **progress_fields(last),
        "driver": result.driver,
        "coverage_binary": result.coverage_binary,
        "corpus_snapshot": result.corpus_snapshot,
        "reaching_input": result.reaching_input,
        "target_marker_path": result.target_marker_path,
    }
    if result.failure is not None:
        record["crash"] = result.failure.to_dict()
    append(jsonl_path, record)
