"""Read-only dashboard snapshots for target-centric driver rounds."""

from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any, Mapping

import yaml
from src.experiment.store import stage_directory

from src.driver_rounds.state import (
    CRASH,
    EXHAUSTED,
    READY_COMPILE,
    READY_GENERATE,
    READY_REACH,
    READY_REFINE,
    READY_TRIAGE,
    REACHED,
    UNRESOLVED_STATIC,
    initial_target_state,
)
from src.ui.stage_dashboard import DashboardColumn, StageDashboardSpec
from src.ui.stage_observer import StageSnapshot, StageTaskSnapshot


_TERMINAL_PHASES = {
    REACHED: "REACHED",
    CRASH: "CRASH",
    EXHAUSTED: "EXHAUSTED",
    UNRESOLVED_STATIC: "UNRESOLVED",
}
_STAGE_PATHS = {
    READY_GENERATE: ("driver_generation", "attempts", "attempt-"),
    READY_COMPILE: ("compile_repair", "actions", "action-"),
    READY_REACH: ("target_reachability", "attempts", "attempt-"),
    READY_TRIAGE: ("compile_repair", "actions", "action-"),
    READY_REFINE: ("driver_refinement", "attempts", "attempt-"),
}


class DriverRoundsStageProvider:
    """Observe state events and active action artifacts without controlling work."""

    def __init__(
        self,
        run_dir: Path,
        run_id: str,
        library: str,
        max_generation_failures: int,
        max_repair_attempts: int,
        max_refine_attempts: int,
    ) -> None:
        self.run_dir = Path(run_dir).resolve(strict=True)
        self.run_id = run_id
        self.library = library
        self.max_generation_failures = max_generation_failures
        self.max_repair_attempts = max_repair_attempts
        self.max_refine_attempts = max_refine_attempts
        self.plan = self._read_json(
            self.run_dir / "stages" / "preprocess" / "candidate_plan.json"
        )
        targets = self.plan.get("targets")
        if not isinstance(targets, list):
            raise ValueError("candidate plan has no targets")
        self.targets = tuple(targets)
        self.max_reach_rounds = self._max_reach_rounds()
        self._active_started: dict[str, tuple[Path, float]] = {}

    def __call__(self) -> StageSnapshot:
        tasks = tuple(self._task(target) for target in self.targets)
        summary = {
            "reached": str(sum(task.phase == "REACHED" for task in tasks)),
            "crashed": str(sum(task.phase == "CRASH" for task in tasks)),
            "exhausted": str(sum(task.phase == "EXHAUSTED" for task in tasks)),
            "unresolved": str(sum(task.phase == "UNRESOLVED" for task in tasks)),
        }
        return StageSnapshot(
            stage="driver_rounds",
            run_id=self.run_id,
            tasks=tasks,
            summary=summary,
        )

    def _task(self, target: Mapping[str, Any]) -> StageTaskSnapshot:
        marker = str(target["marker"])
        state, first_event, latest_event = self._target_state(target)
        state_name = str(state["state"])
        candidate_index = state.get("candidate_index")
        candidate_count = int(state["candidate_count"])
        candidate = self._candidate(target, candidate_index)
        driver_id = str(state.get("active_driver_id") or "")
        active_dir = (
            self._active_action_dir(driver_id, state_name, latest_event)
            if latest_event
            else None
        )
        captured_at = time.time()

        if state_name in _TERMINAL_PHASES:
            phase = _TERMINAL_PHASES[state_name]
            task_state = "DONE"
            attempt = "-"
            outcome = phase
            phase_started_at = None
            updated_at = latest_event
            activity = "-"
        elif active_dir is not None:
            phase = self._active_phase(state, active_dir)
            task_state = "RUNNING"
            attempt = self._attempt(state, phase, active_dir)
            outcome = "-"
            phase_started_at = self._phase_started(marker, active_dir)
            updated_at = self._newest_mtime(active_dir)
            activity = _activity(captured_at - updated_at)
        else:
            self._active_started.pop(marker, None)
            phase = (
                "RETRY_WAIT"
                if state.get("last_infrastructure_error")
                else "WAITING"
            )
            task_state = "WAITING"
            attempt = self._attempt(state, state_name, None)
            outcome = "-"
            phase_started_at = None
            updated_at = latest_event
            activity = (
                _activity(captured_at - latest_event)
                if phase == "RETRY_WAIT" and latest_event
                else "-"
            )

        reach = self._reach(state, active_dir if state_name == READY_REACH else None)
        total = None
        if first_event:
            end = latest_event if task_state == "DONE" else captured_at
            total = max(0.0, end - first_event)
        phase_time = (
            _duration(captured_at - phase_started_at)
            if phase_started_at is not None
            else "-"
        )
        candidate_label = (
            f"{int(candidate_index) + 1}/{candidate_count}"
            if candidate_index is not None
            else "-"
        )
        return StageTaskSnapshot(
            task_id=marker,
            label=marker,
            state=task_state,
            phase=phase,
            attempt=attempt,
            outcome=outcome,
            metrics={
                "candidate": candidate_label,
                "api": str(candidate.get("display_name") or "-"),
                "reach": reach,
                "activity": activity,
                "phase_time": phase_time,
            },
            started_at=first_event or None,
            phase_started_at=phase_started_at,
            updated_at=updated_at,
            total_elapsed_seconds=total,
        )

    def _target_state(
        self,
        target: Mapping[str, Any],
    ) -> tuple[dict[str, Any], float, float]:
        events_dir = (
            self.run_dir
            / "stages"
            / "driver_rounds"
            / "targets"
            / str(target["marker"])
            / "events"
        )
        events = sorted(events_dir.glob("event-[0-9][0-9][0-9][0-9][0-9][0-9].json"))
        if not events:
            return initial_target_state(target), 0.0, 0.0
        payload = self._read_json(events[-1])
        state = payload.get("target_state")
        if not isinstance(state, dict):
            raise ValueError(f"invalid driver-round event: {events[-1]}")
        return state, events[0].stat().st_mtime, events[-1].stat().st_mtime

    def _active_action_dir(
        self,
        driver_id: str,
        state_name: str,
        latest_event: float,
    ) -> Path | None:
        if not driver_id or state_name not in _STAGE_PATHS:
            return None
        stage, collection, prefix = _STAGE_PATHS[state_name]
        root = (
            stage_directory(self.run_dir, stage, driver_id)
            / collection
        )
        candidates = sorted(
            path
            for path in root.glob(f"{prefix}[0-9][0-9][0-9]")
            if path.is_dir()
        )
        if not candidates:
            return None
        latest = candidates[-1]
        return latest if latest.stat().st_mtime > latest_event else None

    @staticmethod
    def _candidate(
        target: Mapping[str, Any],
        index: Any,
    ) -> Mapping[str, Any]:
        candidates = target.get("candidates")
        if (
            not isinstance(candidates, list)
            or index is None
            or not 0 <= int(index) < len(candidates)
        ):
            return {}
        value = candidates[int(index)]
        return value if isinstance(value, Mapping) else {}

    @staticmethod
    def _active_phase(state: Mapping[str, Any], active_dir: Path) -> str:
        state_name = str(state["state"])
        if state_name == READY_GENERATE:
            return "GENERATING"
        if state_name == READY_TRIAGE:
            return "TRIAGE"
        if state_name == READY_REACH:
            return "REACHING"
        if state_name == READY_REFINE:
            return "REFINING"
        if state_name == READY_COMPILE:
            if not (active_dir / "work").is_dir():
                return "COMPILING"
            return "REPAIR_COMPILE"
        raise ValueError(f"no display phase for {state_name}")

    def _attempt(
        self,
        state: Mapping[str, Any],
        phase: str,
        active_dir: Path | None,
    ) -> str:
        if phase in {READY_GENERATE, "GENERATING"}:
            return (
                f"{int(state['generation_failures']) + 1}/"
                f"{self.max_generation_failures}"
            )
        if phase == "REPAIR_COMPILE":
            attempts = state.get("repair_attempts", {})
            return (
                f"{int(attempts.get('compile', 0)) + 1}/"
                f"{self.max_repair_attempts}"
            )
        if phase in {READY_TRIAGE, "TRIAGE"}:
            attempts = state.get("repair_attempts", {})
            return (
                f"{int(attempts.get('runtime', 0)) + 1}/"
                f"{self.max_repair_attempts}"
            )
        if phase in {READY_REACH, "REACHING"}:
            progress = self._latest_reach_progress(active_dir)
            current = int(progress.get("round") or progress.get("total_rounds") or 0)
            return f"{current}/{self.max_reach_rounds}"
        if phase in {READY_REFINE, "REFINING"}:
            current = min(
                int(state["refine_attempts"]) + 1,
                self.max_refine_attempts,
            )
            return (
                f"{current}/{self.max_refine_attempts}"
            )
        return "-"

    def _reach(
        self,
        state: Mapping[str, Any],
        active_dir: Path | None,
    ) -> str:
        progress: Mapping[str, Any] = {}
        if active_dir is not None:
            progress = self._latest_reach_progress(active_dir)
        if not progress:
            feedback = state.get("reach_feedback")
            if isinstance(feedback, Mapping):
                progress = feedback
        if not progress:
            results = state.get("candidate_results")
            if isinstance(results, list) and results and isinstance(results[-1], Mapping):
                progress = results[-1]
        depth = progress.get("depth")
        chain_len = progress.get("chain_len")
        hit = progress.get("hit")
        if depth is None or chain_len is None:
            return "-"
        suffix = f" hit={hit}" if hit is not None else ""
        return f"{depth}/{chain_len}{suffix}"

    @staticmethod
    def _latest_reach_progress(active_dir: Path | None) -> Mapping[str, Any]:
        if active_dir is None:
            return {}
        path = active_dir / "run.jsonl"
        if not path.is_file():
            return {}
        latest: dict[str, Any] = {}
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict) and value.get("event") in {
                    "progress",
                    "phase",
                    "result",
                }:
                    latest.update(
                        {
                            key: item
                            for key, item in value.items()
                            if item is not None
                        }
                    )
                    if "rounds" in value:
                        latest["round"] = value["rounds"]
        return latest

    @staticmethod
    def _newest_mtime(root: Path) -> float:
        latest = root.stat().st_mtime
        try:
            for path in root.iterdir():
                try:
                    latest = max(latest, path.stat().st_mtime)
                except OSError:
                    continue
        except OSError:
            pass
        return latest

    def _phase_started(self, marker: str, active_dir: Path) -> float:
        current = self._active_started.get(marker)
        if current is not None and current[0] == active_dir:
            return current[1]
        started = time.time()
        self._active_started[marker] = (active_dir, started)
        return started

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object: {path}")
        return value

    def _max_reach_rounds(self) -> int:
        config = yaml.safe_load(
            (self.run_dir / "config" / "config.yaml").read_text(encoding="utf-8")
        )
        qualification = config.get("driver_qualification", {})
        chunk = int(qualification["chunk_seconds"])
        total = int(qualification["max_total_time"])
        if chunk <= 0 or total <= 0:
            raise ValueError("invalid driver qualification timing")
        return math.ceil(total / chunk)


def driver_rounds_dashboard_spec(library: str) -> StageDashboardSpec:
    return StageDashboardSpec(
        title=f"Trace2Fuzz / {library} driver rounds",
        task_column="Target",
        task_ratio=1,
        attempt_column="Attempt",
        metric_columns=(
            DashboardColumn("candidate", "Candidate", min_width=9),
            DashboardColumn("api", "API", min_width=18, justify="left"),
            DashboardColumn("reach", "Reach", min_width=12),
            DashboardColumn("activity", "Activity", min_width=8),
            DashboardColumn("phase_time", "Phase Time", min_width=10),
        ),
        compact_status=True,
        waiting_before_done=True,
        show_task_overview=True,
        max_rows=20,
        poll_interval=1.0,
        refresh_per_second=1.0,
    )


def _duration(seconds: float) -> str:
    whole = max(0, int(seconds))
    minutes, remainder = divmod(whole, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{remainder:02d}"
    return f"{minutes:02d}:{remainder:02d}"


def _activity(seconds: float) -> str:
    whole = max(0, int(seconds))
    if whole < 5:
        return "now"
    if whole < 60:
        return f"{whole}s"
    return f"quiet {whole // 60}m"
