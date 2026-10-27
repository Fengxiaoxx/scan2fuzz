"""AFL-style live dashboard for concurrent driver qualification."""

from __future__ import annotations

import time
from typing import Any, Mapping, Sequence

from rich import box
from rich.console import Group
from rich.live import Live
from rich.table import Table
from rich.text import Text

_PHASE_STYLES = {
    "WAITING": "dim",
    "STARTING": "cyan",
    "BUILDING": "cyan",
    "FUZZING": "bright_cyan",
    "MEASURING": "blue",
    "DONE": "green",
    "ERROR": "bold red",
}

_STATE_STYLES = {
    "PENDING": "yellow",
    "PASSED": "green",
    "REPAIR": "red",
    "FAILED": "bold red",
    "UNMEASURED": "dim",
    "PROGRESS": "cyan",
    "STALLED": "yellow",
    "REACHED": "green",
    "GAVE_UP": "magenta",
    "UNLINKED": "magenta",
    "ERROR": "bold red",
}


def _duration(seconds: int) -> str:
    minutes, remainder = divmod(max(seconds, 0), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{remainder:02d}"
    return f"{minutes:02d}:{remainder:02d}"


def _elapsed(info: Mapping[str, Any], now: float) -> tuple[int, int]:
    status = str(info.get("status") or "WAITING")
    if status in {"DONE", "ERROR"}:
        return 0, int(info.get("elapsed") or 0)
    start = float(info.get("start_time") or 0)
    phase_start = float(info.get("phase_started_at") or 0)
    return (
        int(now - phase_start) if phase_start else 0,
        int(now - start) if start else 0,
    )


def _reach_state(info: Mapping[str, Any]) -> str:
    outcome = str(info.get("reachability_outcome") or "")
    if outcome == "reached":
        return "REACHED"
    if outcome in {"gave_up", "budget_exhausted"}:
        return "GAVE_UP"
    if outcome == "target_source_unlinked":
        return "UNLINKED"
    if outcome in {
        "build_failed",
        "infrastructure_failed",
        "measure_failed",
        "coverage_source_unavailable",
        "runtime_failed",
        "worker_failed",
        "error",
    }:
        return "ERROR"
    if info.get("target_reached") or int(info.get("hit") or 0) > 0:
        return "REACHED"
    last = str(info.get("reachability_status") or "")
    if last == "PROGRESSING":
        return "PROGRESS"
    if last in {"STALLED", "REJECTED"}:
        return "STALLED"
    if str(info.get("status") or "") == "ERROR":
        return "ERROR"
    return "UNMEASURED"


def _styled(value: str, styles: Mapping[str, str]) -> Text:
    return Text(value, style=styles.get(value, ""))


def build_qualification_dashboard(
    library: str,
    run_id: str,
    driver_names: Sequence[str],
    statuses: Mapping[int, Mapping[str, Any]],
    *,
    now: float | None = None,
) -> Group:
    """Build one immutable dashboard frame from worker status snapshots."""
    now = time.time() if now is None else now
    snapshots = [
        dict(statuses.get(index, {}))
        for index in range(len(driver_names))
    ]
    running = sum(info.get("status") == "RUNNING" for info in snapshots)
    done = sum(info.get("status") == "DONE" for info in snapshots)
    errors = sum(info.get("status") == "ERROR" for info in snapshots)
    reached = sum(_reach_state(info) == "REACHED" for info in snapshots)

    header = Table.grid(expand=True)
    header.add_column(ratio=1)
    header.add_column(justify="right")
    header.add_row(
        Text(f"Trace2Fuzz / {library} driver qualification", style="bold"),
        Text(
            f"running {running}  done {done}/{len(driver_names)}  "
            f"errors {errors}",
            style="bold",
        ),
    )
    header.add_row(
        Text(f"run {run_id}", style="dim"),
        Text(f"reached {reached}", style="dim"),
    )

    table = Table(
        box=box.SQUARE,
        expand=True,
        show_lines=False,
        header_style="bold",
        pad_edge=False,
    )
    table.add_column("Driver", ratio=3, overflow="ellipsis", no_wrap=True)
    table.add_column("Phase", min_width=9, no_wrap=True)
    table.add_column("Reach", min_width=10)
    table.add_column("Depth", justify="right", min_width=5)
    table.add_column("Hit", justify="right", min_width=3)
    table.add_column("Phase Time", justify="right", min_width=10)
    table.add_column("Total", justify="right", min_width=5)

    for index, driver_name in enumerate(driver_names):
        info = snapshots[index]
        status = str(info.get("status") or "WAITING")
        phase = (
            status
            if status in {"DONE", "ERROR"}
            else str(info.get("phase") or status)
        )
        depth = info.get("depth")
        chain_len = info.get("chain_len")
        depth_value = (
            f"{depth}/{chain_len}"
            if depth is not None and chain_len is not None
            else "-"
        )
        phase_elapsed, total_elapsed = _elapsed(info, now)
        reach = _reach_state(info)
        table.add_row(
            driver_name,
            _styled(phase, _PHASE_STYLES),
            _styled(reach, _STATE_STYLES),
            depth_value,
            str(int(info.get("hit") or 0)),
            _duration(phase_elapsed) if status == "RUNNING" else "-",
            _duration(total_elapsed),
        )

    return Group(header, table)


def run_qualification_dashboard(
    library: str,
    run_id: str,
    driver_names: Sequence[str],
    statuses,
    stop_event,
) -> None:
    """Render one fixed dashboard until the controller signals completion."""
    with Live(
        build_qualification_dashboard(library, run_id, driver_names, statuses),
        refresh_per_second=2,
        screen=False,
        transient=False,
        redirect_stdout=True,
        redirect_stderr=True,
    ) as live:
        while not stop_event.wait(0.5):
            live.update(
                build_qualification_dashboard(
                    library,
                    run_id,
                    driver_names,
                    statuses,
                ),
                refresh=True,
            )
        live.update(
            build_qualification_dashboard(
                library,
                run_id,
                driver_names,
                statuses,
            ),
            refresh=True,
        )
