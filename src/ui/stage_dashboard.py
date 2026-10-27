"""AFL-style terminal dashboard for read-only stage observations."""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
from multiprocessing import Event, Process
import threading
import time
from typing import Callable, Literal, Sequence

from rich import box
from rich.columns import Columns
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.table import Table
from rich.text import Text

from src.ui.stage_observer import (
    SnapshotProvider,
    StageObserver,
    StageSnapshot,
    StageTaskSnapshot,
)


_ERROR_STATES = frozenset(
    {"ERROR", "FAILED", "INFRA_ERROR", "INFRASTRUCTURE_FAILED"}
)
_DONE_STATES = frozenset(
    {"DONE", "SUCCESS", "PASSED", "REUSED", "SKIPPED"}
)
_WAITING_STATES = frozenset({"WAITING", "PENDING", "QUEUED"})

_STATE_STYLES = {
    "WAITING": "dim",
    "PENDING": "dim",
    "QUEUED": "dim",
    "RUNNING": "bright_cyan",
    "DONE": "green",
    "SUCCESS": "green",
    "PASSED": "green",
    "REUSED": "cyan",
    "SKIPPED": "yellow",
    "ERROR": "bold red",
    "FAILED": "bold red",
    "INFRA_ERROR": "bold red",
    "INFRASTRUCTURE_FAILED": "bold red",
}


@dataclass(frozen=True, slots=True)
class DashboardColumn:
    """One optional metric column sourced from task.metrics."""

    key: str
    title: str
    min_width: int = 5
    justify: Literal["left", "center", "right"] = "right"

    def __post_init__(self) -> None:
        if not self.key or not self.title:
            raise ValueError("dashboard column key and title must not be empty")
        if self.min_width < 1:
            raise ValueError("dashboard column min_width must be positive")


@dataclass(frozen=True, slots=True)
class StageDashboardSpec:
    """Presentation-only settings; no field controls stage execution."""

    title: str
    task_column: str = "Task"
    task_ratio: int = 3
    attempt_column: str = "Attempt"
    metric_columns: tuple[DashboardColumn, ...] = ()
    compact_status: bool = False
    waiting_before_done: bool = False
    show_task_overview: bool = False
    max_rows: int = 20
    poll_interval: float = 0.5
    refresh_per_second: float = 2.0

    def __post_init__(self) -> None:
        if not self.title or not self.task_column or not self.attempt_column:
            raise ValueError("dashboard titles must not be empty")
        if self.task_ratio < 1:
            raise ValueError("task_ratio must be positive")
        if self.max_rows < 1:
            raise ValueError("max_rows must be positive")
        if self.poll_interval <= 0 or self.refresh_per_second <= 0:
            raise ValueError("dashboard timing values must be positive")


def _task_group(task: StageTaskSnapshot) -> int:
    if task.state in _ERROR_STATES:
        return 1
    if task.state in _DONE_STATES:
        return 2
    if task.state in _WAITING_STATES:
        return 3
    return 0


def select_visible_tasks(
    tasks: Sequence[StageTaskSnapshot],
    max_rows: int,
    *,
    waiting_before_done: bool = False,
) -> tuple[StageTaskSnapshot, ...]:
    """Select active, error, recent-complete, then waiting rows."""
    if max_rows < 1:
        raise ValueError("max_rows must be positive")

    indexed = list(enumerate(tasks))
    groups: list[list[tuple[int, StageTaskSnapshot]]] = [
        [],
        [],
        [],
        [],
    ]
    for item in indexed:
        groups[_task_group(item[1])].append(item)

    visible: list[StageTaskSnapshot] = []
    group_order = (0, 1, 3, 2) if waiting_before_done else (0, 1, 2, 3)
    for group_index in group_order:
        group = groups[group_index]
        if group_index in {1, 2}:
            group.sort(
                key=lambda item: (item[1].updated_at, -item[0]),
                reverse=True,
            )
        for _, task in group:
            if len(visible) == max_rows:
                return tuple(visible)
            visible.append(task)
    return tuple(visible)


def _duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    whole_seconds = max(0, int(seconds))
    minutes, remainder = divmod(whole_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{remainder:02d}"
    return f"{minutes:02d}:{remainder:02d}"


def _elapsed(
    task: StageTaskSnapshot,
    captured_at: float,
) -> tuple[float | None, float | None]:
    phase_elapsed = task.phase_elapsed_seconds
    total_elapsed = task.total_elapsed_seconds
    if task.state not in _DONE_STATES | _ERROR_STATES:
        if phase_elapsed is None and task.phase_started_at is not None:
            phase_elapsed = captured_at - task.phase_started_at
        if total_elapsed is None and task.started_at is not None:
            total_elapsed = captured_at - task.started_at
    return phase_elapsed, total_elapsed


def _state_counts(
    tasks: Sequence[StageTaskSnapshot],
) -> tuple[int, int, int, int]:
    active = errors = done = waiting = 0
    for task in tasks:
        group = _task_group(task)
        if group == 0:
            active += 1
        elif group == 1:
            errors += 1
        elif group == 2:
            done += 1
        else:
            waiting += 1
    return active, errors, done, waiting


def _observer_error(error: BaseException | None) -> RenderableType:
    if error is None:
        return Text("")
    return Text(
        f"observer error: {type(error).__name__}: {error}",
        style="bold red",
        overflow="ellipsis",
    )


def _compact_status(task: StageTaskSnapshot) -> str:
    if task.state == "RUNNING" and task.phase:
        return task.phase
    if task.state == "DONE" and task.phase not in {"", "-", "DONE"}:
        return task.phase
    return task.state


_OVERVIEW_PHASES = {
    "WAITING": ("W", "dim"),
    "RETRY_WAIT": ("W", "dim yellow"),
    "GENERATING": ("G", "bright_cyan"),
    "COMPILING": ("C", "bright_cyan"),
    "REPAIR_COMPILE": ("C", "yellow"),
    "REACHING": ("R", "bright_cyan"),
    "TRIAGE": ("T", "yellow"),
    "REFINING": ("F", "yellow"),
    "REACHED": ("✓", "green"),
    "CRASH": ("X", "bold red"),
    "EXHAUSTED": ("E", "yellow"),
    "UNRESOLVED": ("?", "yellow"),
}


def _task_overview(tasks: Sequence[StageTaskSnapshot]) -> Group:
    tokens: list[Text] = []
    for task in tasks:
        phase = _compact_status(task)
        symbol, style = _OVERVIEW_PHASES.get(phase, (phase[:1], "cyan"))
        label = task.label.removeprefix("TARGET_")
        tokens.append(Text(f"{label}{symbol}", style=style))
    legend = Text(
        "All targets: W wait  G generate  C compile  "
        "R reaching  T triage  F refine  ✓ reached  X crash  E exhausted  ? unresolved",
        style="dim",
    )
    return Group(legend, Columns(tokens, padding=(0, 1), expand=True))


def build_stage_dashboard(
    snapshot: StageSnapshot | None,
    spec: StageDashboardSpec,
    *,
    observer_error: BaseException | None = None,
) -> Group:
    """Build an immutable dashboard frame from one read-only snapshot."""
    tasks = snapshot.tasks if snapshot is not None else ()
    active, errors, done, waiting = _state_counts(tasks)
    visible = (
        select_visible_tasks(
            tasks,
            spec.max_rows,
            waiting_before_done=spec.waiting_before_done,
        )
        if tasks
        else ()
    )

    header = Table.grid(expand=True)
    header.add_column(ratio=1)
    header.add_column(justify="right")
    header.add_row(
        Text(spec.title, style="bold"),
        Text(
            f"running {active}  done {done}/{len(tasks)}  "
            f"errors {errors}  waiting {waiting}",
            style="bold",
        ),
    )
    if snapshot is None:
        header.add_row(Text("waiting for snapshot", style="dim"), Text(""))
    else:
        summary = "  ".join(
            f"{key} {value}"
            for key, value in snapshot.summary.items()
        )
        header.add_row(
            Text(
                f"stage {snapshot.stage}  run {snapshot.run_id}",
                style="dim",
            ),
            Text(
                f"shown {len(visible)}/{len(tasks)}"
                + (f"  {summary}" if summary else ""),
                style="dim",
            ),
        )

    table = Table(
        box=box.SQUARE,
        expand=True,
        show_lines=False,
        header_style="bold",
        pad_edge=False,
    )
    table.add_column(
        spec.task_column,
        ratio=spec.task_ratio,
        overflow="ellipsis",
        no_wrap=True,
    )
    if spec.compact_status:
        table.add_column("Status", min_width=12, no_wrap=True)
    else:
        table.add_column("State", min_width=8, no_wrap=True)
        table.add_column("Phase", min_width=10, no_wrap=True)
    table.add_column(spec.attempt_column, justify="right", min_width=7)
    for column in spec.metric_columns:
        table.add_column(
            column.title,
            justify=column.justify,
            min_width=column.min_width,
        )
    table.add_column("Outcome", min_width=10, no_wrap=True)
    if not spec.compact_status:
        table.add_column("Phase Time", justify="right", min_width=10)
    table.add_column("Total", justify="right", min_width=7)

    if not visible:
        empty_columns = (
            (5 if spec.compact_status else 7) + len(spec.metric_columns)
        )
        table.add_row(
            Text("No observed tasks", style="dim"),
            *("" for _ in range(empty_columns - 1)),
        )
    else:
        captured_at = snapshot.captured_at if snapshot is not None else time.time()
        for task in visible:
            phase_elapsed, total_elapsed = _elapsed(task, captured_at)
            status = (
                _compact_status(task) if spec.compact_status else task.state
            )
            row: list[RenderableType] = [
                task.label,
                Text(
                    status,
                    style=_STATE_STYLES.get(task.state, "bright_cyan"),
                ),
            ]
            if not spec.compact_status:
                row.append(task.phase)
            row.extend(
                [
                    task.attempt,
                    *(
                        task.metrics.get(column.key, "-")
                        for column in spec.metric_columns
                    ),
                    task.outcome,
                ]
            )
            if not spec.compact_status:
                row.append(_duration(phase_elapsed))
            row.append(_duration(total_elapsed))
            table.add_row(*row)

    renderables: list[RenderableType] = [header]
    if spec.show_task_overview and len(tasks) > spec.max_rows:
        renderables.append(_task_overview(tasks))
    renderables.append(table)
    if observer_error is not None:
        renderables.append(_observer_error(observer_error))
    return Group(*renderables)


def run_stage_dashboard(
    provider: SnapshotProvider,
    spec: StageDashboardSpec,
    stop_event: threading.Event,
    *,
    console: Console | None = None,
) -> None:
    """Poll and display snapshots until the caller-owned event is set."""
    observer = StageObserver(provider, poll_interval=spec.poll_interval)
    observer.start()
    try:
        with Live(
            build_stage_dashboard(None, spec),
            console=console,
            refresh_per_second=spec.refresh_per_second,
            screen=False,
            transient=False,
            redirect_stdout=False,
            redirect_stderr=False,
        ) as live:
            while not stop_event.wait(1.0 / spec.refresh_per_second):
                live.update(
                    build_stage_dashboard(
                        observer.latest,
                        spec,
                        observer_error=observer.error,
                    ),
                    refresh=True,
                )
            try:
                observer.poll_once()
            except Exception:
                pass
            live.update(
                build_stage_dashboard(
                    observer.latest,
                    spec,
                    observer_error=observer.error,
                ),
                refresh=True,
            )
    finally:
        observer.stop()


def _run_dashboard_factory(
    provider_factory: Callable[[], SnapshotProvider],
    spec: StageDashboardSpec,
    stop_event,
) -> None:
    try:
        provider = provider_factory()
        run_stage_dashboard(provider, spec, stop_event)
    except Exception:
        return


@contextmanager
def stage_dashboard_process(
    provider_factory: Callable[[], SnapshotProvider],
    spec: StageDashboardSpec,
):
    """Run the read-only dashboard outside the observed stage process."""
    stop_event = None
    process = None
    try:
        stop_event = Event()
        process = Process(
            target=_run_dashboard_factory,
            args=(provider_factory, spec, stop_event),
            name="trace2fuzz-stage-dashboard",
            daemon=True,
        )
        process.start()
    except Exception:
        process = None

    try:
        yield
    finally:
        if process is not None and stop_event is not None:
            def ignore_failure(action) -> None:
                try:
                    action()
                except Exception:
                    pass

            ignore_failure(stop_event.set)
            ignore_failure(lambda: process.join(timeout=5))
            try:
                alive = process.is_alive()
            except Exception:
                alive = True
            if alive:
                ignore_failure(process.terminate)
                ignore_failure(process.join)
