"""Thread-safe, in-memory polling for read-only stage snapshots."""

from __future__ import annotations

from dataclasses import dataclass, field
import threading
import time
from types import MappingProxyType
from typing import Callable, Mapping, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class StageTaskSnapshot:
    """One immutable task row supplied by a stage-specific adapter."""

    task_id: str
    label: str
    state: str
    phase: str = "-"
    attempt: str = "-"
    outcome: str = "-"
    metrics: Mapping[str, str] = field(default_factory=dict)
    started_at: float | None = None
    phase_started_at: float | None = None
    updated_at: float = 0.0
    phase_elapsed_seconds: float | None = None
    total_elapsed_seconds: float | None = None

    def __post_init__(self) -> None:
        if not self.task_id:
            raise ValueError("task_id must not be empty")
        if not self.label:
            raise ValueError("label must not be empty")
        if not self.state:
            raise ValueError("state must not be empty")

        normalized_metrics = {
            str(key): str(value)
            for key, value in self.metrics.items()
        }
        object.__setattr__(
            self,
            "metrics",
            MappingProxyType(normalized_metrics),
        )
        object.__setattr__(self, "state", self.state.upper())


@dataclass(frozen=True, slots=True)
class StageSnapshot:
    """A complete immutable observation of one stage."""

    stage: str
    run_id: str
    tasks: tuple[StageTaskSnapshot, ...]
    summary: Mapping[str, str] = field(default_factory=dict)
    captured_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.stage:
            raise ValueError("stage must not be empty")
        immutable_tasks = tuple(self.tasks)
        if not all(
            isinstance(task, StageTaskSnapshot)
            for task in immutable_tasks
        ):
            raise TypeError("tasks must contain only StageTaskSnapshot values")
        task_ids = [task.task_id for task in immutable_tasks]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("task_id values must be unique within a snapshot")

        normalized_summary = {
            str(key): str(value)
            for key, value in self.summary.items()
        }
        object.__setattr__(
            self,
            "summary",
            MappingProxyType(normalized_summary),
        )
        object.__setattr__(self, "tasks", immutable_tasks)


@runtime_checkable
class SnapshotProvider(Protocol):
    """Callable that reads current stage state without mutating it."""

    def __call__(self) -> StageSnapshot:
        ...


class StageObserver:
    """Poll a snapshot provider serially and publish its latest value safely."""

    def __init__(
        self,
        provider: SnapshotProvider | Callable[[], StageSnapshot],
        *,
        poll_interval: float = 0.5,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if not callable(provider):
            raise TypeError("provider must be callable")

        self._provider = provider
        self._poll_interval = poll_interval
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._latest: StageSnapshot | None = None
        self._error: BaseException | None = None

    @property
    def latest(self) -> StageSnapshot | None:
        """Return the latest immutable snapshot, if one has been observed."""
        with self._lock:
            return self._latest

    @property
    def error(self) -> BaseException | None:
        """Return the most recent provider exception."""
        with self._lock:
            return self._error

    @property
    def running(self) -> bool:
        thread = self._thread
        return bool(thread and thread.is_alive())

    def poll_once(self) -> StageSnapshot:
        """Read and atomically publish exactly one provider snapshot."""
        snapshot = self._provider()
        if not isinstance(snapshot, StageSnapshot):
            raise TypeError("snapshot provider must return StageSnapshot")
        with self._lock:
            self._latest = snapshot
            self._error = None
        return snapshot

    def start(self) -> None:
        """Start one serial polling thread."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("stage observer is already running")
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._poll_loop,
                name="trace2fuzz-stage-observer",
                daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float | None = None) -> None:
        """Stop polling and wait for the observer thread."""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            started = time.monotonic()
            try:
                self.poll_once()
            except Exception as exc:
                with self._lock:
                    self._error = exc

            elapsed = time.monotonic() - started
            delay = max(0.0, self._poll_interval - elapsed)
            self._stop_event.wait(delay)

    def __enter__(self) -> StageObserver:
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()
