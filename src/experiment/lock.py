"""Exclusive same-library lock for shared scan/preprocess producers."""

from __future__ import annotations

import fcntl
from pathlib import Path
from typing import Optional, TextIO

from .store import validate_driver_id


class LibraryRunLock:
    def __init__(self, project_root: Path, library: str) -> None:
        self.project_root = Path(project_root).resolve(strict=True)
        self.library = validate_driver_id(library)
        self._handle: Optional[TextIO] = None

    def acquire(self) -> None:
        if self._handle is not None:
            raise RuntimeError("library run lock is already held")
        path = self.project_root / "workspace" / self.library / ".pipeline.lock"
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise RuntimeError(
                f"another pipeline is already running for {self.library}"
            ) from exc
        self._handle = handle

    def release(self) -> None:
        if self._handle is None:
            return
        fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        self._handle.close()
        self._handle = None

    def __del__(self) -> None:
        self.release()

    def __enter__(self) -> "LibraryRunLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.release()
