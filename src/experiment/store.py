"""Strict storage for one Trace2Fuzz experiment run."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional, Union


PathLike = Union[str, os.PathLike[str]]

_COMPONENT_RE = re.compile(r"[A-Za-z0-9._-]+", re.ASCII)
_RUN_DIR_ENV = "RUN_DIR"
_RUN_ID_ENV = "RUN_ID"
_DRIVER_SCOPED_STAGES = frozenset(
    {
        "driver_generation",
        "compile_repair",
        "runtime_repair",
        "target_reachability",
        "driver_refinement",
    }
)


def _validate_component(value: str, label: str) -> str:
    if not isinstance(value, str) or not _COMPONENT_RE.fullmatch(value):
        raise ValueError(f"{label} must match ASCII [A-Za-z0-9._-]+")
    if value in {".", ".."}:
        raise ValueError(f"{label} cannot be '.' or '..'")
    return value


def validate_driver_id(driver_id: str) -> str:
    """Validate and return a driver identifier safe for a directory name."""
    return _validate_component(driver_id, "driver_id")


def stage_directory(run_dir: Path, stage: str, driver_id: Optional[str] = None) -> Path:
    stage = _validate_component(stage, "stage")
    path = run_dir / "stages" / stage
    if driver_id is not None:
        path /= validate_driver_id(driver_id)
    _assert_path_is_contained(run_dir, path)
    return path


def artifact_driver_id(run_dir: Path, path: Path) -> Optional[str]:
    try:
        parts = path.resolve().relative_to(run_dir.resolve()).parts
    except ValueError:
        return None
    if (
        len(parts) >= 3
        and parts[0] == "stages"
        and parts[1] in _DRIVER_SCOPED_STAGES
        and parts[2] not in {"logs", "subjects"}
    ):
        return validate_driver_id(parts[2])
    if len(parts) >= 3 and parts[:2] == ("state", "drivers"):
        return validate_driver_id(parts[2])
    return None


def _validate_filename(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError(f"{label} must be a single non-empty file name")
    return value


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _assert_path_is_contained(root: Path, candidate: Path) -> None:
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes run directory: {candidate}") from exc

    current = root
    for part in candidate.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"symbolic links are not allowed in run paths: {current}")


class RunArtifactStore:
    """Store immutable artifacts and append-only events for one pipeline run.

    Instances are opened only through :meth:`create` or
    :meth:`from_environment`. The on-disk root is always
    ``<project_root>/workspace/<library>/runs/<run_id>``.
    """

    def __init__(self, project_root: Path, library: str, run_id: str, run_dir: Path):
        self.project_root = project_root
        self.library = library
        self.run_id = run_id
        self.run_dir = run_dir

    @classmethod
    def create(
        cls,
        project_root: PathLike,
        library: str,
        run_id: Optional[str] = None,
    ) -> "RunArtifactStore":
        """Create a new run directory and its immutable ``run.json`` manifest."""
        root = Path(project_root).resolve(strict=True)
        if not root.is_dir():
            raise NotADirectoryError(f"project root is not a directory: {root}")

        library = _validate_component(library, "library")
        run_id = _validate_component(run_id or cls._new_run_id(), "run_id")
        runs_dir = root / "workspace" / library / "runs"
        _assert_path_is_contained(root, runs_dir)
        runs_dir.mkdir(parents=True, exist_ok=True)
        _assert_path_is_contained(root, runs_dir)

        run_dir = runs_dir / run_id
        run_dir.mkdir(exist_ok=False)
        store = cls(root, library, run_id, run_dir)
        store.write_json(
            "run.json",
            {
                "schema_version": 1,
                "artifact_layout_version": 2,
                "library": library,
                "run_id": run_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return store

    @classmethod
    def from_environment(
        cls,
        project_root: PathLike,
        library: str,
        environ: Optional[Mapping[str, str]] = None,
    ) -> "RunArtifactStore":
        """Open the run named by the ``RUN_DIR`` and ``RUN_ID`` variables."""
        env = os.environ if environ is None else environ
        try:
            raw_dir = env[_RUN_DIR_ENV]
            raw_run_id = env[_RUN_ID_ENV]
        except KeyError as exc:
            raise ValueError(f"missing environment variable: {exc.args[0]}") from exc

        root = Path(project_root).resolve(strict=True)
        if not root.is_dir():
            raise NotADirectoryError(f"project root is not a directory: {root}")
        library = _validate_component(library, "library")
        run_id = _validate_component(raw_run_id, "run_id")

        supplied = Path(raw_dir)
        if not supplied.is_absolute():
            raise ValueError(f"{_RUN_DIR_ENV} must be an absolute path")
        supplied = supplied.resolve(strict=True)
        expected = (root / "workspace" / library / "runs" / run_id).resolve(strict=True)
        if supplied != expected:
            raise ValueError(
                f"{_RUN_DIR_ENV} must equal the run directory for library={library!r} "
                f"and run_id={run_id!r}"
            )
        if not supplied.is_dir():
            raise NotADirectoryError(f"run directory is not a directory: {supplied}")

        _assert_path_is_contained(root, root / "workspace" / library / "runs" / run_id)
        store = cls(root, library, run_id, supplied)
        manifest = store.read_json("run.json")
        if not isinstance(manifest, dict):
            raise ValueError("run.json must contain a JSON object")
        if manifest.get("library") != library or manifest.get("run_id") != run_id:
            raise ValueError("run.json does not match the requested library and run_id")
        if manifest.get("artifact_layout_version") != 2:
            raise ValueError("run uses an unsupported artifact layout")
        return store

    @staticmethod
    def _new_run_id() -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        return f"{timestamp}-{secrets.token_hex(4)}"

    def environment(self) -> dict[str, str]:
        """Return the environment entries to pass to isolated pipeline stages."""
        return {_RUN_DIR_ENV: str(self.run_dir), _RUN_ID_ENV: self.run_id}

    def safe_path(self, relative_path: PathLike) -> Path:
        """Resolve a non-empty relative path without allowing run-root escape."""
        relative = Path(relative_path)
        if relative.is_absolute():
            raise ValueError(f"run artifact path must be relative: {relative}")
        if not relative.parts or relative == Path("."):
            raise ValueError("run artifact path cannot be empty")
        if ".." in relative.parts:
            raise ValueError(f"run artifact path cannot contain '..': {relative}")

        candidate = self.run_dir.joinpath(relative)
        _assert_path_is_contained(self.run_dir, candidate)
        return candidate

    def stage_dir(self, stage: str, driver_id: Optional[str] = None) -> Path:
        return stage_directory(self.run_dir, stage, driver_id)

    def invocation_dir(self, invocation_id: str) -> Path:
        return self.safe_path(
            Path("summary/orchestration")
            / _validate_component(invocation_id, "invocation_id")
        )

    def attempt_logs_dir(self, stage: str, driver_id: str, attempt: Path) -> Path:
        path = self.logs_dir(stage, driver_id) / _validate_component(attempt.name, "attempt")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def logs_dir(self, stage: str, driver_id: Optional[str] = None) -> Path:
        return self.stage_dir(stage, driver_id) / "logs"

    def session_path(self, driver_id: str, kind: str) -> Path:
        if kind == "repair":
            return self.safe_path(
                Path("state/drivers")
                / validate_driver_id(driver_id)
                / "repair-session"
            )
        if kind == "refinement":
            return self.stage_dir("driver_refinement", driver_id) / "session"
        raise ValueError(f"unknown session kind: {kind}")

    def agent_log_path(self, stage: str, driver_id: str, name: str) -> Path:
        path = self.logs_dir(stage, driver_id) / _validate_filename(name, "log name")
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def execution_log_path(self, stage: str, driver_id: str) -> Path:
        """Return the append-only command execution journal for one stage/driver."""
        return self.logs_dir(stage, driver_id) / "executions.jsonl"

    def usage_path(self, stage: str, driver_id: Optional[str] = None,
                   subject: Optional[str] = None) -> Path:
        root = self.stage_dir(stage, driver_id)
        if driver_id is None and subject is not None:
            root = root / "subjects" / _validate_component(subject, "subject")
        return root / "logs" / "calls.jsonl"

    def binary_path(self, driver_id: str, name: str, stage: str) -> Path:
        return self.stage_dir(stage, driver_id) / "binaries" / _validate_filename(name, "binary name")

    def source_path(self, driver_id: str, name: str) -> Path:
        """Return an immutable source-snapshot path for one driver."""
        name = _validate_filename(name, "source name")
        stage = {"generated.cc": "driver_generation"}.get(name, "compile_repair")
        return self.stage_dir(stage, driver_id) / "sources" / name

    def stage_result_path(self, stage: str, driver_id: Optional[str] = None) -> Path:
        """Return the conventional immutable ``result.json`` path for a stage."""
        return self.stage_dir(stage, driver_id) / "result.json"

    def write_json(self, relative_path: PathLike, value: Any) -> Path:
        """Atomically create a JSON file; an existing target is never replaced."""
        return self._write_json(relative_path, value, immutable=True)

    def replace_json(self, relative_path: PathLike, value: Any) -> Path:
        """Atomically refresh a derived JSON view, such as a run summary."""
        return self._write_json(relative_path, value, immutable=False)

    def _write_json(self, relative_path: PathLike, value: Any, *, immutable: bool) -> Path:
        target = self._prepare_target(relative_path)

        def write_temp(temp_path: Path) -> None:
            with temp_path.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(
                    value,
                    handle,
                    allow_nan=False,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            temp_path.chmod(0o644)

        self._atomic_replace(target, write_temp, immutable=immutable)
        return target

    def write_json_or_validate(self, relative_path: PathLike, value: Any) -> Path:
        """Create immutable JSON, or verify that the existing value is identical."""
        target = self._coerce_path(relative_path)
        if target.is_file():
            if self.read_json(target) != value:
                raise ValueError(f"existing JSON artifact differs: {target}")
            return target
        return self.write_json(relative_path, value)

    def append_jsonl(self, relative_path: PathLike, record: Mapping[str, Any]) -> Path:
        """Atomically append one JSON object to a JSON-Lines file."""
        if not isinstance(record, Mapping):
            raise TypeError("JSONL records must be mappings")
        target = self._prepare_target(relative_path)

        def write_temp(temp_path: Path) -> None:
            with temp_path.open("w", encoding="utf-8", newline="\n") as destination:
                if target.exists():
                    if not target.is_file():
                        raise IsADirectoryError(f"JSONL target is not a file: {target}")
                    with target.open("r", encoding="utf-8", newline="") as source:
                        for line_number, line in enumerate(source, 1):
                            if not line.endswith("\n"):
                                raise ValueError(
                                    f"invalid JSONL at line {line_number}: missing newline"
                                )
                            existing = json.loads(
                                line, parse_constant=_reject_nonfinite_json
                            )
                            if not isinstance(existing, dict):
                                raise ValueError(
                                    f"invalid JSONL at line {line_number}: expected object"
                                )
                            destination.write(line)
                json.dump(
                    dict(record),
                    destination,
                    allow_nan=False,
                    ensure_ascii=False,
                    sort_keys=True,
                )
                destination.write("\n")
                destination.flush()
                os.fsync(destination.fileno())
            temp_path.chmod(0o644)

        self._atomic_replace(target, write_temp, immutable=False)
        return target

    def append_event(self, record: Mapping[str, Any]) -> Path:
        """Append one run event to ``events.jsonl``."""
        return self.append_jsonl("events.jsonl", record)

    def copy_file(self, source: PathLike, relative_path: PathLike) -> Path:
        """Atomically copy a file into an immutable artifact target."""
        source_path = Path(source).resolve(strict=True)
        if not source_path.is_file():
            raise FileNotFoundError(f"source is not a file: {source_path}")
        target = self._prepare_target(relative_path)

        def write_temp(temp_path: Path) -> None:
            shutil.copy2(source_path, temp_path)
            with temp_path.open("rb") as handle:
                os.fsync(handle.fileno())

        self._atomic_replace(target, write_temp, immutable=True)
        return target

    def copy_file_or_validate(
        self,
        source: PathLike,
        relative_path: PathLike,
    ) -> Path:
        """Copy immutable content, or verify an existing byte-identical artifact."""
        source_path = Path(source).resolve(strict=True)
        if not source_path.is_file():
            raise FileNotFoundError(f"source is not a file: {source_path}")
        target = self._coerce_path(relative_path)
        if target.is_file():
            if not self._files_equal(source_path, target):
                raise ValueError(f"existing file artifact differs: {target}")
            return target
        return self.copy_file(source_path, relative_path)

    def replace_from_snapshot(
        self,
        snapshot: PathLike,
        canonical_path: PathLike,
    ) -> Path:
        """Atomically replace a canonical file from an immutable run snapshot."""
        source = self._coerce_path(snapshot).resolve(strict=True)
        if not source.is_file():
            raise FileNotFoundError(f"canonical snapshot is not a file: {source}")
        target = self._coerce_path(canonical_path)
        if not target.is_file():
            raise FileNotFoundError(f"canonical artifact is not a file: {target}")

        def write_temp(temp_path: Path) -> None:
            shutil.copy2(source, temp_path)
            with temp_path.open("rb") as handle:
                os.fsync(handle.fileno())

        self._atomic_replace(target, write_temp, immutable=False)
        return target

    def copy_source(
        self,
        source: PathLike,
        driver_id: str,
        name: Optional[str] = None,
    ) -> Path:
        """Append an immutable source snapshot for a driver."""
        source_path = Path(source)
        target = self.source_path(driver_id, name or source_path.name)
        return self.copy_file(source_path, target)

    def read_json(self, relative_path: PathLike) -> Any:
        """Read JSON from a safe run-relative path and propagate parse errors."""
        target = self._coerce_path(relative_path)
        with target.open("r", encoding="utf-8") as handle:
            return json.load(handle, parse_constant=_reject_nonfinite_json)

    def _coerce_path(self, path: PathLike) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            return self.safe_path(candidate)
        _assert_path_is_contained(self.run_dir, candidate)
        return candidate

    def _prepare_target(self, path: PathLike) -> Path:
        target = self._coerce_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        _assert_path_is_contained(self.run_dir, target)
        return target

    @staticmethod
    def _files_equal(left: Path, right: Path) -> bool:
        if left.stat().st_size != right.stat().st_size:
            return False
        with left.open("rb") as left_handle, right.open("rb") as right_handle:
            while True:
                left_chunk = left_handle.read(1024 * 1024)
                right_chunk = right_handle.read(1024 * 1024)
                if left_chunk != right_chunk:
                    return False
                if not left_chunk:
                    return True

    @contextmanager
    def _target_lock(self, target: Path) -> Iterator[None]:
        lock_path = target.with_name(f".{target.name}.lock")
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        try:
            yield
        finally:
            lock_path.unlink()

    def _atomic_replace(
        self,
        target: Path,
        write_temp: Callable[[Path], None],
        *,
        immutable: bool,
    ) -> None:
        with self._target_lock(target):
            if immutable and os.path.lexists(target):
                raise FileExistsError(f"immutable artifact already exists: {target}")

            descriptor, raw_temp = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
            )
            os.close(descriptor)
            temp_path = Path(raw_temp)
            try:
                write_temp(temp_path)
                if immutable and os.path.lexists(target):
                    raise FileExistsError(f"immutable artifact already exists: {target}")
                os.replace(temp_path, target)
            finally:
                if temp_path.exists():
                    temp_path.unlink()
