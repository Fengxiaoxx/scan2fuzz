"""Bind every pipeline stage to one immutable experiment run."""

from __future__ import annotations

import os
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Iterator, Optional

from dotenv import load_dotenv

from src.core import get_project_root
from src.experiment import LibraryRunLock, RunArtifactStore
from src.llm.provider_config import (
    GLOBAL_MODEL_ENV,
    PROVIDER_ENV_KEYS,
    ModelProviderConfig,
)


RUN_DIR_ENV = "RUN_DIR"
RUN_ID_ENV = "RUN_ID"
PARENT_LOCK_ENV = "PARENT_LOCK_HELD"

STAGE_MODEL_ENV_KEYS = (
    "API_DOC_MODEL",
    "DRIVER_GEN_MODEL",
    "FIX_AGENT_MODEL",
    "REFINER_AGENT_MODEL",
)
REQUIRED_AGENT_ENV_KEYS = STAGE_MODEL_ENV_KEYS + (
    "EMBEDDING_MODEL",
    "EMBEDDING_API_BASE",
)
FROZEN_AGENT_ENV_KEYS = REQUIRED_AGENT_ENV_KEYS + PROVIDER_ENV_KEYS

STAGE_PREREQUISITES = {
    "preprocess": "scan",
    "driver_rounds": "preprocess",
    "fuzz_run": "driver_rounds",
}


def _effective_agent_environment(root: Path) -> dict[str, str]:
    """Read the non-secret Agent parameters that define one experiment."""
    load_dotenv(root / ".env", override=False)
    configured = {
        key: os.environ.get(key, "").strip()
        for key in FROZEN_AGENT_ENV_KEYS
    }
    global_model = configured[GLOBAL_MODEL_ENV]
    if global_model:
        for key in STAGE_MODEL_ENV_KEYS:
            configured[key] = configured[key] or global_model

    provider = ModelProviderConfig.from_env()
    configured.update(provider.frozen_environment())
    missing = [
        key for key in REQUIRED_AGENT_ENV_KEYS if not configured[key]
    ]
    if missing:
        raise ValueError(
            "missing required Agent environment parameters: "
            + ", ".join(missing)
        )
    return configured


def _apply_frozen_agent_environment(store: RunArtifactStore) -> None:
    # Load credential values from the current runtime, but never copy them into
    # the immutable run metadata below.
    load_dotenv(store.project_root / ".env", override=False)
    values = store.read_json("config/agent-env.json")
    if (
        not isinstance(values, dict)
        or not set(REQUIRED_AGENT_ENV_KEYS).issubset(values)
    ):
        raise ValueError(
            f"invalid frozen Agent environment for run {store.run_id}"
        )
    if not all(isinstance(value, str) for value in values.values()):
        raise ValueError(
            f"frozen Agent environment contains invalid values for run {store.run_id}"
        )
    if not all(values.get(key, "") for key in REQUIRED_AGENT_ENV_KEYS):
        raise ValueError(
            f"frozen Agent environment contains empty required values for run "
            f"{store.run_id}"
        )

    # Do not let provider settings from the invoking shell bleed into a resumed run.
    for key in PROVIDER_ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(
        {
            key: value
            for key, value in values.items()
            if key in FROZEN_AGENT_ENV_KEYS
        }
    )


def create_run(library: str) -> RunArtifactStore:
    """Create a run and freeze the library configuration used by all stages."""
    root = Path(get_project_root())
    agent_environment = _effective_agent_environment(root)
    store = RunArtifactStore.create(root, library)
    info = root / "info_lib" / library
    store.copy_file(info / "config.yaml", "config/config.yaml")
    store.copy_file(info / "build.sh", "config/build.sh")
    store.write_json("config/agent-env.json", agent_environment)
    os.environ.update(store.environment())
    _apply_frozen_agent_environment(store)
    return store


def require_run(library: str, run_id: Optional[str] = None) -> RunArtifactStore:
    """Open an existing run selected by environment or explicit run id."""
    root = Path(get_project_root())
    has_dir = RUN_DIR_ENV in os.environ
    has_id = RUN_ID_ENV in os.environ
    if has_dir != has_id:
        raise ValueError(f"{RUN_DIR_ENV} and {RUN_ID_ENV} must be set together")
    if has_dir:
        current = RunArtifactStore.from_environment(root, library)
        if run_id is not None and run_id != current.run_id:
            raise ValueError(
                f"--run-id {run_id!r} does not match current run {current.run_id!r}"
            )
        _apply_frozen_agent_environment(current)
        return current
    if run_id is None:
        raise ValueError("--run-id is required when no pipeline run is active")

    run_dir = root / "workspace" / library / "runs" / run_id
    store = RunArtifactStore.from_environment(
        root,
        library,
        {
            RUN_DIR_ENV: str(run_dir.resolve(strict=True)),
            RUN_ID_ENV: run_id,
        },
    )
    os.environ.update(store.environment())
    _apply_frozen_agent_environment(store)
    return store


def require_stage_input(store: RunArtifactStore, stage: str) -> None:
    """Require the canonical result of the immediately preceding stage."""
    prerequisite = STAGE_PREREQUISITES.get(stage)
    if prerequisite is None:
        return
    result = store.stage_result_path(prerequisite)
    if not result.is_file():
        raise FileNotFoundError(
            f"stage {stage} requires {prerequisite} result in run {store.run_id}: "
            f"{result}"
        )
    payload = store.read_json(result)
    if prerequisite == "scan":
        if payload.get("status") != "completed":
            raise RuntimeError(f"run {store.run_id} has no completed scan")
        if payload.get("target_count") == 0:
            raise RuntimeError(f"run {store.run_id} has no scan targets")
    if payload.get("success") is False:
        raise RuntimeError(
            f"stage {prerequisite} produced no reusable output in run "
            f"{store.run_id}"
        )


def require_stage_pending(store: RunArtifactStore, stage: str) -> None:
    """Reject accidental overwrite of a completed immutable stage."""
    result = store.stage_result_path(stage)
    if result.exists():
        raise FileExistsError(
            f"stage {stage} already completed in run {store.run_id}: {result}"
        )


@contextmanager
def stage_run(
    library: str,
    stage: str,
    *,
    run_id: Optional[str] = None,
    create: bool = False,
    allow_completed: bool = False,
) -> Iterator[RunArtifactStore]:
    """Open a stage under the same lock and run contract used by the pipeline.

    ``allow_completed`` is reserved for explicit append-only retry operations;
    callers remain responsible for leaving canonical completed results untouched.
    """
    parent_holds_lock = os.environ.get(PARENT_LOCK_ENV) == "1"
    lock_context = (
        nullcontext()
        if parent_holds_lock
        else LibraryRunLock(Path(get_project_root()), library)
    )
    with lock_context:
        has_active_run = RUN_DIR_ENV in os.environ or RUN_ID_ENV in os.environ
        store = (
            create_run(library)
            if create and run_id is None and not has_active_run
            else require_run(library, run_id)
        )
        require_stage_input(store, stage)
        if not allow_completed:
            require_stage_pending(store, stage)
        yield store
