"""Persistent filesystem store for driver qualification artifacts."""

from __future__ import annotations

from pathlib import Path

from src.core import get_project_root
from src.experiment import RunArtifactStore


class DriverQualificationStore:
    """Manage all run-scoped paths used by driver qualification."""

    def __init__(self, library_name: str):
        self.library = library_name
        self.project_root = get_project_root()
        self.run_store = RunArtifactStore.from_environment(
            self.project_root,
            library_name,
        )
        self.workspace_base = self.project_root / "workspace" / library_name
        self.qualification_base = self.run_store.stage_dir("target_reachability")

    def driver_path(self, driver_name: str, kind: str) -> Path:
        return self.run_store.stage_dir("target_reachability", driver_name) / kind
