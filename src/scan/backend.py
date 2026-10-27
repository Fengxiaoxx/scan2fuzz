"""Boundary between shared analysis builds and replaceable alert generation."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from src.core.targets import Target
from src.scan.evidence import ReportEvidence


@dataclass(frozen=True)
class ScanContext:
    """Completed shared-build inputs supplied to the one selected backend."""

    source_root: str
    reports_dir: str
    database_path: str
    compile_db_path: str
    source_files: list[str]
    language: str = "c"
    build_trace_path: str | None = None
    link_target: str | None = None
    public_include_dir: str | None = None


@dataclass
class ScanResult:
    # Group order controls precedence when findings share a location.
    target_groups: dict[str, list[Target]]
    reports: list[ReportEvidence]
    # Source paths -> run-relative artifact destinations.
    artifacts: dict[Path, str]
    status: Literal["completed", "partial", "failed"] = "completed"


class AlertBackend(Protocol):
    """One alternative alert implementation, invoked after shared preparation.

    Return None or a non-completed result on failure/incomplete coverage.

    Only an empty completed result means zero alerts. Incomplete results may
    retain diagnostic artifacts but must not be consumed as completed output.
    Evidence must reference the same Target objects as target_groups, since
    normalization and location merging happen after the backend returns.
    Backends own their tool requirements and report artifacts, not builds.
    A backend failure does not select another backend or publish partial targets.
    """

    def check_prerequisites(self) -> bool: ...

    def scan(self, context: ScanContext) -> ScanResult | None: ...
