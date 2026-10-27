"""Serializable data contracts for driver qualification."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DriverQualificationSpec:
    """Filesystem contract for one driver qualification."""

    name: str
    binary_path: str
    source_path: str
    log_file: str
    corpus_dir: str
    artifact_dir: str
    command: str = ""
    command_args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DriverQualificationSpec":
        return cls(**data)


@dataclass
class DriverQualificationRecord:
    """Observed execution result for one driver."""

    name: str
    command: str
    log_file: str
    binary_path: str
    source_path: str
    status: str
    exit_code: Optional[int]
    started_at: Optional[str]
    finished_at: Optional[str]
    total_runs: int = 0
    runtime_seconds: int = 0
    exec_per_sec: int = 0
    corpus_size: int = 0
    fuzz_time_seconds: int = 0
    error: Optional[str] = None
    reachability_outcome: Optional[str] = None
    reachability_rounds: int = 0
    crash: Optional[Dict[str, Any]] = None
    coverage_binary: Optional[str] = None
    corpus_snapshot: Optional[str] = None
    reaching_input: Optional[str] = None
    target_marker_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DriverQualificationRecord":
        return cls(**data)


@dataclass
class DriverQualificationResult:
    """Terminal per-driver states for one monitored batch."""

    total: int
    completed: int
    infrastructure_failed: int
    drivers: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @property
    def successful(self) -> bool:
        return self.infrastructure_failed == 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
