"""A finding as the auditor reports it, and the strict parser for one slice's reply."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.scan.unit_audit.units import Unit

_TEXT_FIELDS = ("function", "vulnerability_type", "entry_api", "evidence")


@dataclass
class AuditFinding:
    file: str
    function: str
    line: int
    vulnerability_type: str
    entry_api: str
    call_path: list[dict[str, Any]]  # hops {function, file, line}: entry_api first, the defect last
    evidence: str

    def target_description(self) -> str:
        """The one-line description that reaches targets.txt; preprocessing reads the path back."""
        path = " -> ".join(f"{hop['function']}@{hop['file']}:{hop['line']}" for hop in self.call_path)
        return (
            f"{self.function} (vulnerability_type: {self.vulnerability_type}; "
            f"entry: {self.entry_api}; path: {path})"
        )


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _call_path(value: Any, *, entry_api: str, function: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError("finding call_path must be a non-empty array")
    hops: list[dict[str, Any]] = []
    for hop in value:
        if not isinstance(hop, dict):
            raise ValueError(f"call_path hop must be an object: {hop!r}")
        name, path, at = hop.get("function"), hop.get("file"), hop.get("line")
        if not isinstance(name, str) or not name.strip() or not isinstance(path, str) or not path.strip():
            raise ValueError(f"call_path hop needs a function and a file: {hop!r}")
        if not _positive_int(at):
            raise ValueError(f"call_path hop line must be a positive integer: {hop!r}")
        hops.append({"function": name.strip(), "file": path.strip(), "line": at})
    if hops[0]["function"] != entry_api:
        raise ValueError(f"call_path must start at entry_api {entry_api!r}, not {hops[0]['function']!r}")
    # The last hop's line may differ from the finding's: auditors put it at the crash site
    # while line names the root cause, and preprocessing reads only the earlier hops' lines.
    if hops[-1]["function"] != function:
        raise ValueError(f"call_path must end at {function!r}, not {hops[-1]['function']!r}")
    return hops


def parse_findings(payload: Any, *, file: str, units: tuple[Unit, ...]) -> list[AuditFinding]:
    """Reject the whole reply if any finding is malformed or outside this slice's functions."""
    if not isinstance(payload, dict):
        raise ValueError(f"slice reply must be a JSON object, got {type(payload).__name__}")
    items = payload.get("findings")
    if not isinstance(items, list):
        raise ValueError("slice reply must carry a 'findings' array")

    ranges: dict[str, list[tuple[int, int]]] = {}
    for unit in units:
        if unit.file == file:
            ranges.setdefault(unit.name, []).append((unit.start_line, unit.end_line))

    findings: list[AuditFinding] = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError(f"finding must be an object, got {type(item).__name__}")
        values: dict[str, str] = {}
        for name in _TEXT_FIELDS:
            value = item.get(name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"finding field {name!r} must be a non-empty string")
            values[name] = value.strip()
        line = item.get("line")
        if not _positive_int(line):
            raise ValueError(f"finding line must be a positive integer, got {line!r}")

        function = values["function"]
        if function not in ranges:
            raise ValueError(f"finding function {function!r} is not in the slice for {file}")
        if not any(start <= line <= end for start, end in ranges[function]):
            allowed = ", ".join(f"{start}-{end}" for start, end in ranges[function])
            raise ValueError(
                f"finding line {line} is outside function {function!r} in {file} (allowed: {allowed})"
            )
        call_path = _call_path(item.get("call_path"), entry_api=values["entry_api"], function=function)
        findings.append(AuditFinding(file=file, line=line, call_path=call_path, **values))
    return findings
