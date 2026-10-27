"""Build the deterministic target-first API candidate plan."""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from src.core.driver_names import make_driver_id
from src.core.targets import TargetParser
from src.preprocess.reachability.graph_materializer import (
    SourcePathResolver,
    demangle_names,
    index_locations,
    load_locations,
    normalize_path,
    positional_locations,
)
from src.preprocess.reachability.path_length_ranking import (
    rank_by_path_length,
    shortest_witness_path,
)


def _load_graph(path: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    predecessors: dict[str, set[str]] = defaultdict(set)
    successors: dict[str, set[str]] = defaultdict(set)
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ["caller_name", "callee_name"]:
            raise ValueError(f"invalid graph schema: {path}")
        for row in reader:
            caller = row["caller_name"].strip()
            callee = row["callee_name"].strip()
            if caller and callee and caller != callee:
                predecessors[callee].add(caller)
                successors[caller].add(callee)
    return predecessors, successors


def _api_frontier(
    predecessors: dict[str, set[str]], target: str, api_symbols: set[str]
) -> set[str]:
    """Return the first public API boundary reached while tracing callers."""
    if target in api_symbols:
        return {target}
    result: set[str] = set()
    visited = {target}
    queue = deque([target])
    while queue:
        node = queue.popleft()
        for caller in sorted(predecessors.get(node, ())):
            if caller in api_symbols:
                result.add(caller)
            elif caller not in visited:
                visited.add(caller)
                queue.append(caller)
    return result


def _reachable_callers(
    predecessors: dict[str, set[str]], target: str
) -> set[str]:
    result = {target}
    queue = deque([target])
    while queue:
        node = queue.popleft()
        for caller in sorted(predecessors.get(node, ())):
            if caller not in result:
                result.add(caller)
                queue.append(caller)
    return result


def _rank_candidates(
    high_candidates: list[dict[str, Any]],
    fallback_candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return rank_by_path_length(high_candidates) + rank_by_path_length(
        fallback_candidates
    )


# unit-audit writes the call path it traced last in the target description, one
# hop per call site: "...; path: api@src/a.c:12 -> f@src/b.c:40 -> g@src/b.c:88)".
_AUDIT_PATH = re.compile(r"; path: (?P<path>[^()]+)\)\s*$")
_AUDIT_HOP = re.compile(r"^(?P<function>.+)@(?P<file>[^@]+):(?P<line>\d+)$")
_AUDIT_VULNERABILITY_TYPE = re.compile(
    r"\(vulnerability_type: (?P<type>[^();]+); entry: [^()]*; path: [^()]+\)\s*$"
)


def _audit_vulnerability_type(description: str) -> str:
    match = _AUDIT_VULNERABILITY_TYPE.search(description)
    return match.group("type").strip() if match else ""


def _audit_path(
    description: str, *, apis: set[str]
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Take the auditor's call path as reported; it is not checked.

    Returns (hops, "used"), (None, reason) when the path cannot be used at all
    (unreadable, or its entry has no public API to generate a driver for), and
    (None, None) when the description carries no path.
    """
    match = _AUDIT_PATH.search(description)
    if match is None:
        return None, None
    hops = []
    for text in match.group("path").split(" -> "):
        hop = _AUDIT_HOP.match(text.strip())
        if hop is None:
            return None, f"malformed hop {text.strip()!r}"
        hops.append({"function": hop["function"], "file": hop["file"], "line": int(hop["line"])})
    if hops[0]["function"] not in apis:
        return None, f"entry {hops[0]['function']} is not a public API"
    return hops, "used"


def _api_metadata(path: Path) -> dict[str, dict[str, str]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    apis = value.get("apis") if isinstance(value, dict) else None
    if not isinstance(apis, list) or not apis:
        raise ValueError(f"public API artifact contains no APIs: {path}")
    result: dict[str, dict[str, str]] = {}
    for api in apis:
        symbol = str(api["abi_symbol"])
        if symbol in result:
            raise ValueError(f"duplicate public ABI symbol: {symbol}")
        api_id = str(api["api_id"])
        if api_id != f"abi:{symbol}":
            raise ValueError(f"invalid public API identity: {api_id}")
        result[symbol] = {
            "api_id": api_id,
            "abi_symbol": symbol,
            "display_name": str(api["display_name"]),
            "qualified_name": str(api["qualified_name"]),
            "signature": str(api["signature"]),
            "include": str(api["include"]),
        }
    return result


class CandidatePlanBuilder:
    """Map scan targets to ABI-identified APIs through high/fallback graphs."""

    def __init__(
        self,
        *,
        library: str,
        source_root: Path,
        targets_file: Path,
        compile_commands: Path,
        function_locations: Path,
        graph_high: Path,
        graph_all: Path,
        public_api: Path,
    ) -> None:
        self.library = library
        resolved_source_root = source_root.resolve(strict=True)
        self.targets_file = targets_file.resolve(strict=True)
        self.path_resolver = SourcePathResolver(
            resolved_source_root, compile_commands.resolve(strict=True)
        )
        loaded_locations = load_locations(
            function_locations.resolve(strict=True), self.path_resolver
        )
        self.locations = index_locations(loaded_locations)
        self.locations_by_name = {
            location.name: location for location in loaded_locations
        }
        self.high_predecessors, high_successors = _load_graph(
            graph_high.resolve(strict=True)
        )
        self.all_predecessors, all_successors = _load_graph(
            graph_all.resolve(strict=True)
        )
        self.high_successors = high_successors
        self.all_successors = all_successors
        self.apis = _api_metadata(public_api.resolve(strict=True))
        self.api_symbols = set(self.apis)

    def build(self, output: Path) -> dict[str, Any]:
        targets = TargetParser.parse_file(str(self.targets_file))
        if not targets:
            raise ValueError(f"scan target list is empty: {self.targets_file}")

        records = []
        excluded = []
        for ordinal, target in enumerate(targets, 1):
            project_file = self.path_resolver.resolve_project(target.file_path)
            file_path = project_file or normalize_path(target.file_path)
            anchors = (
                positional_locations(self.locations, file_path, target.line_no)
                if project_file is not None
                else ()
            )
            anchor_names = sorted(location.name for location in anchors)
            if not anchor_names:
                # The line lies in no function the analysis build compiled (code its
                # configuration leaves out): no driver can reach it, so it is no target.
                # Markers keep the scan ordinal, so a dropped target leaves a gap.
                excluded.append(
                    {
                        "target_id": f"{target.file_path}:{target.line_no}",
                        "marker": f"TARGET_{ordinal:04d}",
                        "reason": "target line is in no function of the analysis build",
                    }
                )
                continue
            high_frontiers = [
                (
                    anchor,
                    _api_frontier(
                        self.high_predecessors, anchor, self.api_symbols
                    ),
                )
                for anchor in anchor_names
            ]
            all_frontiers = [
                (
                    anchor,
                    _api_frontier(
                        self.all_predecessors, anchor, self.api_symbols
                    ),
                )
                for anchor in anchor_names
            ]
            high_reachability = [
                (anchor, _reachable_callers(self.high_predecessors, anchor))
                for anchor in anchor_names
            ]
            all_reachability = [
                (anchor, _reachable_callers(self.all_predecessors, anchor))
                for anchor in anchor_names
            ]
            high_symbols = set().union(
                *(symbols for _anchor, symbols in high_frontiers)
            )
            all_symbols = set().union(
                *(symbols for _anchor, symbols in all_frontiers)
            )
            if not high_symbols <= all_symbols:
                raise ValueError(
                    f"high graph is not a subset for {file_path}:{target.line_no}"
                )

            high_candidates = [
                self._candidate(
                    symbol,
                    "high",
                    self.high_successors,
                    high_reachability,
                    target.file_path,
                    target.line_no,
                )
                for symbol in high_symbols
            ]
            fallback_candidates = [
                self._candidate(
                    symbol,
                    "fallback",
                    self.all_successors,
                    all_reachability,
                    target.file_path,
                    target.line_no,
                )
                for symbol in all_symbols - high_symbols
            ]
            # The auditor's own entry and call path go first, used as reported; the
            # static graph's chains follow, tried only after it misses.
            audit_hops, audit_status = _audit_path(target.description, apis=self.api_symbols)
            candidates = _rank_candidates(high_candidates, fallback_candidates)
            if audit_hops is not None:
                path = [hop["function"] for hop in audit_hops]
                chain = self._chain(path, target.file_path, target.line_no)
                for step, hop in zip(chain, audit_hops[:-1]):
                    step["call_line"] = hop["line"]  # where this step calls the next
                audit_candidate = {
                    **self.apis[path[0]],
                    "layer": "audit",
                    "target_function": path[-1],
                    "path_length": len(path) - 1,
                    "path": path,
                    "chain": chain,
                }
                candidates = [
                    audit_candidate,
                    *(c for c in candidates if c["api_id"] != audit_candidate["api_id"]),
                ]
            marker = f"TARGET_{ordinal:04d}"
            for candidate in candidates:
                candidate["driver_id"] = make_driver_id(
                    candidate["api_id"], marker, candidate["display_name"]
                )
            records.append(
                {
                    "target_id": f"{target.file_path}:{target.line_no}",
                    "marker": marker,
                    "file": target.file_path,
                    "canonical_file": file_path,
                    "line": target.line_no,
                    "severity": target.severity,
                    "description": target.description,
                    "vulnerability_type": _audit_vulnerability_type(target.description),
                    "functions": anchor_names,
                    "status": (
                        "ready_audit"
                        if audit_hops is not None
                        else "ready_high"
                        if high_candidates
                        else "ready_fallback"
                        if fallback_candidates
                        else "unresolved"
                    ),
                    "initial_api_id": candidates[0]["api_id"] if candidates else None,
                    "audit_path": audit_status,
                    "candidate_count": len(candidates),
                    "candidates": candidates,
                }
            )

        driver_ids = [
            candidate["driver_id"]
            for record in records
            for candidate in record["candidates"]
        ]
        if len(driver_ids) != len(set(driver_ids)):
            raise ValueError("candidate plan contains colliding driver identities")

        summary = {
            "targets": len(records),
            "excluded_not_built": len(excluded),
            "ready_audit": sum(record["status"] == "ready_audit" for record in records),
            "audit_path_rejected": sum(
                record["audit_path"] not in (None, "used") for record in records
            ),
            "ready_high": sum(record["status"] == "ready_high" for record in records),
            "ready_fallback": sum(
                record["status"] == "ready_fallback" for record in records
            ),
            "unresolved": sum(record["status"] == "unresolved" for record in records),
            "initial_driver_count": sum(
                bool(record["candidates"]) for record in records
            ),
            "preserved_api_target_candidates": sum(
                record["candidate_count"] for record in records
            ),
        }
        result = {
            "schema_version": 8,
            "library": self.library,
            "policy": {
                "scope": "one active API candidate per target",
                "advance": "next candidate only after a terminal candidate miss",
                "stop": "first target-reaching candidate",
                "ordering": [
                    "unit-audit entry and call path first, used as reported",
                    "then call-graph candidates, high before fallback",
                    "shortest call-chain length ascending",
                    "ABI symbol lexical order",
                ],
                "chain": (
                    "the auditor's call path as reported; otherwise the "
                    "deterministic edge-valid shortest call path"
                ),
                "identity": "abi:<exported symbol>; driver IDs collision-checked",
            },
            "summary": summary,
            "source_path_resolution": self.path_resolver.summary,
            "targets": records,
            "excluded_targets": excluded,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return result

    def _candidate(
        self,
        symbol: str,
        layer: str,
        successors: dict[str, set[str]],
        target_reachability: list[tuple[str, set[str]]],
        target_file: str,
        target_line: int,
    ) -> dict[str, Any]:
        paths = [
            shortest_witness_path(successors, symbol, anchor)
            for anchor, reachable in target_reachability
            if symbol in reachable
        ]
        if not paths:
            raise ValueError(f"candidate has no declared path: {symbol}")
        # Shortest chain; the target function (last hop) then the path break ties.
        path = min(paths, key=lambda item: (len(item), item[-1], item))
        return {
            **self.apis[symbol],
            "layer": layer,
            "target_function": path[-1],
            "path_length": len(path) - 1,
            "path": path,
            "chain": self._chain(path, target_file, target_line),
        }

    def _chain(
        self, path: list[str], target_file: str, target_line: int
    ) -> list[dict[str, Any]]:
        demangled = demangle_names(path)
        result = []
        for index, (symbol, qualified_name) in enumerate(
            zip(path, demangled, strict=True)
        ):
            location = self.locations_by_name.get(symbol)
            step: dict[str, Any] = {
                "symbol": symbol,
                "fn": qualified_name,
            }
            if location is not None:
                step.update(
                    {
                        "file": location.file_path,
                        "line": location.anchor_line,
                        "col": location.anchor_col,
                        "start_line": location.start_line,
                        "end_line": location.end_line,
                        "coord": {
                            "file": location.file_path,
                            "line": location.anchor_line,
                            "col": location.anchor_col,
                        },
                    }
                )
            if index == len(path) - 1:
                step["target"] = {
                    "file": target_file,
                    "line": target_line,
                    "col": None,
                }
            result.append(step)
        return result
