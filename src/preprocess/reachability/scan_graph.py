"""Build run-frozen direct-call and provenance evidence from one analysis build."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
import time
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

from src.scan.bitcode_builder import get_target_sources


_QUERY_COLUMNS = {
    "callee_name",
    "callee_qualified_name",
    "callee_file",
    "callee_line",
    "caller_name",
    "caller_qualified_name",
    "callsite_file",
    "callsite_line",
    "callsite_column",
    "target_expression",
    "evidence_tier",
    "mechanism_kind",
    "storage_root",
    "dispatch_path",
    "binding_path",
    "binding_file",
    "binding_line",
}
_INTEGER_COLUMNS = {
    "callee_line",
    "callsite_line",
    "callsite_column",
    "binding_line",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    return {
        "path": str(resolved),
        "sha256": _sha256(resolved),
        "size": resolved.stat().st_size,
    }


def _project_file(value: str, source_root: Path) -> Path | None:
    raw = Path(value)
    candidate = raw if raw.is_absolute() else source_root / raw
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(source_root)
    except (FileNotFoundError, OSError, ValueError):
        return None
    return resolved


class ReachabilityScanBuilder:
    """Create all structural inputs needed by preprocess without SVF."""

    def __init__(
        self,
        *,
        source_root: Path,
        database: Path,
        build_trace: Path,
        link_target: str,
        linked_bitcode: Path,
        output_dir: Path,
        codeql: str = "codeql",
        direct_extractor: str = "/usr/local/bin/trace2fuzz-direct-calls",
        location_extractor: str = "/usr/local/bin/trace2fuzz-function-locations",
    ) -> None:
        self.source_root = source_root.resolve(strict=True)
        self.database = database.resolve(strict=True)
        self.build_trace = build_trace.resolve(strict=True)
        self.link_target = link_target
        self.linked_bitcode = linked_bitcode.resolve(strict=True)
        self.output_dir = output_dir.resolve()
        self.codeql = shutil.which(codeql)
        self.direct_extractor = Path(direct_extractor).resolve(strict=True)
        self.location_extractor = Path(location_extractor).resolve(strict=True)
        if self.codeql is None:
            raise FileNotFoundError("codeql is not available on PATH")

    def build(self) -> dict[str, Any]:
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)
        self.output_dir.mkdir(parents=True)

        direct_graph = self.output_dir / "call_graph.direct.csv"
        locations = self.output_dir / "function_locations.csv"
        self._extract_native(direct_graph, locations)

        scope_base = self._base_scope()
        include_csv = self._run_query(
            "ProjectIncludeEdges.ql", "include-edges"
        )
        scope = self._extend_scope(scope_base, include_csv)
        query_started = time.monotonic()
        query_csv = self._run_query(
            "CallsiteBindingEdges.ql", "provenance-edges"
        )
        query_seconds = time.monotonic() - query_started
        strict_path, strict_summary = self._filter_query(query_csv, scope)

        scope_path = self.output_dir / "scope.json"
        scope_path.write_text(
            json.dumps(scope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        summary = {
            "schema_version": 1,
            "link_target": self.link_target,
            "query_seconds": query_seconds,
            "scope_file_count": len(scope["scope_files"]),
            "query": strict_summary,
            "inputs": {
                "database": str(self.database),
                "build_trace": _artifact(self.build_trace),
                "linked_bitcode": _artifact(self.linked_bitcode),
                "direct_extractor": _artifact(self.direct_extractor),
                "location_extractor": _artifact(self.location_extractor),
            },
            "outputs": {
                "direct_graph": _artifact(direct_graph),
                "function_locations": _artifact(locations),
                "scope": _artifact(scope_path),
                "include_edges": _artifact(include_csv),
                "query_csv": _artifact(query_csv),
                "strict_edges": _artifact(strict_path),
            },
        }
        summary_path = self.output_dir / "result.json"
        summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return summary

    def _extract_native(self, direct_graph: Path, locations: Path) -> None:
        self._run_logged(
            [str(self.direct_extractor), str(self.linked_bitcode)],
            direct_graph,
            self.output_dir / "direct-extractor.log",
        )
        self._run_logged(
            [
                str(self.location_extractor),
                str(self.linked_bitcode),
                str(self.source_root),
            ],
            locations,
            self.output_dir / "function-location-extractor.log",
        )
        for path, required in (
            (direct_graph, {"caller_name", "callee_name"}),
            (
                locations,
                {
                    "name",
                    "mangled",
                    "file_path",
                    "start_line",
                    "end_line",
                    "anchor_line",
                    "anchor_col",
                },
            ),
        ):
            with path.open(newline="", encoding="utf-8") as stream:
                reader = csv.DictReader(stream)
                if set(reader.fieldnames or ()) != required or not next(reader, None):
                    raise ValueError(f"invalid or empty extractor output: {path}")

    def _base_scope(self) -> dict[str, Any]:
        sources = sorted(
            {
                path.resolve(strict=True)
                for path in get_target_sources(self.build_trace, self.link_target)
            }
        )
        if not sources:
            raise ValueError("linked build contains no source files")
        outside = [str(path) for path in sources if not path.is_relative_to(self.source_root)]
        if outside:
            raise ValueError("linked source is outside source root: " + ", ".join(outside))
        return {
            "linked_compile_units": sources,
            "build_trace": _artifact(self.build_trace),
        }

    def _run_query(self, query_name: str, stem: str) -> Path:
        query = Path(__file__).with_name("queries") / query_name
        bqrs = self.output_dir / f"{stem}.bqrs"
        csv_path = self.output_dir / f"{stem}.csv"
        log_path = self.output_dir / f"{stem}.log"
        with log_path.open("x", encoding="utf-8") as log:
            subprocess.run(
                [
                    self.codeql,
                    "query",
                    "run",
                    str(query),
                    f"--database={self.database}",
                    f"--output={bqrs}",
                ],
                check=True,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            subprocess.run(
                [
                    self.codeql,
                    "bqrs",
                    "decode",
                    "--format=csv",
                    f"--output={csv_path}",
                    str(bqrs),
                ],
                check=True,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
        return csv_path

    def _extend_scope(
        self, base: dict[str, Any], include_csv: Path
    ) -> dict[str, Any]:
        seeds = set(base["linked_compile_units"])
        edges: dict[Path, set[Path]] = defaultdict(set)
        with include_csv.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            if set(reader.fieldnames or ()) != {"including_file", "included_file"}:
                raise ValueError(f"invalid include-edge schema: {include_csv}")
            for row in reader:
                source = _project_file(row["including_file"], self.source_root)
                target = _project_file(row["included_file"], self.source_root)
                if source is not None and target is not None:
                    edges[source].add(target)

        depth = {path: 0 for path in seeds}
        queue = deque(sorted(seeds))
        while queue:
            source = queue.popleft()
            for target in sorted(edges.get(source, ())):
                if target in depth:
                    continue
                depth[target] = depth[source] + 1
                queue.append(target)

        def record(path: Path) -> dict[str, Any]:
            return {
                "path": str(path),
                "relative_path": path.relative_to(self.source_root).as_posix(),
                "sha256": _sha256(path),
                "size": path.stat().st_size,
                "include_depth": depth[path],
            }

        return {
            "schema_version": 1,
            "source_root": str(self.source_root),
            "build_trace": base["build_trace"],
            "link_target": self.link_target,
            "linked_compile_units": [record(path) for path in sorted(seeds)],
            "scope_files": [record(path) for path in sorted(depth)],
        }

    def _filter_query(
        self, query_csv: Path, scope: dict[str, Any]
    ) -> tuple[Path, dict[str, Any]]:
        scope_by_path = {
            Path(record["path"]).resolve(strict=True): record["relative_path"]
            for record in scope["scope_files"]
        }
        excluded: Counter[str] = Counter()
        strict: list[dict[str, Any]] = []
        with query_csv.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            if set(reader.fieldnames or ()) != _QUERY_COLUMNS:
                raise ValueError(f"invalid provenance query schema: {query_csv}")
            raw_rows = 0
            for source in reader:
                raw_rows += 1
                row: dict[str, Any] = dict(source)
                valid = True
                for field in ("callsite_file", "callee_file", "binding_file"):
                    resolved = _project_file(str(row[field]), self.source_root)
                    if resolved is None or resolved not in scope_by_path:
                        excluded[field] += 1
                        valid = False
                        break
                    row[field] = scope_by_path[resolved]
                if not valid:
                    continue
                for field in _INTEGER_COLUMNS:
                    row[field] = int(str(row[field]))
                strict.append(row)

        strict.sort(
            key=lambda row: (
                str(row["evidence_tier"]),
                str(row["callsite_file"]),
                int(row["callsite_line"]),
                int(row["callsite_column"]),
                str(row["caller_qualified_name"]),
                str(row["callee_file"]),
                int(row["callee_line"]),
                str(row["callee_qualified_name"]),
            )
        )
        strict_path = self.output_dir / "provenance-edges.jsonl"
        with strict_path.open("x", encoding="utf-8") as stream:
            for row in strict:
                stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
                stream.write("\n")
        return strict_path, {
            "raw_rows": raw_rows,
            "strict_rows": len(strict),
            "excluded_rows": dict(sorted(excluded.items())),
            "evidence_tiers": dict(
                sorted(Counter(row["evidence_tier"] for row in strict).items())
            ),
        }

    @staticmethod
    def _run_logged(command: list[str], stdout: Path, stderr: Path) -> None:
        with stdout.open("xb") as output, stderr.open("xb") as errors:
            subprocess.run(command, check=True, stdout=output, stderr=errors)
