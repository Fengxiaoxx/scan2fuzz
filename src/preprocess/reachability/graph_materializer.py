#!/usr/bin/env python3
"""Map location-grounded CodeQL edges into the LLVM ABI identity space."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


HIGH_TIERS = {
    "storage_exact",
    "selector_binding",
    "schema_binding",
    "lifecycle_binding",
}


@dataclass(frozen=True)
class FunctionLocation:
    name: str
    mangled: str
    qualified_name: str
    file_path: str
    start_line: int
    end_line: int
    anchor_line: int
    anchor_col: int

    @property
    def span(self) -> int:
        return self.end_line - self.start_line

    @property
    def canonical_identity(self) -> tuple[str, str, int, int]:
        return (self.mangled, self.file_path, self.start_line, self.end_line)


@dataclass(frozen=True)
class IdentityResolution:
    status: str
    positional: tuple[FunctionLocation, ...]
    qualified: tuple[FunctionLocation, ...]

    @property
    def accepted(self) -> tuple[FunctionLocation, ...]:
        if self.status in {"exact", "clone_set"}:
            return self.qualified
        return ()


class SourcePathResolver:
    """Canonicalize debug and CodeQL paths through the build manifest."""

    def __init__(self, source_root: Path, compile_commands: Path) -> None:
        self.source_root = source_root.resolve(strict=True)
        commands = json.loads(compile_commands.read_text(encoding="utf-8"))
        if not isinstance(commands, list) or not commands:
            raise ValueError("compile_commands.json is empty")

        aliases: dict[str, set[str]] = {}
        directories = set()
        for command in commands:
            directory = Path(command["directory"]).resolve(strict=True)
            source = Path(command["file"])
            if not source.is_absolute():
                source = directory / source
            source = source.resolve(strict=True)
            try:
                source_relative = source.relative_to(self.source_root).as_posix()
                directory_relative = directory.relative_to(self.source_root).as_posix()
            except ValueError:
                continue

            directories.add(directory)
            keys = {
                normalize_path(source_relative),
                normalize_path(os.path.relpath(source, directory)),
                normalize_path(f"{directory_relative}/{source_relative}"),
            }
            if source.is_relative_to(directory):
                keys.add(normalize_path(source.relative_to(directory).as_posix()))
            for key in keys:
                aliases.setdefault(key, set()).add(source_relative)

        if not directories:
            raise ValueError("compile database has no source-root entries")
        self.directories = tuple(sorted(directories))
        self.aliases = aliases

    def resolve(self, value: str) -> str:
        resolved = self.resolve_project(value)
        return resolved if resolved is not None else normalize_path(value)

    def resolve_project(self, value: str) -> str | None:
        """Resolve a path only when it belongs to the analyzed source tree."""
        key = normalize_path(value)
        alias_targets = self.aliases.get(key, set())
        if len(alias_targets) == 1:
            return next(iter(alias_targets))
        if len(alias_targets) > 1:
            raise ValueError(f"ambiguous compile path alias: {value}")

        raw = Path(value)
        candidates = [raw] if raw.is_absolute() else [self.source_root / raw]
        resolved = set()
        for candidate in candidates:
            if not candidate.exists():
                continue
            candidate = candidate.resolve(strict=True)
            try:
                resolved.add(candidate.relative_to(self.source_root).as_posix())
            except ValueError:
                continue
        if len(resolved) == 1:
            return next(iter(resolved))
        if len(resolved) > 1:
            raise ValueError(f"ambiguous source path: {value}")
        return None

    @property
    def summary(self) -> dict[str, int]:
        return {
            "alias_keys": len(self.aliases),
            "ambiguous_alias_keys": sum(
                len(targets) > 1 for targets in self.aliases.values()
            ),
            "compile_directories": len(self.directories),
        }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_path(value: str) -> str:
    parts = []
    for part in PurePosixPath(value.replace("\\", "/")).parts:
        if part in {"", ".", "/"}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


_ABI_TAG_RE = re.compile(r"\[abi:[^\]]+\]")
_ANONYMOUS_NAMESPACE_RE = re.compile(
    r"\((?:anonymous|unnamed) namespace\)"
)


def normalize_qualified_name(value: str) -> str:
    value = _ABI_TAG_RE.sub("", value).strip()
    return _ANONYMOUS_NAMESPACE_RE.sub("(anonymous namespace)", value)


def demangle_names(names: list[str]) -> list[str]:
    if not names:
        return []
    result = subprocess.run(
        ["c++filt", "--no-params"],
        input="\n".join(names),
        capture_output=True,
        text=True,
        check=True,
    )
    demangled = result.stdout.splitlines()
    if len(demangled) != len(names):
        raise ValueError("c++filt returned an unexpected number of identities")
    return [normalize_qualified_name(name) for name in demangled]


def load_locations(
    path: Path, path_resolver: SourcePathResolver | None = None
) -> list[FunctionLocation]:
    rows = []
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        required = {
            "name",
            "mangled",
            "file_path",
            "start_line",
            "end_line",
            "anchor_line",
            "anchor_col",
        }
        if not reader.fieldnames or not required <= set(reader.fieldnames):
            raise ValueError(f"function location schema is incomplete: {path}")
        for row_number, row in enumerate(reader, 2):
            name = row["name"].strip()
            mangled = row["mangled"].strip()
            file_path = (
                path_resolver.resolve(row["file_path"])
                if path_resolver
                else normalize_path(row["file_path"])
            )
            if not name or not mangled or not file_path:
                raise ValueError(
                    f"empty function identity at {path}:{row_number}"
                )
            start_line = int(row["start_line"])
            end_line = int(row["end_line"])
            anchor_line = int(row["anchor_line"])
            anchor_col = int(row["anchor_col"])
            if (
                start_line <= 0
                or end_line < start_line
                or not start_line <= anchor_line <= end_line
                or anchor_col <= 0
            ):
                raise ValueError(
                    f"invalid function range at {path}:{row_number}"
                )
            rows.append(
                (
                    name,
                    mangled,
                    file_path,
                    start_line,
                    end_line,
                    anchor_line,
                    anchor_col,
                )
            )

    names = [row[0] for row in rows]
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        raise ValueError(f"duplicate LLVM function identities: {duplicates[:5]}")

    canonical_names = sorted({row[1] for row in rows})
    qualified_by_mangled = dict(
        zip(canonical_names, demangle_names(canonical_names), strict=True)
    )
    return [
        FunctionLocation(
            name=name,
            mangled=mangled,
            qualified_name=qualified_by_mangled[mangled],
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            anchor_line=anchor_line,
            anchor_col=anchor_col,
        )
        for (
            name,
            mangled,
            file_path,
            start_line,
            end_line,
            anchor_line,
            anchor_col,
        ) in rows
    ]


def index_locations(
    locations: list[FunctionLocation],
) -> dict[str, list[FunctionLocation]]:
    index: dict[str, list[FunctionLocation]] = {}
    for location in locations:
        index.setdefault(location.file_path, []).append(location)
    return index


def positional_locations(
    locations: dict[str, list[FunctionLocation]], file_path: str, line: int
) -> tuple[FunctionLocation, ...]:
    candidates = [
        location
        for location in locations.get(normalize_path(file_path), [])
        if location.start_line <= line <= location.end_line
    ]
    if not candidates:
        return ()
    minimum_span = min(location.span for location in candidates)
    return tuple(
        sorted(
            {
                location
                for location in candidates
                if location.span == minimum_span
            },
            key=lambda location: location.name,
        )
    )


def resolve_identity(
    locations: dict[str, list[FunctionLocation]],
    file_path: str,
    line: int,
    qualified_name: str,
    path_resolver: SourcePathResolver | None = None,
) -> IdentityResolution:
    resolved_path = (
        path_resolver.resolve(file_path)
        if path_resolver
        else normalize_path(file_path)
    )
    positional = positional_locations(locations, resolved_path, line)
    if not positional:
        return IdentityResolution("unmapped_location", (), ())

    expected = normalize_qualified_name(qualified_name)
    qualified = tuple(
        location
        for location in positional
        if location.qualified_name == expected
    )
    if not qualified:
        return IdentityResolution("qualified_name_mismatch", positional, ())

    identities = {location.canonical_identity for location in qualified}
    if len(identities) != 1:
        return IdentityResolution("ambiguous_identity", positional, qualified)
    status = "exact" if len(qualified) == 1 else "clone_set"
    return IdentityResolution(status, positional, qualified)


def read_graph(path: Path) -> set[tuple[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return {
            (row["caller_name"], row["callee_name"])
            for row in csv.DictReader(stream)
            if row["caller_name"] != row["callee_name"]
        }


def write_graph(path: Path, edges: set[tuple[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["caller_name", "callee_name"])
        writer.writerows(sorted(edges))


def read_elf_aliases(
    analysis_library: Path,
) -> tuple[set[tuple[str, str]], list[dict[str, object]]]:
    result = subprocess.run(
        ["readelf", "--syms", "--wide", str(analysis_library)],
        capture_output=True,
        text=True,
        check=True,
    )
    groups: dict[tuple[str, str, str], set[str]] = {}
    exported_groups: set[tuple[str, str, str]] = set()
    for line in result.stdout.splitlines():
        fields = line.split(None, 7)
        if len(fields) != 8 or not fields[0].rstrip(":").isdigit():
            continue
        _number, value, size, symbol_type, binding, visibility, index, name = fields
        if (
            symbol_type not in {"FUNC", "IFUNC", "GNU_IFUNC"}
            or binding not in {"GLOBAL", "WEAK", "LOCAL"}
            or index == "UND"
            or int(value, 16) == 0
        ):
            continue
        symbol = name.split(None, 1)[0].split("@", 1)[0]
        key = (value, size, index)
        groups.setdefault(key, set()).add(symbol)
        if binding in {"GLOBAL", "WEAK"} and visibility in {
            "DEFAULT",
            "PROTECTED",
        }:
            exported_groups.add(key)

    aliases = []
    edges = set()
    for (value, size, index), symbols in sorted(groups.items()):
        ordered = sorted(symbols)
        if len(ordered) < 2 or (value, size, index) not in exported_groups:
            continue
        aliases.append(
            {
                "value": value,
                "size": int(size),
                "section_index": index,
                "symbols": ordered,
            }
        )
        edges.update(
            (source, target)
            for source in ordered
            for target in ordered
            if source != target
        )
    return edges, aliases


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", required=True, type=Path)
    parser.add_argument("--direct-graph", required=True, type=Path)
    parser.add_argument("--analysis-library", required=True, type=Path)
    parser.add_argument("--function-locations", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--compile-commands", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    path_resolver = SourcePathResolver(
        args.source_root.resolve(strict=True),
        args.compile_commands.resolve(strict=True),
    )
    locations = index_locations(
        load_locations(args.function_locations, path_resolver)
    )
    direct_edges = read_graph(args.direct_graph)
    alias_edges, alias_groups = read_elf_aliases(
        args.analysis_library.resolve(strict=True)
    )
    base_edges = direct_edges | alias_edges
    indirect_edges: dict[str, set[tuple[str, str]]] = {
        "high": set(),
        "all": set(),
    }
    row_audit = []
    mapped_rows = 0
    expanded_edges = 0
    resolution_counts: Counter[str] = Counter()
    rejected_rows: Counter[str] = Counter()
    with args.strict.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            row = json.loads(line)
            caller = resolve_identity(
                locations,
                str(row["callsite_file"]),
                int(row["callsite_line"]),
                str(row["caller_qualified_name"]),
                path_resolver,
            )
            callee = resolve_identity(
                locations,
                str(row["callee_file"]),
                int(row["callee_line"]),
                str(row["callee_qualified_name"]),
                path_resolver,
            )
            resolution_counts[f"caller:{caller.status}"] += 1
            resolution_counts[f"callee:{callee.status}"] += 1
            mapped = {
                (caller_location.name, callee_location.name)
                for caller_location in caller.accepted
                for callee_location in callee.accepted
                if caller_location.name != callee_location.name
            }
            if mapped:
                mapped_rows += 1
                expanded_edges += len(mapped)
                indirect_edges["all"].update(mapped)
                if row["evidence_tier"] in HIGH_TIERS:
                    indirect_edges["high"].update(mapped)
            elif caller.accepted and callee.accepted:
                rejected_rows["self_edge"] += 1
            else:
                rejected_rows[
                    f"caller={caller.status},callee={callee.status}"
                ] += 1
            row_audit.append(
                {
                    "line": line_number,
                    "evidence_tier": row["evidence_tier"],
                    "caller_qualified_name": row["caller_qualified_name"],
                    "callee_qualified_name": row["callee_qualified_name"],
                    "caller_resolution": caller.status,
                    "callee_resolution": callee.status,
                    "caller_location_candidates": [
                        item.name for item in caller.positional
                    ],
                    "callee_location_candidates": [
                        item.name for item in callee.positional
                    ],
                    "caller_symbols": [item.name for item in caller.accepted],
                    "callee_symbols": [item.name for item in callee.accepted],
                    "mapped_edge_count": len(mapped),
                }
            )

    outputs = {}
    for name in ("high", "all"):
        path = output_dir / f"call_graph.{name}.csv"
        edges = base_edges | indirect_edges[name]
        write_graph(path, edges)
        outputs[name] = {
            "direct_edges": len(direct_edges),
            "alias_edges": len(alias_edges),
            "indirect_edges": len(indirect_edges[name]),
            "combined_edges": len(edges),
            "path": str(path),
            "sha256": sha256(path),
        }

    audit_path = output_dir / "mapping.jsonl"
    with audit_path.open("w", encoding="utf-8") as stream:
        for record in row_audit:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
    aliases_path = output_dir / "elf-alias-groups.json"
    aliases_path.write_text(
        json.dumps(alias_groups, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary = {
        "schema_version": 2,
        "input_rows": len(row_audit),
        "mapped_rows": mapped_rows,
        "unmapped_rows": len(row_audit) - mapped_rows,
        "expanded_edges_before_deduplication": expanded_edges,
        "identity_resolution": dict(sorted(resolution_counts.items())),
        "source_path_resolution": path_resolver.summary,
        "rejected_rows": dict(sorted(rejected_rows.items())),
        "mapping_audit": {
            "path": str(audit_path),
            "sha256": sha256(audit_path),
        },
        "elf_alias_groups": {
            "groups": len(alias_groups),
            "edges": len(alias_edges),
            "path": str(aliases_path),
            "sha256": sha256(aliases_path),
        },
        "outputs": outputs,
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
