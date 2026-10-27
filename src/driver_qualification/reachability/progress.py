"""Measure target hits, the covered chain prefix, and optional frontier branches.

Local branch growth describes exploration activity, not distance to the target.
The stall policy compares these snapshots; this module only collects evidence.
"""
from __future__ import annotations

import filecmp
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Sequence

from src.core.llvm_cov import ReplayCrash, bare_name, replay_and_export, segment_span_count

from .branches import BranchCoverage, extract_branch_coverage


@dataclass(frozen=True)
class Progress:
    """How far the accumulated corpus drives execution toward the target line."""

    hit: int            # exec count of the target line (>0 == REACHED)
    depth: int          # deepest entered function index on the chain (higher == closer)
    frontier_fn: str    # name of that deepest entered function
    chain_len: int
    branch_coverage: Optional[BranchCoverage] = None

    @property
    def reached(self) -> bool:
        return self.hit > 0

    def key(self) -> tuple[int, int]:
        """Coarse progress; local branch novelty is tracked separately."""
        return (1 if self.hit > 0 else 0, self.depth)


@dataclass(frozen=True)
class ChainStep:
    fn: str
    file: Optional[str] = None
    line: Optional[int] = None
    col: Optional[int] = None
    symbol: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None


class CoveragePathResolutionError(RuntimeError):
    """Coverage source paths cannot be matched to analysis source identities."""


class CoverageSourceAbsentError(CoveragePathResolutionError):
    """An analysis source has no independently measurable coverage region."""


_HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx", ".inc"})


def _coverage_files(data: dict) -> tuple[str, ...]:
    files: set[str] = set()
    for block in data.get("data", []):
        for file_data in block.get("files", []):
            filename = file_data.get("filename")
            if isinstance(filename, str) and filename:
                files.add(filename)
        for function in block.get("functions", []):
            for filename in function.get("filenames", []):
                if isinstance(filename, str) and filename:
                    files.add(filename)
    return tuple(sorted(files))


def _identical_header_copies(source: Path, candidates: Sequence[str]) -> list[str]:
    """Match installed header copies only when their full contents agree."""
    if source.suffix not in _HEADER_SUFFIXES or not source.is_file():
        return []
    matches = []
    for filename in candidates:
        candidate = Path(filename)
        if candidate.name != source.name or not candidate.is_file():
            continue
        try:
            if filecmp.cmp(source, candidate, shallow=False):
                matches.append(filename)
        except OSError:
            continue
    return matches


class CoverageSourceResolver:
    """Resolve analysis source paths to llvm-cov files by explicit identity."""

    def __init__(self, data: dict, source_root: str | None) -> None:
        self.source_root = Path(source_root).resolve() if source_root else None
        self.coverage_files = _coverage_files(data)
        self._resolved: dict[str, dict[str, str]] = {}

    def _coverage_build_path(self, analysis_path: Path) -> Path | None:
        """Return the explicitly configured coverage-build counterpart.

        Build-generated sources are emitted once per build mode.  Static
        analysis records their ``build_analysis`` coordinates, while llvm-cov
        records the corresponding ``build_coverage`` coordinates.  These are
        fixed build roles, so select the coverage path directly instead of
        searching for an equivalent file.
        """
        if self.source_root is None:
            return None
        try:
            relative = analysis_path.resolve().relative_to(self.source_root)
        except ValueError:
            return None
        if not relative.parts or relative.parts[0] != "build_analysis":
            return None
        return self.source_root.joinpath(
            "build_coverage", *relative.parts[1:]
        ).resolve()

    def resolve(self, requested: str) -> str:
        key = _normalize_file(requested)
        if not key:
            raise CoveragePathResolutionError("empty analysis source path")
        cached = self._resolved.get(key)
        if cached is not None:
            return cached["coverage_file"]

        analysis_path = Path(requested)
        if not analysis_path.is_absolute() and self.source_root is not None:
            analysis_path = self.source_root / analysis_path

        coverage_build_path = self._coverage_build_path(analysis_path)
        if coverage_build_path is not None:
            configured = [
                filename
                for filename in self.coverage_files
                if Path(filename).resolve() == coverage_build_path
            ]
            if len(configured) == 1:
                self._resolved[key] = {
                    "analysis_file": requested,
                    "coverage_file": configured[0],
                    "method": "coverage_build_directory",
                }
                return configured[0]
            if len(configured) > 1:
                raise CoveragePathResolutionError(
                    f"ambiguous configured coverage source path: {requested}: "
                    f"{configured}"
                )
            raise CoverageSourceAbsentError(
                f"configured coverage source path is absent from coverage data: "
                f"{requested} (required {coverage_build_path})"
            )

        exact = [
            filename
            for filename in self.coverage_files
            if _normalize_file(filename) == key
        ]
        if len(exact) == 1:
            self._resolved[key] = {
                "analysis_file": requested,
                "coverage_file": exact[0],
                "method": "exact_path",
            }
            return exact[0]
        if len(exact) > 1:
            raise CoveragePathResolutionError(
                f"ambiguous exact coverage source path: {requested}: {exact}"
            )

        rooted = [
            filename
            for filename in self.coverage_files
            if Path(filename).resolve() == analysis_path.resolve()
        ]
        if len(rooted) == 1:
            self._resolved[key] = {
                "analysis_file": requested,
                "coverage_file": rooted[0],
                "method": "source_root_path",
            }
            return rooted[0]
        if len(rooted) > 1:
            raise CoveragePathResolutionError(
                f"ambiguous source-root coverage path: {requested}: {rooted}"
            )
        copies = _identical_header_copies(analysis_path, self.coverage_files)
        if copies:
            selected = copies[0]
            self._resolved[key] = {
                "analysis_file": requested,
                "coverage_file": selected,
                "method": "identical_header_copy",
            }
            return selected
        raise CoverageSourceAbsentError(
            f"analysis source path is absent from coverage data: "
            f"{requested} (expected {analysis_path.resolve()})"
        )

    def audit(self) -> dict:
        return {
            "schema_version": 1,
            "coverage_files": list(self.coverage_files),
            "resolutions": [self._resolved[key] for key in sorted(self._resolved)],
        }


def _write_resolution_audit(path: str | None, payload: dict) -> None:
    if not path:
        return
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def resolve_coverage_sources(
    data: dict,
    target_file: str,
    chain: Sequence[Any],
    *,
    source_root: str | None,
    audit_path: str | None = None,
) -> tuple[str, List[ChainStep]]:
    """Resolve target and chain files to the exact files named by llvm-cov."""
    resolver = CoverageSourceResolver(data, source_root)
    try:
        resolved_target = resolver.resolve(target_file)
        resolved_chain = []
        skipped_chain_steps = []
        for step in normalize_chain(chain):
            if step.file is None:
                resolved_chain.append(step)
                continue
            try:
                resolved_file = resolver.resolve(step.file)
            except CoverageSourceAbsentError as exc:
                skipped_chain_steps.append(
                    {
                        "fn": step.fn,
                        "file": step.file,
                        "line": step.line,
                        "col": step.col,
                        "symbol": step.symbol,
                        "reason": str(exc),
                    }
                )
                continue
            resolved_chain.append(
                ChainStep(
                    step.fn,
                    resolved_file,
                    step.line,
                    step.col,
                    step.symbol,
                    step.start_line,
                    step.end_line,
                )
            )
    except CoveragePathResolutionError as exc:
        payload = resolver.audit()
        payload.update({
            "status": "unresolved",
            "target_file": target_file,
            "error": str(exc),
        })
        _write_resolution_audit(audit_path, payload)
        raise
    payload = resolver.audit()
    payload.update(
        {
            "status": (
                "resolved_with_unmeasurable_chain_steps"
                if skipped_chain_steps
                else "resolved"
            ),
            "target_file": target_file,
            "target_equivalent_files": sorted(
                _equivalent_target_files(data, resolved_target)
            ),
            "skipped_chain_steps": skipped_chain_steps,
        }
    )
    _write_resolution_audit(audit_path, payload)
    return resolved_target, resolved_chain


def _to_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_file(file: Any) -> Optional[str]:
    if file is None:
        return None
    out = str(file).strip().replace("\\", "/")
    if not out:
        return None
    while out.startswith("../") or out.startswith("./"):
        if out.startswith("../"):
            out = out[3:]
        elif out.startswith("./"):
            out = out[2:]
    return out


def normalize_chain(chain: Sequence[Any]) -> List[ChainStep]:
    """Normalize legacy and coordinate-aware reach chains."""
    out: List[ChainStep] = []
    for step in chain:
        if isinstance(step, ChainStep):
            out.append(ChainStep(step.fn, _normalize_file(step.file),
                                 _to_int(step.line), _to_int(step.col),
                                 step.symbol, _to_int(step.start_line),
                                 _to_int(step.end_line)))
        elif isinstance(step, dict):
            out.append(ChainStep(str(step.get("fn", "")),
                                 _normalize_file(step.get("file")),
                                 _to_int(step.get("line")),
                                 _to_int(step.get("col")),
                                 str(step.get("symbol") or "") or None,
                                 _to_int(step.get("start_line")),
                                 _to_int(step.get("end_line"))))
        else:
            out.append(ChainStep(str(step)))
    return out


# --- llvm-cov plumbing -------------------------------------------------------

def _fn_entry_counts(data: dict) -> dict:
    """function bare-name -> entry count (max over occurrences / clones)."""
    out: dict = {}
    for d in data.get("data", []):
        for fn in d.get("functions", []):
            name = bare_name(fn.get("name", ""))   # strip file: prefix + .NNN clone suffix
            out[name] = max(out.get(name, 0), _to_int(fn.get("count")) or 0)
    return out


def _file_matches(export_file: Any, step_file: str) -> bool:
    left = _normalize_file(export_file)
    right = _normalize_file(step_file)
    return bool(left and right and left == right)


def _step_identities(step: ChainStep) -> set[str]:
    return {
        value
        for value in (step.symbol, step.fn)
        if isinstance(value, str) and value
    }


def llvm_function_matches_step(fn: dict, step: ChainStep) -> bool:
    """Match one chain node to an LLVM coverage function mechanically.

    Candidate-plan coordinates identify declarations, while LLVM coverage
    regions start at function bodies. Function identity and source file are
    therefore the stable join keys; declaration containment is not.
    """
    raw_name = str(fn.get("name") or "")
    identities = _step_identities(step)
    if not identities or (
        raw_name not in identities and bare_name(raw_name) not in identities
    ):
        return False
    if step.file is None:
        return True
    return any(
        _file_matches(filename, step.file)
        for filename in fn.get("filenames", [])
    )


def _identified_step_entered(data: dict, step: ChainStep) -> bool:
    return any(
        max(_to_int(fn.get("count")) or 0, 0) > 0
        for block in data.get("data", [])
        for fn in block.get("functions", [])
        if llvm_function_matches_step(fn, step)
    )


def _step_entered(data: dict, counts: dict, step: ChainStep) -> bool:
    if step.file is not None:
        return _identified_step_entered(data, step)
    return counts.get(bare_name(step.fn), 0) > 0


def _equivalent_target_files(data: dict, target_file: str) -> set[str]:
    """Find byte-identical header copies represented separately by llvm-cov.

    A driver can compile an installed public header while a linked library
    also records the original source header.  llvm-cov treats those copies as
    separate files even though their line numbers and contents are identical.
    """
    source = Path(target_file)
    aliases = {_normalize_file(target_file)}
    for filename in _identical_header_copies(source, _coverage_files(data)):
        aliases.add(_normalize_file(filename))
    return aliases


def _target_line_count(data: dict, target_file: str, line: int) -> int:
    """Count target line hits across byte-identical header copies."""
    aliases = _equivalent_target_files(data, target_file)
    best = 0
    for d in data.get("data", []):
        for f in d.get("files", []):
            filename = f.get("filename", "")
            if _normalize_file(filename) not in aliases:
                continue
            count = segment_span_count(f.get("segments", []), line)
            if count is not None:
                best = max(best, count)
    return best


# --- the probe ---------------------------------------------------------------

def probe(coverage_binary: str, corpus_dir: str, target: str, chain: Sequence[Any],
          *, workdir: str = "/tmp", timeout: int = 600,
          rss_limit_mb: int | None = None,
          source_root: str | None = None,
          resolution_audit_path: str | None = None,
          target_marker_path: str | None = None) -> Progress | ReplayCrash | None:
    """Replay the WHOLE corpus over `coverage_binary` and measure progress.

    target = "file.c:123"; chain = [shallow ... deep] function names ending at the
    target's enclosing function. Returns ReplayCrash for a failed input execution
    and None for a measurement tool failure. Replaying
    the full corpus keeps the progress signal monotone (min-distance over the
    accumulated corpus).
    """
    target_file, line_s = target.rsplit(":", 1)
    line = int(line_s)

    diagnostic_path = str(Path(workdir) / "measurement-failure.json")
    marker = Path(target_marker_path) if target_marker_path else None
    if marker is not None:
        marker.unlink(missing_ok=True)
    data = replay_and_export(
        coverage_binary,
        corpus_dir,
        workdir=workdir,
        tag="reachability_monitor",
        timeout=timeout,
        rss_limit_mb=rss_limit_mb,
        diagnostic_path=diagnostic_path,
    )
    if data is None or isinstance(data, ReplayCrash):
        return data

    try:
        target_file, steps = resolve_coverage_sources(
            data,
            target_file,
            chain,
            source_root=source_root,
            audit_path=resolution_audit_path,
        )
    except CoveragePathResolutionError as exc:
        Path(diagnostic_path).write_text(
            json.dumps({"phase": "source_resolution", "error": str(exc)}, indent=2) + "\n",
            encoding="utf-8",
        )
        return None

    counts = _fn_entry_counts(data)
    depth, frontier = 0, ""
    for i, step in enumerate(steps):
        if _step_entered(data, counts, step):
            depth, frontier = i + 1, step.fn
        else:
            break

    hit = (
        int(marker.is_file())
        if marker is not None
        else _target_line_count(data, target_file, line)
    )
    branches = None
    if depth > 0:
        frontier_step = steps[depth - 1]
        branches = extract_branch_coverage(
            function
            for block in data.get("data", [])
            for function in block.get("functions", [])
            if llvm_function_matches_step(function, frontier_step)
        )
    return Progress(hit=hit,
                    depth=depth, frontier_fn=frontier, chain_len=len(steps),
                    branch_coverage=branches)
