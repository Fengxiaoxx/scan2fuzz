"""Choose one covered function and show its source with per-line counts.

The static chain is only a search order for selecting source context. It is
not an observed call trace and is not included in the agent-facing report.
"""
from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Callable, Optional

from src.core import get_project_root

from src.core.llvm_cov import bare_name as _bare
from src.core.llvm_cov import ReplayCrash, replay_and_export, segment_span_count
from .progress import (
    ChainStep,
    CoveragePathResolutionError,
    Progress,
    normalize_chain,
    resolve_coverage_sources,
)

PROJECT_ROOT = get_project_root()


def _path_key(path: str) -> str:
    return os.path.normpath(os.fspath(path)).replace(os.sep, "/")


def _filename_matches(candidate: str, wanted: str) -> bool:
    cand = _path_key(candidate)
    want = _path_key(wanted)
    if "/" in want:
        return cand == want or cand.endswith(f"/{want}") or want.endswith(f"/{cand}")
    return os.path.basename(cand) == want


def _region_file(fnames: list, reg: list) -> Optional[str]:
    if len(reg) < 6:
        return None
    idx = reg[5]
    if not isinstance(idx, int) or idx < 0 or idx >= len(fnames):
        return None
    return fnames[idx]


def _step_fn(step) -> str:
    return str(getattr(step, "fn", step))


def _step_line(step) -> Optional[int]:
    line = getattr(step, "line", None)
    if line is None:
        return None
    try:
        return int(line)
    except (TypeError, ValueError):
        return None


def _line_counts(data: dict, file_name: str, l0: int, l1: int) -> dict:
    # Use the same line-count interpretation as the reachability probe when
    # llvm-cov provides file segments. Function regions are a fallback for
    # older/synthetic exports that omit file records.
    segments = [
        file_record["segments"]
        for block in data.get("data", [])
        for file_record in block.get("files", [])
        if _filename_matches(str(file_record.get("filename") or ""), file_name)
        and file_record.get("segments")
    ]
    if segments:
        counts = {}
        for line in range(l0, l1 + 1):
            values = [segment_span_count(items, line) for items in segments]
            present = [value for value in values if value is not None]
            if present:
                counts[line] = max(present)
        return counts
    best = {}
    for d in data.get("data", []):
        for fn in d.get("functions", []):
            fnames = [os.fspath(x) for x in fn.get("filenames", [])]
            for reg in fn.get("regions", []):
                reg_file = _region_file(fnames, reg)
                if reg_file is None or not _filename_matches(reg_file, file_name):
                    continue
                rl0, rl1, cnt = reg[0], reg[2], reg[4]
                span = rl1 - rl0
                for ln in range(max(rl0, l0), min(rl1, l1) + 1):
                    if ln not in best or span < best[ln][0]:
                        best[ln] = (span, cnt)
    return {ln: c for ln, (s, c) in best.items()}


def _src_path(lib: str, file_name: str):
    p = Path(file_name)
    if p.is_absolute() and p.exists():
        return p
    lib_root = PROJECT_ROOT / "test_lib" / lib
    direct = lib_root / file_name
    if direct.exists():
        return direct
    file_base = os.path.basename(file_name)
    for sub in ("src", "include", "."):
        p = PROJECT_ROOT / "test_lib" / lib / sub / file_base
        if p.exists():
            return p
    hits = [
        hit for hit in lib_root.rglob(file_base)
        if _filename_matches(str(hit.relative_to(lib_root)), file_name)
    ]
    if not hits:
        hits = list(lib_root.rglob(file_base))
    return hits[0] if hits else None


def _display_file(lib: str, file_name: str) -> str:
    p = Path(file_name)
    if not p.is_absolute():
        return p.as_posix()
    lib_root = PROJECT_ROOT / "test_lib" / lib
    try:
        return p.resolve().relative_to(lib_root.resolve()).as_posix()
    except (OSError, ValueError):
        parts = p.parts
        for idx, part in enumerate(parts[:-1]):
            if part == "test_lib" and idx + 1 < len(parts) and parts[idx + 1] == lib:
                return Path(*parts[idx + 2:]).as_posix()
        return os.path.basename(file_name)


def _function_source_spans(fn: dict) -> list[tuple[str, int, int]]:
    """Return source ranges from one llvm-cov function record."""
    filenames = [os.fspath(name) for name in fn.get("filenames", [])]
    spans = []
    for filename in dict.fromkeys(filenames):
        regions = [
            region for region in fn.get("regions", [])
            if _region_file(filenames, region) == filename
            and len(region) >= 5
            and isinstance(region[0], int)
            and isinstance(region[2], int)
        ]
        if regions:
            spans.append((filename, min(region[0] for region in regions),
                          max(region[2] for region in regions)))
    return spans


def _covered_span_for_step(
    data: dict,
    step: ChainStep,
    *,
    target_file: Optional[str] = None,
    target_line: Optional[int] = None,
) -> Optional[tuple[str, int, int]]:
    """Identify a chain function, then require positive entry coverage.

    Match identity and source location before checking the count: selecting
    the only executed same-name function could otherwise pick a different
    function in another translation unit. Ambiguous equal-ranked matches are
    deliberately left unresolved.
    """
    symbol = step.symbol or ""
    name = step.fn
    candidates = []
    for block in data.get("data", []):
        for fn in block.get("functions", []):
            raw = str(fn.get("name") or "")
            simple = _bare(raw)
            if symbol and raw == symbol:
                identity = 3
            elif symbol and simple == _bare(symbol):
                identity = 2
            elif raw == name or simple == _bare(name):
                identity = 1
            else:
                continue
            try:
                count = max(int(fn.get("count") or 0), 0)
            except (TypeError, ValueError):
                count = 0
            for filename, lo, hi in _function_source_spans(fn):
                if step.file and not _filename_matches(filename, step.file):
                    continue
                if target_file and not _filename_matches(filename, target_file):
                    continue
                if target_line is not None and not lo <= target_line <= hi:
                    continue
                file_rank = (
                    2 if step.file and _path_key(filename) == _path_key(step.file)
                    else 1 if step.file else 0
                )
                line = _step_line(step)
                distance = 0 if line is None or lo <= line <= hi else min(
                    abs(line - lo), abs(line - hi)
                )
                candidates.append(((identity, file_rank, -distance),
                                   (filename, lo, hi), count))
    if not candidates:
        return None
    best_rank = max(rank for rank, _, _ in candidates)
    best = [(span, count) for rank, span, count in candidates if rank == best_rank]
    distinct_spans = {span for span, _ in best}
    if len(distinct_spans) != 1 or not any(count > 0 for _, count in best):
        return None
    filename, lo, hi = next(iter(distinct_spans))
    # LLVM regions often begin at the opening brace.  Candidate-plan source
    # extents include the declaration (including multiline signatures).
    declaration_line = step.start_line or _step_line(step)
    if declaration_line is not None and declaration_line > 0:
        lo = min(lo, declaration_line)
    if step.end_line is not None and step.end_line >= lo:
        hi = max(hi, step.end_line)
    return filename, lo, hi


def make_region_diagnose(lib: str, target: str, chain, build_cov: Callable[[str], Optional[str]],
                         corpus_dir: str, *, workdir: str = "/tmp/reachability_monitor",
                         window: int = 18,
                         source_root: Optional[str] = None) -> Callable[[str, Optional[Progress]], str]:
    chain: list[ChainStep] = list(normalize_chain(chain))
    tgt_file, tgt_line_s = target.rsplit(":", 1)
    tgt_line = int(tgt_line_s)

    def diagnose(driver_src: str, p: Optional[Progress]) -> str:
        report = f"Specified code line {target}: not covered in this bounded run."

        covbin = build_cov(driver_src)
        data = (replay_and_export(
                    covbin, corpus_dir, workdir=workdir, tag="diag",
                    diagnostic_path=str(Path(workdir) / "diagnosis-failure.json"),
                )
                if covbin else None)
        if isinstance(data, ReplayCrash):
            return (
                report + "\nCrash observed while replaying the corpus over the coverage binary.\n"
                f"Command: {shlex.join(data.command)}\n"
                f"Return code: {data.returncode}\n"
                f"Crash input: {data.input_path}\n"
                f"Replay output:\n{data.stdout}\n{data.stderr}"
            )
        if data is None:
            return report + "\nLine-by-line coverage data is unavailable."
        search_chain = chain
        search_target_file = tgt_file
        if source_root is not None:
            try:
                search_target_file, search_chain = resolve_coverage_sources(
                    data, tgt_file, chain, source_root=source_root,
                )
            except CoveragePathResolutionError:
                return report + "\nCoverage source paths could not be matched reliably."
        span = None
        detail_step = None
        if search_chain:
            span = _covered_span_for_step(
                data, search_chain[-1],
                target_file=search_target_file, target_line=tgt_line,
            )
            if span:
                detail_step = search_chain[-1]
            else:
                for step in reversed(search_chain):
                    span = _covered_span_for_step(data, step)
                    if span:
                        detail_step = step
                        break
        if not span or detail_step is None:
            return report + "\nNo reliably matched source for a covered function was found."
        file_name, l0, l1 = span
        file_display = _display_file(lib, file_name)
        lc = _line_counts(data, file_name, l0, l1)
        src = _src_path(lib, file_name)
        if src is None:
            return report + "\nA function was selected, but its source file is unavailable."
        lines = src.read_text(errors="ignore").splitlines()
        if l0 < 1 or l0 > len(lines):
            return report + "\nA function was selected, but its source line range is unavailable."
        out = [report,
               f"Line-by-line source coverage for {_step_fn(detail_step)} ({file_display}:{l0}-{l1}):",
               f"  {'Line':>5} {'Count':>8}  Source"]
        for ln in range(l0, min(l1, len(lines)) + 1):
            cnt = lc.get(ln)
            out.append(f"  {ln:>5} {('—' if cnt is None else cnt):>8}  {lines[ln - 1]}")
        return "\n".join(out)

    return diagnose
