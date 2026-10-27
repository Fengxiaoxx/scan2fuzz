"""
Build the source-bundled driver corpus for a library.

Scans test_lib/<lib> for the library's own fuzz driver sources (upstream /
OSS-Fuzz fuzzers) and records, per driver, which library APIs it calls — found
by libclang token lexing (no compilation needed) — so the generator agent can
be shown a relevant example template.

Output: info_lib/<lib>/drivers.json — a list of:
    {"path": <path>, "apis_used": ["<api>", ...], "source": "<code>"}
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Set

import clang.cindex
from clang.cindex import TokenKind
from loguru import logger

DRIVER_EXTS = {".c", ".cc", ".cpp", ".cxx"}
MAX_BYTES = 256 * 1024


def _api_set(library_name: str) -> Set[str]:
    p = Path("info_lib") / library_name / "txt" / "api_list.txt"
    if not p.exists():
        return set()
    return {ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()}


def _apis_used(path: str, api_set: Set[str]) -> List[str]:
    """Library APIs called in the driver source: an IDENTIFIER token immediately
    followed by '(' that is a known library API. Pure lexing — tolerates a
    driver that does not compile (missing includes, etc.)."""
    lang = "c++" if path.endswith((".cc", ".cpp", ".cxx")) else "c"
    try:
        tu = clang.cindex.Index.create().parse(path, args=["-x", lang])
        f = clang.cindex.File.from_name(tu, path)
        extent = clang.cindex.SourceRange.from_locations(
            clang.cindex.SourceLocation.from_offset(tu, f, 0),
            clang.cindex.SourceLocation.from_offset(tu, f, os.path.getsize(path)),
        )
        toks = list(tu.get_tokens(extent=extent))
    except Exception as exc:
        logger.warning(f"driver_corpus: tokenize failed for {path}: {exc}")
        return []
    called = {
        t.spelling
        for i, t in enumerate(toks)
        if t.kind == TokenKind.IDENTIFIER
        and i + 1 < len(toks)
        and toks[i + 1].spelling == "("
    }
    return sorted(called & api_set)


def _find_driver_sources(test_lib_root: Path) -> List[Path]:
    """Library-bundled fuzz drivers under test_lib/<lib>, excluding dot-dirs."""
    found: List[Path] = []
    if not test_lib_root.exists():
        return found
    for src in test_lib_root.rglob("*"):
        if not src.is_file() or src.suffix.lower() not in DRIVER_EXTS:
            continue
        rel = src.relative_to(test_lib_root)
        if any(part.startswith(".") for part in rel.parts):
            continue
        if "fuzz" not in src.name.lower():
            continue
        try:
            if src.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        found.append(src)
    return found


def build_driver_corpus(library_name: str) -> Dict[str, object]:
    """Build info_lib/<lib>/api/drivers.json from the library's bundled fuzzers."""
    test_lib_root = Path("test_lib") / library_name
    out_path = Path("info_lib") / library_name / "drivers.json"
    api_set = _api_set(library_name)

    corpus: List[Dict[str, object]] = []
    for src in _find_driver_sources(test_lib_root):
        try:
            source = src.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        corpus.append(
            {
                "path": str(src),
                "apis_used": _apis_used(str(src), api_set),
                "source": source,
            }
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(corpus, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info(f"driver corpus: {len(corpus)} source fuzzers -> {out_path}")
    return {"output": str(out_path), "driver_count": len(corpus)}
