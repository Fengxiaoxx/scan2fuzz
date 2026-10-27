"""Guard: the audited source tree must be exactly the checked-out library.

Research and audit agents grep the whole tree. Anything that is not part of
the checkout — leftovers of earlier experiments, downloaded patches, fuzz logs,
another project's sources — sits outside every provenance gate and can hand an
audit its own prior results. The pipeline's own build outputs are the only
additions allowed.

A git checkout of an autotools library ships no generated build system; its
build script runs autogen.sh/autoreconf in-tree, writing the configure script,
Makefile.in files, aclocal.m4, m4 macros and build-aux helpers that release
tarballs track as source. Those git-ignored bootstrap outputs are treated like
the pipeline's own build outputs; everything else stays stray.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# What the pipeline itself writes into the checkout: the scan's analysis build and
# clangd config, and preprocessing's sanitizer and coverage builds.
PIPELINE_ENTRIES: frozenset[str] = frozenset(
    {"build_analysis", "build_sanitize", "build_coverage", ".clangd"}
)

# Canonical autotools bootstrap outputs (autoconf, autoheader, automake,
# libtoolize, gnulib-tool), matched by name at any depth. Only git-ignored
# entries can match them: a modified tracked file of the same name still counts.
AUTOTOOLS_BOOTSTRAP_NAMES: frozenset[str] = frozenset(
    {
        "INSTALL",
        "Makefile.in",
        "aclocal.m4",
        "ar-lib",
        "compile",
        "config.guess",
        "config.h.in",
        "config.sub",
        "configure",
        "depcomp",
        "install-sh",
        "libtool.m4",
        "ltmain.sh",
        "ltoptions.m4",
        "ltsugar.m4",
        "ltversion.m4",
        "lt~obsolete.m4",
        "mdate-sh",
        "missing",
        "test-driver",
        "texinfo.tex",
    }
)
AUTOTOOLS_BOOTSTRAP_DIRS: frozenset[str] = frozenset({"autom4te.cache"})


def _is_autotools_bootstrap(status: str, path: str) -> bool:
    """True for a git-ignored autotools bootstrap output."""
    if status != "!!":
        return False
    parts = path.split("/")
    return parts[-1] in AUTOTOOLS_BOOTSTRAP_NAMES or any(
        part in AUTOTOOLS_BOOTSTRAP_DIRS for part in parts[:-1]
    )


def stray_entries(source_root: Path, *, allow: frozenset[str] = PIPELINE_ENTRIES) -> list[str]:
    """Status lines for everything in the tree that is not the checkout.

    Untracked, modified and ignored paths all count: an ignored fuzz log is as
    readable to an agent as an untracked one, and a modified source file means
    the audit is not of the version that was checked out. The one exception is
    a git-ignored autotools bootstrap output of a git checkout, which the
    library's own build creates and which no release checkout contains.
    """
    root = Path(source_root).resolve()
    # Without its own checkout there is nothing to compare against, and git
    # would silently report the enclosing repository instead.
    top = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=False,
    )
    if top.returncode or Path(top.stdout.strip()).resolve() != root:
        raise ValueError(
            f"{root} is not the top of its own git checkout, so the tree cannot be "
            f"shown to match any version: {top.stderr.strip() or top.stdout.strip()}"
        )
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain",
         "--untracked-files=all", "--ignored"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise ValueError(
            f"cannot read the git status of {root}: {result.stderr.strip()}"
        )
    stray: list[str] = []
    for line in result.stdout.splitlines():
        path = line[3:].split(" -> ")[-1].strip().strip('"')
        if path.split("/")[0] in allow:
            continue
        if _is_autotools_bootstrap(line[:2], path):
            continue
        stray.append(line.rstrip())
    return stray


def require_clean_tree(source_root: str | Path, *, allow: frozenset[str] = PIPELINE_ENTRIES) -> None:
    """Refuse to read a tree that carries anything beyond the checkout."""
    stray = stray_entries(Path(source_root), allow=allow)
    if not stray:
        return
    shown = "\n".join(stray[:20])
    more = f"\n... and {len(stray) - 20} more" if len(stray) > 20 else ""
    raise ValueError(
        f"{source_root} is not a clean checkout: {len(stray)} stray entries would be "
        f"visible to the agent; move them out of the tree first\n{shown}{more}"
    )
