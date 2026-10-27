"""A neutral copy of the library's tracked sources for the audit sessions to read.

The checkout carries material that is not the code under audit: the repository path,
the git history and the build trees with their fuzzing flags. From those, auditors
concluded that a bug had been planted and went looking for it. The sessions now read
only this copy of the tracked files, placed outside any git worktree.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SourceCopy:
    root: Path
    commit: str
    tracked_files: int


def _git(source_root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(source_root), *args], check=True, capture_output=True
    ).stdout


def copy_tracked_sources(
    source_root: Path, *, build_inputs: list[str] | None = None
) -> SourceCopy:
    """Copy tracked sources and selected generated build inputs outside the checkout."""
    names = [os.fsdecode(name) for name in _git(source_root, "ls-files", "-z").split(b"\0") if name]
    root = Path(tempfile.mkdtemp(prefix="src-")) / source_root.name
    for name in names:
        source, target = source_root / name, root / name
        if source.is_dir() and not source.is_symlink():  # an uninitialized submodule
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=False)
    for entry in build_inputs or []:
        source = Path(entry).resolve(strict=True)
        relative = source.relative_to(source_root.resolve(strict=True))
        target = root / relative
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    commit = _git(source_root, "rev-parse", "HEAD").decode().strip()
    return SourceCopy(root=root, commit=commit, tracked_files=len(names))
