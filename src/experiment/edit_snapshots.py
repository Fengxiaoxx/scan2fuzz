"""Immutable source snapshots for auditing one editing attempt.

The caller owns the attempt directory and must stop editing while capturing a
snapshot. Validation and disposition belong to the workflow's result record.
"""

from __future__ import annotations

import difflib
import hashlib
from pathlib import Path

from .store import RunArtifactStore


def render_full_diff(
    before: bytes,
    after: bytes,
    *,
    fromfile: str = "before.cpp",
    tofile: str = "after.cpp",
) -> str:
    """Render all source lines, marking additions and deletions.

    Identical inputs produce only unchanged context lines, without hunks.
    """
    before_lines = before.decode("utf-8").splitlines(keepends=True)
    after_lines = after.decode("utf-8").splitlines(keepends=True)
    if before == after:
        lines = (" " + line for line in after_lines)
    else:
        lines = difflib.unified_diff(
            before_lines, after_lines,
            fromfile=fromfile, tofile=tofile,
            n=max(len(before_lines), len(after_lines)),
        )
    # Preserve the distinction between a final newline and no final newline.
    return "".join(
        line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
        for line in lines
    )


class EditSnapshots:
    def __init__(self, store: RunArtifactStore, attempt_dir: Path):
        self.store = store
        self.directory = Path(attempt_dir)
        if not self.directory.is_absolute():
            self.directory = store.run_dir / self.directory
        self.directory = self.directory.absolute()
        self.directory.relative_to(store.run_dir)
        if self.directory.resolve() != self.directory:
            raise ValueError("snapshot directory must not contain symlinks or '..'")

    @property
    def before(self) -> Path:
        return self.directory / "before.cpp"

    @property
    def after(self) -> Path:
        return self.directory / "after.cpp"

    def capture_before(self, source: Path) -> Path:
        """Capture before invoking the editor; never overwrite an old attempt."""
        if self.after.exists():
            raise FileExistsError("attempt already contains an after snapshot")
        return self.store.copy_file(source, self.before)

    def capture_after(self, source: Path) -> Path:
        """Capture immediately after editing, before any other writer runs."""
        if not self.before.is_file():
            raise FileNotFoundError("before snapshot is required")
        return self.store.copy_file(source, self.after)

    def describe(self) -> dict[str, str | None]:
        """Return version identities; missing after means incomplete, not no change."""
        before = self.before.read_bytes()
        after = self.after.read_bytes() if self.after.exists() else None
        return {
            "status": "incomplete" if after is None else (
                "no_change" if before == after else "changed"
            ),
            "before_sha256": hashlib.sha256(before).hexdigest(),
            "after_sha256": hashlib.sha256(after).hexdigest() if after is not None else None,
        }

    def diff(self) -> str:
        """Render this attempt's before/after as a full-file diff.

        Identical snapshots produce only unchanged context lines, without hunks.
        """
        return render_full_diff(self.before.read_bytes(), self.after.read_bytes())
