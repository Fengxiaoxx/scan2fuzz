"""Pack function units into slices and render a slice's numbered source; a slice never splits a function."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.scan.unit_audit.units import Unit

DEFAULT_SLICE_LINES = 800


@dataclass(frozen=True)
class Slice:
    """A contiguous run of one file's functions, read in a single session."""

    file: str
    start: int
    end: int
    units: tuple[Unit, ...]

    def listing(self) -> str:
        """The function list that goes into the prompt."""
        return "\n".join(
            f"- {unit.name} (lines {unit.start_line}-{unit.end_line})"
            for unit in self.units
        )


def build_slices(units: list[Unit], max_lines: int = DEFAULT_SLICE_LINES) -> list[Slice]:
    """Pack consecutive units of one file up to a line budget.

    A single function longer than the budget becomes its own slice rather than
    being cut, because a partial function cannot be audited soundly.
    """
    if max_lines < 1:
        raise ValueError("max_lines must be at least 1")

    slices: list[Slice] = []
    current: list[Unit] = []
    current_lines = 0
    for unit in sorted(units, key=lambda item: (item.file, item.start_line)):
        same_file = bool(current) and current[0].file == unit.file
        if current and (not same_file or current_lines + unit.lines > max_lines):
            slices.append(_make_slice(current))
            current, current_lines = [], 0
        current.append(unit)
        current_lines += unit.lines
    if current:
        slices.append(_make_slice(current))
    return slices


def _make_slice(units: list[Unit]) -> Slice:
    return Slice(
        file=units[0].file,
        start=min(unit.start_line for unit in units),
        end=max(unit.end_line for unit in units),
        units=tuple(units),
    )


def render_source(source_root: Path, slice_: Slice) -> str:
    """Render the slice's span with real line numbers at the start of each line."""
    path = source_root / slice_.file
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    last = min(slice_.end, len(lines))
    return "\n".join(
        f"{number:5d}  {lines[number - 1]}"
        for number in range(slice_.start, last + 1)
    )
