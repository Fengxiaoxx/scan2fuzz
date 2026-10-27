"""Pure extraction of branch outcomes from LLVM function coverage records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


# Coordinates, file IDs (including macro expansions), and true/false direction.
BranchOutcome = tuple[int, int, int, int, int, int, bool]
FunctionIdentity = tuple[str, tuple[str, ...]]


@dataclass(frozen=True)
class BranchCoverage:
    """One unambiguous function's covered outcomes within a single build."""

    identity: FunctionIdentity
    covered: frozenset[BranchOutcome]


def extract_branch_coverage(functions: Iterable[dict]) -> BranchCoverage | None:
    """Read matched LLVM functions without I/O or progress-policy decisions.

    Missing, malformed or ambiguous records return None. An explicit empty
    branch list is a valid measurement. Duplicate records of the same function
    are merged; distinct functions are never combined into a local signal.
    """
    identity: FunctionIdentity | None = None
    covered: set[BranchOutcome] = set()
    for function in functions:
        if not isinstance(function, dict):
            return None
        name = function.get("name")
        filenames = function.get("filenames")
        branches = function.get("branches")
        if (
            not isinstance(name, str) or not name
            or not isinstance(filenames, list) or not filenames
            or any(not isinstance(file, str) or not file for file in filenames)
            or not isinstance(branches, list)
        ):
            return None
        current_identity = (name, tuple(filenames))
        if identity is not None and identity != current_identity:
            return None
        identity = current_identity

        for branch in branches:
            # LLVM 15: [start line/column, end line/column, true/false counts,
            #           file ID, expanded file ID, region kind].
            if (
                not isinstance(branch, list) or len(branch) < 9
                or any(type(value) is not int for value in branch[:9])
            ):
                return None
            (
                line, col, end_line, end_col, true_count, false_count,
                file_id, expanded_id, kind,
            ) = branch[:9]
            if (
                min(line, col, end_line, end_col) <= 0
                or (end_line, end_col) < (line, col)
                or min(true_count, false_count) < 0
                or not 0 <= file_id < len(filenames)
                or not 0 <= expanded_id < len(filenames)
                or kind != 4  # CounterMappingRegion::BranchRegion
            ):
                return None
            location = (line, col, end_line, end_col, file_id, expanded_id)
            if true_count > 0:
                covered.add((*location, True))
            if false_count > 0:
                covered.add((*location, False))

    if identity is None:
        return None
    return BranchCoverage(identity, frozenset(covered))
