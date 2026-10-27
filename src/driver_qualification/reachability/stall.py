"""Pure stall policy using chain depth and cumulative local branch novelty.

State belongs to one driver build. A new detector or reset() starts a new
baseline. Missing local coverage preserves the original coarse progress rule.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .branches import BranchOutcome, FunctionIdentity
from .progress import Progress

REACHED = "REACHED"
PROGRESSING = "PROGRESSING"
STALLED = "STALLED"


@dataclass(frozen=True)
class StallDecision:
    """Why the last poll progressed or consumed stall patience."""

    status: str
    reason: str
    new_branch_outcomes: Optional[int]
    stale_checks: int


class StallDetector:
    def __init__(self, patience: int = 4):
        self.patience = patience
        self.reset()

    def reset(self) -> None:
        """Start a new epoch (call after the harness changes)."""
        self._best: Optional[tuple[int, int]] = None
        self._stale = 0
        self._branch_scope: Optional[tuple[int, str, FunctionIdentity]] = None
        self._seen_branches: set[BranchOutcome] = set()
        self.last_decision: Optional[StallDecision] = None

    def _observe_branches(self, p: Progress) -> Optional[int]:
        coverage = p.branch_coverage
        if coverage is None:
            return None
        scope = (p.depth, p.frontier_fn, coverage.identity)
        if scope != self._branch_scope:
            self._branch_scope = scope
            self._seen_branches = set(coverage.covered)
            return 0  # A new scope establishes a baseline, not branch novelty.
        new = coverage.covered - self._seen_branches
        self._seen_branches.update(new)
        return len(new)

    def _record(self, status: str, reason: str, new: Optional[int]) -> str:
        self.last_decision = StallDecision(status, reason, new, self._stale)
        return status

    def update(self, p: Optional[Progress]) -> str:
        """Feed one poll; return REACHED / PROGRESSING / STALLED."""
        if p is not None and p.reached:
            self._stale = 0
            return self._record(REACHED, "target_hit", self._observe_branches(p))

        # A failed measurement (p is None) counts as no-progress, never as progress.
        key = p.key() if p is not None else None
        if key is not None and (self._best is None or key > self._best):
            reason = "baseline" if self._best is None else "chain_depth"
            self._best = key
            self._stale = 0
            self._branch_scope = None
            self._seen_branches.clear()
            return self._record(PROGRESSING, reason, self._observe_branches(p))

        new = self._observe_branches(p) if p is not None and key == self._best else None
        if new is not None and new > 0:
            self._stale = 0
            return self._record(PROGRESSING, "local_branches", new)

        self._stale += 1
        status = STALLED if self._stale >= self.patience else PROGRESSING
        reason = "no_progress" if p is not None else "measurement_failed"
        return self._record(status, reason, new)
