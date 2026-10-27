"""Measure progress from a pre-sanitized driver toward a target line.

Decoupled layers:
  branches.py  -- pure LLVM branch extraction, without progress policy
  progress.py  -- WHAT we measure   (Progress + probe)
  stall.py     -- WHEN we give up   (StallDetector; pure policy)
  monitor.py   -- HOW we orchestrate(ReachabilityMonitor; all I/O injected)
  adapters.py  -- project wiring    (clang++/libFuzzer/config; the only project-coupled file)
"""
from .adapters import chain_step_fn, make_adapters, resolve_target
from .assert_target_marker import prepare_assert_target_marker
from .audit import log_phase, log_result, make_event_logger
from .monitor import (
    STALL_PATIENCE,
    QualificationPhase,
    QualificationPhaseEvent,
    ReachabilityMonitor,
    ReachabilityOutcome,
    ReachabilityResult,
    RuntimeBuild,
)
from .progress import Progress, probe
from .stall import PROGRESSING, REACHED, STALLED, StallDetector

__all__ = [
    "ReachabilityMonitor",
    "ReachabilityResult",
    "ReachabilityOutcome",
    "RuntimeBuild",
    "STALL_PATIENCE",
    "QualificationPhase",
    "QualificationPhaseEvent",
    "Progress",
    "probe",
    "StallDetector",
    "REACHED",
    "PROGRESSING",
    "STALLED",
    "chain_step_fn",
    "make_adapters",
    "prepare_assert_target_marker",
    "resolve_target",
    "make_event_logger",
    "log_phase",
    "log_result",
]
