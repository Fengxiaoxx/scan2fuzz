"""Run merged Trace2Fuzz drivers under the final AFL++ protocol."""

from .runner import RunOptions, run_fuzz

__all__ = ["RunOptions", "run_fuzz"]
