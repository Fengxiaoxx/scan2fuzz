"""
Shared helpers for CLI entrypoints.
"""

from __future__ import annotations

import argparse
import os
import warnings

from src.core.config import DEFAULT_CONCURRENCY
from src.core.log_config import add_file_log_sink, configure_logger
from src.llm.api_key_pool import configure_concurrency

__all__ = [
    "add_concurrency_argument",
    "add_file_log_sink",
    "add_fuzz_concurrency_argument",
    "apply_concurrency",
    "configure_logger",
    "positive_int",
    "suppress_async_cleanup_warnings",
    "suppress_langchain_user_warnings",
]


def suppress_async_cleanup_warnings() -> None:
    """Hide noisy async cleanup warnings from third-party libraries."""
    warnings.filterwarnings(
        "ignore",
        message="coroutine.*was never awaited",
        category=RuntimeWarning,
    )
    warnings.filterwarnings(
        "ignore",
        message="Enable tracemalloc.*",
        category=RuntimeWarning,
    )


def suppress_langchain_user_warnings() -> None:
    """Hide deprecated-user warnings emitted by legacy LangChain packages."""
    warnings.filterwarnings(
        "ignore",
        category=UserWarning,
        module="langchain_core.globals",
    )


def positive_int(value: str) -> int:
    """Parse a positive integer for CLI counts, timeouts and concurrency."""
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def add_concurrency_argument(parser: argparse.ArgumentParser) -> None:
    """A stage's LLM budget: its parallel LLM-facing work and its simultaneous LLM calls."""
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=DEFAULT_CONCURRENCY,
        help="parallel LLM-facing work units and simultaneous LLM calls of this stage (default: %(default)s)",
    )


def add_fuzz_concurrency_argument(parser: argparse.ArgumentParser) -> None:
    """driver_rounds' CPU budget: reachability fuzzers run outside the LLM budget, one per core."""
    parser.add_argument(
        "--fuzz-concurrency",
        type=positive_int,
        default=len(os.sched_getaffinity(0)),
        help="reachability fuzzers running at once in driver_rounds (default: the CPUs available, %(default)s)",
    )


def apply_concurrency(concurrency: int) -> None:
    """Bind the stage's LLM key pool to its --concurrency before any Agent runs."""
    configure_concurrency(concurrency)
