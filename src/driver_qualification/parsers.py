"""Small parsing helpers for qualification-time libFuzzer output."""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Dict, Optional


_LOG_HEAD_BYTES = 64 * 1024
_LOG_TAIL_BYTES = 2 * 1024 * 1024


def _read_log_excerpt(log_file: str) -> str:
    """Read the portions of a potentially unbounded binary fuzzer log we need."""
    size = os.path.getsize(log_file)
    with open(log_file, "rb") as handle:
        if size <= _LOG_HEAD_BYTES + _LOG_TAIL_BYTES:
            payload = handle.read()
        else:
            head = handle.read(_LOG_HEAD_BYTES)
            handle.seek(-_LOG_TAIL_BYTES, os.SEEK_END)
            tail = handle.read(_LOG_TAIL_BYTES)
            payload = head + b"\n[... log middle omitted ...]\n" + tail
    return payload.decode("utf-8", errors="replace")


def parse_fuzzer_log(log_file: str) -> Dict[str, Optional[int]]:
    """Extract stable runtime statistics from a libFuzzer log."""
    if not os.path.exists(log_file):
        return {
            "status": "MISSING",
            "exit_code": None,
            "started_at": None,
            "finished_at": None,
            "total_runs": 0,
            "runtime_seconds": 0,
            "exec_per_sec": 0,
            "corpus_size": 0,
            "fuzz_time_seconds": 0,
            "error": "log file missing",
        }

    content = _read_log_excerpt(log_file)

    stats: Dict[str, Optional[int]] = {
        "status": "UNKNOWN",
        "exit_code": None,
        "started_at": None,
        "finished_at": None,
        "total_runs": 0,
        "runtime_seconds": 0,
        "exec_per_sec": 0,
        "corpus_size": 0,
        "fuzz_time_seconds": 0,
        "error": None,
    }

    exit_matches = re.findall(r"Exit code:\s*(-?\d+)", content)
    if exit_matches:
        stats["exit_code"] = int(exit_matches[-1])
        stats["status"] = "DONE" if stats["exit_code"] == 0 else "ERROR"
        if stats["exit_code"] != 0:
            reachability_matches = re.findall(
                r"Reachability outcome:\s*(.+)", content
            )
            error_matches = re.findall(r"\nError:\s*(.+)", content)
            if reachability_matches:
                stats["error"] = (
                    "reachability_outcome="
                    f"{reachability_matches[-1].strip()}"
                )
            elif error_matches:
                stats["error"] = error_matches[-1].strip()

    start_match = re.search(r"Started at:\s*(.+)", content)
    finish_matches = re.findall(r"Finished at:\s*(.+)", content)
    if start_match:
        stats["started_at"] = start_match.group(1).strip()
    if finish_matches:
        stats["finished_at"] = finish_matches[-1].strip()

    done_matches = re.findall(r"Done\s+(\d+)\s+runs\s+in\s+(\d+)\s+second", content)
    if done_matches:
        runs, seconds = done_matches[-1]
        stats["total_runs"] = int(runs)
        stats["runtime_seconds"] = int(seconds)
        stats["fuzz_time_seconds"] = int(seconds)

    pulse_matches = re.findall(r"#\d+.*?corp:\s*(\d+).*?exec/s:?\s*(\d+)", content)
    if pulse_matches:
        corpus_size, exec_per_sec = pulse_matches[-1]
        stats["corpus_size"] = int(corpus_size)
        stats["exec_per_sec"] = int(exec_per_sec)

    if stats["runtime_seconds"] == 0 and stats["started_at"] and stats["finished_at"]:
        try:
            start = datetime.fromisoformat(str(stats["started_at"]))
            finish = datetime.fromisoformat(str(stats["finished_at"]))
            stats["runtime_seconds"] = max(0, int((finish - start).total_seconds()))
            if stats["fuzz_time_seconds"] == 0:
                stats["fuzz_time_seconds"] = stats["runtime_seconds"]
        except ValueError:
            pass

    return stats
