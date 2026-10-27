"""Run a merged external-method binary under the common empty-seed AFL++ protocol.

This file can be copied with selector_seeds.py into a PromeFuzz container and
run directly. It does not change any method's generated drivers or merge code.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import threading
import time

if __package__:
    from .selector_seeds import driver_ids_from_entry, selector_layout, write_selector_seeds
else:
    from selector_seeds import driver_ids_from_entry, selector_layout, write_selector_seeds


_ASAN_OPTIONS = "abort_on_error=1:symbolize=0:detect_odr_violation=0:allocator_may_return_null=1"
_UBSAN_OPTIONS = "halt_on_error=1:print_stacktrace=1"
_AFLPP_VERSION = "4.33c"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stats(output: Path) -> dict[str, str]:
    path = output / "default" / "fuzzer_stats"
    if not path.is_file():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    return values


def _status(record: dict) -> str:
    try:
        run_time = int(record["stats"].get("run_time", "0"))
    except (ValueError, TypeError):
        run_time = 0
    if run_time <= 0:
        return "failed"
    return "completed" if record.get("returncode") in {0, 124} else "partial"


class _Processes:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running: set[subprocess.Popen] = set()

    def add(self, process: subprocess.Popen) -> None:
        with self.lock:
            self.running.add(process)

    def discard(self, process: subprocess.Popen) -> None:
        with self.lock:
            self.running.discard(process)

    def stop(self) -> None:
        with self.lock:
            processes = tuple(self.running)
        for process in processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass


def _run_one(
    index: int, root: Path, corpus: Path, binary: Path, afl_fuzz: str,
    seconds: int, timeout_ms: int, processes: _Processes,
) -> dict:
    directory = root / f"rep_{index:02d}"
    directory.mkdir()
    output = directory / "out"
    log = directory / "afl.log"
    command = [
        "timeout", "-s", "1", str(seconds), afl_fuzz,
        "-i", str(corpus), "-o", str(output), "-t", str(timeout_ms),
        "--", str(binary), "@@",
    ]
    environment = os.environ.copy()
    environment.update(
        AFL_NO_UI="1", AFL_SKIP_CPUFREQ="1",
        AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1",
    )
    environment.pop("MSAN_OPTIONS", None)
    environment.pop("AFL_CRASH_EXITCODE", None)
    environment.update(ASAN_OPTIONS=_ASAN_OPTIONS, UBSAN_OPTIONS=_UBSAN_OPTIONS)
    record: dict = {"repetition": index, "output_dir": str(output), "log_file": str(log)}
    started = time.monotonic()
    try:
        with log.open("xb") as handle:
            process = subprocess.Popen(
                command, cwd=directory, env=environment, stdin=subprocess.DEVNULL,
                stdout=handle, stderr=subprocess.STDOUT, start_new_session=True,
            )
            processes.add(process)
            try:
                record["returncode"] = process.wait()
            finally:
                processes.discard(process)
    except Exception as exc:
        record["error"] = str(exc)
    record["duration_seconds"] = round(time.monotonic() - started, 3)
    record["stats"] = _stats(output)
    crashes = output / "default" / "crashes"
    record["crashes"] = sorted(
        path.name for path in crashes.iterdir() if path.is_file() and path.name != "README.txt"
    ) if crashes.is_dir() else []
    record["status"] = _status(record)
    return record


def run(
    *, method: str, entry: Path, binary: Path, output_root: Path,
    afl_fuzz: str, repetitions: int, seconds: int, parallel: int, timeout_ms: int,
) -> dict:
    if any(value <= 0 for value in (repetitions, seconds, parallel, timeout_ms)):
        raise ValueError("repetitions, seconds, parallel, and timeout must be positive")
    entry = entry.resolve(strict=True)
    binary = binary.resolve(strict=True)
    output_root = output_root.resolve()
    if not os.access(binary, os.X_OK):
        raise ValueError(f"merged binary is not executable: {binary}")
    symbol = "__asan_init"
    dynamic_symbols = subprocess.run(
        ["nm", "-D", str(binary)], capture_output=True, text=True, check=False,
    )
    if dynamic_symbols.returncode != 0 or symbol not in dynamic_symbols.stdout:
        raise ValueError(f"merged binary lacks {symbol}: {binary}")
    if shutil.which(afl_fuzz) is None:
        raise FileNotFoundError(f"AFL++ fuzzer not found: {afl_fuzz}")
    version = subprocess.run(
        [afl_fuzz, "-V", "x"], capture_output=True, text=True, check=False,
    )
    if _AFLPP_VERSION not in version.stdout + version.stderr:
        raise RuntimeError(
            f"AFL++ fuzzer must be version {_AFLPP_VERSION}: {afl_fuzz}"
        )
    driver_ids = driver_ids_from_entry(entry, method)
    selector_bytes, byteorder = selector_layout(entry, method, len(driver_ids))
    output_root.mkdir(parents=True, exist_ok=False)
    corpus = output_root / "empty_in"
    seed_count = write_selector_seeds(
        corpus, driver_ids, selector_bytes=selector_bytes, byteorder=byteorder
    )
    started_utc = datetime.now(timezone.utc).isoformat()
    processes = _Processes()
    records = []
    interrupted = False
    pool = ThreadPoolExecutor(max_workers=min(parallel, repetitions))
    futures = []
    try:
        futures = [
            pool.submit(
                _run_one, index, output_root, corpus, binary, afl_fuzz,
                seconds, timeout_ms, processes,
            )
            for index in range(repetitions)
        ]
        for future in as_completed(futures):
            record = future.result()
            records.append(record)
            print(
                f"rep_{record['repetition']:02d}: {record['status']} "
                f"rc={record.get('returncode')} crashes={len(record['crashes'])}",
                flush=True,
            )
    except KeyboardInterrupt:
        interrupted = True
        processes.stop()
        for future in futures:
            future.cancel()
    finally:
        pool.shutdown(wait=True, cancel_futures=interrupted)
    records.sort(key=lambda record: record["repetition"])
    if interrupted:
        status = "interrupted"
    elif all(record["status"] == "completed" for record in records):
        status = "completed"
    elif any(record["status"] in {"completed", "partial"} for record in records):
        status = "partial"
    else:
        status = "failed"
    summary = {
        "schema_version": 1,
        "method": method,
        "status": status,
        "started_utc": started_utc,
        "entry": str(entry),
        "entry_sha256": _sha256(entry),
        "binary": str(binary),
        "binary_sha256": _sha256(binary),
        "output_root": str(output_root),
        "seed_mode": "selector_only",
        "profile": "asan_ubsan",
        "seed_count": seed_count,
        "selector_bytes": selector_bytes,
        "driver_ids": list(driver_ids),
        "seconds_per_run": seconds,
        "timeout_ms": timeout_ms,
        "parallel": parallel,
        "aflpp_version": _AFLPP_VERSION,
        "runs": records,
    }
    (output_root / "result.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--method", choices=("promefuzz", "promptfuzz", "trace2fuzz"), required=True,
    )
    parser.add_argument("--entry", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--afl-fuzz", default="afl-fuzz")
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--seconds", type=int, default=86400)
    parser.add_argument("--parallel", type=int, default=4)
    parser.add_argument("--timeout-ms", type=int, default=5000)
    args = parser.parse_args()
    summary = run(**vars(args))
    print(f"campaign: {summary['status']} ({summary['output_root']})", flush=True)
    return 0 if summary["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
