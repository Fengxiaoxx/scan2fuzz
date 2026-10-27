"""Run a Trace2Fuzz driver set as one merged AFL++ binary.

It loads the REACHED drivers of a completed run, merges them into a single
``LLVMFuzzerTestOneInput`` entry with a one-byte selector, links the merged
entry against a separate AFL++ sanitizer library, and runs independent
AFL++ campaigns (24h by default, repeated 10 times).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import threading
import time

from src.core import build_compile_flags
from .inventory import load_fuzzable_drivers
from .selector_seeds import write_selector_seeds


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z", re.ASCII)
_C_IDENTIFIER = re.compile(r"[^A-Za-z0-9_]", re.ASCII)

# PromeFuzz's default fuzzing environment (database/utils/fuzz.py).
_ASAN_OPTIONS = (
    "abort_on_error=1:symbolize=0:detect_odr_violation=0:"
    "allocator_may_return_null=1"
)
_LEAK_ASAN_OPTIONS = _ASAN_OPTIONS + ":detect_leaks=1"
_LEAK_LSAN_OPTIONS = "exitcode=23:symbolize=0:detect_leaks=1"
_UBSAN_OPTIONS = "halt_on_error=1:print_stacktrace=1"

_AFLPP_DIR = Path(__file__).resolve().parents[2] / ".local" / "aflpp" / "4.33c"
_DEFAULT_AFL_CC = str(_AFLPP_DIR / "afl-clang-fast++")
_DEFAULT_AFL_FUZZ = str(_AFLPP_DIR / "afl-fuzz")
_AFLPP_VERSION = "4.33c"


@dataclass(frozen=True)
class RunOptions:
    """One merged AFL++ campaign over a completed run's drivers."""

    project_root: Path
    library: str
    run_id: str
    repetitions: int = 10
    seconds_per_run: int = 86400
    concurrency: int = 4
    timeout_ms: int = 5000
    drivers: tuple[str, ...] = ()
    detect_leaks: bool = False

    def validate(self) -> None:
        for label, value in (("library", self.library), ("run_id", self.run_id)):
            if not _NAME.fullmatch(value) or value in {".", ".."}:
                raise ValueError(f"invalid {label}: {value!r}")
        for label in ("repetitions", "seconds_per_run", "concurrency", "timeout_ms"):
            if getattr(self, label) <= 0:
                raise ValueError(f"{label} must be positive")


@dataclass(frozen=True)
class _Driver:
    driver_id: str
    source: Path


class _Processes:
    """Track running AFL++ processes so Ctrl-C/SIGTERM terminates them."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._running: set[subprocess.Popen] = set()

    def add(self, process: subprocess.Popen) -> None:
        with self._lock:
            self._running.add(process)

    def discard(self, process: subprocess.Popen) -> None:
        with self._lock:
            self._running.discard(process)

    def stop(self) -> None:
        with self._lock:
            running = tuple(self._running)
        for process in running:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_drivers(options: RunOptions) -> tuple[_Driver, ...]:
    _, inventory = load_fuzzable_drivers(
        options.project_root, options.library, options.run_id
    )
    selected = set(options.drivers)
    available = {driver.driver_id for driver in inventory}
    missing = selected - available
    if missing:
        raise ValueError(f"requested drivers not in the run: {sorted(missing)}")

    drivers = tuple(
        _Driver(
            driver_id=driver.driver_id,
            source=driver.source_path,
        )
        for driver in inventory
        if not selected or driver.driver_id in selected
    )
    if not drivers:
        raise ValueError("run has no fuzzable drivers")
    return drivers


def _identifier(driver_id: str) -> str:
    return _C_IDENTIFIER.sub("_", driver_id)


def _write_merged_sources(
    drivers: tuple[_Driver, ...], work: Path, *, detect_leaks: bool = False
) -> tuple[Path, tuple[str, ...]]:
    source_dir = work / "drivers"
    source_dir.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    used: set[str] = set()
    for driver in drivers:
        name = _identifier(driver.driver_id)
        candidate = name
        suffix = 1
        while candidate in used:
            suffix += 1
            candidate = f"{name}_{suffix}"
        used.add(candidate)
        text = driver.source.read_text(encoding="utf-8", errors="replace")
        text = text.replace(
            "LLVMFuzzerTestOneInput", f"LLVMFuzzerTestOneInput_{candidate}"
        )
        (source_dir / f"{candidate}.cc").write_text(text, encoding="utf-8")
        names.append(candidate)

    lines = [
        "#include <stdint.h>",
        "#include <stddef.h>",
        "",
    ]
    if detect_leaks:
        lines[2:2] = ["#include <stdlib.h>", "#include <sanitizer/lsan_interface.h>"]
    for name in names:
        lines.append(
            'extern "C" int LLVMFuzzerTestOneInput_%s(const uint8_t* data, size_t size);'
            % name
        )
    lines += [
        "",
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {',
        "    if (size < 2) return 0;",
    ]
    if detect_leaks:
        lines.append("    int result = 0;")
    lines += [
        f"    switch (data[0] % {len(names)}) {{",
    ]
    for index, name in enumerate(names):
        lines.append(
            ("        case %d: result = LLVMFuzzerTestOneInput_%s(data + 1, size - 1); break;"
             if detect_leaks else
             "        case %d: return LLVMFuzzerTestOneInput_%s(data + 1, size - 1);")
            % (index, name)
        )
    lines += [
        "        default: break;",
        "    }",
    ]
    if detect_leaks:
        lines.append("    if (__lsan_do_recoverable_leak_check()) abort();")
        lines.append("    return result;")
    else:
        lines.append("    return 0;")
    lines += ["}", ""]
    entry = work / "entry.cc"
    entry.write_text("\n".join(lines), encoding="utf-8")
    return entry, tuple(names)


def _write_initial_corpus(drivers: tuple[_Driver, ...], corpus: Path) -> int:
    """Create one selector-only seed per driver, with no payload."""
    if not 1 <= len(drivers) <= 256:
        raise ValueError("the one-byte selector requires 1 to 256 drivers")
    return write_selector_seeds(
        corpus,
        tuple(driver.driver_id for driver in drivers),
        selector_bytes=1,
        byteorder="big",
    )


def _build_merged(options: RunOptions, work: Path, entry: Path) -> Path:
    compiler = os.environ.get("TRACE2FUZZ_AFL_CC", _DEFAULT_AFL_CC)
    compiler_path = Path(shutil.which(compiler) or compiler).resolve()
    driver_library = Path(os.environ.get(
        "TRACE2FUZZ_AFL_DRIVER", str(compiler_path.parent / "libAFLDriver.a")
    ))
    if not driver_library.is_file():
        raise FileNotFoundError(f"AFL++ driver library not found: {driver_library}")

    library_variant = "aflpp"
    source_run = (
        options.project_root / "workspace" / options.library / "runs" / options.run_id
    )
    flags = shlex.split(build_compile_flags(
        options.library, library_variant=library_variant, run_dir=source_run
    ))
    for flag in flags:
        if (
            not flag.startswith("-")
            and f"build_{library_variant}" in Path(flag).parts
            and not (options.project_root / flag).is_file()
        ):
            raise FileNotFoundError(
                f"AFL++ library missing: {flag}; build it with "
                f"(cd test_lib/{options.library} && bash ../../info_lib/{options.library}/build.sh {library_variant})"
            )
    output = work / "merged_driver"
    command = [
        compiler,
        "-std=c++17",
        "-O1",
        "-g",
        "-fno-omit-frame-pointer",
        "-fPIC",
        "-fsanitize=address,undefined",
        "-fno-sanitize-recover=all",
        str(entry),
        *sorted(str(path) for path in (work / "drivers").glob("*.cc")),
        str(driver_library),
        *flags,
        "-o",
        str(output),
    ]
    log = work / "build.log"
    build_environment = os.environ.copy()
    for name in ("AFL_USE_ASAN", "AFL_USE_UBSAN", "AFL_USE_MSAN"):
        build_environment.pop(name, None)
    build_environment.update(AFL_LLVM_USE_TRACE_PC="1", AFL_DONT_OPTIMIZE="1")
    build_environment.update(AFL_USE_ASAN="1", AFL_USE_UBSAN="1")
    # ASan already links LSan. AFL_USE_LSAN alongside AFL_USE_ASAN breaks the
    # pinned AFL++ forkserver, so use LSan's explicit API in the entry instead.
    build_environment.pop("AFL_USE_LSAN", None)
    with log.open("xb") as handle:
        result = subprocess.run(
            command,
            cwd=options.project_root,
            env=build_environment,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(f"merged driver build failed (see {log})")
    if not output.is_file():
        raise RuntimeError(f"merged driver was not produced: {output}")
    return output


def _fuzzer_stats(path: Path) -> dict[str, str]:
    stats = path / "default" / "fuzzer_stats"
    if not stats.is_file():
        return {}
    values: dict[str, str] = {}
    for line in stats.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    return values


def _crashes(path: Path) -> list[str]:
    directory = path / "default" / "crashes"
    if not directory.is_dir():
        return []
    return sorted(
        entry.name for entry in directory.iterdir() if entry.name != "README.txt"
    )


def _command(options: RunOptions, merged: Path, corpus: Path, output: Path) -> list[str]:
    afl_fuzz = os.environ.get("TRACE2FUZZ_AFL_FUZZ", _DEFAULT_AFL_FUZZ)
    return [
        "timeout",
        "-s",
        "1",
        str(options.seconds_per_run),
        afl_fuzz,
        "-i",
        str(corpus),
        "-o",
        str(output),
        "-t",
        str(options.timeout_ms),
        "--",
        str(merged),
        "@@",
    ]


def _run_repetition(
    options: RunOptions,
    merged: Path,
    corpus: Path,
    directory: Path,
    processes: _Processes,
) -> dict:
    log_file = directory / "afl.log"
    output = directory / "out"
    record: dict = {
        "repetition": directory.name,
        "log_file": str(log_file),
        "output_dir": str(output),
    }
    environment = os.environ.copy()
    environment.update(
        AFL_NO_UI="1", AFL_SKIP_CPUFREQ="1",
        AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1",
    )
    environment.pop("MSAN_OPTIONS", None)
    environment.pop("AFL_CRASH_EXITCODE", None)
    environment.update(
        ASAN_OPTIONS=_LEAK_ASAN_OPTIONS if options.detect_leaks else _ASAN_OPTIONS,
        UBSAN_OPTIONS=_UBSAN_OPTIONS,
    )
    if options.detect_leaks:
        environment["LSAN_OPTIONS"] = _LEAK_LSAN_OPTIONS
    if options.library == "liblouis":
        environment["LOUIS_TABLEPATH"] = str(
            options.project_root / "test_lib" / "liblouis" / "tables"
        )
    started = time.monotonic()
    try:
        with log_file.open("xb") as log:
            process = subprocess.Popen(
                _command(options, merged, corpus, output),
                cwd=directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            processes.add(process)
            try:
                returncode = process.wait()
            finally:
                processes.discard(process)
        record.update(
            returncode=returncode,
            duration_seconds=round(time.monotonic() - started, 3),
            stats=_fuzzer_stats(output),
            crashes=_crashes(output),
        )
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # infrastructure failure, keep other repetitions running
        record.update(error=str(exc), stats={}, crashes=[])
    record["status"] = _repetition_status(record)
    return record


def _repetition_status(record: dict) -> str:
    stats = record.get("stats") or {}
    try:
        run_time = int(stats.get("run_time", "0"))
    except (TypeError, ValueError):
        run_time = 0
    if run_time <= 0:
        return "failed"
    if record.get("returncode") in {0, 124}:
        return "completed"
    return "partial"


def run_fuzz(options: RunOptions) -> dict:
    """Build one merged AFL++ binary and run ``repetitions`` 24h campaigns."""
    options.validate()
    compiler = os.environ.get("TRACE2FUZZ_AFL_CC", _DEFAULT_AFL_CC)
    fuzzer = os.environ.get("TRACE2FUZZ_AFL_FUZZ", _DEFAULT_AFL_FUZZ)
    if shutil.which(compiler) is None:
        raise RuntimeError("afl-clang-fast++ is unavailable")
    if shutil.which(fuzzer) is None:
        raise RuntimeError("afl-fuzz is unavailable")
    for label, executable in (("compiler", compiler), ("fuzzer", fuzzer)):
        version = subprocess.run(
            [executable, "-V", "x"] if label == "fuzzer" else [executable, "-h"],
            capture_output=True, text=True, check=False,
        )
        if f"4.33c" not in version.stdout + version.stderr:
            raise RuntimeError(
                f"AFL++ {label} must be version {_AFLPP_VERSION}: {executable}"
            )

    drivers = _load_drivers(options)
    if len(drivers) > 256:
        raise ValueError("the one-byte selector supports at most 256 drivers")
    invocation = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        + "-"
        + secrets.token_hex(4)
    )
    run_directory = (
        options.project_root
        / "workspace"
        / options.library
        / "fuzz_runs"
        / options.run_id
        / invocation
    )
    run_directory.mkdir(parents=True, exist_ok=False)

    entry, names = _write_merged_sources(
        drivers, run_directory, detect_leaks=options.detect_leaks
    )
    merged = _build_merged(options, run_directory, entry)
    corpus = run_directory / "corpus"
    seed_count = _write_initial_corpus(drivers, corpus)

    processes = _Processes()
    repetitions = [
        run_directory / f"rep_{index:02d}" for index in range(options.repetitions)
    ]
    for directory in repetitions:
        directory.mkdir(parents=True, exist_ok=False)

    records: list[dict] = []
    interrupted = False
    pool = ThreadPoolExecutor(max_workers=min(options.concurrency, options.repetitions))
    futures = []
    try:
        futures = [
            pool.submit(_run_repetition, options, merged, corpus, directory, processes)
            for directory in repetitions
        ]
        for future in as_completed(futures):
            record = future.result()
            records.append(record)
            print(
                "%s: returncode=%s crashes=%d"
                % (
                    record["repetition"],
                    record.get("returncode"),
                    len(record.get("crashes", ())),
                ),
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
        "engine": "aflpp",
        "library": options.library,
        "run_id": options.run_id,
        "status": status,
        "output_dir": str(run_directory),
        "merged_driver": str(merged),
        "merged_driver_sha256": _sha256(merged),
        "driver_count": len(names),
        "driver_selectors": [
            {"index": index, "driver_id": driver.driver_id}
            for index, driver in enumerate(drivers)
        ],
        "seed_mode": "selector_only",
        "profile": "asan_ubsan",
        "detect_leaks": options.detect_leaks,
        "selector_bytes": 1,
        "seed_count": seed_count,
        "repetitions": options.repetitions,
        "seconds_per_run": options.seconds_per_run,
        "concurrency": options.concurrency,
        "timeout_ms": options.timeout_ms,
        "aflpp_version": _AFLPP_VERSION,
        "runs": records,
    }
    (run_directory / "result.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary
