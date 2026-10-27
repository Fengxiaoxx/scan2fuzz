"""Unified Trace2Fuzz pipeline orchestrator.

Chains the live stages, each run as an ISOLATED subprocess
(`python3 -m src.cli.<stage>`) so stages never share global/logging state and the
orchestrator owns ordering, stage selection, timing, and per-stage status:

    scan -> preprocess -> driver_rounds -> fuzz_run

``driver_rounds`` repeatedly executes generation, compile repair, target
reachability and crash triage for unresolved targets only.

Usage:
    python3 -m src.cli.pipeline <lib> [--only STAGE | --from STAGE [--to STAGE]]
                                      [--list]

Run inside the Trace2Fuzz container.
"""
from __future__ import annotations

import argparse
import codecs
import errno
import fcntl
import os
import pty
import shlex
import secrets
import subprocess
import sys
import termios
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, TextIO

from src.cli.common import add_concurrency_argument, add_fuzz_concurrency_argument
from src.cli.run_context import PARENT_LOCK_ENV, create_run, require_run
from src.core import get_project_root
from src.experiment import LibraryRunLock, RunArtifactStore, collect_metrics

GREEN = "\033[0;32m"; RED = "\033[0;31m"; YELLOW = "\033[1;33m"; BLUE = "\033[0;34m"; NC = "\033[0m"


@dataclass
class Stage:
    name: str
    module: str
    args: List[str] = field(default_factory=list)
    fatal: bool = True  # a fatal stage's failure aborts the pipeline
    concurrent: bool = False  # takes the pipeline's --concurrency
    fuzzing: bool = False  # takes the pipeline's --fuzz-concurrency


def build_stages() -> List[Stage]:
    return [
        Stage("scan", "src.cli.scan", concurrent=True),
        Stage("preprocess", "src.cli.preprocess", concurrent=True),
        Stage("driver_rounds", "src.cli.driver_rounds", concurrent=True, fuzzing=True),
        Stage("fuzz_run", "src.cli.fuzz_run_stage"),
    ]


def _stage_args(stage: Stage, concurrency: int, fuzz_concurrency: int) -> List[str]:
    """A stage's fixed arguments plus the pipeline's concurrency budgets it takes."""
    return [
        *stage.args,
        *(["--concurrency", str(concurrency)] if stage.concurrent else []),
        *(["--fuzz-concurrency", str(fuzz_concurrency)] if stage.fuzzing else []),
    ]


def _parse_stage_args(items: List[str], valid: set) -> Dict[str, List[str]]:
    """`STAGE=ARGS` strings -> {stage: [tokens]}; ARGS is shell-split."""
    extra: Dict[str, List[str]] = {}
    for item in items:
        if "=" not in item:
            sys.exit(f"ERROR: --stage-args must be STAGE=ARGS, got '{item}'")
        name, rest = item.split("=", 1)
        if name not in valid:
            sys.exit(f"ERROR: --stage-args unknown stage '{name}'. Stages: {', '.join(sorted(valid))}")
        extra.setdefault(name, []).extend(shlex.split(rest))
    return extra


def _select(stages: List[Stage], only: Optional[str], frm: Optional[str],
            to: Optional[str]) -> List[Stage]:
    names = [s.name for s in stages]

    def idx(n: str, label: str) -> int:
        if n not in names:
            sys.exit(f"ERROR: unknown {label} stage '{n}'. Stages: {', '.join(names)}")
        return names.index(n)

    if only:
        return [stages[idx(only, "--only")]]
    lo = idx(frm, "--from") if frm else 0
    hi = idx(to, "--to") if to else len(stages) - 1
    if lo > hi:
        sys.exit(f"ERROR: --from '{frm}' comes after --to '{to}'")
    return stages[lo:hi + 1]


def _invocation_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{timestamp}-{secrets.token_hex(4)}"


def _pipeline_log(store: RunArtifactStore, message: str) -> None:
    with store.safe_path("pipeline.log").open("a", encoding="utf-8") as handle:
        handle.write(f"{datetime.now(timezone.utc).isoformat()} {message}\n")


def _write_pipeline_summary(
    store: RunArtifactStore,
    status: str,
    results: List[tuple],
    invocation_id: str,
) -> None:
    invocation_root = store.invocation_dir(invocation_id)
    _pipeline_log(store, f"invocation={invocation_id} status={status}")
    store.write_json(
        f"{invocation_root}/result.json",
        {"status": status, "stages": results},
    )

    metrics = collect_metrics(store)
    if metrics:
        store.write_json(f"{invocation_root}/metrics.json", metrics)


def _write_console(data: bytes) -> None:
    stream = getattr(sys.stdout, "buffer", None)
    if stream is not None:
        stream.write(data)
    else:
        sys.stdout.write(data.decode("utf-8", errors="replace"))
    sys.stdout.flush()


def _forward_output(source_fd: int, log_handle: TextIO) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    while True:
        try:
            data = os.read(source_fd, 65536)
        except OSError as exc:
            if exc.errno == errno.EIO:
                break
            raise
        if not data:
            break
        _write_console(data)
        log_handle.write(decoder.decode(data))
        log_handle.flush()
    remainder = decoder.decode(b"", final=True)
    if remainder:
        log_handle.write(remainder)
        log_handle.flush()


def _run_stage_command(
    cmd: List[str],
    *,
    cwd: str,
    env: Dict[str, str],
    log_handle: TextIO,
) -> int:
    if not sys.stdout.isatty():
        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        assert process.stdout is not None
        try:
            _forward_output(process.stdout.fileno(), log_handle)
        finally:
            process.stdout.close()
        return process.wait()

    master_fd, slave_fd = pty.openpty()
    try:
        try:
            size = fcntl.ioctl(
                sys.stdout.fileno(),
                termios.TIOCGWINSZ,
                b"\0" * 8,
            )
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)
        except (OSError, ValueError):
            pass
        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
    finally:
        os.close(slave_fd)
    try:
        _forward_output(master_fd, log_handle)
    finally:
        os.close(master_fd)
    return process.wait()


def main() -> int:
    ap = argparse.ArgumentParser(description="Trace2Fuzz unified pipeline orchestrator.")
    ap.add_argument("library")
    ap.add_argument("--run-id", help="resume an existing experiment run")
    ap.add_argument("--only", help="run ONLY this stage")
    ap.add_argument("--from", dest="frm", help="start from this stage")
    ap.add_argument("--to", help="stop at this stage (inclusive)")
    ap.add_argument("--stage-args", action="append", default=[], metavar="STAGE=ARGS",
                    help="forward extra CLI args to ONE stage (repeatable). "
                         "E.g. --stage-args "
                         "'driver_rounds=--max-repair-attempts 5' "
                         "--stage-args 'scan=--debug'")
    ap.add_argument("--list", action="store_true", help="list the stages (with extra args) and exit")
    add_concurrency_argument(ap)
    add_fuzz_concurrency_argument(ap)
    args = ap.parse_args()

    stages = build_stages()
    extra = _parse_stage_args(args.stage_args, {s.name for s in stages})
    selected = _select(stages, args.only, args.frm, args.to)
    if args.list:
        for s in selected:
            tail = "" if s.fatal else "   (non-fatal)"
            full = _stage_args(s, args.concurrency, args.fuzz_concurrency) + extra.get(s.name, [])
            command = " ".join(
                ["python3", "-m", s.module, args.library, *full]
            )
            print(
                f"  {s.name:22} {command}{tail}"
            )
        return 0

    if args.run_id is None and selected[0].name != "scan":
        ap.error("--run-id is required when the selected stages do not start at scan")

    root_path = get_project_root()
    root = str(root_path)
    run_lock = LibraryRunLock(root_path, args.library)
    run_lock.acquire()
    store = (
        require_run(args.library, args.run_id)
        if args.run_id is not None
        else create_run(args.library)
    )
    invocation_id = _invocation_id()
    invocation_root = store.invocation_dir(invocation_id)
    env = os.environ.copy()
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    env.update(store.environment())
    env[PARENT_LOCK_ENV] = "1"

    print(
        f"{BLUE}=== Trace2Fuzz pipeline: {args.library}  "
        f"({len(selected)} stage(s)) ==={NC}",
        flush=True,
    )
    print(f"Run artifacts: {store.run_dir}", flush=True)
    results: List[tuple] = []
    for i, s in enumerate(selected, 1):
        existing_result = store.stage_result_path(s.name)
        if existing_result.exists():
            results.append((s.name, "ALREADY_COMPLETED"))
            _write_pipeline_summary(
                store,
                "failed",
                results,
                invocation_id,
            )
            print(
                f"{RED}✗ {s.name} already completed in run {store.run_id}; "
                "resume from the next stage{NC}",
                flush=True,
            )
            run_lock.release()
            return 1
        cmd = [sys.executable, "-m", s.module, args.library,
               *_stage_args(s, args.concurrency, args.fuzz_concurrency), *extra.get(s.name, [])]
        _pipeline_log(store, f"invocation={invocation_id} stage={s.name} command={shlex.join(cmd)}")
        print(f"\n{YELLOW}>>> [{i}/{len(selected)}] {s.name}{NC}  ({' '.join(cmd)})", flush=True)
        t0 = time.monotonic()
        stage_log = store.logs_dir(s.name) / f"{invocation_id}.log"
        stage_log.parent.mkdir(parents=True, exist_ok=True)
        with stage_log.open(
            "x",
            encoding="utf-8",
            newline="",
        ) as log_handle:
            rc = _run_stage_command(
                cmd,
                cwd=root,
                env=env,
                log_handle=log_handle,
            )
        dt = time.monotonic() - t0
        reported_status = "completed"
        result_path = store.stage_result_path(s.name)
        if rc == 0 and not result_path.is_file():
            rc = 1
            reported_status = "missing_result"
        elif rc == 0:
            stage_result = store.read_json(result_path)
            reported_status = stage_result.get("status", "completed")
            if s.name == "scan" and stage_result.get("status") != "completed":
                rc = 1
        store.write_json(
            f"{invocation_root}/stages/{s.name}/orchestrator.json",
            {
                "command": cmd,
                "duration_seconds": dt,
                "returncode": rc,
                "status": reported_status if rc == 0 else "failed",
            },
        )
        _pipeline_log(store, f"invocation={invocation_id} stage={s.name} returncode={rc} duration_seconds={dt}")
        if rc == 0:
            if reported_status == "partial":
                print(
                    f"{YELLOW}~ {s.name} completed with driver failures "
                    f"({dt:.0f}s){NC}",
                    flush=True,
                )
            else:
                print(f"{GREEN}✓ {s.name} ({dt:.0f}s){NC}", flush=True)
            results.append((s.name, reported_status))
            if s.name == "scan":
                scan_result = store.read_json(result_path)
                if scan_result["target_count"] == 0:
                    results[-1] = (s.name, "no_targets")
                    _write_pipeline_summary(
                        store,
                        "no_targets",
                        results,
                        invocation_id,
                    )
                    print(
                        f"{YELLOW}No scan targets; pipeline completed "
                        f"without driver work.{NC}"
                    )
                    _summary(results)
                    run_lock.release()
                    return 0
        elif s.fatal:
            print(f"{RED}✗ {s.name} failed (rc={rc}, {dt:.0f}s) — aborting{NC}", flush=True)
            results.append((s.name, "FAIL"))
            _write_pipeline_summary(
                store, "failed", results, invocation_id
            )
            _summary(results)
            run_lock.release()
            return rc
        else:
            print(f"{YELLOW}~ {s.name} rc={rc} ({dt:.0f}s) — non-fatal, continuing{NC}", flush=True)
            results.append((s.name, f"rc={rc}"))

    final_status = (
        "partial"
        if any(status == "partial" for _, status in results)
        else "completed"
    )
    _write_pipeline_summary(
        store,
        final_status,
        results,
        invocation_id,
    )
    _summary(results)
    run_lock.release()
    return 0


def _summary(results: List[tuple]) -> None:
    print(f"\n{BLUE}=== summary ==={NC}", flush=True)
    for name, status in results:
        print(f"  {name:22} {status}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
