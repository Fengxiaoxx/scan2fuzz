"""Shared llvm-cov / llvm-profdata primitives.

The single home for low-level coverage operations used by qualification:
profdata merge, llvm-cov JSON export, segment-span line counting, corpus replay,
coverage-binary compilation, and pinned tool names.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

PROFDATA = "llvm-profdata-15"
COV = "llvm-cov-15"

# Reserve libFuzzer's timeout exit code so input timeouts remain measurement
# failures rather than crash observations.
REPLAY_TIMEOUT_EXIT_CODE = 70


@dataclass(frozen=True)
class ReplayCrash:
    """A failed input execution, observed in a fresh coverage process."""

    command: tuple[str, ...]
    returncode: int
    input_path: str
    stdout: str
    stderr: str

    def to_dict(self) -> dict:
        return {
            "command": list(self.command),
            "returncode": self.returncode,
            "input_path": self.input_path,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def bare_name(name: str) -> str:
    """Normalize an llvm-cov function name to a comparable base name.

    Strips the `file.c:` prefix llvm-cov sometimes prepends and the `.NNN` clone
    suffix llvm-link adds when separately-compiled static/inline header functions
    collapse together.
    """
    import re
    return re.sub(r"\.\d+$", "", name.split(":")[-1])


def segment_span_count(segments: List, line: int) -> Optional[int]:
    """Match LLVM 15 LineCoverageStats for sorted six-field export segments.

    Combine non-gap region entries on this line with the count carried from
    the preceding line. A same-line region exit must not contribute its outer
    count: it can follow a statement that was never executed. Return None for
    unmapped lines. A covered line does not imply every statement on it ran.
    """
    if not segments or line < segments[0][0] or line > segments[-1][0]:
        return None
    wrapped = None
    current = []
    for segment in segments:
        if segment[0] < line:
            wrapped = segment
        elif segment[0] == line:
            current.append(segment)
        else:
            break

    entries = [s for s in current if s[3] and s[4] and not s[5]]
    skipped = bool(current and not current[0][3] and current[0][4])
    if skipped or not ((wrapped is not None and wrapped[3]) or entries):
        return None
    return max([wrapped[2] if wrapped is not None else 0] + [s[2] for s in entries])


def replay_corpus(binary: str, corpus_dir: str, profraw: str, *,
                  timeout: int = 3600, unit_timeout: int = 100,
                  rss_limit_mb: Optional[int] = None,
                  diagnostic: Optional[dict] = None) -> bool | ReplayCrash:
    """Replay a whole corpus over a coverage binary to write fresh `profraw`.

    Each input runs in its own process, as a reproduction would: a driver that keeps
    state across inputs (sockets, global handles) can fail when they share one. The
    runs add their counters into one profile (`%m`, LLVM's online merging).

    Return True on success, a ReplayCrash for a non-zero exit or signal, and
    False for a timeout, launch failure, or missing profile. Partial profiles
    are never used, including when an input crashes after hitting the target.
    """
    p = Path(profraw)
    p.unlink(missing_ok=True)
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryDirectory() as replay_dir:
        env = os.environ.copy()
        env["LLVM_PROFILE_FILE"] = f"{replay_dir}/replay-%m.profraw"
        for unit in sorted(Path(corpus_dir).iterdir()):
            command = [str(Path(binary).resolve()), str(unit.resolve()),
                       f"-timeout={unit_timeout}",
                       f"-timeout_exitcode={REPLAY_TIMEOUT_EXIT_CODE}"]
            if rss_limit_mb is not None:
                command.append(f"-rss_limit_mb={rss_limit_mb}")
            if diagnostic is not None:
                diagnostic["command"] = command
            proc = None
            try:
                # restore_signals=False keeps Python's ignored SIGPIPE: a driver writing to
                # a socket its peer closed gets EPIPE instead of dying mid-measurement.
                proc = subprocess.Popen(
                    command,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=replay_dir,
                    start_new_session=True,
                    restore_signals=False,
                )
                output, errors = proc.communicate(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                if proc is not None:
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                        proc.communicate(timeout=5)
                    except (OSError, subprocess.TimeoutExpired):
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except OSError:
                            pass
                        proc.communicate()
                if diagnostic is not None:
                    diagnostic.update({"returncode": None, "timed_out": True})
                return False
            except OSError:
                if diagnostic is not None:
                    diagnostic.update({"returncode": None, "spawn_failed": True})
                return False
            if proc.returncode != 0:
                stdout = (output or b"").decode("utf-8", errors="replace")
                stderr = (errors or b"").decode("utf-8", errors="replace")
                timed_out = proc.returncode == REPLAY_TIMEOUT_EXIT_CODE
                if diagnostic is not None:
                    diagnostic.update(
                        {
                            "returncode": proc.returncode,
                            "input_path": str(unit.resolve()),
                            "timed_out": timed_out,
                            "stderr": stderr[-16000:],
                            "stdout": stdout[-4000:],
                        }
                    )
                if timed_out:
                    return False
                return ReplayCrash(tuple(command), proc.returncode,
                                   str(unit.resolve()), stdout, stderr)
        profiles = list(Path(replay_dir).glob("replay-*.profraw"))
        if len(profiles) != 1:
            return False
        shutil.move(profiles[0], p)
    return True


def replay_and_export(coverage_binary: str, corpus_dir: str, *,
                      workdir: str = "/tmp", tag: str = "cov",
                      timeout: int = 3600, unit_timeout: int = 100,
                      rss_limit_mb: Optional[int] = None,
                      diagnostic_path: Optional[str] = None) -> dict | ReplayCrash | None:
    """Return the coverage JSON, a replay crash, or None for tool failures.
    `tag` names the scratch profraw/profdata so distinct callers never collide.
    `timeout` is the outer limit and `unit_timeout` is the per-input limit."""
    profraw = Path(workdir) / f"{tag}.profraw"
    profdata = Path(workdir) / f"{tag}.profdata"
    diagnostic = {
        "coverage_binary": str(coverage_binary),
        "corpus_dir": str(corpus_dir),
        "tag": tag,
    }
    replay = replay_corpus(
        coverage_binary,
        corpus_dir,
        str(profraw),
        timeout=timeout,
        unit_timeout=unit_timeout,
        rss_limit_mb=rss_limit_mb,
        diagnostic=diagnostic,
    )
    if isinstance(replay, ReplayCrash):
        diagnostic["phase"] = "replay"
        _write_diagnostic(diagnostic_path, diagnostic)
        return replay
    if not replay:
        diagnostic["phase"] = "replay"
        _write_diagnostic(diagnostic_path, diagnostic)
        return None
    merge = subprocess.run(
        [PROFDATA, "merge", "-sparse", str(profraw), "-o", str(profdata)],
        capture_output=True,
        text=True,
    )
    if merge.returncode != 0 or not profdata.is_file():
        diagnostic.update(
            {
                "phase": "profdata_merge",
                "returncode": merge.returncode,
                "stderr": merge.stderr[-16000:],
                "stdout": merge.stdout[-4000:],
            }
        )
        _write_diagnostic(diagnostic_path, diagnostic)
        return None
    export = subprocess.run(
        [COV, "export", str(coverage_binary), f"-instr-profile={profdata}"],
        capture_output=True,
        text=True,
    )
    if export.returncode != 0 or not export.stdout:
        diagnostic.update(
            {
                "phase": "cov_export",
                "returncode": export.returncode,
                "stderr": export.stderr[-16000:],
                "stdout": export.stdout[-4000:],
            }
        )
        _write_diagnostic(diagnostic_path, diagnostic)
        return None
    try:
        data = json.loads(export.stdout)
    except json.JSONDecodeError as exc:
        diagnostic.update({"phase": "cov_export_json", "error": str(exc)})
        _write_diagnostic(diagnostic_path, diagnostic)
        return None
    profraw.unlink(missing_ok=True)
    profdata.unlink(missing_ok=True)
    return data


def _write_diagnostic(path: Optional[str], payload: dict) -> None:
    if path:
        Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def compile_coverage_binary(source: str, out: str, includes: List[str], cov_lib: str,
                            extra_libs: Optional[List[str]] = None, *,
                            replacement_objects: Optional[List[str]] = None,
                            timeout: int = 180) -> Optional[str]:
    """Compile a libFuzzer COVERAGE binary (clang++ with fuzzer + coverage-mapping
    + profile-instr-generate). Returns the output path on success, else None."""
    cmd = [
        "clang++",
        "-std=c++17",
        "-O1",
        "-g",
        "-fno-omit-frame-pointer",
        "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
        "-fsanitize=fuzzer",
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
        *includes,
        str(source),
        *(replacement_objects or []),
        str(cov_lib),
        *(extra_libs or []),
        "-o",
        str(out),
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return str(out) if r.returncode == 0 and Path(out).exists() else None
