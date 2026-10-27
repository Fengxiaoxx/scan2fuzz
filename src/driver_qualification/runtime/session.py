"""A persistent, sanitizer-enabled libFuzzer process session."""

from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Mapping, Optional, Sequence

from src.core.sanitizer_report import format_sanitizer_report_for_repair


# compiler-rt libFuzzer's fixed exit code for a controller interrupt.
INTERRUPT_EXIT_CODE = 72


@dataclass(frozen=True)
class FuzzCheckpoint:
    snapshot_dir: str
    elapsed_seconds: float
    output: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class FuzzProcessFailure:
    command: tuple[str, ...]
    returncode: int
    output: str
    artifacts: tuple[str, ...]
    work_dir: str

    def to_dict(self) -> dict[str, object]:
        return {
            "command": list(self.command),
            "returncode": self.returncode,
            "output": self.output,
            "artifacts": list(self.artifacts),
            "work_dir": self.work_dir,
        }

    def failure_context(self, max_output_chars: int = 128_000) -> str:
        raw_output = self.output
        if len(raw_output) > max_output_chars:
            head_size = min(4_000, max_output_chars // 4)
            tail_size = max_output_chars - head_size
            raw_output = (
                raw_output[:head_size]
                + "\n\n...[sanitizer output truncated]...\n\n"
                + raw_output[-tail_size:]
            )
        artifacts = "\n".join(f"- {path}" for path in self.artifacts) or "- (none)"
        if self.returncode < 0:
            try:
                termination = (
                    f"signal {-self.returncode} "
                    f"({signal.Signals(-self.returncode).name})"
                )
            except ValueError:
                termination = f"signal {-self.returncode}"
        else:
            termination = f"exit code {self.returncode}"
        return (
            f"Command: {shlex.join(self.command)}\n"
            f"Return code: {self.returncode}\n"
            f"Termination: {termination}\n"
            f"Artifacts:\n{artifacts}\n\n"
            f"Parsed sanitizer report:\n"
            f"{format_sanitizer_report_for_repair(self.output)}\n\n"
            f"Raw fuzzer output:\n{raw_output}"
        )


class FuzzProcessExited(RuntimeError):
    """Raised when the persistent fuzzer exits without an explicit stop."""

    def __init__(self, failure: FuzzProcessFailure) -> None:
        self.failure = failure
        super().__init__(
            f"persistent fuzzer exited before checkpoint "
            f"(returncode={failure.returncode})"
        )


class PersistentFuzzSession:
    """Own one libFuzzer process and produce immutable corpus checkpoints."""

    def __init__(
        self,
        *,
        corpus_dir: str,
        workdir: str,
        checkpoint_seconds: float,
        artifact_dir: Optional[str] = None,
        output_path: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        fuzzer_args: Sequence[str] = (),
        on_fuzzer_start: Optional[Callable[[int], None]] = None,
        on_fuzzer_stop: Optional[Callable[[], None]] = None,
    ) -> None:
        if checkpoint_seconds <= 0:
            raise ValueError("checkpoint_seconds must be positive")

        args = tuple(str(arg) for arg in fuzzer_args)
        self._validate_fuzzer_args(args)

        self.corpus_dir = Path(corpus_dir).resolve()
        self.workdir = Path(workdir).resolve()
        self.checkpoint_seconds = float(checkpoint_seconds)
        self.artifact_dir = (
            Path(artifact_dir).resolve()
            if artifact_dir is not None
            else self.workdir / "artifacts"
        )
        self.output_path = (
            Path(output_path).resolve()
            if output_path is not None
            else self.workdir / "fuzzer.log"
        )
        self.env = dict(env or {})
        self.fuzzer_args = args
        self.on_fuzzer_start = on_fuzzer_start
        self.on_fuzzer_stop = on_fuzzer_stop

        self._proc: Optional[subprocess.Popen[bytes]] = None
        self._binary: Optional[str] = None
        self._command: tuple[str, ...] = ()
        self._epoch_started_at: Optional[float] = None
        self._next_checkpoint_at: Optional[float] = None
        self._epoch_workdir: Optional[Path] = None
        self._output_handle: Optional[BinaryIO] = None
        self._output_offset = 0
        self._artifact_baseline: dict[str, tuple[int, int, int]] = {}
        self._stored_digests: frozenset[str] = frozenset()
        self._notified_running = False

        self.workdir.mkdir(parents=True, exist_ok=True)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        (self.workdir / "epochs").mkdir(parents=True, exist_ok=True)
        (self.workdir / "snapshots").mkdir(parents=True, exist_ok=True)
        (self.workdir / "checkpoint-store").mkdir(parents=True, exist_ok=True)
        self._read_checkpoint_store()
        self._ensure_seed()

    @staticmethod
    def _validate_fuzzer_args(args: Sequence[str]) -> None:
        reserved = ("-artifact_prefix", "-print_final_stats")
        for arg in args:
            if arg == "-max_total_time" or arg.startswith("-max_total_time="):
                raise ValueError("max_total_time is owned by the session controller")
            if any(arg == name or arg.startswith(f"{name}=") for name in reserved):
                raise ValueError(f"fuzzer argument is owned by the session: {arg}")

    @property
    def pid(self) -> Optional[int]:
        return self._proc.pid if self._proc is not None else None

    def assert_running(self) -> None:
        if self._proc is None:
            raise RuntimeError("persistent fuzzer is not running")
        returncode = self._proc.poll()
        if returncode is not None:
            self._raise_process_exited(returncode)

    def checkpoint(self, binary: str) -> FuzzCheckpoint:
        resolved_binary = str(Path(binary).resolve())
        if self._proc is None:
            self._start(resolved_binary)
        else:
            self.assert_running()
            if self._binary != resolved_binary:
                raise RuntimeError(
                    "fuzzer binary changed while the current process is running; "
                    "stop the session before starting a new binary"
                )

        self._wait_until_checkpoint()
        try:
            snapshot_dir = self._snapshot_corpus()
        except Exception:
            self.stop()
            raise

        self.assert_running()

        assert self._epoch_started_at is not None
        assert self._next_checkpoint_at is not None
        elapsed = time.monotonic() - self._epoch_started_at
        output = self._read_epoch_output()
        command = self._command
        self._next_checkpoint_at += self.checkpoint_seconds
        return FuzzCheckpoint(
            snapshot_dir=snapshot_dir,
            elapsed_seconds=elapsed,
            output=output,
            command=command,
        )

    def add_corpus_files(self, paths: Iterable[str]) -> tuple[str, ...]:
        added: list[str] = []
        for path in paths:
            source = Path(path).resolve()
            data = self._read_stable_file(source)
            digest = hashlib.sha256(data).hexdigest()
            destination = self.corpus_dir / digest
            if destination.exists():
                existing = self._read_stable_file(destination)
                if hashlib.sha256(existing).hexdigest() != digest:
                    raise RuntimeError(f"active corpus entry has invalid content: {destination}")
            else:
                self._write_atomic(destination, data)
            added.append(str(destination))
        return tuple(added)

    def replay_runtime(
        self,
        binary: str,
        corpus_dir: str,
        *,
        timeout_seconds: float = 600,
    ) -> Optional[FuzzProcessFailure]:
        """Replay one immutable corpus with the sanitizer runtime binary.

        This is used only to classify a failed coverage replay. A sanitizer
        failure is returned for runtime repair; a clean replay returns None.
        Process-launch and controller-timeout failures remain infrastructure
        errors and are raised to the caller.
        """
        if self._proc is not None:
            raise RuntimeError("cannot replay while the persistent fuzzer is running")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        resolved_binary = Path(binary).resolve()
        resolved_corpus = Path(corpus_dir).resolve()
        if not resolved_binary.is_file():
            raise FileNotFoundError(f"runtime binary not found: {resolved_binary}")
        if not resolved_corpus.is_dir():
            raise NotADirectoryError(f"corpus directory not found: {resolved_corpus}")

        replay_workdir = Path(
            tempfile.mkdtemp(prefix="replay-", dir=str(self.workdir / "epochs"))
        )
        artifact_prefix = f"{self.artifact_dir}{os.sep}"
        command = (
            str(resolved_binary),
            *self.fuzzer_args,
            "-runs=0",
            "-print_final_stats=0",
            f"-artifact_prefix={artifact_prefix}",
            str(resolved_corpus),
        )
        process_env = os.environ.copy()
        process_env.update(self.env)
        artifact_baseline = self._artifact_state()
        proc: Optional[subprocess.Popen[bytes]] = None
        notified_running = False

        try:
            proc = subprocess.Popen(
                command,
                cwd=str(replay_workdir),
                env=process_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            if self.on_fuzzer_start is not None:
                notified_running = True
                self.on_fuzzer_start(proc.pid)
            output_bytes, _ = proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            assert proc is not None
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output_bytes, _ = proc.communicate()
            self._append_output(output_bytes)
            raise RuntimeError(
                f"sanitizer corpus replay exceeded {timeout_seconds:g} seconds"
            ) from exc
        except BaseException:
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            shutil.rmtree(replay_workdir, ignore_errors=True)
            raise
        finally:
            if notified_running and self.on_fuzzer_stop is not None:
                self.on_fuzzer_stop()

        self._append_output(output_bytes)
        output = output_bytes.decode("utf-8", errors="replace")
        if proc.returncode == 0:
            shutil.rmtree(replay_workdir)
            return None
        return FuzzProcessFailure(
            command=command,
            returncode=proc.returncode,
            output=output,
            artifacts=tuple(
                path
                for path, signature in self._artifact_state().items()
                if artifact_baseline.get(path) != signature
            ),
            work_dir=str(replay_workdir),
        )

    def stop(self) -> None:
        proc = self._proc
        if proc is None:
            return

        returncode = proc.poll()
        if returncode is not None:
            self._raise_process_exited(returncode)

        killed = False
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError as exc:
            returncode = proc.poll()
            if returncode is not None:
                self._raise_process_exited(returncode)
            raise RuntimeError("failed to send SIGTERM to the fuzzer process group") from exc
        else:
            try:
                returncode = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                killed = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired as exc:
                    self._finish_epoch()
                    raise RuntimeError(
                        "persistent fuzzer did not exit after SIGKILL"
                    ) from exc

        if not killed and returncode != INTERRUPT_EXIT_CODE:
            self._raise_process_exited(returncode)

        self._finish_epoch()
        if killed:
            raise RuntimeError("persistent fuzzer ignored SIGTERM and required SIGKILL")

    def _start(self, binary: str) -> None:
        self._ensure_seed()
        epoch_workdir = Path(
            tempfile.mkdtemp(prefix="epoch-", dir=str(self.workdir / "epochs"))
        )
        artifact_prefix = f"{self.artifact_dir}{os.sep}"
        command = (
            binary,
            *self.fuzzer_args,
            "-print_final_stats=0",
            f"-artifact_prefix={artifact_prefix}",
            str(self.corpus_dir),
        )
        process_env = os.environ.copy()
        process_env.update(self.env)

        output_handle = self.output_path.open("ab")
        output_handle.flush()
        output_offset = os.fstat(output_handle.fileno()).st_size
        artifact_baseline = self._artifact_state()
        try:
            proc = subprocess.Popen(
                command,
                cwd=str(epoch_workdir),
                env=process_env,
                stdout=output_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except Exception:
            output_handle.close()
            raise

        started_at = time.monotonic()
        self._proc = proc
        self._binary = binary
        self._command = command
        self._epoch_started_at = started_at
        self._next_checkpoint_at = started_at + self.checkpoint_seconds
        self._epoch_workdir = epoch_workdir
        self._output_handle = output_handle
        self._output_offset = output_offset
        self._artifact_baseline = artifact_baseline
        self._notified_running = True
        if self.on_fuzzer_start is not None:
            try:
                self.on_fuzzer_start(proc.pid)
            except Exception:
                self.stop()
                raise

    def _wait_until_checkpoint(self) -> None:
        assert self._proc is not None
        assert self._next_checkpoint_at is not None
        while True:
            returncode = self._proc.poll()
            if returncode is not None:
                self._raise_process_exited(returncode)
            remaining = self._next_checkpoint_at - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.1, remaining))

    def _raise_process_exited(self, returncode: int) -> None:
        assert self._proc is not None
        self._proc.wait()
        failure = FuzzProcessFailure(
            command=self._command,
            returncode=returncode,
            output=self._read_epoch_output(),
            artifacts=self._new_artifacts(),
            work_dir=str(self._epoch_workdir),
        )
        self._finish_epoch()
        raise FuzzProcessExited(failure)

    def _finish_epoch(self) -> None:
        if self._output_handle is not None:
            self._output_handle.close()
            self._output_handle = None
        notify_stop = self._notified_running and self.on_fuzzer_stop is not None
        self._notified_running = False
        self._proc = None
        self._binary = None
        self._command = ()
        self._epoch_started_at = None
        self._next_checkpoint_at = None
        self._epoch_workdir = None
        self._output_offset = 0
        self._artifact_baseline = {}
        if notify_stop:
            assert self.on_fuzzer_stop is not None
            self.on_fuzzer_stop()

    def _read_epoch_output(self) -> str:
        if self._output_handle is not None:
            self._output_handle.flush()
        with self.output_path.open("rb") as handle:
            handle.seek(self._output_offset)
            return handle.read().decode("utf-8", errors="replace")

    def _append_output(self, output: bytes) -> None:
        with self.output_path.open("ab") as handle:
            handle.write(output)

    def _artifact_state(self) -> dict[str, tuple[int, int, int]]:
        state: dict[str, tuple[int, int, int]] = {}
        for path in sorted(self.artifact_dir.rglob("*")):
            try:
                info = path.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                state[str(path)] = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        return state

    def _new_artifacts(self) -> tuple[str, ...]:
        current = self._artifact_state()
        return tuple(
            path
            for path, signature in current.items()
            if self._artifact_baseline.get(path) != signature
        )

    def _ensure_seed(self) -> None:
        for path in self.corpus_dir.iterdir():
            try:
                if stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
                    return
            except FileNotFoundError:
                continue
        (self.corpus_dir / "seed-empty").write_bytes(b"")

    def _snapshot_corpus(self) -> str:
        snapshots_root = self.workdir / "snapshots"
        checkpoint_store = self.workdir / "checkpoint-store"

        for source in sorted(self.corpus_dir.iterdir(), key=lambda path: path.name):
            data = self._read_live_corpus_file(source)
            if data is None:
                continue
            digest = hashlib.sha256(data).hexdigest()
            self._store_checkpoint_content(checkpoint_store, digest, data)

        contents = self._read_checkpoint_store()
        if not contents:
            empty = b""
            digest = hashlib.sha256(empty).hexdigest()
            self._store_checkpoint_content(checkpoint_store, digest, empty)
            contents = self._read_checkpoint_store()

        staging = Path(tempfile.mkdtemp(prefix=".building-", dir=str(snapshots_root)))
        digests = set(contents)
        try:
            for digest, data in contents.items():
                destination = staging / digest
                destination.write_bytes(data)

            snapshot_hash = hashlib.sha256(
                "\n".join(sorted(digests)).encode("ascii")
            ).hexdigest()
            snapshot = snapshots_root / snapshot_hash
            for path in staging.iterdir():
                path.chmod(0o444)

            if snapshot.exists():
                self._verify_snapshot(snapshot, digests)
                shutil.rmtree(staging)
            else:
                try:
                    staging.rename(snapshot)
                except FileExistsError:
                    self._verify_snapshot(snapshot, digests)
                    shutil.rmtree(staging)
                snapshot.chmod(0o555)
            return str(snapshot)
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            raise

    def _store_checkpoint_content(
        self,
        checkpoint_store: Path,
        digest: str,
        data: bytes,
    ) -> None:
        destination = checkpoint_store / digest
        if destination.exists():
            existing = self._read_stable_file(destination)
            if hashlib.sha256(existing).hexdigest() != digest:
                raise RuntimeError(f"checkpoint store entry was modified: {destination}")
            return
        self._write_atomic(destination, data)
        destination.chmod(0o444)

    def _read_checkpoint_store(self) -> dict[str, bytes]:
        checkpoint_store = self.workdir / "checkpoint-store"
        contents: dict[str, bytes] = {}
        for path in sorted(checkpoint_store.iterdir(), key=lambda entry: entry.name):
            try:
                info = path.stat(follow_symlinks=False)
            except FileNotFoundError as exc:
                raise RuntimeError(f"checkpoint store entry disappeared: {path}") from exc
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError(f"checkpoint store entry is not a regular file: {path}")
            data = self._read_stable_file(path)
            digest = hashlib.sha256(data).hexdigest()
            if path.name != digest:
                raise RuntimeError(f"checkpoint store entry was modified: {path}")
            contents[digest] = data

        missing = self._stored_digests.difference(contents)
        if missing:
            missing_text = ", ".join(sorted(missing))
            raise RuntimeError(
                f"checkpoint store lost historical digests: {missing_text}"
            )
        self._stored_digests = frozenset(contents)
        return contents

    @staticmethod
    def _verify_snapshot(snapshot: Path, expected_digests: set[str]) -> None:
        actual = {path.name for path in snapshot.iterdir() if path.is_file()}
        if actual != expected_digests:
            raise RuntimeError(f"immutable corpus snapshot was modified: {snapshot}")
        for path in snapshot.iterdir():
            if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() != path.name:
                raise RuntimeError(f"immutable corpus snapshot was modified: {snapshot}")

    @staticmethod
    def _read_stable_file(path: Path) -> bytes:
        try:
            return PersistentFuzzSession._read_open_file(path)
        except FileNotFoundError as exc:
            raise RuntimeError(f"file disappeared while reading: {path}") from exc

    @staticmethod
    def _read_live_corpus_file(path: Path) -> Optional[bytes]:
        """Read one entry from a corpus concurrently managed by libFuzzer."""
        try:
            return PersistentFuzzSession._read_open_file(path)
        except (FileNotFoundError, IsADirectoryError):
            return None

    @staticmethod
    def _read_open_file(path: Path) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                if stat.S_ISDIR(before.st_mode):
                    raise IsADirectoryError(path)
                raise RuntimeError(f"not a regular file: {path}")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                data = handle.read()
            after = os.fstat(fd)
        finally:
            os.close(fd)

        before_signature = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_signature = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_signature != after_signature:
            raise RuntimeError(f"file changed while reading: {path}")
        return data

    @staticmethod
    def _write_atomic(destination: Path, data: bytes) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".import-", dir=str(destination.parent))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            if destination.exists():
                os.unlink(temporary)
            else:
                os.replace(temporary, destination)
        except Exception:
            if os.path.exists(temporary):
                os.unlink(temporary)
            raise
