"""Regression coverage for crashes observed during fresh-process corpus replay.

The driver fixtures are real executable processes. Only the LLVM merge/export
tools are replaced when a successful measurement needs synthetic coverage data.
Run with: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest.mock import call, patch

from src.core import llvm_cov
from src.driver_qualification.reachability.monitor import (
    QualificationPhase,
    ReachabilityMonitor,
    ReachabilityOutcome,
    RuntimeBuild,
)
from src.driver_qualification.reachability.diagnose import make_region_diagnose
from src.driver_qualification.reachability.progress import Progress
from src.driver_qualification.runtime import (
    FuzzCheckpoint,
    FuzzProcessExited,
    FuzzProcessFailure,
)


SANITIZER_OUTPUT = (
    "ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed\n"
    "    #0 cmsDeleteContext cmsplugin.c:1029\n"
)
REPLAY_PROVENANCE = (
    "Crash observed while replaying the corpus over the coverage binary."
)


class FakeFuzzSession:
    """Supply an immutable checkpoint while recording controller cleanup."""

    def __init__(self, snapshot: Path, stop_failure=None):
        self.snapshot = snapshot
        self.stop_failure = stop_failure
        self.checkpoint_calls = []
        self.assert_calls = 0
        self.stop_calls = 0
        self.running = False

    def checkpoint(self, binary):
        self.checkpoint_calls.append(binary)
        self.running = True
        return FuzzCheckpoint(str(self.snapshot), 1.0, "fuzzer still running", (binary,))

    def assert_running(self):
        self.assert_calls += 1
        if not self.running:
            raise AssertionError("the fuzzer was stopped before measurement finished")

    def stop(self):
        self.stop_calls += 1
        self.running = False
        if self.stop_failure is not None:
            raise FuzzProcessExited(self.stop_failure)


class ReplayFailureTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.corpus = self.root / "snapshot"
        self.corpus.mkdir()
        self.input = self.corpus / "crash-input"
        self.input.write_bytes(b"\x27")
        self.profraw = self.root / "measurement.profraw"
        self.source = self.root / "cmsplugin.c"

    def script(self, body, name="coverage-driver"):
        binary = self.root / name
        binary.write_text(
            f"#!{sys.executable}\n" + textwrap.dedent(body), encoding="utf-8"
        )
        binary.chmod(0o755)
        return str(binary)

    def crashing_binary(self):
        return self.script(
            f"""
            import sys
            print("replaying input", flush=True)
            sys.stderr.write({SANITIZER_OUTPUT!r})
            sys.exit(23)
            """
        )

    def profile_binary(self):
        return self.script(
            """
            import os
            from pathlib import Path
            profile = Path(os.environ["LLVM_PROFILE_FILE"].replace("%m", "fixture"))
            with profile.open("a") as output:
                output.write(str(os.getpid()) + "\\n")
            """
        )

    def exported_coverage(self):
        return {
            "data": [{
                "files": [{
                    "filename": str(self.source),
                    "segments": [
                        [1029, 1, 1, True, True, False],
                        [1030, 1, 0, False, False, False],
                    ],
                }],
                "functions": [{
                    "name": "cmsDeleteContext", "count": 1,
                    "filenames": [str(self.source)], "branches": [],
                }],
            }],
        }

    def export_tools(self, data):
        def run(command, **kwargs):
            if command[0] == llvm_cov.PROFDATA:
                Path(command[command.index("-o") + 1]).write_bytes(b"profdata")
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[0] == llvm_cov.COV:
                return subprocess.CompletedProcess(command, 0, json.dumps(data), "")
            raise AssertionError(f"unexpected tool: {command}")
        return patch.object(llvm_cov.subprocess, "run", side_effect=run)

    def monitor(self, binary, *, session=None, timeout=3):
        session = session or FakeFuzzSession(self.corpus)
        events = []
        phases = []
        monitor = ReachabilityMonitor(
            "driver.cpp", f"{self.source}:1029", ["cmsDeleteContext"],
            build_runtime=lambda _: RuntimeBuild("driver.cpp", "runtime-binary"),
            build_cov=lambda _: binary,
            coverage_workdir=str(self.root),
            fuzz_session=session,
            max_rounds=1,
            measurement_timeout_seconds=timeout,
            on_event=lambda *event: events.append(event),
            on_phase=phases.append,
        )
        return monitor, session, events, phases

    def test_nonzero_exit_returns_replay_evidence_without_diagnostic_argument(self):
        self.profraw.write_bytes(b"stale profile")
        binary = self.crashing_binary()
        crash = llvm_cov.replay_corpus(binary, str(self.corpus), str(self.profraw))

        self.assertIsInstance(crash, llvm_cov.ReplayCrash)
        self.assertEqual(crash.returncode, 23)
        self.assertEqual(crash.command[0], binary)
        self.assertEqual(crash.command[1], str(self.input))
        self.assertEqual(crash.input_path, str(self.input))
        self.assertIn("replaying input", crash.stdout)
        self.assertIn(SANITIZER_OUTPUT, crash.stderr)
        self.assertFalse(self.profraw.exists())

    def test_signal_exit_preserves_negative_returncode_and_output(self):
        binary = self.script(
            """
            import os, resource, signal, sys
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            print("invalid pointer before abort", file=sys.stderr, flush=True)
            os.kill(os.getpid(), signal.SIGABRT)
            """
        )
        diagnostic = {}
        crash = llvm_cov.replay_corpus(
            binary, str(self.corpus), str(self.profraw), diagnostic=diagnostic
        )

        self.assertIsInstance(crash, llvm_cov.ReplayCrash)
        self.assertEqual(crash.returncode, -signal.SIGABRT)
        self.assertIn("invalid pointer before abort", crash.stderr)
        self.assertEqual(diagnostic["returncode"], -signal.SIGABRT)
        self.assertEqual(diagnostic["command"][1], str(self.input))

    def test_libfuzzer_timeout_is_infrastructure_failure(self):
        binary = self.script(
            """
            import sys
            assert "-timeout_exitcode=70" in sys.argv
            print("ERROR: libFuzzer: timeout after 100 seconds", file=sys.stderr)
            sys.exit(70)
            """
        )
        diagnostic = {}
        result = llvm_cov.replay_corpus(
            binary, str(self.corpus), str(self.profraw), diagnostic=diagnostic
        )

        self.assertIs(result, False)
        self.assertEqual(diagnostic["returncode"], 70)
        self.assertTrue(diagnostic["timed_out"])

    @staticmethod
    def process_is_live(pid):
        try:
            state = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[0]
        except FileNotFoundError:
            return False
        return state not in ("Z", "X")

    @unittest.skipUnless(sys.platform.startswith("linux"), "uses Linux process states")
    def test_outer_timeout_reaps_the_replay_process_and_stops_its_child(self):
        pid_path = self.root / "pids.json"
        binary = self.script(
            f"""
            import json, os, subprocess, sys, time
            from pathlib import Path
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            Path({str(pid_path)!r}).write_text(json.dumps([os.getpid(), child.pid]))
            time.sleep(60)
            """
        )
        diagnostic = {}
        try:
            result = llvm_cov.replay_corpus(
                binary, str(self.corpus), str(self.profraw), timeout=1,
                diagnostic=diagnostic,
            )
            self.assertIs(result, False)
            self.assertTrue(diagnostic["timed_out"])
            self.assertIsNone(diagnostic["returncode"])
            self.assertTrue(pid_path.is_file(), "the timeout fixture never started")
            pids = json.loads(pid_path.read_text())
            deadline = time.monotonic() + 1
            while any(self.process_is_live(pid) for pid in pids) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(any(self.process_is_live(pid) for pid in pids))
            self.assertFalse(Path(f"/proc/{pids[0]}").exists(), "replay parent was not reaped")
        finally:
            if pid_path.is_file():
                for pid in json.loads(pid_path.read_text()):
                    if self.process_is_live(pid):
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_spawn_failure_is_infrastructure_failure(self):
        diagnostic = {}
        result = llvm_cov.replay_corpus(
            str(self.root / "absent-binary"), str(self.corpus), str(self.profraw),
            diagnostic=diagnostic,
        )
        self.assertIs(result, False)
        self.assertTrue(diagnostic["spawn_failed"])
        self.assertIsNone(diagnostic["returncode"])

    def test_success_without_profile_is_infrastructure_failure(self):
        result = llvm_cov.replay_corpus(
            self.script("pass\n"), str(self.corpus), str(self.profraw)
        )
        self.assertIs(result, False)
        self.assertFalse(self.profraw.exists())

    def test_success_runs_each_input_in_a_fresh_process(self):
        (self.corpus / "other-input").write_bytes(b"\x41")
        result = llvm_cov.replay_corpus(
            self.profile_binary(), str(self.corpus), str(self.profraw)
        )
        self.assertIs(result, True)
        pids = self.profraw.read_text().splitlines()
        self.assertEqual(len(pids), 2)
        self.assertEqual(len(set(pids)), 2)

    def test_exporter_returns_crash_and_never_exports_partial_profiles(self):
        (self.corpus / "00-success").write_bytes(b"\x41")
        binary = self.script(
            f"""
            import os, sys
            from pathlib import Path
            if Path(sys.argv[1]).read_bytes() == b"\\x27":
                sys.stderr.write({SANITIZER_OUTPUT!r})
                sys.exit(23)
            Path(os.environ["LLVM_PROFILE_FILE"].replace("%m", "fixture")).write_bytes(b"partial")
            """
        )
        diagnostic_path = self.root / "failure.json"
        with patch.object(llvm_cov.subprocess, "run") as llvm_tool:
            result = llvm_cov.replay_and_export(
                binary, str(self.corpus), workdir=str(self.root),
                diagnostic_path=str(diagnostic_path),
            )
        self.assertIsInstance(result, llvm_cov.ReplayCrash)
        llvm_tool.assert_not_called()
        self.assertEqual(result.input_path, str(self.input))
        diagnostic = json.loads(diagnostic_path.read_text())
        self.assertEqual(diagnostic["phase"], "replay")
        self.assertEqual(diagnostic["command"][1], str(self.input))
        self.assertIn("cmsplugin.c:1029", diagnostic["stderr"])
        self.assertFalse((self.root / "cov.profraw").exists())

    def test_exporter_returns_crash_without_a_diagnostic_file(self):
        with patch.object(llvm_cov.subprocess, "run") as llvm_tool:
            result = llvm_cov.replay_and_export(
                self.crashing_binary(), str(self.corpus), workdir=str(self.root)
            )
        self.assertIsInstance(result, llvm_cov.ReplayCrash)
        self.assertIn(SANITIZER_OUTPUT, result.stderr)
        llvm_tool.assert_not_called()

    def test_successful_export_still_returns_coverage_and_removes_profiles(self):
        data = self.exported_coverage()
        with self.export_tools(data) as llvm_tools:
            result = llvm_cov.replay_and_export(
                self.profile_binary(), str(self.corpus), workdir=str(self.root)
            )
        self.assertEqual(result, data)
        self.assertEqual(llvm_tools.call_count, 2)
        self.assertFalse((self.root / "cov.profraw").exists())
        self.assertFalse((self.root / "cov.profdata").exists())

    def test_diagnosis_preserves_replay_crash_evidence(self):
        binary = self.crashing_binary()
        diagnose = make_region_diagnose(
            "lcms", f"{self.source}:1029", ["cmsDeleteContext"],
            lambda _: binary, str(self.corpus), workdir=str(self.root),
        )
        report = diagnose("driver.cpp", Progress(0, 1, "cmsDeleteContext", 1))
        self.assertIn(REPLAY_PROVENANCE, report)
        self.assertIn(str(self.input), report)
        self.assertIn(SANITIZER_OUTPUT, report)
        self.assertIn("Return code: 23", report)
        diagnostic = json.loads((self.root / "diagnosis-failure.json").read_text())
        self.assertEqual(diagnostic["input_path"], str(self.input))
        self.assertIn("cmsplugin.c:1029", diagnostic["stderr"])

    def test_llvm_tool_failure_is_infrastructure_failure(self):
        diagnostic_path = self.root / "failure.json"
        with patch.object(
            llvm_cov.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 1, "", "merge failed"),
        ):
            result = llvm_cov.replay_and_export(
                self.profile_binary(), str(self.corpus), workdir=str(self.root),
                diagnostic_path=str(diagnostic_path),
            )
        self.assertIsNone(result)
        self.assertEqual(json.loads(diagnostic_path.read_text())["phase"], "profdata_merge")

    def test_monitor_routes_replay_crash_to_runtime_failure_with_input_evidence(self):
        binary = self.crashing_binary()
        monitor, session, events, phases = self.monitor(binary)
        result = monitor.run()

        self.assertEqual(result.outcome, ReachabilityOutcome.RUNTIME_FAILED)
        self.assertEqual(result.rounds, 1)
        self.assertIsNone(result.last)
        self.assertIsInstance(result.failure, FuzzProcessFailure)
        self.assertEqual(result.failure.command[0], binary)
        self.assertEqual(result.failure.command[1], str(self.input))
        self.assertEqual(result.failure.returncode, 23)
        self.assertEqual(result.failure.artifacts, (str(self.input),))
        self.assertEqual(result.failure.work_dir, str(self.corpus))
        self.assertTrue(Path(result.failure.artifacts[0]).is_file())
        self.assertIn(REPLAY_PROVENANCE, result.failure.output)
        self.assertIn("replaying input", result.failure.output)
        self.assertIn(SANITIZER_OUTPUT, result.failure.output)
        self.assertIn(str(self.input), result.failure.failure_context())
        self.assertIn("cmsplugin.c:1029", result.failure.failure_context())
        self.assertEqual(result.coverage_binary, binary)
        self.assertEqual(result.corpus_snapshot, str(self.corpus))
        self.assertEqual(session.checkpoint_calls, ["runtime-binary"])
        self.assertFalse(session.running)
        self.assertGreaterEqual(session.stop_calls, 1)
        self.assertEqual(events, [(1, None, "RUNTIME_FAILED")])
        self.assertEqual(
            [event.phase for event in phases],
            [QualificationPhase.BUILDING, QualificationPhase.FUZZING, QualificationPhase.MEASURING],
        )

    def test_stop_race_does_not_overwrite_the_replay_crash(self):
        stop_failure = FuzzProcessFailure(
            ("runtime-binary",), 99, "concurrent fuzzer exit", (), str(self.root)
        )
        session = FakeFuzzSession(self.corpus, stop_failure=stop_failure)
        monitor, _, _, _ = self.monitor(self.crashing_binary(), session=session)
        result = monitor.run()
        self.assertEqual(result.outcome, ReachabilityOutcome.RUNTIME_FAILED)
        self.assertEqual(result.failure.returncode, 23)
        self.assertEqual(result.failure.artifacts, (str(self.input),))
        self.assertIn(REPLAY_PROVENANCE, result.failure.output)
        self.assertFalse(session.running)

    def test_monitor_keeps_missing_profile_as_measure_failed_and_stops_session(self):
        monitor, session, events, _ = self.monitor(self.script("pass\n"))
        result = monitor.run()
        self.assertEqual(result.outcome, ReachabilityOutcome.MEASURE_FAILED)
        self.assertEqual(result.rounds, 1)
        self.assertIsNone(result.failure)
        self.assertEqual(events, [(1, None, "MEASURE_FAILED")])
        self.assertFalse(session.running)
        self.assertGreaterEqual(session.stop_calls, 1)

    def test_monitor_keeps_libfuzzer_timeout_as_measure_failed(self):
        binary = self.script("import sys\nsys.exit(70)\n")
        monitor, session, _, _ = self.monitor(binary)
        result = monitor.run()
        self.assertEqual(result.outcome, ReachabilityOutcome.MEASURE_FAILED)
        self.assertIsNone(result.failure)
        self.assertFalse(session.running)

    def test_monitor_keeps_outer_timeout_as_measure_failed(self):
        binary = self.script("import time\ntime.sleep(60)\n")
        monitor, session, _, _ = self.monitor(binary, timeout=0.1)
        result = monitor.run()
        self.assertEqual(result.outcome, ReachabilityOutcome.MEASURE_FAILED)
        self.assertIsNone(result.failure)
        self.assertFalse(session.running)

    def test_monitor_successful_measurement_still_reaches_the_target(self):
        monitor, session, events, _ = self.monitor(self.profile_binary())
        with self.export_tools(self.exported_coverage()):
            result = monitor.run()
        self.assertEqual(result.outcome, ReachabilityOutcome.REACHED)
        self.assertEqual(result.rounds, 1)
        self.assertTrue(result.last.reached)
        self.assertEqual(result.last.frontier_fn, "cmsDeleteContext")
        self.assertEqual(events[0][2], "REACHED")
        self.assertIsNone(result.failure)
        self.assertFalse(session.running)

    def test_monitor_returns_the_exact_binary_and_latest_completed_snapshot(self):
        second_snapshot = self.root / "snapshot-2"
        second_snapshot.mkdir()
        (second_snapshot / "later-input").write_bytes(b"later")

        class SequentialFuzzSession(FakeFuzzSession):
            def __init__(self, snapshots):
                super().__init__(snapshots[0])
                self.snapshots = list(snapshots)

            def checkpoint(self, binary):
                self.snapshot = self.snapshots[len(self.checkpoint_calls)]
                return super().checkpoint(binary)

        binary = self.script("pass\n", name="exact-coverage-driver")
        session = SequentialFuzzSession([self.corpus, second_snapshot])
        monitor, _, _, _ = self.monitor(binary, session=session)
        monitor.max_rounds = 2
        measurements = [
            Progress(0, 0, "cmsDeleteContext", 1),
            Progress(1, 0, "cmsDeleteContext", 1),
        ]

        with patch.object(monitor, "_probe", side_effect=measurements) as probe:
            result = monitor.run()

        self.assertEqual(result.outcome, ReachabilityOutcome.REACHED)
        self.assertEqual(result.coverage_binary, binary)
        self.assertEqual(result.corpus_snapshot, str(second_snapshot))
        self.assertEqual(
            probe.call_args_list,
            [
                call(binary, str(self.corpus)),
                call(binary, str(second_snapshot)),
            ],
        )


if __name__ == "__main__":
    unittest.main()
