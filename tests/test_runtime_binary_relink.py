"""Saved sanitizer binaries must match the library used by reachability."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.driver_rounds.state import READY_REACH, initial_target_state
from src.driver_rounds.workflow import DriverRoundWorkflow
from src.experiment import RunArtifactStore
from src.tools.compiler import file_sha256


class RuntimeBinaryRelinkTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = RunArtifactStore.create(self.root, "curl")
        self.source = self.root / "driver.cc"
        self.source.write_text("int driver = 1;\n", encoding="utf-8")
        self.old_binary = self.root / "old.out"
        self.old_binary.write_bytes(b"old curl binary")
        self.archive = self.root / "libcurl.a"
        self.archive.write_bytes(b"new curl archive")
        self.target = {
            "target_id": "lib/uint-hash.c:130",
            "marker": "TARGET_0027",
            "candidates": [{"driver_id": "curl_multi_perform__TARGET_0027"}],
        }
        self.state = initial_target_state(self.target)
        self.state.update({
            "state": READY_REACH,
            "source_path": str(self.source),
            "binary_path": str(self.old_binary),
        })
        self.workflow = DriverRoundWorkflow.__new__(DriverRoundWorkflow)
        self.workflow.library = "curl"
        self.workflow.store = self.store
        self.workflow.root = self.store.safe_path("stages/driver_rounds")

    def _fake_compile(self, source: str, library: str, *, output_path: str):
        self.assertEqual(source, str(self.source))
        self.assertEqual(library, "curl")
        output = Path(output_path)
        output.write_bytes(b"relinked curl binary")
        return {
            "success": True,
            "binary_file": str(output),
            "compile_command": "clang++ current source and archive",
            "binary_provenance": {
                "binary_path": str(output),
                "binary_sha256": file_sha256(output),
                "source_sha256": file_sha256(self.source),
                "sanitizer_library": str(self.archive),
                "sanitizer_sha256": file_sha256(self.archive),
                "compile_flags": "-lcurrent",
                "compiler_signature": "current-clang",
            },
        }

    def test_relink_event_precedes_reachability_and_resume_uses_new_binary(self):
        driver_id = "curl_multi_perform__TARGET_0027"
        with (
            patch("src.driver_rounds.workflow.work_item", return_value={"driver_id": driver_id}),
            patch("src.driver_rounds.workflow.load_generation_record", return_value={"success": True}),
            patch("src.driver_rounds.workflow.compile_driver", side_effect=self._fake_compile) as compile_mock,
            patch("src.driver_rounds.workflow.sanitizer_library_path", return_value=self.archive),
            patch("src.driver_rounds.workflow.build_compile_flags", return_value="-lcurrent"),
            patch("src.driver_rounds.workflow.compile_driver_signature", return_value="current-clang"),
            patch("src.driver_rounds.workflow.TargetReachabilityWorkflow") as qualification,
        ):
            first = self.workflow._execute_action(self.state, self.target)
            self.assertEqual(first["phase"], "runtime_relink")
            qualification.assert_not_called()
            updated, event = self.workflow._apply_action(self.state, self.target, first)
            self.assertEqual(event, "runtime_binary_relinked")
            self.workflow._persist_state(self.state["marker"], event, updated, first)
            saved = self.store.read_json(
                "stages/driver_rounds/targets/TARGET_0027/events/event-000001.json"
            )["target_state"]
            self.assertEqual(saved["binary_path"], updated["binary_path"])
            self.assertNotEqual(saved["binary_path"], str(self.old_binary))
            self.assertTrue(Path(saved["binary_path"]).is_relative_to(self.store.run_dir))
            self.assertEqual(self.old_binary.read_bytes(), b"old curl binary")

            qualification.return_value.run_artifact_candidate.return_value = SimpleNamespace(
                drivers={driver_id: {"status": "DONE", "reachability_outcome": "reached"}}
            )
            second = self.workflow._execute_action(updated, self.target)
            self.assertEqual(second["phase"], "target_reachability")
            compile_mock.assert_called_once()
            qualification.return_value.run_artifact_candidate.assert_called_once_with(
                driver_id, str(self.source), saved["binary_path"], show_progress=False
            )

    def test_changed_archive_invalidates_relinked_binary(self):
        with (
            patch("src.driver_rounds.workflow.sanitizer_library_path", return_value=self.archive),
            patch("src.driver_rounds.workflow.build_compile_flags", return_value="-lcurrent"),
            patch("src.driver_rounds.workflow.compile_driver_signature", return_value="current-clang"),
        ):
            self.assertTrue(self.workflow._needs_runtime_relink(self.state))
            self.state["binary_provenance"] = {
                "binary_path": str(self.old_binary),
                "binary_sha256": file_sha256(self.old_binary),
                "source_sha256": file_sha256(self.source),
                "sanitizer_library": str(self.archive),
                "sanitizer_sha256": file_sha256(self.archive),
                "compile_flags": "-lcurrent",
                "compiler_signature": "current-clang",
            }
            self.assertFalse(self.workflow._needs_runtime_relink(self.state))
            self.archive.write_bytes(b"another curl archive")
            self.assertTrue(self.workflow._needs_runtime_relink(self.state))

    def test_relink_compile_failure_never_qualifies_old_binary(self):
        driver_id = "curl_multi_perform__TARGET_0027"
        with (
            patch("src.driver_rounds.workflow.work_item", return_value={"driver_id": driver_id}),
            patch("src.driver_rounds.workflow.load_generation_record", return_value={"success": True}),
            patch("src.driver_rounds.workflow.compile_driver", return_value={
                "success": False, "stderr": "undefined reference to current curl"
            }),
            patch("src.driver_rounds.workflow.TargetReachabilityWorkflow") as qualification,
        ):
            action = self.workflow._execute_action(self.state, self.target)
            self.assertEqual(action["phase"], "runtime_relink")
            self.assertEqual(action["record"]["status"], "ERROR")
            self.assertIn("undefined reference", action["record"]["error"])
            updated, event = self.workflow._apply_action(self.state, self.target, action)
            self.assertEqual(event, "infrastructure_retry")
            self.assertEqual(updated["binary_path"], str(self.old_binary))
            qualification.assert_not_called()

    def test_relink_failure_is_nonretryable_for_the_scheduler(self):
        self.workflow.concurrency = 1
        self.workflow.fuzz_concurrency = 1
        self.workflow.max_infrastructure_retries = 5
        action = {
            "phase": "runtime_relink",
            "record": {
                "status": "ERROR",
                "success": False,
                "error": "saved driver cannot link against the current sanitizer archive",
            },
        }
        with (
            patch("src.driver_rounds.workflow.load_candidate_plan", return_value={
                "schema_version": 8,
                "targets": [self.target],
            }),
            patch.object(self.workflow, "_write_state_manifest"),
            patch.object(self.workflow, "_restore_states", return_value={
                "TARGET_0027": self.state,
            }),
            patch.object(self.workflow, "_execute_action", return_value=action) as execute,
            patch.object(self.workflow, "_persist_state"),
        ):
            with self.assertRaisesRegex(RuntimeError, "cannot link"):
                self.workflow.run()
        self.assertEqual(execute.call_count, 1)


if __name__ == "__main__":
    unittest.main()
