"""Pipeline integration and driver inventory for final AFL++ campaigns."""

from contextlib import nullcontext, redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.cli import fuzz_run_stage
from src.cli.pipeline import build_stages
from src.experiment import RunArtifactStore, collect_stage_statuses
from src.fuzz_run.inventory import load_fuzzable_drivers


class FuzzRunStageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = RunArtifactStore.create(self.root, "sample", "run-001")
        self.store.write_json("stages/driver_rounds/result.json", {
            "status": "completed",
            "targets": [{"state": "REACHED"}],
        })

    def _invoke(self):
        with patch.object(sys, "argv", [
            "fuzz_run_stage", "sample", "--run-id", "run-001",
            "--repetitions", "1", "--seconds-per-run", "2",
        ]), patch.object(fuzz_run_stage, "stage_run", return_value=nullcontext(self.store)), redirect_stdout(io.StringIO()):
            return fuzz_run_stage.main()

    def test_pipeline_ends_in_final_fuzz_stage(self):
        self.assertEqual([stage.name for stage in build_stages()], [
            "scan", "preprocess", "driver_rounds", "fuzz_run",
        ])

    def test_stage_retries_incomplete_campaign(self):
        def result(status):
            return {
                "status": status, "output_dir": "/tmp/campaign",
                "driver_count": 1, "seed_count": 1,
            }

        with patch.object(fuzz_run_stage, "_prepare_library"), patch.object(
            fuzz_run_stage, "run_fuzz", side_effect=[
                result("partial"), result("completed")
            ]
        ) as runner, patch("src.experiment.report.collect_metrics", return_value={}):
            self.assertEqual(self._invoke(), 1)
            self.assertFalse(self.store.safe_path("stages/fuzz_run/campaign.json").is_file())
            self.assertFalse(self.store.stage_result_path("fuzz_run").exists())
            self.assertEqual(self._invoke(), 0)
        self.assertEqual(runner.call_count, 2)
        self.assertTrue(self.store.safe_path("stages/fuzz_run/campaign.json").is_file())
        self.assertEqual(self.store.read_json(self.store.stage_result_path("fuzz_run"))["status"], "completed")
        self.assertIn(("fuzz_run", "completed"), collect_stage_statuses(self.store))

    def test_stage_skips_when_no_fuzzable_driver_exists(self):
        self.store.replace_json("stages/driver_rounds/result.json", {
            "status": "completed", "targets": [{"state": "EXHAUSTED"}, {"state": "CRASH"}],
        })
        with patch("src.experiment.report.collect_metrics", return_value={}):
            self.assertEqual(self._invoke(), 0)
        self.assertEqual(self.store.read_json(self.store.stage_result_path("fuzz_run"))["status"], "skipped")


class FuzzInventoryTests(unittest.TestCase):
    def test_inventory_selects_only_reached_drivers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = RunArtifactStore.create(root, "sample", "run-001")
            targets = []
            for marker, state in (("TARGET_0001", "REACHED"), ("TARGET_0002", "CRASH")):
                driver_id = f"sample__{marker}"
                source = store.run_dir / "stages" / "compile_repair" / driver_id / "sources" / "compile-passed.cc"
                source.parent.mkdir(parents=True)
                source.write_text("driver", encoding="utf-8")
                attempt = store.run_dir / "stages" / "target_reachability" / driver_id / "attempts" / "attempt-001"
                attempt.mkdir(parents=True)
                feedback = {"attempt_dir": str(attempt)}
                target = {"marker": marker, "target_id": "sample.c:1", "state": state, "source_path": str(source), "reach_feedback": feedback}
                if state == "REACHED":
                    target.update(selected_driver_id=driver_id, stable_source_path=str(source))
                    feedback["hit"] = 1
                else:
                    witness = store.run_dir / "stages" / "target_reachability" / driver_id / "artifacts" / "crash"
                    witness.parent.mkdir(parents=True)
                    witness.write_bytes(b"crash")
                    target["active_driver_id"] = driver_id
                    feedback.update(verdict="library_bug", crash={"returncode": 77, "artifacts": [str(witness)]})
                targets.append(target)
            store.write_json("stages/driver_rounds/result.json", {"targets": targets})
            _, inventory = load_fuzzable_drivers(root, "sample", store.run_id)
            self.assertEqual([item.state for item in inventory], ["REACHED"])
            self.assertEqual(inventory[0].hit_count, 1)
            targets[1]["reach_feedback"]["verdict"] = "harness_bug"
            store.replace_json("stages/driver_rounds/result.json", {"targets": targets})
            _, inventory = load_fuzzable_drivers(root, "sample", store.run_id)
            self.assertEqual(len(inventory), 1)
            store.replace_json("stages/driver_rounds/result.json", {"targets": targets[1:]})
            with self.assertRaisesRegex(ValueError, "no REACHED targets"):
                load_fuzzable_drivers(root, "sample", store.run_id)


if __name__ == "__main__":
    unittest.main()
