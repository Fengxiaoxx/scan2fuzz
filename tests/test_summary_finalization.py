"""Regression coverage for refreshing one run's canonical summary."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.experiment.report import finalize_run
from src.experiment.store import RunArtifactStore


class SummaryFinalizationTests(unittest.TestCase):
    def test_finalize_refreshes_summary_after_repeated_call_and_stage_rerun(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RunArtifactStore.create(Path(tmp), "sample", "run-001")
            store.write_json("stages/scan/result.json", {"status": "completed"})
            store.write_json("stages/preprocess/result.json", {"status": "completed"})
            rounds_path = store.stage_result_path("driver_rounds")
            original_rounds = {"status": "partial", "summary": {"reached": 1}}
            store.write_json(rounds_path, original_rounds)

            with patch(
                "src.experiment.report.collect_metrics",
                side_effect=(
                    {"revision": 1},
                    {"revision": 2},
                    {"revision": 3},
                ),
            ) as collect_metrics:
                finalize_run(store)
                self.assertEqual(
                    store.read_json("summary/result.json"),
                    {
                        "status": "partial",
                        "stages": [
                            ["scan", "completed"],
                            ["preprocess", "completed"],
                            ["driver_rounds", "partial"],
                        ],
                    },
                )
                self.assertEqual(store.read_json("summary/metrics.json"), {"revision": 1})

                finalize_run(store)
                self.assertEqual(store.read_json("summary/metrics.json"), {"revision": 2})
                self.assertEqual(store.read_json(rounds_path), original_rounds)
                with self.assertRaises(FileExistsError):
                    store.write_json(rounds_path, {"status": "completed"})

                archive = store.run_dir / "archive" / "driver_rounds-result.json"
                archive.parent.mkdir()
                rounds_path.rename(archive)
                replacement_rounds = {"status": "completed", "summary": {"reached": 2}}
                store.write_json(rounds_path, replacement_rounds)

                finalize_run(store)
                self.assertEqual(
                    store.read_json("summary/result.json"),
                    {
                        "status": "completed",
                        "stages": [
                            ["scan", "completed"],
                            ["preprocess", "completed"],
                            ["driver_rounds", "completed"],
                        ],
                    },
                )
                self.assertEqual(store.read_json("summary/metrics.json"), {"revision": 3})
                self.assertEqual(store.read_json(archive), original_rounds)
                self.assertEqual(store.read_json(rounds_path), replacement_rounds)
                with self.assertRaises(FileExistsError):
                    store.write_json(rounds_path, original_rounds)
                self.assertEqual(collect_metrics.call_count, 3)


if __name__ == "__main__":
    unittest.main()
