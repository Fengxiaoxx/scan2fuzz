"""Regression tests for reachability evidence passed to driver enhancement."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.driver_qualification.contracts import DriverQualificationSpec
from src.driver_qualification.reachability.monitor import (
    ReachabilityOutcome,
    ReachabilityResult,
)
from src.driver_qualification.workflow import (
    INFRASTRUCTURE_OUTCOMES,
    REACHABILITY_STAGE,
    DriverQualificationWorkflow,
    _run_driver_qualification,
)
from src.experiment import RunArtifactStore
from src.driver_rounds.state import READY_REACH, initial_target_state
from src.driver_rounds.workflow import DriverRoundWorkflow


class QualificationEvidenceFlowTests(unittest.TestCase):
    def test_run_artifact_candidate_preserves_enhancement_evidence(self):
        evidence = {
            "status": "DONE",
            "reachability_outcome": "gave_up",
            "branch_coverage_available": False,
            "covered_branch_outcomes": 0,
            "progress_reason": "stale",
            "new_branch_outcomes": 0,
            "stale_checks": 3,
            "target_reached": False,
            "elapsed": 17,
            "qualification_error": None,
            "coverage_binary": "/run/attempt/final/qualification-coverage.out",
            "corpus_snapshot": "/run/attempt/work/snapshots/abc123",
        }

        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            source = root / "driver.cc"
            binary = root / "driver.out"
            source.write_text("// driver\n", encoding="utf-8")
            binary.write_bytes(b"binary")
            spec = DriverQualificationSpec(
                name="driver-001",
                binary_path=str(binary),
                source_path=str(source),
                log_file=str(root / "qualification.log"),
                corpus_dir=str(root / "corpus"),
                artifact_dir=str(root / "artifacts"),
            )
            workflow = DriverQualificationWorkflow.__new__(
                DriverQualificationWorkflow
            )
            workflow.store = SimpleNamespace(
                run_store=SimpleNamespace(run_id="test-run")
            )

            with (
                patch.object(workflow, "_build_run_specs", return_value=[spec]),
                patch.object(workflow, "_execute_specs", return_value={0: evidence}),
                patch.object(workflow, "_apply_qualification_results"),
                patch.object(
                    workflow,
                    "_execution_payload",
                    return_value={
                        "name": "driver-001",
                        "status": "DONE",
                        "reachability_outcome": "gave_up",
                        "reachability_rounds": 2,
                    },
                ),
            ):
                result = workflow.run_artifact_candidate(
                    "driver-001",
                    str(source),
                    str(binary),
                )

        payload = result.drivers["driver-001"]
        self.assertEqual(payload["coverage_binary"], evidence["coverage_binary"])
        self.assertEqual(payload["corpus_snapshot"], evidence["corpus_snapshot"])
        details = DriverRoundWorkflow._reach_details(payload)
        for field in (
            "branch_coverage_available",
            "covered_branch_outcomes",
            "progress_reason",
            "new_branch_outcomes",
            "stale_checks",
            "target_reached",
            "elapsed",
            "qualification_error",
        ):
            with self.subTest(field=field):
                self.assertIn(field, payload)
                self.assertIn(field, details)
                self.assertEqual(details[field], evidence[field])

    def test_reachability_infrastructure_outcomes_enter_retry_state(self):
        state = initial_target_state(
            {
                "target_id": "target-001",
                "marker": "TARGET_0001",
                "candidates": [{"driver_id": "driver-001"}],
            }
        )
        state.update(
            {
                "state": READY_REACH,
                "source_path": "/tmp/driver-001.cc",
                "binary_path": "/tmp/driver-001",
            }
        )
        workflow = DriverRoundWorkflow.__new__(DriverRoundWorkflow)

        for outcome in sorted(INFRASTRUCTURE_OUTCOMES):
            with self.subTest(outcome=outcome):
                updated, event = workflow._apply_action(
                    state,
                    {},
                    {
                        "phase": "target_reachability",
                        "record": {
                            "status": "ERROR",
                            "reachability_outcome": outcome,
                            "qualification_error": f"{outcome} evidence",
                        },
                    },
                )

                self.assertEqual(event, "infrastructure_retry")
                self.assertEqual(updated["state"], READY_REACH)
                self.assertEqual(
                    updated["infrastructure_retries"]["target_reachability"],
                    1,
                )
                self.assertEqual(
                    updated["last_infrastructure_error"],
                    f"{outcome} evidence",
                )

    def _artifact_case(self, root: Path):
        project_root = root / "project"
        project_root.mkdir()
        run_store = RunArtifactStore.create(project_root, "lcms", "test-run")
        attempt = (
            run_store.stage_dir(REACHABILITY_STAGE, "driver-001")
            / "attempts"
            / "attempt-001"
        )
        work = attempt / "work"
        snapshots = work / "snapshots"
        snapshots.mkdir(parents=True)
        corpus_snapshot = snapshots / "snapshot-exact"
        corpus_snapshot.mkdir()
        (corpus_snapshot / "seed").write_bytes(b"seed")

        source = run_store.run_dir / "candidate.cc"
        runtime_binary = run_store.run_dir / "candidate.out"
        log_file = attempt / "qualification.log"
        source.write_text("// candidate\n", encoding="utf-8")
        runtime_binary.write_bytes(b"runtime")
        log_file.write_text("qualification\n", encoding="utf-8")

        spec = DriverQualificationSpec(
            name="driver-001",
            binary_path=str(runtime_binary),
            source_path=str(source),
            log_file=str(log_file),
            corpus_dir=str(run_store.run_dir / "corpus"),
            artifact_dir=str(run_store.run_dir / "artifacts"),
        )
        workflow = DriverQualificationWorkflow.__new__(
            DriverQualificationWorkflow
        )
        workflow.library = "lcms"
        workflow.check_interval_seconds = 1
        workflow.qualification_budget_seconds = 1
        workflow.store = SimpleNamespace(run_store=run_store)
        return workflow, spec, attempt, work, corpus_snapshot

    def test_apply_results_freezes_the_exact_reported_coverage_binary(self):
        with tempfile.TemporaryDirectory() as tempdir:
            workflow, spec, attempt, work, corpus_snapshot = self._artifact_case(
                Path(tempdir)
            )
            exact_coverage = work / "cov-exact.out"
            exact_coverage.write_bytes(b"exact coverage binary")
            (work / "cov-decoy.out").write_bytes(b"decoy")
            status = {
                0: {
                    "status": "DONE",
                    "reachability_outcome": "gave_up",
                    "reachability_rounds": 2,
                    "log_file": spec.log_file,
                    "final_driver": spec.source_path,
                    "final_binary": spec.binary_path,
                    "coverage_binary": str(exact_coverage),
                    "corpus_snapshot": str(corpus_snapshot),
                    "attempt_dir": str(attempt),
                }
            }

            workflow._apply_qualification_results([spec], status)

            frozen_coverage = attempt / "final" / "qualification-coverage.out"
            self.assertEqual(status[0]["status"], "DONE")
            self.assertEqual(status[0]["coverage_binary"], str(frozen_coverage))
            self.assertEqual(frozen_coverage.read_bytes(), b"exact coverage binary")
            self.assertEqual(
                status[0]["corpus_snapshot"],
                str(corpus_snapshot.resolve()),
            )
            self.assertEqual(
                Path(spec.binary_path),
                attempt / "final" / "qualification-final.out",
            )

    def test_apply_results_never_globs_for_a_missing_coverage_binary(self):
        with tempfile.TemporaryDirectory() as tempdir:
            workflow, spec, attempt, work, _ = self._artifact_case(Path(tempdir))
            (work / "cov-decoy.out").write_bytes(b"decoy")
            status = {
                0: {
                    "status": "DONE",
                    "reachability_outcome": "runtime_failed",
                    "reachability_rounds": 0,
                    "log_file": spec.log_file,
                    "final_driver": spec.source_path,
                    "final_binary": spec.binary_path,
                    "coverage_binary": str(work / "cov-missing.out"),
                    "corpus_snapshot": None,
                    "attempt_dir": str(attempt),
                }
            }

            workflow._apply_qualification_results([spec], status)

            self.assertEqual(status[0]["status"], "ERROR")
            self.assertEqual(
                status[0]["reachability_outcome"], "infrastructure_failed"
            )
            self.assertIn("cov-missing.out", status[0]["qualification_error"])
            self.assertFalse(
                (attempt / "final" / "qualification-coverage.out").exists()
            )

    def test_worker_result_records_monitor_artifact_paths(self):
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            project_root = root / "project"
            project_root.mkdir()
            run_store = RunArtifactStore.create(project_root, "lcms", "test-run")
            attempt = (
                run_store.stage_dir(REACHABILITY_STAGE, "driver-001")
                / "attempts"
                / "attempt-001"
            )
            attempt.mkdir(parents=True)
            coverage_binary = attempt / "work" / "cov-exact.out"
            corpus_snapshot = attempt / "work" / "snapshots" / "snapshot-exact"
            coverage_binary.parent.mkdir(parents=True)
            corpus_snapshot.mkdir(parents=True)
            coverage_binary.write_bytes(b"coverage")
            (corpus_snapshot / "seed").write_bytes(b"seed")

            source = run_store.run_dir / "candidate.cc"
            runtime_binary = run_store.run_dir / "candidate.out"
            source.write_text("// candidate\n", encoding="utf-8")
            runtime_binary.write_bytes(b"runtime")
            spec = DriverQualificationSpec(
                name="driver-001",
                binary_path=str(runtime_binary),
                source_path=str(source),
                log_file=str(run_store.run_dir / "unused.log"),
                corpus_dir=str(run_store.run_dir / "corpus"),
                artifact_dir=str(run_store.run_dir / "artifacts"),
            )
            result = ReachabilityResult(
                outcome=ReachabilityOutcome.REACHED,
                driver=str(source),
                rounds=1,
                coverage_binary=str(coverage_binary),
                corpus_snapshot=str(corpus_snapshot),
            )
            fake_monitor = SimpleNamespace(run=lambda: result)
            status = {}

            with (
                patch(
                    "src.driver_qualification.workflow.RunArtifactStore.from_environment",
                    return_value=run_store,
                ),
                patch(
                    "src.driver_qualification.workflow.get_project_root",
                    return_value=project_root,
                ),
                patch(
                    "src.driver_qualification.workflow.prepare_assert_target_marker",
                    return_value=None,
                ),
                patch(
                    "src.driver_qualification.workflow.make_adapters",
                    return_value=(lambda _: str(coverage_binary), object()),
                ),
                patch(
                    "src.driver_qualification.workflow.ReachabilityMonitor",
                    return_value=fake_monitor,
                ),
                patch("src.driver_qualification.workflow._redirect_worker_console"),
            ):
                _run_driver_qualification(
                    "lcms",
                    spec,
                    "source.c:10",
                    ["target_fn"],
                    "candidate_plan.json",
                    run_store.run_id,
                    1,
                    1,
                    status,
                    0,
                    str(attempt),
                )

            worker_result = run_store.read_json(attempt / "worker-result.json")
            self.assertEqual(
                worker_result["coverage_binary"], str(coverage_binary)
            )
            self.assertEqual(
                worker_result["corpus_snapshot"], str(corpus_snapshot)
            )
            self.assertEqual(status[0]["coverage_binary"], str(coverage_binary))
            self.assertEqual(status[0]["corpus_snapshot"], str(corpus_snapshot))


if __name__ == "__main__":
    unittest.main()
