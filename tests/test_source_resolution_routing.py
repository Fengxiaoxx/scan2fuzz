"""Deterministic missing-source diagnostics must not consume retry budgets."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.driver_qualification.reachability.source_diagnostics import (
    _llvm_tool,
    classify_source_resolution_failure,
)
from src.driver_rounds.state import READY_REACH, READY_REFINE, initial_target_state
from src.driver_rounds.workflow import DriverRoundWorkflow


class SourceResolutionRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.diagnostic = self.root / "measurement-failure.json"

    def _missing_source(self, source: str, expected: Path | None = None) -> None:
        self.diagnostic.write_text(
            json.dumps({
                "phase": "source_resolution",
                "error": (
                    "analysis source path is absent from coverage data: "
                    f"{source} (expected {expected or Path('/project') / source})"
                ),
            }),
            encoding="utf-8",
        )

    def _archive(
        self,
        member: str,
        source: Path | None = None,
        *,
        instrumented: bool = True,
    ) -> Path:
        if shutil.which("ar") is None:
            self.skipTest("ar is required to inspect coverage archives")
        object_path = self.root / member
        if source is not None:
            compiler = shutil.which("clang++-15") or shutil.which("clang++")
            if compiler is None or any(
                _llvm_tool(tool) is None
                for tool in ("llvm-dwarfdump", "llvm-readelf")
            ):
                self.skipTest("Clang and LLVM tools are required for object identity")
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("int target() { return 1; }\n", encoding="utf-8")
            flags = (
                ["-fprofile-instr-generate", "-fcoverage-mapping"]
                if instrumented else []
            )
            subprocess.run(
                [compiler, "-g", *flags, "-c", str(source), "-o", str(object_path)],
                check=True,
                capture_output=True,
            )
        else:
            object_path.write_bytes(b"test object")
        archive = self.root / "coverage.a"
        subprocess.run(
            ["ar", "q", str(archive), str(object_path)],
            check=True,
            capture_output=True,
        )
        return archive

    def test_versioned_llvm_tools_are_resolved_first(self):
        with patch(
            "src.driver_qualification.reachability.source_diagnostics.shutil.which",
            side_effect=lambda name: "/usr/bin/llvm-readelf-15"
            if name == "llvm-readelf-15" else None,
        ):
            self.assertEqual(_llvm_tool("llvm-readelf"), "/usr/bin/llvm-readelf-15")

    def test_present_source_object_identifies_unlinked_candidate(self):
        source = self.root / "project" / "src" / "basicio.cpp"
        self._missing_source("src/basicio.cpp", source)
        archive = self._archive("basicio.cpp.o", source)

        outcome, error = classify_source_resolution_failure(
            self.diagnostic, archive, "src/basicio.cpp:1283"
        )

        self.assertEqual(outcome, "target_source_unlinked")
        self.assertIn("feature guards", error)

    def test_missing_source_object_identifies_coverage_build_problem(self):
        self._missing_source("lib/uint-hash.c")
        archive = self._archive("http2.c.o")

        outcome, error = classify_source_resolution_failure(
            self.diagnostic, archive, "lib/uint-hash.c:130"
        )

        self.assertEqual(outcome, "coverage_source_unavailable")
        self.assertIn("rebuild", error)
        self.assertIn("uint-hash.c.o", error)

    def test_missing_header_does_not_claim_archive_needs_header_object(self):
        self._missing_source("include/public.h")

        outcome, error = classify_source_resolution_failure(
            self.diagnostic, self.root / "coverage.a", "include/public.h:42"
        )

        self.assertEqual(outcome, "coverage_source_unavailable")
        self.assertIn("Header coverage", error)
        self.assertNotIn("public.h.o", error)

    def test_same_basename_from_wrong_source_does_not_reject_candidate(self):
        expected = self.root / "project" / "src" / "basicio.cpp"
        other = self.root / "other" / "basicio.cpp"
        self._missing_source("src/basicio.cpp", expected)
        archive = self._archive("basicio.cpp.o", other)

        outcome, error = classify_source_resolution_failure(
            self.diagnostic, archive, "src/basicio.cpp:1283"
        )

        self.assertEqual(outcome, "coverage_source_unavailable")
        self.assertIn("DWARF", error)

    def test_matching_source_without_coverage_sections_stays_build_problem(self):
        source = self.root / "project" / "src" / "basicio.cpp"
        self._missing_source("src/basicio.cpp", source)
        archive = self._archive("basicio.cpp.o", source, instrumented=False)

        outcome, error = classify_source_resolution_failure(
            self.diagnostic, archive, "src/basicio.cpp:1283"
        )

        self.assertEqual(outcome, "coverage_source_unavailable")
        self.assertIn("coverage sections", error)

    def test_duplicate_basename_members_do_not_reject_candidate(self):
        expected = self.root / "project" / "src" / "basicio.cpp"
        self._missing_source("src/basicio.cpp", expected)
        archive = self._archive("basicio.cpp.o", expected)
        second = self.root / "other" / "basicio.cpp.o"
        second.parent.mkdir()
        second.write_bytes(b"another object")
        subprocess.run(
            ["ar", "q", str(archive), str(second)],
            check=True,
            capture_output=True,
        )

        outcome, error = classify_source_resolution_failure(
            self.diagnostic, archive, "src/basicio.cpp:1283"
        )

        self.assertEqual(outcome, "coverage_source_unavailable")
        self.assertIn("ambiguous", error)

    def test_replay_failures_keep_the_normal_retry_path(self):
        self.diagnostic.write_text(
            json.dumps({"phase": "replay", "error": "profile not produced"}),
            encoding="utf-8",
        )

        self.assertIsNone(classify_source_resolution_failure(
            self.diagnostic, self.root / "coverage.a", "src/basicio.cpp:1283"
        ))

    @staticmethod
    def _ready_state() -> dict:
        state = initial_target_state({
            "target_id": "src/basicio.cpp:1283",
            "marker": "TARGET_0002",
            "candidates": [{"driver_id": "getb__TARGET_0002"}],
        })
        state.update({
            "state": READY_REACH,
            "source_path": "/tmp/getb.cc",
            "binary_path": "/tmp/getb.out",
        })
        return state

    def test_unlinked_candidate_goes_to_refinement_with_diagnostic(self):
        workflow = DriverRoundWorkflow.__new__(DriverRoundWorkflow)
        state = self._ready_state()
        updated, event = workflow._apply_action(
            state,
            {},
            {
                "phase": "target_reachability",
                "record": {
                    "status": "DONE",
                    "reachability_outcome": "target_source_unlinked",
                    "qualification_error": "candidate omitted target source",
                    "reach_report": "check feature guards",
                },
            },
        )

        self.assertEqual(event, "target_not_reached")
        self.assertEqual(updated["state"], READY_REFINE)
        self.assertEqual(updated["reach_feedback"]["reach_report"], "check feature guards")
        self.assertEqual(updated["infrastructure_retries"], {})

    def test_unavailable_coverage_source_pauses_after_one_attempt(self):
        workflow = DriverRoundWorkflow.__new__(DriverRoundWorkflow)
        workflow.library = "curl"
        workflow.store = object()
        workflow.concurrency = 1
        workflow.fuzz_concurrency = 1
        workflow.max_infrastructure_retries = 5
        state = self._ready_state()
        target = {"marker": "TARGET_0002"}
        action = {
            "phase": "target_reachability",
            "record": {
                "status": "ERROR",
                "reachability_outcome": "coverage_source_unavailable",
                "qualification_error": "coverage archive lacks uint-hash.c.o",
            },
        }

        with (
            patch("src.driver_rounds.workflow.load_candidate_plan", return_value={
                "targets": [target]
            }),
            patch.object(workflow, "_write_state_manifest"),
            patch.object(workflow, "_restore_states", return_value={
                "TARGET_0002": state
            }),
            patch.object(workflow, "_execute_action", return_value=action) as execute,
            patch.object(workflow, "_persist_state") as persist,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "coverage archive lacks uint-hash.c.o"
            ):
                workflow.run()

        self.assertEqual(execute.call_count, 1)
        self.assertEqual(persist.call_args.args[1], "infrastructure_retry")
