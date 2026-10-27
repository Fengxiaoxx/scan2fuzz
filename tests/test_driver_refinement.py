"""Reachability-only Driver Refiner regressions."""

from __future__ import annotations

import importlib.util
import inspect
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from unittest.mock import patch

from src.driver_refinement.agent import (
    ReachabilityRefinerAgent,
    _model_turn_failure,
    _parse_refiner_response,
    _render_user_prompt,
)
from src.driver_refinement.kinds import REACHABILITY_GAP
from src.driver_refinement.prompt import REFINER_PROMPT_TEMPLATE
from src.driver_refinement.workflow import (
    _coverage_evidence_text,
    _refinement_hint,
)
from src.driver_rounds.state import (
    CRASH,
    READY_REACH,
    READY_REFINE,
    REACHED,
    TARGET_STATES,
    apply_compile_action,
    apply_refine_action,
    initial_target_state,
    validate_target_state,
)
from src.driver_rounds.workflow import DriverRoundWorkflow


def _ready_reach_state() -> dict:
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
    validate_target_state(state)
    return state


class ReachabilityOnlyRefinerTests(unittest.TestCase):
    def test_target_miss_is_the_only_refiner_transition(self):
        workflow = DriverRoundWorkflow.__new__(DriverRoundWorkflow)
        updated, event = workflow._apply_action(
            _ready_reach_state(),
            {},
            {
                "phase": "target_reachability",
                "record": {
                    "status": "DONE",
                    "reachability_outcome": "gave_up",
                    "reachability_rounds": 2,
                    "target_reached": False,
                },
            },
        )

        self.assertEqual(event, "target_not_reached")
        self.assertEqual(updated["state"], READY_REFINE)
        self.assertEqual(updated["reach_feedback"]["target_reached"], False)

    def test_target_hit_finishes_without_an_intermediate_gate(self):
        workflow = DriverRoundWorkflow.__new__(DriverRoundWorkflow)
        updated, event = workflow._apply_action(
            _ready_reach_state(),
            {},
            {
                "phase": "target_reachability",
                "record": {
                    "status": "DONE",
                    "reachability_outcome": "reached",
                    "reachability_rounds": 1,
                    "target_reached": True,
                },
            },
        )

        self.assertEqual(event, "target_reached")
        self.assertEqual(updated["state"], REACHED)
        self.assertEqual(updated["selected_driver_id"], "driver-001")
        self.assertNotIn("READY_COUPLING", TARGET_STATES)

    def test_no_edit_resumes_fuzzing_with_existing_driver(self):
        state = _ready_reach_state()
        state["state"] = READY_REFINE
        state["stable_source_path"] = state["source_path"]
        state["stable_binary_path"] = state["binary_path"]
        validate_target_state(state)

        for max_refinements in (1, 3):
            with self.subTest(max_refinements=max_refinements):
                updated, event = apply_refine_action(
                    state,
                    {
                        "driver_id": "driver-001",
                        "refine_attempt": 1,
                        "status": "no_edit",
                        "edited": False,
                        "agent_decision": "no_edit",
                        "agent_evidence": "源码未显示固定参数阻断路径",
                        "agent_changes": "",
                    },
                    max_refinements=max_refinements,
                )

                self.assertEqual(event, "continue_fuzz")
                self.assertEqual(updated["state"], READY_REACH)
                self.assertEqual(updated["source_path"], state["source_path"])
                self.assertEqual(updated["binary_path"], state["binary_path"])
                self.assertEqual(
                    updated["refine_history"][-1]["agent_evidence"],
                    "源码未显示固定参数阻断路径",
                )

    def test_proven_build_guard_stops_repeating_refinement(self):
        state = _ready_reach_state()
        state["state"] = READY_REFINE
        state["stable_source_path"] = state["source_path"]
        state["stable_binary_path"] = state["binary_path"]
        validate_target_state(state)
        evidence = (
            "sizeof(wchar_t) > 2 is true in this build; coverage records "
            "9206 entries on its true side and zero on the target else side."
        )
        updated, event = apply_refine_action(
            state,
            {
                "driver_id": "driver-001",
                "refine_attempt": 1,
                "status": "unreachable",
                "edited": False,
                "agent_decision": "unreachable",
                "agent_evidence": evidence,
                "agent_changes": "",
            },
        )
        self.assertEqual(event, "candidates_exhausted")
        self.assertEqual(updated["candidate_results"][-1]["reason"], "refiner_unreachable")
        self.assertEqual(updated["candidate_results"][-1]["evidence"], evidence)

        with self.assertRaisesRegex(ValueError, "requires evidence"):
            apply_refine_action(
                state,
                {
                    "driver_id": "driver-001",
                    "refine_attempt": 1,
                    "status": "unreachable",
                    "edited": False,
                },
            )

    def test_proven_library_invariant_advances_to_next_candidate(self):
        state = initial_target_state(
            {
                "target_id": "target-001",
                "marker": "TARGET_0037",
                "candidates": [
                    {"driver_id": "curl_multi_perform__TARGET_0037"},
                    {"driver_id": "curl_multi_socket__TARGET_0037"},
                ],
            }
        )
        state.update(
            state=READY_REFINE,
            source_path="/tmp/first.cc",
            binary_path="/tmp/first",
            stable_source_path="/tmp/first.cc",
            stable_binary_path="/tmp/first",
        )
        updated, event = apply_refine_action(
            state,
            {
                "driver_id": "curl_multi_perform__TARGET_0037",
                "refine_attempt": 1,
                "status": "unreachable",
                "edited": False,
                "agent_decision": "unreachable",
                "agent_evidence": (
                    "The enabled OpenSSL caller returns if i2d_SSL_SESSION yields 0 "
                    "and otherwise passes non-null session data; the zero-data "
                    "branch in Curl_ssl_session_create2 cannot run through this API."
                ),
                "agent_changes": "",
            },
            next_driver_id="curl_multi_socket__TARGET_0037",
        )
        self.assertEqual(event, "candidate_activated")
        self.assertEqual(updated["state"], "READY_GENERATE")
        self.assertEqual(updated["active_driver_id"], "curl_multi_socket__TARGET_0037")
        self.assertEqual(updated["candidate_results"][0]["reason"], "refiner_unreachable")

    def test_confirmed_library_bug_finishes_as_crash(self):
        state = _ready_reach_state()
        state.update(
            {
                "state": "READY_TRIAGE",
                "repair_request": {
                    "kind": "runtime",
                    "error": "ASan failure",
                    "reach_details": {"attribution": "target"},
                },
            }
        )
        validate_target_state(state)

        updated, event = apply_compile_action(
            state,
            {
                "driver_id": "driver-001",
                "action": "compile_repair",
                "outcome": "library_bug",
                "success": False,
                "failure_origin": "runtime",
                "repair_attempts": {"compile": 0, "runtime": 1},
                "repair_history": [],
                "source_path": "/tmp/driver-001.cc",
                "evidence": "library frame owns the fault",
            },
        )

        self.assertEqual(event, "library_crash_confirmed")
        self.assertEqual(updated["state"], CRASH)

    def test_only_reachability_kind_exists(self):
        self.assertEqual(REACHABILITY_GAP, "reachability_gap")

    def test_refiner_entrypoints_reject_other_objectives(self):
        parameters = inspect.signature(ReachabilityRefinerAgent.run).parameters
        self.assertNotIn("enhancement_kind", parameters)
        self.assertNotIn("enhancement_reason", parameters)
        self.assertNotIn("vulnerability_type", parameters)
        self.assertNotIn(
            "vulnerability_type", inspect.signature(_render_user_prompt).parameters
        )
        self.assertNotIn(
            "refine_history", inspect.signature(_render_user_prompt).parameters
        )

    def test_prompt_preserves_input_control_of_path_selection(self):
        prompt = REFINER_PROMPT_TEMPLATE
        self.assertIn("during this fuzzing run", prompt)
        self.assertIn("Runtime coverage evidence:", prompt)
        self.assertIn("controlled by Data/Size and explorable through input mutation", prompt)
        self.assertIn("change its call path", prompt)
        self.assertIn("compile and link in the current build configuration", prompt)
        self.assertIn("unreachable at runtime in this build", prompt)
        self.assertIn("Failure to execute the line in this run alone does not prove unreachability", prompt)
        self.assertGreater(prompt.index("Use only Edit to modify"), prompt.index("Current driver:"))
        self.assertNotIn("vulnerability", prompt)
        self.assertNotIn("{vulnerability_type}", prompt)
        self.assertIn('one JSON object: {"changes":"..."}', prompt)
        self.assertNotIn('"status"', prompt)
        self.assertNotIn("public entry API", prompt)
        self.assertNotIn("minimal change", prompt)
        self.assertNotIn("replaying", prompt)
        self.assertNotIn("enhancement", prompt)
        self.assertNotIn("refine_history_section", prompt)
        self.assertNotIn("##", prompt)

    def test_structured_reply_is_parsed_and_checked_against_disk_edit(self):
        source = "int LLVMFuzzerTestOneInput() { return 0; }\n"
        cases = (
            (False, "sizeof(wchar_t) is fixed at 4 in this build", "unreachable"),
            (True, "Added an input-controlled call path", "edited"),
        )
        for make_edit, explanation, expected_decision in cases:
            with self.subTest(make_edit=make_edit):
                with tempfile.TemporaryDirectory() as tmp:
                    candidate = Path(tmp) / "driver.cc"
                    candidate.write_text(source)
                    agent = ReachabilityRefinerAgent.__new__(ReachabilityRefinerAgent)
                    agent.candidate_path = candidate
                    agent.library = "lcms"
                    agent.language = "c++"
                    agent.model = "mock-model"
                    agent._bundle = Mock(tool_names=[], opencode_config=Mock(return_value={}))
                    agent._client = Mock(has_session=False)
                    reply = json.dumps({"changes": explanation})

                    def run_model(**kwargs):
                        if make_edit:
                            candidate.write_text(source + "// updated\n")
                        return SimpleNamespace(
                            tool_calls=[], result_text=reply, transcript=[], user_message_id="u1"
                        )

                    agent._client.run.side_effect = run_model
                    with patch(
                        "src.driver_refinement.agent._render_user_prompt", return_value="prompt"
                    ), patch("src.driver_refinement.agent.record_agent_call"), patch(
                        "src.driver_refinement.agent.normalize_tool_names_for_logs"
                    ), patch("src.driver_refinement.agent.write_driver_generation_log"), patch(
                        "src.driver_refinement.agent.write_agent_transcript"
                    ):
                        result = agent.run(
                            driver_id="driver-001",
                            entry_api="cmsEntry",
                            code_location="src/example.c:42",
                            coverage_evidence="coverage",
                            driver_source=source,
                            log_file=Path(tmp) / "agent.log",
                            call_index=1,
                        )
                    self.assertEqual(result.edited, make_edit)
                    self.assertEqual(result.decision, expected_decision)
                    self.assertEqual(result.evidence, explanation)
                    self.assertEqual(result.changes, explanation if make_edit else "")
                    self.assertEqual(result.error, "")
                    configured = agent._client.run.call_args.kwargs["configured_tools"]
                    self.assertIn("edit", configured)
                    self.assertNotIn("write", configured)

    def test_structured_reply_rejects_prose_and_invalid_fields(self):
        for reply in (
            "保持当前 driver，继续 fuzz",
            '{"status":"edited","changes":"modified"}',
            '{"changes":""}',
            '{"changes":42}',
            '[]',
        ):
            with self.subTest(reply=reply):
                parsed, error = _parse_refiner_response(reply)
                self.assertEqual(parsed, {})
                self.assertTrue(error)

    def test_provider_failure_is_reported_before_json_validation(self):
        execution = SimpleNamespace(
            is_error=True,
            stop_reason="failed",
            message_usage=[
                {"error": {"name": "AI_APICallError", "data": {"message": "Too Many Requests"}}}
            ],
        )
        self.assertEqual(
            _model_turn_failure(execution),
            "Driver Refiner model turn failed: Too Many Requests",
        )

    def test_structured_reply_recovers_one_final_object(self):
        decision = '{"changes":"fixed guard proves runtime unreachability"}'
        for reply in (
            "The branch is already exercised.\n\n" + decision,
            "\u200b" + decision,
            "Explanation mentions SEQUENCE{ values }.\n" + decision,
        ):
            with self.subTest(reply=reply[:30]):
                parsed, error = _parse_refiner_response(reply)
                self.assertEqual(error, "")
                self.assertEqual(parsed["changes"], "fixed guard proves runtime unreachability")

    def test_structured_reply_rejects_multiple_or_nonfinal_objects(self):
        decision = '{"changes":"actual edit"}'
        for reply in (decision + "\n" + decision, decision + "\nFurther explanation"):
            with self.subTest(reply=reply):
                parsed, error = _parse_refiner_response(reply)
                self.assertEqual(parsed, {})
                self.assertTrue(error)

    def test_first_turn_and_followup_use_same_runtime_contract(self):
        values = dict(
            library="lcms",
            candidate_path=Path("/tmp/driver.cc"),
            entry_api="cmsExample",
            code_location="src/example.c:42",
            coverage_evidence="覆盖标注源码：cmsExample\n42       0  process_data();",
            driver_source="int LLVMFuzzerTestOneInput() { return 0; }",
        )
        first = _render_user_prompt(**values)
        followup = _render_user_prompt(**values, continuation=True)

        self.assertEqual(first, followup)
        for rendered in (first, followup):
            self.assertIn("src/example.c:42", rendered)
            self.assertIn("Runtime coverage evidence:", rendered)
            self.assertIn("Use only Edit to modify /tmp/driver.cc", rendered)
            self.assertIn('one JSON object: {"changes":"..."}', rendered)
            self.assertIn("42       0  process_data();", rendered)
            self.assertIn("int LLVMFuzzerTestOneInput() { return 0; }", rendered)
            self.assertNotIn("{driver_diff}", rendered)
            self.assertNotIn("previous ineffective changes", rendered)
            self.assertNotIn("previous edit failed validation", rendered)

    def test_rollback_prompt_adds_only_failed_validation_diagnostic(self):
        values = dict(
            library="lcms",
            candidate_path=Path("/tmp/driver.cc"),
            entry_api="cmsExample",
            code_location="src/example.c:42",
            coverage_evidence="覆盖标注源码：cmsExample",
            driver_source="当前稳定 driver",
        )
        for continuation in (False, True):
            with self.subTest(continuation=continuation):
                prompt = _render_user_prompt(
                    **values,
                    continuation=continuation,
                    validation_error="unknown public API cmsMissing",
                )
                self.assertIn("current driver has been rolled back", prompt)
                self.assertIn("unknown public API cmsMissing", prompt)
                self.assertIn("当前稳定 driver", prompt)
                self.assertNotIn("previous ineffective changes", prompt)

        prompt = _render_user_prompt(
            **values,
            continuation=True,
            validation_error="unrelated log\nfile.cc:12: error: invalid API call\nmore log",
        )
        self.assertIn("file.cc:12: error: invalid API call", prompt)
        self.assertNotIn("unrelated log", prompt)
        self.assertNotIn("more log", prompt)

    def test_refinement_hint_keeps_location_but_omits_finding_hypothesis(self):
        item = {
            "qualified_name": "cmsEntry",
            "signature": "void cmsEntry(void)",
            "vulnerability_type": "memory leak",
            "target": {
                "file": "src/example.c",
                "line": 42,
                "description": "must use fixed trigger value 129",
                "chain": [{"fn": "cmsEntry", "file": "src/example.c", "line": 10}],
            },
        }
        with patch(
            "src.driver_refinement.workflow.resolve_driver_identity",
            return_value=("api-1", "MARKER_1"),
        ), patch(
            "src.driver_refinement.workflow.resolve_work_item", return_value=item
        ):
            location = _refinement_hint("lcms", "/tmp/driver.cc")

        self.assertEqual(location, "src/example.c:42")

    def test_refiner_receives_coverage_evidence_without_repeated_status(self):
        report = "指定代码行 src/example.c:42：本次有界运行未覆盖。\ncmsEntry 的逐行覆盖源码："
        self.assertEqual(
            _coverage_evidence_text(
                {
                    "reach_report": report,
                    "log_file": "/tmp/qualification.log",
                    "corpus_snapshot": "/tmp/corpus",
                    "vulnerability_type": "memory leak",
                }
            ),
            "cmsEntry 的逐行覆盖源码：",
        )
        self.assertEqual(
            _coverage_evidence_text({"reach_report": None}),
            "Reliable line-by-line coverage information is not yet available.",
        )
        self.assertEqual(
            _coverage_evidence_text(
                {"reach_report": report.split("\n")[0]}
            ),
            "Reliable line-by-line coverage information is not yet available.",
        )
        self.assertEqual(
            _coverage_evidence_text(
                {"reach_report": report.split("\n")[0] + "\nCrash observed while replaying the corpus.\nCommand: huge log"}
            ),
            "Coverage replay crashed; reliable line-by-line coverage information is not yet available.",
        )
        self.assertEqual(
            _coverage_evidence_text(
                {
                    "reach_report": report,
                    "reachability_rounds": 4,
                    "depth": 2,
                    "chain_len": 2,
                    "new_branch_outcomes": 0,
                    "progress_reason": "no_progress",
                }
            ),
            "Probe progress (this bounded run): bounded rounds: 4; observed call-chain depth: 2; call-chain length: 2; new branch outcomes: 0; progress reason: no_progress\n"
            "cmsEntry 的逐行覆盖源码：",
        )

    def test_input_coupling_module_is_removed(self):
        self.assertIsNone(importlib.util.find_spec("src.input_coupling"))


if __name__ == "__main__":
    unittest.main()
