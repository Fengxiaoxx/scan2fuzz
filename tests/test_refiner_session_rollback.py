"""Regression checks for a failed Refiner edit and session rollback."""

from __future__ import annotations

import unittest
import tempfile
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from unittest.mock import patch

from src.driver_refinement.agent import RefinerResult
from src.driver_refinement.workflow import refine_candidate_once
from src.driver_rounds.state import (
    READY_COMPILE,
    READY_REFINE,
    apply_compile_action,
    apply_refine_action,
    initial_target_state,
)
from src.experiment import RunArtifactStore
from src.llm.opencode_query import (
    OpenCodeQueryClient,
    OpenCodeQueryResult,
    _OpenCodeRuntime,
    normalize_opencode_response,
)


class RefinerSessionRollbackTests(unittest.TestCase):
    def test_unreachable_decision_is_persisted_without_becoming_no_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RunArtifactStore.create(root, "lcms", "fixed-build-guard")
            source = root / "stable.cc"
            source.write_text("int LLVMFuzzerTestOneInput() { return 0; }\n")

            class FakeAgent:
                def __init__(self, *args, **kwargs):
                    pass

                def run(self, **kwargs):
                    return RefinerResult(
                        edited=False,
                        source_path=str(source),
                        error="",
                        tool_calls=0,
                        model="mock-model",
                        decision="unreachable",
                        evidence="sizeof(wchar_t) > 2 is fixed true; true side hit 9206, else hit 0",
                    )

                def close(self):
                    pass

            with patch(
                "src.driver_refinement.workflow.ReachabilityRefinerAgent", FakeAgent
            ), patch(
                "src.driver_refinement.workflow._refinement_hint",
                return_value="src/example.c:42",
            ), patch(
                "src.driver_refinement.workflow.driver_agent_usage_summary",
                return_value={},
            ):
                result = refine_candidate_once(
                    store,
                    "lcms",
                    "c++",
                    {
                        "driver_id": "driver-001",
                        "candidate_index": 0,
                        "qualified_name": "cmsExample",
                    },
                    source_path=str(source),
                    reach_feedback={"reach_report": "coverage report"},
                    refine_attempts=0,
                    refine_history=[],
                )
            self.assertEqual(result["status"], "unreachable")
            self.assertFalse(result["edited"])
            self.assertIn("sizeof(wchar_t)", result["agent_evidence"])

    def test_invalid_decision_does_not_consume_refinement_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RunArtifactStore.create(root, "lcms", "invalid-reply")
            source = root / "stable.cc"
            source.write_text("int LLVMFuzzerTestOneInput() { return 0; }\n")

            class FakeAgent:
                def __init__(self, *args, **kwargs):
                    pass

                def run(self, **kwargs):
                    return RefinerResult(
                        edited=False,
                        source_path=str(source),
                        error="Refiner response is not a single final JSON object",
                        tool_calls=0,
                        model="mock-model",
                    )

                def close(self):
                    pass

            with patch(
                "src.driver_refinement.workflow.ReachabilityRefinerAgent", FakeAgent
            ), patch(
                "src.driver_refinement.workflow._refinement_hint",
                return_value="src/example.c:42",
            ), patch(
                "src.driver_refinement.workflow.driver_agent_usage_summary",
                return_value={},
            ):
                result = refine_candidate_once(
                    store,
                    "lcms",
                    "c++",
                    {
                        "driver_id": "driver-001",
                        "candidate_index": 0,
                        "qualified_name": "cmsExample",
                    },
                    source_path=str(source),
                    reach_feedback={"reach_report": "coverage report"},
                    refine_attempts=0,
                    refine_history=[],
                )

            self.assertEqual(result["status"], "infrastructure_failed")
            self.assertIn("invalid Refiner result", result["error"])
            state = initial_target_state(
                {
                    "target_id": "src/example.c:42",
                    "marker": "TARGET_0001",
                    "candidates": [{"driver_id": "driver-001"}],
                }
            )
            state["state"] = READY_REFINE
            state["source_path"] = str(source)
            state["binary_path"] = str(source)
            updated, event = apply_refine_action(state, result)
            self.assertEqual(event, "infrastructure_retry")
            self.assertEqual(updated["refine_attempts"], 0)

    def test_current_turn_user_message_id_is_recovered_from_response(self):
        result = normalize_opencode_response(
            {
                "info": {"id": "a2", "role": "assistant", "finish": "stop"},
                "parts": [{"type": "text", "text": "done"}],
                "history": [
                    {"info": {"id": "u2", "role": "user"}, "parts": []},
                    {
                        "info": {"id": "a2", "role": "assistant", "finish": "stop"},
                        "parts": [{"type": "text", "text": "done"}],
                    },
                ],
            },
            model="test-model",
            duration_ms=1,
        )
        self.assertEqual(result.user_message_id, "u2")

    def test_client_persists_fork_boundary_and_skips_duplicate_on_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session_dir = root / "session"
            session_dir.mkdir()
            identity = {
                "cwd": str(root.resolve()),
                "model": "test-model",
                "temperature": None,
                "provider": "test-provider",
            }
            session_file = session_dir / "session.json"
            session_file.write_text(
                json.dumps({"identity": identity, "session_id": "old-session"})
            )
            events = []

            class FakeRuntime:
                def __init__(self, **kwargs):
                    self.session_id = ""

                def start(self):
                    pass

                def fork_before_message(self, message_id):
                    events.append(("fork", self.session_id, message_id))
                    self.session_id = "new-session"

                def add_mcp_servers(self, *args):
                    pass

                def prompt(self, **kwargs):
                    events.append(("prompt", self.session_id))
                    return {}

                def close(self):
                    pass

            client = OpenCodeQueryClient(
                str(root),
                provider_config=SimpleNamespace(
                    provider_id="test-provider",
                    api_key_env="T2F_SESSION_TEST_KEY",
                    base_url="http://127.0.0.1",
                ),
                session_dir=str(session_dir),
            )
            with patch.dict(
                os.environ,
                {"T2F_SESSION_TEST_KEY": "", "OPENCODE_TEMPERATURE": ""},
            ), patch(
                "src.llm.opencode_query._OpenCodeRuntime", FakeRuntime
            ), patch(
                "src.llm.opencode_query.normalize_opencode_response",
                return_value=OpenCodeQueryResult("", "", "completed"),
            ):
                for _ in range(2):
                    client.run(
                        prompt="new coverage evidence",
                        system_prompt="",
                        model="test-model",
                        mcp_config={},
                        configured_tools=(),
                        fork_before_message_id="u2",
                    )

            self.assertEqual(
                events,
                [
                    ("fork", "old-session", "u2"),
                    ("prompt", "new-session"),
                    ("prompt", "new-session"),
                ],
            )
            saved = json.loads(session_file.read_text())
            self.assertEqual(saved["session_id"], "new-session")
            self.assertEqual(saved["fork_boundary_message_id"], "u2")

    def test_workflow_forks_exact_failed_turn_or_starts_fresh(self):
        cases = (
            (
                "normal_followup",
                2,
                [
                    {"attempt": 1, "status": "no_edit", "user_message_id": "u1"},
                    {"attempt": 2, "status": "no_edit", "user_message_id": "u2"},
                ],
                False,
                None,
            ),
            (
                "first_failed_turn",
                1,
                [
                    {"attempt": 1, "status": "edited", "user_message_id": "u1"},
                    {"attempt": 1, "status": "validation_failed", "error": "compile failed"},
                ],
                True,
                None,
            ),
            (
                "later_failed_turn",
                2,
                [
                    {"attempt": 1, "status": "no_edit", "user_message_id": "u1"},
                    {"attempt": 2, "status": "edited", "user_message_id": "u2"},
                    {"attempt": 2, "status": "validation_failed", "error": "compile failed"},
                ],
                False,
                "u2",
            ),
            (
                "missing_boundary",
                2,
                [
                    {"attempt": 1, "status": "no_edit", "user_message_id": "u1"},
                    {"attempt": 2, "status": "edited"},
                    {"attempt": 2, "status": "validation_failed", "error": "compile failed"},
                ],
                True,
                None,
            ),
        )
        for label, attempts, history, expected_new, expected_boundary in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                store = RunArtifactStore.create(root, "lcms", f"test-{label}")
                source = root / "stable.cc"
                source.write_text("int LLVMFuzzerTestOneInput() { return 0; }\n")
                previous = (
                    store.stage_dir("driver_refinement", "driver-001")
                    / "attempts"
                    / "attempt-001"
                )
                previous.mkdir(parents=True)
                (previous / "before.cpp").write_bytes(source.read_bytes())
                seen = {}

                class FakeAgent:
                    def __init__(self, *args, **kwargs):
                        seen["constructor"] = kwargs

                    def run(self, **kwargs):
                        seen["run"] = kwargs
                        return RefinerResult(
                            edited=False,
                            source_path=str(source),
                            error="",
                            tool_calls=0,
                            model="mock-model",
                            user_message_id="u3",
                            decision="no_edit",
                            evidence="当前输入映射未排除合法路径",
                        )

                    def close(self):
                        pass

                with patch(
                    "src.driver_refinement.workflow.ReachabilityRefinerAgent",
                    FakeAgent,
                ), patch(
                    "src.driver_refinement.workflow._refinement_hint",
                    return_value="src/example.c:42",
                ), patch(
                    "src.driver_refinement.workflow.driver_agent_usage_summary",
                    return_value={},
                ):
                    result = refine_candidate_once(
                        store,
                        "lcms",
                        "c++",
                        {
                            "driver_id": "driver-001",
                            "candidate_index": 0,
                            "qualified_name": "cmsExample",
                        },
                        source_path=str(source),
                        reach_feedback={"reach_report": "coverage report"},
                        refine_attempts=attempts,
                        refine_history=history,
                    )

                self.assertEqual(result["status"], "no_edit")
                self.assertEqual(result["error"], "")
                self.assertEqual(result["agent_decision"], "no_edit")
                self.assertEqual(result["agent_evidence"], "当前输入映射未排除合法路径")
                self.assertEqual(result["user_message_id"], "u3")
                self.assertEqual(seen["constructor"]["new_session"], expected_new)
                self.assertEqual(
                    seen["run"]["fork_before_message_id"], expected_boundary
                )
                self.assertEqual(seen["run"]["coverage_evidence"], "coverage report")
                self.assertEqual(seen["run"]["entry_api"], "cmsExample")
                self.assertEqual(
                    seen["run"]["driver_source"], source.read_text()
                )
                self.assertEqual(
                    seen["run"]["validation_error"],
                    "compile failed" if expected_new or expected_boundary else "",
                )

    def test_fork_discards_only_the_last_refiner_turn(self):
        runtime = _OpenCodeRuntime.__new__(_OpenCodeRuntime)
        runtime.cwd = "/tmp/library"
        runtime.session_id = "old-session"

        def request(method, path, **kwargs):
            self.assertEqual(method, "POST")
            self.assertEqual(path, "/session/old-session/fork")
            self.assertEqual(kwargs["body"], {"messageID": "u2"})
            return {"id": "new-session"}

        runtime.request = Mock(side_effect=request)
        runtime.fork_before_message("u2")

        self.assertEqual(runtime.session_id, "new-session")
        self.assertEqual(runtime.request.call_count, 1)

    def test_failed_fork_keeps_the_saved_session_pointer(self):
        runtime = _OpenCodeRuntime.__new__(_OpenCodeRuntime)
        runtime.cwd = "/tmp/library"
        runtime.session_id = "old-session"

        def request(method, path, **kwargs):
            raise RuntimeError("fork failed")

        runtime.request = Mock(side_effect=request)
        with self.assertRaisesRegex(RuntimeError, "fork failed"):
            runtime.fork_before_message("u2")
        self.assertEqual(runtime.session_id, "old-session")

    def test_failed_edit_is_recorded_as_latest_refiner_turn(self):
        state = initial_target_state(
            {
                "target_id": "target-001",
                "marker": "TARGET_0001",
                "candidates": [{"driver_id": "driver-001"}],
            }
        )
        state.update(
            state=READY_REFINE,
            source_path="/tmp/stable.cc",
            binary_path="/tmp/stable-bin",
            stable_source_path="/tmp/stable.cc",
            stable_binary_path="/tmp/stable-bin",
        )
        edited, event = apply_refine_action(
            state,
            {
                "driver_id": "driver-001",
                "refine_attempt": 1,
                "status": "edited",
                "edited": True,
                "source_path": "/tmp/edited.cc",
                "user_message_id": "u1",
            },
        )
        self.assertEqual(event, "refined")
        self.assertEqual(edited["state"], READY_COMPILE)

        rolled_back, event = apply_compile_action(
            edited,
            {
                "driver_id": "driver-001",
                "action": "compile_repair",
                "outcome": "compile_failed",
                "success": False,
                "failure_origin": "compile",
                "repair_attempts": {"compile": 0, "runtime": 0},
                "source_path": "/tmp/edited.cc",
                "error": "compile failed",
            },
        )
        self.assertEqual(event, "refinement_validation_failed")
        self.assertEqual(rolled_back["state"], READY_REFINE)
        self.assertEqual(rolled_back["source_path"], "/tmp/stable.cc")
        self.assertEqual(
            [(item["attempt"], item["status"]) for item in rolled_back["refine_history"]],
            [(1, "edited"), (1, "validation_failed")],
        )
        self.assertEqual(rolled_back["refine_history"][0]["user_message_id"], "u1")


if __name__ == "__main__":
    unittest.main()
