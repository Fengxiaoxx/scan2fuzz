"""Contract tests for separating initial generation from later diagnosis."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from src.driver_generation.context_builder import DriverContextBuilder
from src.driver_generation.driver_generation_agent import DriverGenerationAgent
from src.driver_generation.prompt import DRIVER_GENERATION_PROMPT_TEMPLATE


def _builder() -> DriverContextBuilder:
    builder = DriverContextBuilder.__new__(DriverContextBuilder)
    builder.target_api = "cmsEntry"
    builder.api_doc = {
        "signature": "void cmsEntry(const void *data, size_t size)",
        "summary": "Parse a memory object.",
        "source": "void cmsEntry(const void *data, size_t size) { /* ... */ }",
        "file_path": "src/entry.c",
    }
    builder.targets = [
        {
            "marker": "TARGET_0001",
            "severity": "HIGH",
            "file": "src/target.c",
            "line": 42,
            "description": "fixed trigger bytes must be present",
            "chain": [
                {"fn": "cmsEntry", "file": "src/entry.c", "line": 10},
                {"fn": "cmsInternal", "file": "src/target.c", "line": 30},
            ],
        }
    ]
    return builder


class DriverGenerationContractTests(unittest.TestCase):
    def test_failed_model_turn_is_infrastructure_failure_not_candidate_failure(self):
        agent = DriverGenerationAgent.__new__(DriverGenerationAgent)
        agent.library_name = "abseil-cpp"
        agent.api_id = "test-api"
        agent.model_name = "test-model"
        agent.quiet = True
        agent._mcp_bundle = SimpleNamespace(opencode_config=lambda: {})
        agent._query_client = SimpleNamespace(
            run=lambda **kwargs: SimpleNamespace(
                is_error=True,
                stop_reason="failed",
                message_usage=[
                    {
                        "error": {
                            "data": {
                                "statusCode": 401,
                                "message": "Invalid credential",
                            }
                        }
                    }
                ],
                result_text="",
            )
        )
        agent._build_prompt_bundle = lambda: SimpleNamespace(prompt="test prompt")
        agent._build_tool_names = lambda: []
        agent._write_log = lambda *args: None

        with patch(
            "src.driver_generation.driver_generation_agent.record_agent_call"
        ):
            result = agent.run(retry_feedback="previous feedback")

        self.assertFalse(result["success"])
        self.assertEqual(result["failure_kind"], "infrastructure_failed")
        self.assertIn("HTTP 401", result["error"])
        self.assertEqual(result["retry_feedback"], "previous feedback")

    def test_downstream_navigation_omits_finding_but_keeps_static_chain(self):
        context = _builder().target_context()

        self.assertIn("TARGET_0001", context)
        self.assertIn("cmsEntry", context)
        self.assertIn("cmsInternal", context)
        self.assertNotIn("fixed trigger bytes", context)

    def test_generation_prompt_includes_target_line_only(self):
        agent = DriverGenerationAgent.__new__(DriverGenerationAgent)
        agent.library_name = "lcms"
        agent.language = "C"
        agent.target_function = "cmsEntry"
        agent.context_builder = _builder()
        with patch.dict("os.environ", {"T2F_PROMPT_DESCRIPTION": "1"}), patch.object(
            DriverContextBuilder, "get_headers", return_value="#include <lcms2.h>"
        ):
            prompts = agent._build_prompt_bundle()
        rendered = prompts.prompt

        self.assertIn("cmsEntry", rendered)
        self.assertIn("void cmsEntry(const void *data, size_t size)", rendered)
        self.assertNotIn("Parse a memory object", rendered)
        self.assertIn("TARGET_0001", rendered)
        self.assertIn("src/target.c:42", rendered)
        self.assertNotIn("cmsInternal", rendered)
        self.assertNotIn("fixed trigger bytes", rendered)
        self.assertNotIn("报告中的发现", rendered)
        self.assertNotIn("{target_context}", rendered)

    def test_generation_prompt_does_not_depend_on_finding_render_policy(self):
        agent = DriverGenerationAgent.__new__(DriverGenerationAgent)
        agent.library_name = "lcms"
        agent.language = "C"
        agent.target_function = "cmsEntry"
        agent.context_builder = _builder()
        with patch.dict("os.environ", {"T2F_PROMPT_DESCRIPTION": "0"}), patch.object(
            DriverContextBuilder, "get_headers", return_value="#include <lcms2.h>"
        ):
            prompts = agent._build_prompt_bundle()

        self.assertNotIn("fixed trigger bytes", prompts.prompt)
        self.assertIn("src/target.c:42", prompts.prompt)

    def test_later_repair_context_restores_finding_and_static_chain(self):
        with patch.dict("os.environ", {"T2F_PROMPT_DESCRIPTION": "1"}):
            context = _builder().format_target_info()

        self.assertIn("Reported finding", context)
        self.assertIn("fixed trigger bytes", context)
        self.assertIn("candidate static call chain", context)
        self.assertIn("cmsInternal", context)
        self.assertIn("TARGET_0001", context)
        self.assertIn("src/target.c:42", context)
        self.assertNotIn("Parse a memory object", context)

    def test_initial_prompt_keeps_cause_analysis_as_a_fuzzing_hypothesis(self):
        prompt = DRIVER_GENERATION_PROMPT_TEMPLATE.format(
            library_name="lcms",
            target_function="cmsEntry",
            language="C",
            headers="#include <lcms2.h>",
            target_api="cmsEntry",
            signature="void cmsEntry(void)",
            defined_in="src/entry.c:10",
            api_source="void cmsEntry(void) {}",
            target_lines="- Target TARGET_0001 (HIGH) at src/target.c:42",
            entry_signature=(
                'extern "C" int LLVMFuzzerTestOneInput('
                "const uint8_t *Data, size_t Size)"
            ),
            vulnerability_type="heap-buffer-overflow",
        )

        self.assertIn("complete, compilable libFuzzer driver", prompt)
        self.assertIn("determine whether that line contains a vulnerability whose type is heap-buffer-overflow", prompt)
        self.assertNotIn("may contain a vulnerability", prompt)
        self.assertIn("All such judgments are hypotheses to be verified", prompt)
        self.assertIn("identify dimensions for the fuzz input to explore", prompt)
        self.assertIn("Never fix any hypothesis as a specific triggering value", prompt)
        self.assertIn("Even if the causal hypothesis is wrong", prompt)
        self.assertIn("src/target.c:42", prompt)


if __name__ == "__main__":
    unittest.main()
