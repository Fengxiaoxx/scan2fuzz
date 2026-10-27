"""OpenCode-driven libFuzzer driver generation."""

from __future__ import annotations

import os
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional

from dotenv import load_dotenv
from loguru import logger

from src.core import extract_code_from_markdown, normalize_language
from src.llm.agent_utils.log_manager import (
    append_error_log,
    write_agent_transcript,
    write_driver_generation_log,
)
from src.llm.opencode_query import OPENCODE_BUILTIN_FILE_TOOLS, OpenCodeQueryClient
from src.llm.provider_config import resolve_model_name
from src.llm.usage import record_agent_call
from src.tools.trace2fuzz_mcp import create_trace2fuzz_mcp_bundle
from src.driver_generation.context_builder import DriverContextBuilder
from src.driver_generation.prompt import DRIVER_GENERATION_PROMPT_TEMPLATE

load_dotenv()


DEFAULT_DRIVER_MODEL = "gpt-5.6-luna"
# Use OpenCode's native read/grep/glob tools for source and API catalog access.
# find_api is the only MCP tool, for optional API discovery.
DRIVER_BUILTIN_ALLOWED_TOOLS: list[str] = list(OPENCODE_BUILTIN_FILE_TOOLS)

# Driver is always compiled as C++ (.cc), so the entrypoint always needs
# `extern "C"` linkage regardless of the library's source language.
_ENTRY_SIGNATURE = (
    'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)'
)
_ENTRYPOINT_RE = re.compile(
    r'(?:extern\s+"C"\s+)?int\s+LLVMFuzzerTestOneInput\s*\('
)


@dataclass(frozen=True)
class DriverGenerationPromptBundle:
    """The exact prompt sent to the agent."""
    prompt: str


class DriverGenerationAgent:
    """Generate a libFuzzer driver for one entry API via OpenCode."""

    def __init__(
        self,
        target_api: str,
        api_doc: Dict,
        targets: List[Dict],
        library_name: str,
        language: str = "C",
        *,
        api_id: str,
        quiet: bool = False,
        vulnerability_type: str = "",
    ):
        self.library_name = library_name
        self.language = normalize_language(language)
        self.target_function = target_api or "unknown"
        self.api_id = api_id
        self.quiet = quiet
        self.vulnerability_type = vulnerability_type.strip()

        # cwd anchors source access and the copied public API catalog.
        self.workspace_root = os.path.abspath(
            os.path.join("test_lib", library_name)
        )

        self.context_builder = DriverContextBuilder(library_name, language)
        self.context_builder.load_target(api_id, target_api, api_doc, targets)

        # Keep find_api for discovery; use native file tools for source access.
        self._mcp_bundle = create_trace2fuzz_mcp_bundle(
            library_name,
            include_search_function=False,
            include_fact_base=True,
            include_drivers=False,
            include_lsp=False,
        )

        self.model_name = resolve_model_name(
            "DRIVER_GEN_MODEL", DEFAULT_DRIVER_MODEL
        )
        self._query_client = OpenCodeQueryClient(
            self.workspace_root,
            client_name="trace2fuzz_driver_generation_agent",
            client_title="Trace2Fuzz Driver Generation Agent",
        )

        logger.debug(
            "DriverGenerationAgent initialized: model={}, lib={}",
            self.model_name,
            library_name,
        )

    def close(self) -> None:
        self._query_client.close()

    def run(
        self,
        log_file: Optional[str] = None,
        call_index_offset: int = 0,
        retry_feedback: str = "",
    ) -> Dict:
        """Perform exactly one model-backed Generator action.

        Returns:
            On success: {"success": True, "code": str, "full_response": str}
            On failure: {"success": False, "error": str, ...}
        """
        prompts = self._build_prompt_bundle()
        active_prompt = prompts.prompt + retry_feedback
        configured_tools = self._build_tool_names()
        try:
            query_result = self._query_client.run(
                prompt=active_prompt,
                system_prompt="",
                model=self.model_name,
                mcp_config=self._mcp_bundle.opencode_config(),
                configured_tools=configured_tools,
                transcript_path=str(Path(log_file).parent / "agent.jsonl") if log_file else None,
            )
        except Exception as exc:
            record_agent_call(
                self.library_name,
                agent="driver_generation",
                stage="driver_generation",
                model=self.model_name,
                call_index=call_index_offset + 1,
                configured_tools=configured_tools,
                error=str(exc),
                result=getattr(exc, "agent_result", None),
                call_id=getattr(exc, "agent_call_id", None),
                artifact_path=log_file,
                subject_id=self.api_id,
                subject_kind="target_api",
            )
            if log_file:
                write_driver_generation_log(
                    log_file,
                    self.library_name,
                    self.language,
                    "",
                    active_prompt,
                    [],
                    f"ERROR: {exc}",
                    "",
                    title="DRIVER GENERATION LOG [FAILED]",
                )
                append_error_log(log_file, f"FINAL STATUS: failed\nREASON: {exc}")
            return {
                "success": False,
                "error": str(exc),
                "failure_kind": "infrastructure_failed",
                "retry_feedback": retry_feedback,
            }

        record_agent_call(
            self.library_name,
            agent="driver_generation",
            stage="driver_generation",
            model=self.model_name,
            call_index=call_index_offset + 1,
            configured_tools=configured_tools,
            result=query_result,
            artifact_path=log_file,
            subject_id=self.api_id,
            subject_kind="target_api",
        )
        model_error = self._model_turn_failure(query_result)
        if model_error:
            self._write_log(log_file, active_prompt, query_result, "")
            if log_file:
                append_error_log(
                    log_file, f"FINAL STATUS: infrastructure_failed\nREASON: {model_error}"
                )
            return {
                "success": False,
                "error": model_error,
                "failure_kind": "infrastructure_failed",
                "retry_feedback": retry_feedback,
            }
        code = self._extract_code(query_result.result_text or "")
        self._write_log(log_file, active_prompt, query_result, code)
        if code:
            return {
                "success": True,
                "code": code,
                "full_response": query_result.result_text,
            }

        error = "no LLVMFuzzerTestOneInput emitted (exploration-only)"
        feedback = (
            "\n\nPrevious attempt explored extensively and never emitted code. "
            "STOP reading files. Output ONE complete ```cpp``` block now with "
            "the driver body."
        )
        if not getattr(self, "quiet", False):
            logger.warning("Driver generation action failed: {}", error)
        if log_file:
            append_error_log(log_file, f"FINAL STATUS: failed\nREASON: {error}")
        return {
            "success": False,
            "error": error,
            "failure_kind": "candidate_failed",
            "retry_feedback": feedback,
        }

    @staticmethod
    def _model_turn_failure(query_result) -> str:
        if not getattr(query_result, "is_error", False) and getattr(
            query_result, "stop_reason", "completed"
        ) == "completed":
            return ""
        reason = str(getattr(query_result, "stop_reason", "failed"))
        for entry in reversed(getattr(query_result, "message_usage", []) or []):
            error = entry.get("error") if isinstance(entry, Mapping) else None
            if not isinstance(error, Mapping):
                continue
            data = error.get("data")
            data = data if isinstance(data, Mapping) else {}
            message = str(
                data.get("message")
                or error.get("message")
                or error.get("name")
                or reason
            )
            status = data.get("statusCode")
            if status:
                return f"model turn {reason}: HTTP {status}: {message}"
            return f"model turn {reason}: {message}"
        return f"model turn {reason}"

    def _build_prompt_bundle(self) -> DriverGenerationPromptBundle:
        """Build the prompt once so generation and logging see identical inputs."""
        headers = self.context_builder.get_headers()
        fields = self.context_builder.api_doc_fields()
        target_lines = self.context_builder.target_lines()
        return DriverGenerationPromptBundle(
            prompt=DRIVER_GENERATION_PROMPT_TEMPLATE.format(
                library_name=self.library_name,
                target_function=self.target_function,
                language=self.language,
                headers=headers,
                target_api=fields["target_api"],
                signature=fields["signature"],
                defined_in=fields["defined_in"],
                api_source=fields["api_source"],
                target_lines=target_lines,
                entry_signature=_ENTRY_SIGNATURE,
                vulnerability_type=getattr(self, "vulnerability_type", "") or "unspecified",
            ),
        )

    def _build_tool_names(self) -> List[str]:
        return list(DRIVER_BUILTIN_ALLOWED_TOOLS) + list(self._mcp_bundle.tool_names)

    def _write_log(
        self,
        log_file: Optional[str],
        prompt: str,
        query_result,
        extracted_code: str,
    ) -> None:
        if not log_file:
            return
        write_driver_generation_log(
            log_file,
            self.library_name,
            self.language,
            "",
            prompt,
            query_result.tool_calls,
            query_result.result_text,
            extracted_code,
        )
        write_agent_transcript(
            log_file,
            query_result.transcript,
            title="AGENT TRANSCRIPT (Interleaved)",
        )

    def _extract_code(self, response_content: str) -> str:
        """Extract driver code from an LLM response.

        Fallback regexes intentionally require a full libFuzzer entrypoint so
        partial analysis text never gets treated as generated code.
        """
        fallback_patterns = [
            r'(#include.*?int\s+LLVMFuzzerTestOneInput.*?^\})',
            r'(#include.*?extern\s+"C"\s+int\s+LLVMFuzzerTestOneInput.*?^\})',
        ]
        code = extract_code_from_markdown(response_content, fallback_patterns)
        if _ENTRYPOINT_RE.search(code):
            return code
        if not getattr(self, "quiet", False):
            logger.warning("Could not extract libFuzzer driver source")
        return ""
