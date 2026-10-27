"""
LspDocAgent - LSP-driven function documentation generation agent.

Uses clangd LSP tools to explore a function before generating its
documentation JSON.
"""

import os
from dataclasses import dataclass
from typing import Dict, Optional

from dotenv import load_dotenv
from loguru import logger

from src.core import get_project_root, load_library_config, normalize_language
from src.experiment import RunArtifactStore
from src.llm.agent_utils.json_parser import extract_json_object
from src.llm.agent_utils.log_manager import (
    append_error_log,
    write_agent_transcript,
    write_lsp_doc_initial_log,
    write_lsp_doc_final_log,
)
from src.llm.opencode_query import OpenCodeQueryClient, OPENCODE_BUILTIN_FILE_TOOLS
from src.llm.provider_config import resolve_model_name
from src.llm.usage import record_agent_call, _safe_subject_component
from src.preprocess.docs.lsp_doc_prompt import (
    LSP_DOC_SYSTEM_PROMPT_TEMPLATE,
    LSP_DOC_USER_PROMPT_TEMPLATE,
)

load_dotenv()


DEFAULT_LSP_DOC_MODEL = "gpt-5.6-luna"

# Documentation uses OpenCode native source tools without custom MCP/LSP tools.
LSP_DOC_BUILTIN_TOOLS: list[str] = list(OPENCODE_BUILTIN_FILE_TOOLS)


@dataclass(frozen=True)
class LspPromptBundle:
    """All prompt-side data for one LSP doc request."""
    system_prompt: str
    user_prompt: str


class LspDocAgent:
    """
    Documentation agent that uses clangd LSP to explore a function before
    generating its documentation.

    Output JSON format:
        {
            "function_name":    str,
            "signature":        str,
            "handle_lifecycle": list[str],   # acquire_handle | use_handle | release_handle | none
            "summary":          str,
            "constraints":      list[{"param": str, "value_kind": str}],
            "file_path":        str,
            "header_file":      str,
            "comment":          str,
            "source":           str,
        }

    The agent LLM produces "handle_lifecycle", "summary", and "constraints"
    (value_kind = a natural-language phrase describing what each parameter expects).
    All other fields are assembled statically from pre-collected data.
    """

    def __init__(self, library_name: str = "libaom"):
        self.library_name = library_name
        self.language = self._load_language()
        self.workspace_root = os.path.abspath(os.path.join("test_lib", library_name))
        self.run_store = RunArtifactStore.from_environment(
            get_project_root(), library_name
        )

        self.model_name = resolve_model_name(
            "API_DOC_MODEL", DEFAULT_LSP_DOC_MODEL
        )
        self._query_client = OpenCodeQueryClient(self.workspace_root)

        logger.debug(
            "LspDocAgent initialized: model={}, lib={}",
            self.model_name,
            library_name,
        )

    def _load_language(self) -> str:
        config = load_library_config(self.library_name)
        language = config.get("language", "cpp") if config else "cpp"
        return normalize_language(language)

    def close(self) -> None:
        self._query_client.close()

    def _build_prompt_bundle(
        self,
        function_name: str,
        file_hint: str = "",
        signature_hint: str = "",
        header_file: str = "",
        comment: str = "",
        source: str = "",
        start_line: int = 0,
        end_line: int = 0,
        character: int = 1,
    ) -> LspPromptBundle:
        return LspPromptBundle(
            system_prompt=(
                LSP_DOC_SYSTEM_PROMPT_TEMPLATE
                .replace("{language}", self.language)
                .replace("{library_name}", self.library_name)
            ),
            user_prompt=LSP_DOC_USER_PROMPT_TEMPLATE.format(
                function_name=function_name,
                language=self.language,
                library_name=self.library_name,
                file_hint=file_hint or "unknown",
                start_line=start_line or "unknown",
                end_line=end_line or "unknown",
                character=character,
                signature_hint=signature_hint or "unknown",
                header_file=header_file or "unknown",
                comment=comment or "(none)",
                source=source or "(none)",
            ),
        )

    def _build_tool_names(self) -> list[str]:
        return list(LSP_DOC_BUILTIN_TOOLS)

    def analyze_function(
        self,
        function_name: str,
        *,
        api_id: str,
        abi_symbol: str,
        display_name: str,
        file_hint: str = "",
        signature_hint: str = "",
        header_file: str = "",
        comment: str = "",
        source: str = "",
        start_line: int = 0,
        end_line: int = 0,
        character: int = 1,
        attempt: int = 1,
    ) -> Optional[Dict]:
        """
        Explore a function via LSP and return structured JSON documentation.

        The agent LLM produces "handle_lifecycle", "summary", and "constraints".
        All other fields (signature, file_path, header_file, comment, source)
        are assembled statically from the pre-collected arguments.

        Args:
            function_name:  The function to document.
            file_hint:      Candidate source file path (relative to workspace_root).
            signature_hint: Known signature (used verbatim in output).
            header_file:    Known header file path.
            comment:        Pre-collected header comment/docstring.
            source:         Pre-collected function source code.

        Returns:
            Dict with keys: function_name, signature, summary, constraints,
                            file_path, header_file, comment, source
            Returns None on failure.
        """
        prompts = self._build_prompt_bundle(
            function_name, file_hint, signature_hint, header_file, comment, source,
            start_line=start_line, end_line=end_line, character=character,
        )

        log_path = self.run_store.usage_path("preprocess", subject=_safe_subject_component(api_id)).parent / f"attempt-{attempt:02d}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = str(log_path)

        write_lsp_doc_initial_log(
            log_file=log_file,
            library_name=self.library_name,
            language=self.language,
            function_name=function_name,
            model_name=self.model_name,
            system_prompt=prompts.system_prompt,
            user_prompt=prompts.user_prompt,
        )

        response_text = ""
        configured_tools = self._build_tool_names()
        try:
            try:
                query_result = self._query_client.run(
                    prompt=prompts.user_prompt,
                    system_prompt=prompts.system_prompt,
                    model=self.model_name,
                    mcp_config={"mcp": {}},
                    configured_tools=configured_tools,
                    transcript_path=str(log_path.parent / "agent.jsonl"),
                )
            except Exception as exc:
                record_agent_call(
                    self.library_name,
                    agent="lsp_doc_agent",
                    stage="preprocess",
                    model=self.model_name,
                    call_index=attempt,
                    configured_tools=configured_tools,
                    error=str(exc),
                    result=getattr(exc, "agent_result", None),
                    call_id=getattr(exc, "agent_call_id", None),
                    artifact_path=log_file,
                    subject_id=api_id,
                    subject_kind="api",
                )
                raise
            record_agent_call(
                self.library_name,
                agent="lsp_doc_agent",
                stage="preprocess",
                model=self.model_name,
                call_index=attempt,
                configured_tools=configured_tools,
                result=query_result,
                artifact_path=log_file,
                subject_id=api_id,
                subject_kind="api",
            )
            response_text = query_result.result_text.strip() if query_result.result_text else ""

            # Write full agent transcript (thinking + tool calls)
            write_agent_transcript(
                log_file,
                query_result.transcript,
                title="AGENT TRANSCRIPT",
            )

            if not response_text:
                logger.warning(f"LspDocAgent: empty response for {function_name}")
                write_lsp_doc_final_log(
                    log_file, function_name, response_text, None, False,
                    error_message="empty LLM response",
                )
                return None

            llm_result = extract_json_object(response_text)
            if not llm_result:
                logger.warning(f"LspDocAgent: no valid JSON object found for {function_name}")
                write_lsp_doc_final_log(
                    log_file, function_name, response_text, None, False,
                    error_message="no valid JSON object found",
                )
                return None

            # Validate that the agent returned the required fields
            if "summary" not in llm_result or "handle_lifecycle" not in llm_result:
                missing = [f for f in ("summary", "handle_lifecycle") if f not in llm_result]
                logger.warning(f"LspDocAgent: missing {missing} for {function_name}")
                write_lsp_doc_final_log(
                    log_file, function_name, response_text, None, False,
                    error_message=f"missing required fields: {missing}",
                )
                return None

            # handle_lifecycle is a list; tolerate a bare string from the LLM.
            handle_lifecycle = llm_result.get("handle_lifecycle", [])
            if isinstance(handle_lifecycle, str):
                handle_lifecycle = [handle_lifecycle] if handle_lifecycle else []

            # Statically assemble the full document from LLM output + pre-collected data
            result: Dict = {
                "api_id":           api_id,
                "abi_symbol":       abi_symbol,
                "function_name":    display_name,
                "qualified_name":   function_name,
                "signature":        signature_hint or "",
                "handle_lifecycle": handle_lifecycle,
                "summary":          llm_result["summary"],
                "constraints":   llm_result.get("constraints", []),
                "file_path":     file_hint or "",
                "header_file":   header_file or "",
                "comment":       comment or "",
                "source":        source or "",
            }
            write_lsp_doc_final_log(log_file, function_name, response_text, result, True)
            return result

        except Exception as e:
            logger.error(f"LspDocAgent: failed for {function_name}: {e}")
            append_error_log(log_file, str(e))
            write_lsp_doc_final_log(
                log_file, function_name, response_text, None, False,
                error_message=f"agent execution error: {e}",
            )
            return None
