"""One feedback-guided reachability refinement with a path-bound edit surface."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from src.core import get_project_root
from src.llm.agent_utils.log_manager import (
    write_agent_transcript,
    write_driver_generation_log,
)
from src.llm.opencode_query import (
    OPENCODE_BUILTIN_FILE_TOOLS,
    OpenCodeQueryClient,
    normalize_tool_names_for_logs,
)
from src.llm.provider_config import resolve_model_name
from src.llm.usage import record_agent_call
from src.tools.trace2fuzz_mcp import create_trace2fuzz_mcp_bundle

from .prompt import (
    REFINER_FOLLOWUP_MESSAGE,
    REFINER_PROMPT_TEMPLATE,
)


DEFAULT_REFINER_MODEL = "gpt-5.6-luna"
_ENTRYPOINT = "LLVMFuzzerTestOneInput"


@dataclass(frozen=True)
class RefinerResult:
    edited: bool
    source_path: str
    error: str
    tool_calls: int
    model: str
    response_text: str = ""
    user_message_id: str = ""
    decision: str = ""
    evidence: str = ""
    changes: str = ""


class ReachabilityRefinerAgent:
    """Ask OpenCode for one evidence-bound edit of one isolated candidate."""

    def __init__(
        self,
        library: str,
        language: str,
        candidate_path: Path,
        *,
        session_dir: Path,
        new_session: bool = False,
    ) -> None:
        self.library = library
        self.language = language
        self.candidate_path = candidate_path.resolve(strict=True)
        self.library_root = (
            Path(get_project_root()) / "test_lib" / library
        ).resolve(strict=True)
        self.model = resolve_model_name(
            "REFINER_AGENT_MODEL", DEFAULT_REFINER_MODEL
        )
        self._bundle = create_trace2fuzz_mcp_bundle(
            library,
            include_file_tools=False,
            include_search_function=False,
            include_compile_driver=False,
            include_lsp=False,
            include_fact_base=True,
        )
        self._client = OpenCodeQueryClient(
            str(self.library_root),
            client_name="trace2fuzz_driver_refiner",
            client_title="Trace2Fuzz Driver Refiner",
            session_dir=str(session_dir),
            new_session=new_session,
            editable_file=str(self.candidate_path),
            readable_roots=[str(self.library_root)],
        )

    def close(self) -> None:
        self._client.close()

    def run(
        self,
        *,
        driver_id: str,
        entry_api: str,
        code_location: str,
        coverage_evidence: str,
        driver_source: str,
        log_file: Path,
        call_index: int,
        fork_before_message_id: str | None = None,
        validation_error: str = "",
    ) -> RefinerResult:
        original = self.candidate_path.read_text(encoding="utf-8")
        user_prompt = _render_user_prompt(
            library=self.library,
            candidate_path=self.candidate_path,
            entry_api=entry_api,
            code_location=code_location,
            coverage_evidence=coverage_evidence,
            driver_source=driver_source,
            continuation=self._client.has_session,
            validation_error=validation_error,
        )
        configured_tools = (
            list(OPENCODE_BUILTIN_FILE_TOOLS)
            + ["edit"]
            + list(self._bundle.tool_names)
        )
        try:
            execution = self._client.run(
                prompt=user_prompt,
                system_prompt="",
                model=self.model,
                mcp_config=self._bundle.opencode_config(),
                configured_tools=configured_tools,
                transcript_path=str(log_file.parent / "agent.jsonl"),
                fork_before_message_id=fork_before_message_id,
            )
        except Exception as exc:
            record_agent_call(
                self.library,
                agent="driver_refiner",
                stage="driver_refinement",
                model=self.model,
                call_index=call_index,
                configured_tools=configured_tools,
                error=str(exc),
                result=getattr(exc, "agent_result", None),
                call_id=getattr(exc, "agent_call_id", None),
                artifact_path=str(log_file),
                driver_id=driver_id,
            )
            write_driver_generation_log(
                str(log_file),
                self.library,
                self.language,
                "",
                user_prompt,
                [],
                f"ERROR: {exc}",
                original,
                title="DRIVER ENHANCEMENT LOG [SDK ERROR]",
            )
            raise RuntimeError(f"Driver Refiner SDK error: {exc}") from exc

        normalize_tool_names_for_logs(execution, configured_tools=configured_tools)
        record_agent_call(
            self.library,
            agent="driver_refiner",
            stage="driver_refinement",
            model=self.model,
            call_index=call_index,
            configured_tools=configured_tools,
            result=execution,
            artifact_path=str(log_file),
            driver_id=driver_id,
        )
        candidate = self.candidate_path.read_text(encoding="utf-8")
        changed = candidate != original
        edited = changed and _valid_driver(candidate)
        model_error = _model_turn_failure(execution)
        response, response_error = (
            ({}, "") if model_error else _parse_refiner_response(execution.result_text)
        )
        errors = []
        if changed and not edited:
            errors.append("Driver Refiner output is not a structurally valid libFuzzer driver")
        if model_error:
            errors.append(model_error)
        if response_error:
            errors.append(response_error)

        if edited:
            decision = "edited"
        elif response and not changed:
            decision = "unreachable"
        else:
            decision = ""
        explanation = response.get("changes", "")

        write_driver_generation_log(
            str(log_file),
            self.library,
            self.language,
            "",
            user_prompt,
            execution.tool_calls,
            execution.result_text,
            candidate,
            title="DRIVER ENHANCEMENT LOG",
        )
        write_agent_transcript(str(log_file), execution.transcript)
        return RefinerResult(
            edited=edited,
            source_path=str(self.candidate_path),
            error="; ".join(errors),
            tool_calls=len(execution.tool_calls),
            model=self.model,
            response_text=execution.result_text,
            user_message_id=execution.user_message_id,
            decision=decision,
            evidence=explanation,
            changes=explanation if edited else "",
        )


def _model_turn_failure(execution: object) -> str:
    """Report a failed provider turn before trying to parse its absent final text."""
    if not getattr(execution, "is_error", False):
        return ""
    reason = str(getattr(execution, "stop_reason", "failed"))
    for message in reversed(getattr(execution, "message_usage", []) or []):
        if not isinstance(message, Mapping):
            continue
        error = message.get("error")
        if isinstance(error, Mapping):
            data = error.get("data")
            detail = error.get("message") or (
                data.get("message") if isinstance(data, Mapping) else None
            ) or error.get("name")
        else:
            detail = error
        if detail:
            return f"Driver Refiner model turn {reason}: {detail}"
    return f"Driver Refiner model turn {reason} without a final response"


def _parse_refiner_response(text: str) -> tuple[dict[str, str], str]:
    """Read one final change summary, allowing harmless leading commentary."""
    if not isinstance(text, str):
        return {}, "Refiner response is not a JSON object"
    raw = text.strip("\ufeff\u200b \t\r\n")
    try:
        response = json.loads(raw)
    except ValueError:
        decoder = json.JSONDecoder()
        objects = []
        for index, character in enumerate(raw):
            if character != "{":
                continue
            try:
                candidate, end = decoder.raw_decode(raw, index)
            except ValueError:
                continue
            if isinstance(candidate, dict) and set(candidate) == {"changes"}:
                objects.append((candidate, end))
        if len(objects) != 1 or raw[objects[0][1]:].strip("\ufeff\u200b \t\r\n"):
            return {}, "Refiner response is not a single final JSON object"
        response = objects[0][0]
    if not isinstance(response, dict) or set(response) != {"changes"}:
        return {}, "Refiner response must contain only changes"
    if not isinstance(response["changes"], str) or not response["changes"].strip():
        return {}, "Refiner response changes must be a nonempty string"
    return response, ""


def _valid_driver(source: str) -> bool:
    if _ENTRYPOINT not in source:
        return False
    depth = 0
    for character in source:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _render_user_prompt(
    *,
    library: str,
    candidate_path: Path,
    entry_api: str,
    code_location: str,
    coverage_evidence: str,
    driver_source: str,
    continuation: bool = False,
    validation_error: str = "",
) -> str:
    library_root = (Path(get_project_root()) / "test_lib" / library).resolve()
    values = dict(
        library_name=library,
        entry_api=entry_api,
        library_root=library_root,
        driver_file=candidate_path,
        code_location=code_location,
        coverage_evidence=coverage_evidence,
        driver_source=driver_source,
    )
    template = REFINER_FOLLOWUP_MESSAGE if continuation else REFINER_PROMPT_TEMPLATE
    prompt = re.sub(
        r"\{([a-z_]+)\}",
        lambda match: str(values[match.group(1)]),
        template,
    )
    lines = [line.strip() for line in validation_error.splitlines() if line.strip()]
    if lines:
        diagnostic = next(
            (line for line in lines if "error:" in line.lower()), lines[0]
        )
        prompt += (
            "\n\nValidation of the previous edit failed, and the current driver has been rolled back. "
            "Diagnostic: " + diagnostic[:400]
        )
    return prompt
