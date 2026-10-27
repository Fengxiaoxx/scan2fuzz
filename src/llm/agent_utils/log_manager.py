"""Strict, run-scoped agent transcript writers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from src.core import get_project_root
from src.experiment import RunArtifactStore, validate_driver_id


def generate_log_path(
    library_name: str,
    driver_path: str,
    log_type: str = "compile_repair",
) -> str:
    driver_id = validate_driver_id(Path(driver_path).stem)
    stage = validate_driver_id(log_type)
    store = RunArtifactStore.from_environment(get_project_root(), library_name)
    path = store.logs_dir(stage, driver_id) / "agent.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


def write_initial_log(
    log_file: str,
    library_name: str,
    language: str,
    driver_path: str,
    driver_code: str,
    error_message: str,
    model_name: str,
    temperature: float,
    tools: List,
    max_attempts: int = 5,
    log_type: str = "compile_repair",
) -> None:
    title = "CRASH FIX LOG" if log_type == "crash_fix" else "COMPILATION FIX LOG"
    error_title = "CRASH REPORT" if log_type == "crash_fix" else "COMPILATION ERROR"
    with open(log_file, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("=" * 80 + f"\n{title}\n" + "=" * 80 + "\n\n")
        handle.write(
            f"Library: {library_name}\nLanguage: {language}\n"
            f"Driver File: {driver_path}\nMax Attempts: {max_attempts}\n"
            f"LLM Model: {model_name}\nTemperature: {temperature}\n\n"
        )
        handle.write("=" * 80 + "\nAVAILABLE TOOLS\n" + "=" * 80 + "\n")
        for tool in tools:
            handle.write(f"\n- {tool.name}\n  {tool.description}\n")
        handle.write("\n" + "=" * 80 + "\nORIGINAL DRIVER CODE\n" + "=" * 80 + "\n")
        handle.write(driver_code)
        handle.write("\n\n" + "=" * 80 + f"\n{error_title}\n" + "=" * 80 + "\n")
        handle.write(error_message)
        handle.write("\n\n" + "=" * 80 + "\nAGENT THOUGHT PROCESS\n" + "=" * 80 + "\n")


def append_failed_attempts_log(
    log_file: str,
    failed_attempts: List[Dict],
    language: str,
    attempt_num: int,
    error_label: str = "Compilation Error",
    original_driver_code: Optional[str] = None,
    driver_file_path: Optional[str] = None,
) -> None:
    from src.llm.agent_utils.prompt_builder import build_failed_attempts_section

    with open(log_file, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"\n=== ATTEMPT {attempt_num} ===\n")
        if original_driver_code is None:
            raise ValueError("original_driver_code is required for git-diff logs")
        handle.write(
            build_failed_attempts_section(
                failed_attempts,
                language,
                error_label=error_label,
                original_driver_code=original_driver_code,
                driver_file_path=driver_file_path,
            )
        )


def write_final_log(
    log_file: str,
    result_output: str,
    extracted_code: str,
    tool_calls: int,
    success: bool,
) -> None:
    with open(log_file, "a", encoding="utf-8", newline="\n") as handle:
        handle.write("\n\n" + "=" * 80 + "\nFINAL ANSWER\n" + "=" * 80 + "\n")
        handle.write(result_output or "")
        handle.write("\n\n" + "=" * 80 + "\nEXTRACTED FIXED CODE\n" + "=" * 80 + "\n")
        handle.write(extracted_code or "")
        handle.write(
            "\n\n" + "=" * 80 + "\nSUMMARY\n" + "=" * 80 + "\n"
            f"Tool Calls: {tool_calls}\nStatus: {'SUCCESS' if success else 'FAILED'}\n"
        )


def write_agent_transcript(
    log_file: str,
    transcript: list,
    title: str = "AGENT TRANSCRIPT",
) -> None:
    if not transcript:
        return
    with open(log_file, "a", encoding="utf-8", newline="\n") as handle:
        handle.write("\n" + "=" * 80 + f"\n{title}\n" + "=" * 80 + "\n")
        tool_index = 0
        for entry in transcript:
            entry_type = entry.get("type")
            if entry_type in {"thinking", "text"}:
                content = entry.get("content", "").strip()
                if content:
                    handle.write(f"\n[{entry_type.upper()}]\n{content}\n")
            elif entry_type == "tool_call":
                tool_index += 1
                handle.write(
                    f"\n--- Tool Call {tool_index}: "
                    f"{entry.get('name', 'unknown')} ---\n"
                )
                handle.write(
                    json.dumps(entry.get("input", {}), ensure_ascii=False, indent=2)
                )
                handle.write("\n[RESULT]\n")
                if entry.get("is_error"):
                    handle.write("TOOL FAILURE\n")
                handle.write(str(entry.get("output") or "(no output)").strip() + "\n")


def append_error_log(log_file: str, error: str) -> None:
    with open(log_file, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"\n\nERROR: {error}\n")


def append_tool_calls_log(log_file: str, tool_calls: int) -> None:
    with open(log_file, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"\nTool Calls: {tool_calls}\n" + "=" * 80 + "\n")


def write_driver_generation_log(
    log_file: str,
    library_name: str,
    language: str,
    system_prompt: str,
    user_prompt: str,
    tool_calls: List[Dict],
    llm_response: str,
    extracted_code: str,
    title: str = "DRIVER GENERATION LOG",
) -> None:
    with open(log_file, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("=" * 80 + f"\n{title}\n" + "=" * 80 + "\n\n")
        handle.write(f"Library: {library_name}\nLanguage: {language}\n\n")
        handle.write("=" * 80 + "\nSYSTEM PROMPT\n" + "=" * 80 + "\n")
        handle.write(system_prompt + "\n\n")
        handle.write("=" * 80 + "\nUSER PROMPT\n" + "=" * 80 + "\n")
        handle.write(user_prompt + "\n\n")
        handle.write(
            "=" * 80
            + f"\nTOOL CALLS ({len(tool_calls)} total)\n"
            + "=" * 80
            + "\n"
        )
        for index, call in enumerate(tool_calls, 1):
            handle.write(f"\n[{index}] {call['name']}\n")
            handle.write(
                json.dumps(call.get("input", {}), ensure_ascii=False, indent=2)
            )
            output = str(call.get("output_text") or "").strip()
            if output:
                prefix = "TOOL FAILURE - " if call.get("is_error") else ""
                handle.write(f"\nResult:\n{prefix}{output}\n")
        handle.write("\n" + "=" * 80 + "\nLLM RESPONSE\n" + "=" * 80 + "\n")
        handle.write((llm_response or "") + "\n\n")
        handle.write("=" * 80 + "\nEXTRACTED CODE\n" + "=" * 80 + "\n")
        handle.write((extracted_code or "") + "\n")


def write_lsp_doc_initial_log(
    log_file: str,
    library_name: str,
    language: str,
    function_name: str,
    model_name: str,
    system_prompt: str,
    user_prompt: str,
) -> None:
    with open(log_file, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("=" * 80 + "\nLSP DOC GENERATION LOG\n" + "=" * 80 + "\n\n")
        handle.write(
            f"Library: {library_name}\nLanguage: {language}\n"
            f"Target Function: {function_name}\nLLM Model: {model_name}\n\n"
        )
        handle.write("=" * 80 + "\nSYSTEM PROMPT\n" + "=" * 80 + "\n")
        handle.write(system_prompt + "\n\n")
        handle.write("=" * 80 + "\nUSER PROMPT\n" + "=" * 80 + "\n")
        handle.write(user_prompt + "\n\n")


def write_unit_audit_initial_log(
    log_file: str,
    library_name: str,
    slice_label: str,
    model_name: str,
    system_prompt: str,
    user_prompt: str,
) -> None:
    with open(log_file, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("=" * 80 + "\nUNIT AUDIT LOG\n" + "=" * 80 + "\n\n")
        handle.write(f"Library: {library_name}\nSlice: {slice_label}\nLLM Model: {model_name}\n\n")
        handle.write("=" * 80 + "\nSYSTEM PROMPT\n" + "=" * 80 + "\n")
        handle.write(system_prompt + "\n\n")
        handle.write("=" * 80 + "\nUSER PROMPT\n" + "=" * 80 + "\n")
        handle.write(user_prompt + "\n\n")


def write_unit_audit_final_log(
    log_file: str,
    raw_response: str,
    findings: List[Dict],
    error: str,
) -> None:
    with open(log_file, "a", encoding="utf-8", newline="\n") as handle:
        handle.write("\n" + "=" * 80 + "\nRAW LLM RESPONSE\n" + "=" * 80 + "\n")
        handle.write((raw_response or "(empty)") + "\n\n")
        handle.write("=" * 80 + "\nPARSED FINDINGS\n" + "=" * 80 + "\n")
        handle.write(f"FAILED: {error}" if error else json.dumps(findings, ensure_ascii=False, indent=2))
        handle.write(
            "\n\n" + "=" * 80 + "\nSUMMARY\n" + "=" * 80 + "\n"
            f"Status: {'FAILED' if error else 'SUCCESS'}\nFindings: {len(findings)}\n"
        )


def write_lsp_doc_final_log(
    log_file: str,
    function_name: str,
    raw_response: str,
    result: object,
    success: bool,
    error_message: str = "",
) -> None:
    with open(log_file, "a", encoding="utf-8", newline="\n") as handle:
        handle.write("\n" + "=" * 80 + "\nRAW LLM RESPONSE\n" + "=" * 80 + "\n")
        handle.write((raw_response or "(empty)") + "\n\n")
        handle.write("=" * 80 + "\nPARSED RESULT\n" + "=" * 80 + "\n")
        if success:
            handle.write(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            reason = error_message or f"no valid JSON produced for {function_name}"
            handle.write(f"FAILED: {reason}")
        handle.write(
            "\n\n" + "=" * 80 + "\nSUMMARY\n" + "=" * 80 + "\n"
            f"Status: {'SUCCESS' if success else 'FAILED'}\n"
        )
