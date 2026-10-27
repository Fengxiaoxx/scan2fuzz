#!/usr/bin/env python3
"""
Compile Repair Agent - Fix compilation and runtime errors in fuzzing drivers.

This module preserves the existing public interface while using OpenCode.
"""

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv
from loguru import logger
from src.core import get_project_root
from src.tools.trace2fuzz_mcp import create_trace2fuzz_mcp_bundle
from src.llm.opencode_query import (
    OPENCODE_BUILTIN_FILE_TOOLS,
    OpenCodeQueryClient,
    normalize_tool_names_for_logs,
)
from src.llm.provider_config import resolve_model_name
from src.llm.usage import record_agent_call
from src.llm.agent_utils import (
    append_error_log,
    append_failed_attempts_log,
    append_tool_calls_log,
    generate_log_path,
    validate_agent_output,
    write_agent_transcript,
    write_final_log,
    write_initial_log,
)
from src.llm.agent_utils.prompt_builder import build_failed_attempts_section
from src.compile_repair.prompt import (
    REPAIR_CONTINUATION_CLOSING,
    REPAIR_CONTINUATION_PROMPT,
    get_repair_prompt_template,
)

load_dotenv()


DEFAULT_FIX_MODEL = "gpt-5.6-luna"
VERDICTS = ("driver_fault", "library_bug")


def reply_verdict(reply: str) -> Optional[str]:
    """The runtime Repair's closing ``VERDICT: ...`` line, or None when it gave none."""
    lines = [line.replace("`", "").replace("*", "").strip() for line in reply.splitlines()]
    lines = [line for line in lines if line]
    if not lines or not lines[-1].startswith("VERDICT:"):
        return None
    verdict = lines[-1].removeprefix("VERDICT:").strip()
    return verdict if verdict in VERDICTS else None


@dataclass(frozen=True)
class ToolDescriptor:
    """Small log-only representation of a tool."""

    name: str
    description: str


class ProgressIndicator:
    """Console progress indicator kept independent from any SDK callback model."""

    def __init__(self, start_time: float):
        self.start_time = start_time
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        last_second = 0
        while self._running:
            elapsed = int(time.time() - self.start_time)
            if elapsed > last_second:
                last_second = elapsed
                print(f"\r│     └─> Fixing... {elapsed}s", end="", flush=True)
            time.sleep(0.1)

    def stop(self) -> None:
        self._running = False
        self._thread.join(timeout=0.5)
        print("\r" + " " * 60 + "\r", end="", flush=True)


class CompileRepairAgent:
    """Repair generated drivers with dynamically selected repair prompts."""

    def __init__(
        self,
        library_name: str,
        original_driver_path: str,
        language: str = "C",
        temperature: float = 0,
        max_compile_attempts: int = 5,
        quiet: bool = False,
        session_dir: Optional[str] = None,
        new_session: bool = False,
    ):
        """
        Args:
            library_name: Name of the library (e.g., 'cjson')
            original_driver_path: Original driver file path
            language: Programming language (C or C++)
            temperature: LLM sampling temperature
            max_compile_attempts: Maximum compilation attempts
        """
        self.library_name = library_name
        # Resolve to absolute so native file tools locate the candidate reliably.
        self.original_driver_path = os.path.abspath(original_driver_path)
        self.language = language
        self.library_root = str(
            (Path(get_project_root()) / "test_lib" / library_name).resolve(strict=True)
        )
        # Start OpenCode in the target source tree. The driver remains outside
        # this directory and is explicitly whitelisted as the sole editable
        # external file by OpenCodeQueryClient.
        self.workspace_root = self.library_root
        self.max_compile_attempts = max_compile_attempts
        self.quiet = quiet
        # Compile-fix uses the stage-specific model override when present and
        # otherwise falls back to the stage default.
        self.model_name = self._resolve_model_name()
        self.temperature = float(temperature)

        # Diagnose through native file tools and edit the path-bound candidate.
        # Compilation is owned by the workflow after the agent turn returns.
        self._tool_catalog = self._build_tool_catalog()
        self.tools = [desc for _, desc in self._tool_catalog]

        # Publicly observed state retained for workflow compatibility.
        self._last_validation_error = None
        self.last_reply = ""
        self.last_verdict: Optional[str] = None
        self.current_driver_code: Optional[str] = None
        self.current_error_message: Optional[str] = None
        self.current_failed_attempts_section: Optional[str] = None
        self.current_repair_mode = "compile"
        self.current_artifact_paths: List[str] = []
        self._query_client = OpenCodeQueryClient(
            self.workspace_root,
            client_name="trace2fuzz_compile_repair_agent",
            client_title="Trace2Fuzz Compile Repair Agent",
            session_dir=session_dir or str(Path(self.original_driver_path).parent / ".repair-session" / Path(self.original_driver_path).name),
            new_session=new_session,
            editable_file=self.original_driver_path,
            readable_roots=[self.library_root],
        )

        if not self.quiet:
            logger.info(f"CompileRepairAgent initialized: {self.model_name}")

    def close(self) -> None:
        self._query_client.close()

    def _resolve_model_name(self) -> str:
        """Resolve the configured model name."""
        return resolve_model_name("FIX_AGENT_MODEL", DEFAULT_FIX_MODEL)

    def _build_tool_catalog(self) -> List[tuple]:
        """Single source of truth: ordered list of (sdk_name, ToolDescriptor).

        The catalog drives both the OpenCode-visible MCP tool list and the
        log-display set. New tools should be added here only.

        Native Edit applies fixes. Read/Grep/Glob provide direct source inspection.
        Compiler and LSP descriptors remain available below but are not exposed.
        """
        mcp_descriptions = {
            "read": ToolDescriptor(
                name="Read",
                description="Read file contents directly.",
            ),
            "grep": ToolDescriptor(
                name="Grep",
                description="Search file contents by pattern.",
            ),
            "glob": ToolDescriptor(
                name="Glob",
                description="Find files by glob pattern.",
            ),
            "edit": ToolDescriptor(
                name="Edit",
                description="Edit the isolated driver candidate using OpenCode's native file editor.",
            ),
            "mcp__t2f__find_api": ToolDescriptor(
                name="find_api",
                description="Find relevant library APIs by handle lifecycle, handle type, and intent.",
            ),
            "mcp__t2f__compile_driver": ToolDescriptor(
                name="compile_driver",
                description=(
                    "Compile the driver file with project clang flags. "
                    "Returns {success, error, command, output_file}. "
                    "Call after each native Edit update to verify the fix; iterate until success is true."
                ),
            ),
            "mcp__t2f__get_source": ToolDescriptor(
                name="get_source",
                description="clangd: full source of the function/type at a definition coordinate {file,line,col}.",
            ),
            "mcp__t2f__goto_definition": ToolDescriptor(
                name="goto_definition",
                description="clangd: from a symbol use site {file,line,col} resolve where it is defined (fixes undefined symbols / wrong signatures).",
            ),
            "mcp__t2f__callees": ToolDescriptor(
                name="callees",
                description="clangd: functions directly called by the function at {file,line,col}.",
            ),
            "mcp__t2f__callers": ToolDescriptor(
                name="callers",
                description="clangd: functions that directly call the function at {file,line,col}.",
            ),
            "mcp__t2f__types_used": ToolDescriptor(
                name="types_used",
                description="clangd: types used inside the function at {file,line,col} (companion to get_source).",
            ),
        }
        catalog: List[tuple] = []
        for sdk_name in (
            list(OPENCODE_BUILTIN_FILE_TOOLS)
            + ["edit", "mcp__t2f__find_api"]
        ):
            descriptor = mcp_descriptions.get(sdk_name)
            if descriptor is not None:
                catalog.append((sdk_name, descriptor))

        return catalog

    def _build_tool_list(self) -> List[str]:
        """Return the exact tools allowed for the active repair mode."""
        return [sdk_name for sdk_name, _ in self._tool_catalog]

    def _repair_tool_bundle(self):
        return create_trace2fuzz_mcp_bundle(
            self.library_name,
            include_search_function=False,
            include_fact_base=True,
        )

    def _build_tool_descriptors(self) -> List[ToolDescriptor]:
        allowed = set(self._build_tool_list())
        return [
            descriptor
            for sdk_name, descriptor in self._tool_catalog
            if sdk_name in allowed
        ]

    def _is_repair_continuation(self) -> bool:
        """Reuse mode instructions only when they belong to this saved session."""
        if not self._query_client.has_session:
            return False
        session_dir = self._query_client.session_dir
        if session_dir is None:
            return False
        try:
            session = json.loads((Path(session_dir) / "session.json").read_text())
            context = json.loads(
                (Path(session_dir) / "repair-prompt.json").read_text()
            )
            return bool(session.get("session_id")) and context == {
                "session_id": session["session_id"],
                "repair_mode": self.current_repair_mode,
            }
        except (OSError, ValueError, TypeError, AttributeError):
            return False

    def _remember_repair_prompt(self) -> None:
        """Persist the active mode because workflow turns create new agents."""
        session_dir = self._query_client.session_dir
        if session_dir is None:
            return
        try:
            session = json.loads((Path(session_dir) / "session.json").read_text())
            session_id = session.get("session_id")
            if not session_id:
                return
            path = Path(session_dir) / "repair-prompt.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps({
                    "session_id": session_id,
                    "repair_mode": self.current_repair_mode,
                }, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            temporary.replace(path)
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            # Without this marker the next turn safely sends the full prompt.
            logger.warning("Could not save repair prompt context: {}", exc)

    def _build_user_prompt(self) -> str:
        """Render a full mode prompt or the next message in that conversation."""
        if self._is_repair_continuation():
            runtime = self.current_repair_mode == "runtime"
            artifact_section = ""
            if runtime:
                artifacts = "\n".join(
                    f"- {path}" for path in self.current_artifact_paths
                ) or "(none produced)"
                artifact_section = (
                    "Crash artifacts retained for the next sanitizer run:\n"
                    f"{artifacts}\n"
                )
            return REPAIR_CONTINUATION_PROMPT.format(
                repair_mode=self.current_repair_mode,
                driver_file=self.original_driver_path,
                driver_code=self.current_driver_code or "",
                diagnostic_label=(
                    "sanitizer runtime failure" if runtime else "compilation error"
                ),
                error_message=self.current_error_message or "",
                artifact_section=artifact_section,
                closing_instruction=REPAIR_CONTINUATION_CLOSING[self.current_repair_mode],
            )
        user_prompt = get_repair_prompt_template(self.current_repair_mode)
        prompt_fields = dict(
            library_name=self.library_name,
            library_root=self.library_root,
            language=self.language,
            driver_file=self.original_driver_path,
            driver_code=self.current_driver_code or "",
            error_message=self.current_error_message or "",
        )
        if self.current_repair_mode == "compile":
            prompt_fields["failed_attempts_section"] = self.current_failed_attempts_section or ""
        else:
            prompt_fields["artifact_paths"] = "\n".join(
                f"- {path}" for path in self.current_artifact_paths
            ) or "(none produced)"
        return user_prompt.format(**prompt_fields)

    def repair_compile_error(
        self,
        driver_code: str,
        compile_error: str,
        failed_attempts: List[dict] = None,
        log_file: str = None,
        *,
        _repair_mode: str = "compile",
        _artifact_paths: Optional[List[str]] = None,
    ) -> tuple[Optional[str], int]:
        """
        Fix a driver based on compilation error message.

        Args:
            driver_code: Compatibility copy of the driver source; the current
                source is reloaded from original_driver_path before prompting.
            compile_error: Compilation error message from compiler
            failed_attempts: Previous failed attempts
            log_file: Optional log file path

        Returns:
            Tuple of (fixed code or None, number of tool calls)
        """
        # Validate and activate the mode before creating logs or SDK options.
        # Runtime repair reuses this class but dynamically omits the compiler;
        # the sanitizer smoke workflow owns the one-shot compile check.
        get_repair_prompt_template(_repair_mode)
        self.current_repair_mode = _repair_mode
        log_type = "compile_repair" if _repair_mode == "compile" else "runtime_repair"
        error_label = "Compilation Error" if _repair_mode == "compile" else "Sanitizer Runtime Failure"

        if log_file is None:
            log_file = generate_log_path(
                self.library_name,
                self.original_driver_path,
                log_type,
            )

        if failed_attempts is None:
            failed_attempts = []

        # Each turn describes the exact file that native Edit will modify. The
        # caller-provided string may predate another workflow repair or restore.
        try:
            driver_code = Path(self.original_driver_path).read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(
                f"Could not read current driver before repair: {exc}"
            ) from exc

        if log_file and not failed_attempts:
            write_initial_log(
                log_file,
                self.library_name,
                self.language,
                self.original_driver_path,
                driver_code,
                compile_error,
                self.model_name,
                self.temperature,
                self._build_tool_descriptors(),
                self.max_compile_attempts,
                log_type="compile_repair" if _repair_mode == "compile" else "crash_fix",
            )
        elif log_file and failed_attempts:
            append_failed_attempts_log(
                log_file,
                failed_attempts,
                self.language,
                len(failed_attempts) + 1,
                error_label=error_label,
                original_driver_code=driver_code,
                driver_file_path=self.original_driver_path,
            )

        quiet = bool(getattr(self, "quiet", False))
        progress = None if quiet else ProgressIndicator(time.time())

        try:
            self.current_driver_code = driver_code
            self.current_error_message = compile_error
            self.current_artifact_paths = list(_artifact_paths or [])
            self.current_failed_attempts_section = None
            if _repair_mode == "compile" and not self._is_repair_continuation():
                self.current_failed_attempts_section = build_failed_attempts_section(
                    failed_attempts,
                    self.language,
                    error_label=error_label,
                    original_driver_code=driver_code,
                    driver_file_path=self.original_driver_path,
                )

            user_prompt = self._build_user_prompt()
            usage_stage = (
                "compile_repair" if _repair_mode == "compile" else "runtime_repair"
            )
            usage_call_index = len(failed_attempts) + 1
            configured_tools = self._build_tool_list()
            repair_bundle = self._repair_tool_bundle()
            try:
                execution = self._query_client.run(
                    prompt=user_prompt,
                    system_prompt="",
                    model=self.model_name,
                    mcp_config=repair_bundle.opencode_config(),
                    configured_tools=configured_tools,
                    temperature=self.temperature,
                    transcript_path=str(Path(log_file).parent / "agent.jsonl") if log_file else None,
                )
            except Exception as exc:
                record_agent_call(
                    self.library_name,
                    agent="compile_repair_agent",
                    stage=usage_stage,
                    model=self.model_name,
                    call_index=usage_call_index,
                    configured_tools=configured_tools,
                    error=str(exc),
                    result=getattr(exc, "agent_result", None),
                    call_id=getattr(exc, "agent_call_id", None),
                    artifact_path=log_file,
                    subject_id=os.path.basename(self.original_driver_path),
                    subject_kind="driver_candidate",
                )
                raise
            self._remember_repair_prompt()
            normalize_tool_names_for_logs(execution, configured_tools=configured_tools)
            record_agent_call(
                self.library_name,
                agent="compile_repair_agent",
                stage=usage_stage,
                model=self.model_name,
                call_index=usage_call_index,
                configured_tools=configured_tools,
                result=execution,
                artifact_path=log_file,
                subject_id=os.path.basename(self.original_driver_path),
                subject_kind="driver_candidate",
            )
            tool_calls = len(execution.tool_calls)
            self.last_reply = execution.result_text or ""
            self.last_verdict = reply_verdict(self.last_reply)

            if log_file:
                write_agent_transcript(log_file, execution.transcript)
                append_tool_calls_log(log_file, tool_calls)

            # Disk is the primary source of truth: native Edit is permission-bound
            # to original_driver_path, and the workflow compiles that edited file.
            from pathlib import Path as _Path
            try:
                fixed_code = _Path(self.original_driver_path).read_text(encoding="utf-8")
            except Exception as exc:
                self._last_validation_error = f"Could not read driver from disk: {exc}"
                if log_file:
                    append_error_log(log_file, self._last_validation_error)
                raise RuntimeError(self._last_validation_error) from exc

            disk_changed = fixed_code != driver_code
            if not disk_changed:
                error_msg = "Agent made no disk edit"
                if not execution.result_text:
                    error_msg = "Agent produced no text and made no disk edit"
                if not quiet:
                    print(f"❌ {error_msg}")
                self._last_validation_error = error_msg
                if log_file:
                    append_error_log(log_file, error_msg)
                return None, tool_calls

            is_valid, reason = validate_agent_output(fixed_code, self.language)
            if not is_valid:
                if not quiet:
                    print(f"❌ Driver validation failed: {reason}")
                    print(f"   Output: {fixed_code[:100]}...")
                self._last_validation_error = f"Validation failed: {reason}"
                if log_file:
                    append_error_log(log_file, self._last_validation_error)
                return None, tool_calls

            if not quiet:
                print(f"✅ Driver fixed on disk ({len(fixed_code)} chars)")

            if log_file:
                write_final_log(
                    log_file,
                    execution.raw_result,
                    fixed_code,
                    tool_calls,
                    bool(fixed_code),
                )

            return fixed_code, tool_calls

        except Exception as e:
            error_str = str(e)
            if "403" in error_str or "insufficient_user_quota" in error_str or "额度" in error_str:
                error_msg = "API quota insufficient - please check API configuration or increase quota"
                if not quiet:
                    print(f"❌ {error_msg}")
                self._last_validation_error = error_msg
            else:
                error_msg = f"Agent execution error: {error_str}"
                if not quiet:
                    print(f"❌ {error_msg}")
                self._last_validation_error = error_msg

            if log_file:
                append_error_log(log_file, f"ERROR: {error_str}")
            raise
        finally:
            if progress is not None:
                progress.stop()

    def repair_runtime_error(
        self,
        driver_code: str,
        sanitizer_output: str,
        artifact_paths: Optional[List[str]] = None,
        failed_attempts: List[dict] = None,
        log_file: str = None,
    ) -> tuple[Optional[str], int]:
        """Repair a sanitizer failure using the same agent with runtime prompts."""
        return self.repair_compile_error(
            driver_code,
            sanitizer_output,
            failed_attempts=failed_attempts,
            log_file=log_file,
            _repair_mode="runtime",
            _artifact_paths=artifact_paths,
        )
