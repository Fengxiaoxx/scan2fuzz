"""
Compile Fix Workflow - Fix compilation errors in fuzzing drivers
"""

from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from src.compile_repair.compile_repair_agent import CompileRepairAgent
from src.core import resolve_driver_identity
from src.experiment import RunArtifactStore, validate_driver_id
from src.llm import driver_agent_usage_summary
from src.llm.journal import append_record
from src.tools.compiler import compile_driver


def resolve_sequence_info(library_name: str, driver_file: str, language: str) -> str:
    """Build full target context for target-directed refinement.

    Parse ``{api}__{marker}`` from the driver filename, then render the target
    location, static chain, and finding through the shared context builder.
    """
    api_id, marker = resolve_driver_identity(library_name, driver_file)
    if not marker:
        raise ValueError(f"driver has no target marker: {driver_file}")

    from src.driver_generation.context_builder import DriverContextBuilder
    from src.driver_generation.inputs import load_api_document, resolve_work_item

    item = resolve_work_item(library_name, api_id, marker)
    builder = DriverContextBuilder(library_name, language)
    builder.load_target(
        api_id,
        item["qualified_name"],
        load_api_document(library_name, api_id),
        [item["target"]],
    )
    return builder.format_target_info()


def _record_compile_execution(
    store: RunArtifactStore,
    driver_id: str,
    result: Mapping[str, Any],
    operation: str,
) -> None:
    append_record(
        store.execution_log_path("compile_repair", driver_id),
        {
            "type": "compile",
            "operation": operation,
            "command": str(result.get("compile_command") or ""),
            "returncode": result.get("returncode"),
            "success": bool(result.get("success")),
            "stdout": str(result.get("stdout") or ""),
            "stderr": str(result.get("stderr") or ""),
        },
    )


def load_compile_result(
    store: RunArtifactStore,
    generated_record: dict[str, Any],
) -> Optional[dict[str, Any]]:
    driver_id = validate_driver_id(generated_record["driver_id"])
    result_path = store.stage_result_path("compile_repair", driver_id)
    if not result_path.is_file():
        return None
    result = store.read_json(result_path)
    if not isinstance(result, dict) or result.get("driver_id") != driver_id:
        raise ValueError(f"invalid compile result for {driver_id}: {result_path}")
    if result.get("outcome") not in {
        "pass_first_time",
        "fixed",
        "failed",
        "infrastructure_failed",
    }:
        raise ValueError(f"invalid compile outcome for {driver_id}: {result.get('outcome')!r}")
    generated_source = Path(generated_record["generated_source"]).resolve()
    if Path(str(result.get("generated_source") or "")).resolve() != generated_source:
        raise ValueError(f"compile result source mismatch for {driver_id}")
    source_value = str(result.get("source_path") or "")
    if result["outcome"] != "infrastructure_failed":
        if not source_value or not Path(source_value).is_file():
            raise ValueError(f"compile result has no retained source for {driver_id}")
    elif source_value and not Path(source_value).is_file():
        raise ValueError(f"compile result retained source is missing for {driver_id}")
    if result["outcome"] in {"pass_first_time", "fixed"}:
        binary_path = Path(str(result.get("binary_path") or ""))
        if not binary_path.is_file():
            raise ValueError(f"compile result has no retained binary for {driver_id}")
    return result


def _new_compile_action(stage_dir: Path) -> Path:
    actions_dir = stage_dir / "actions"
    actions_dir.mkdir(parents=True, exist_ok=True)
    numbers = [
        int(path.name.removeprefix("action-"))
        for path in actions_dir.iterdir()
        if path.is_dir()
        and path.name.startswith("action-")
        and path.name.removeprefix("action-").isdigit()
    ]
    action_dir = actions_dir / f"action-{max(numbers, default=0) + 1:03d}"
    action_dir.mkdir(exist_ok=False)
    return action_dir


def _compile_action_infrastructure(
    driver_id: str,
    action: str,
    source_path: str,
    error: str,
    *,
    repair_attempt: int,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "driver_id": driver_id,
        "action": action,
        "outcome": "infrastructure_failed",
        "success": False,
        "source_path": source_path,
        "binary_path": "",
        "compile_error": "",
        "repair_attempt": repair_attempt,
        "error": error,
    }


def _repair_attempt_counts(value: Mapping[str, Any]) -> dict[str, int]:
    if set(value) != {"compile", "runtime"}:
        raise ValueError("Repair counts must contain compile and runtime")
    counts = {}
    for kind in ("compile", "runtime"):
        attempts = value[kind]
        if isinstance(attempts, bool) or not isinstance(attempts, int):
            raise ValueError(f"invalid {kind} Repair count")
        if attempts < 0:
            raise ValueError(f"invalid {kind} Repair count")
        counts[kind] = attempts
    return counts


def compile_repair_candidate_once(
    store: RunArtifactStore,
    library_name: str,
    language: str,
    generated_record: dict[str, Any],
    *,
    source_path: str,
    repair_attempts: Mapping[str, Any],
    max_repair_attempts: int,
    failed_attempts: Sequence[Mapping[str, Any]],
    repair_request: Optional[Mapping[str, Any]] = None,
    quiet: bool = False,
) -> dict[str, Any]:
    """Compile once and invoke the single Repair for at most one diagnostic."""
    driver_id = validate_driver_id(generated_record["driver_id"])
    repair_counts = _repair_attempt_counts(repair_attempts)
    if any(value > max_repair_attempts for value in repair_counts.values()):
        raise ValueError("invalid Repair count")
    request = dict(repair_request or {})
    if request and request.get("kind") != "runtime":
        raise ValueError("invalid repair request")

    existing = load_compile_result(store, generated_record)
    source_value = str(Path(source_path).resolve())
    if (
        existing is not None
        and not request
        and Path(str(existing.get("source_path") or "")).resolve()
        == Path(source_value)
    ):
        outcome = str(existing["outcome"])
        return {
            **existing,
            "action": "compile_repair",
            "outcome": "compile_failed" if outcome == "failed" else outcome,
            "success": outcome in {"pass_first_time", "fixed"},
            "compile_error": str(existing.get("error") or ""),
            "repair_attempt": repair_counts["compile"],
            "repair_attempts": repair_counts,
            "repair_history": list(failed_attempts),
            "repair_request": {},
            "terminal": True,
        }

    stage_dir = store.stage_dir("compile_repair", driver_id)
    action_dir = _new_compile_action(stage_dir)
    agent = None
    try:
        source = Path(source_path).resolve(strict=True)
        compiled = compile_driver(str(source), library_name)
        _record_compile_execution(store, driver_id, compiled, "candidate")
        compile_error = (
            compiled.get("stderr")
            or compiled.get("stdout")
            or ("" if compiled["success"] else "compilation failed without diagnostics")
        )
        record: dict[str, Any] = {
            "schema_version": 1,
            "driver_id": driver_id,
            "action": "compile_repair",
            "outcome": "compiled" if compiled["success"] else "compile_failed",
            "success": bool(compiled["success"]),
            "source_path": str(source),
            "binary_path": str(compiled.get("binary_file") or ""),
            "compile_error": compile_error,
            "compile_command": str(compiled.get("compile_command") or ""),
            "stdout": str(compiled.get("stdout") or ""),
            "stderr": str(compiled.get("stderr") or ""),
            "repair_attempt": repair_counts["compile"],
            "repair_attempts": repair_counts,
            "repair_history": list(failed_attempts),
            "repair_request": request,
            "terminal": False,
            "error": "",
        }
        if compiled["success"] and not request:
            binary = Path(str(compiled.get("binary_file") or "")).resolve()
            if not binary.is_file():
                raise RuntimeError(
                    f"compiler reported success without a binary for {driver_id}"
                )
            if existing is None:
                final_source = store.copy_file_or_validate(
                    source,
                    store.source_path(driver_id, "compile-passed.cc"),
                )
                final_binary = store.copy_file_or_validate(
                    binary,
                    store.binary_path(driver_id, "sanitized.out", "compile_repair"),
                )
            else:
                final_source = source
                final_binary = binary
            binary_provenance = dict(compiled.get("binary_provenance") or {})
            if binary_provenance:
                binary_provenance["binary_path"] = str(final_binary)
            outcome = (
                "pass_first_time"
                if repair_counts["compile"] == 0
                else "fixed"
            )
            if existing is None:
                canonical = {
                    "driver_id": driver_id,
                    "outcome": outcome,
                    "attempts": repair_counts["compile"],
                    "generated_source": str(
                        Path(generated_record["generated_source"]).resolve()
                    ),
                    "source_path": str(final_source),
                    "binary_path": str(final_binary),
                    "binary_provenance": binary_provenance,
                    "error": "",
                    "agent_usage": driver_agent_usage_summary(store, driver_id),
                }
                store.write_json_or_validate(
                    store.stage_result_path("compile_repair", driver_id),
                    canonical,
                )
            record.update(
                outcome=outcome,
                source_path=str(final_source),
                binary_path=str(final_binary),
                binary_provenance=binary_provenance,
                repair_request={},
                terminal=True,
            )
        else:
            failure_origin = "runtime" if compiled["success"] else "compile"
            repair_error = (
                str(request.get("error") or "SAN smoke crashed")
                if failure_origin == "runtime"
                else str(compile_error)
            )
            artifact_paths = (
                [str(path) for path in request.get("artifact_paths", [])]
                if failure_origin == "runtime"
                else []
            )
            origin_attempts = repair_counts[failure_origin]

            if origin_attempts >= max_repair_attempts:
                final_source = source
                if failure_origin == "compile" and existing is None:
                    final_source = store.copy_file_or_validate(
                        source,
                        store.source_path(driver_id, "compile-failed.cc"),
                    )
                    canonical = {
                        "driver_id": driver_id,
                        "outcome": "failed",
                        "attempts": repair_counts["compile"],
                        "generated_source": str(
                            Path(generated_record["generated_source"]).resolve()
                        ),
                        "source_path": str(final_source),
                        "binary_path": "",
                        "error": repair_error,
                        "agent_usage": driver_agent_usage_summary(
                            store,
                            driver_id,
                        ),
                    }
                    store.write_json_or_validate(
                        store.stage_result_path("compile_repair", driver_id),
                        canonical,
                    )
                record.update(
                    outcome="repair_exhausted",
                    success=False,
                    source_path=str(final_source),
                    binary_path="",
                    repair_request=request,
                    failure_origin=failure_origin,
                    terminal=True,
                    error=repair_error,
                )
            else:
                history = [dict(entry) for entry in failed_attempts]
                if origin_attempts and not any(
                    entry.get("kind") == failure_origin
                    and int(entry.get("attempt") or 0) == origin_attempts
                    for entry in history
                ):
                    history.append(
                        {
                            "attempt": origin_attempts,
                            "kind": failure_origin,
                            "source_path": str(source),
                            "error": repair_error,
                        }
                    )

                work_dir = action_dir / "work"
                work_dir.mkdir(parents=True, exist_ok=False)
                work_source = work_dir / f"{driver_id}.cc"
                with work_source.open("xb") as handle:
                    handle.write(source.read_bytes())
                session_dir = store.session_path(driver_id, "repair")
                session_dir.mkdir(parents=True, exist_ok=True)
                session_work_dir = session_dir / "work"
                session_work_dir.mkdir(parents=True, exist_ok=True)
                session_source = session_work_dir / f"{driver_id}.cc"
                session_source.write_bytes(source.read_bytes())
                driver_code = session_source.read_text(encoding="utf-8")
                agent = CompileRepairAgent(
                    library_name,
                    str(session_source),
                    language,
                    max_compile_attempts=max_repair_attempts,
                    quiet=quiet,
                    session_dir=str(session_dir),
                    new_session=not any(repair_counts.values()),
                )
                if failure_origin == "runtime":
                    fixed_code, _ = agent.repair_runtime_error(
                        driver_code,
                        repair_error,
                        artifact_paths=artifact_paths,
                        failed_attempts=_repair_history(
                            history,
                            kind="runtime",
                        ),
                        log_file=str(store.agent_log_path("runtime_repair", driver_id, f"{action_dir.name}.log")),
                    )
                else:
                    fixed_code, _ = agent.repair_compile_error(
                        driver_code,
                        repair_error,
                        failed_attempts=_repair_history(
                            history,
                            kind="compile",
                        ),
                        log_file=str(store.agent_log_path("compile_repair", driver_id, f"{action_dir.name}.log")),
                    )
                attempt = origin_attempts + 1
                updated_counts = dict(repair_counts)
                updated_counts[failure_origin] = attempt
                if failure_origin == "runtime":
                    record.update(
                        verdict=agent.last_verdict or "",
                        evidence=agent.last_reply,
                    )
                if fixed_code:
                    work_source.write_text(fixed_code, encoding="utf-8")
                    record.update(
                        outcome="repair_applied",
                        success=False,
                        source_path=str(work_source.resolve()),
                        binary_path="",
                        repair_attempt=attempt,
                        repair_attempts=updated_counts,
                        repair_history=history,
                        repair_request={},
                        failure_origin=failure_origin,
                    )
                elif failure_origin == "runtime" and agent.last_verdict == "library_bug":
                    # The driver is legal and the crash is the library's own defect:
                    # that crash is the result, not something to repair away.
                    record.update(
                        outcome="library_bug",
                        success=False,
                        repair_attempt=attempt,
                        repair_attempts=updated_counts,
                        repair_history=history,
                        repair_request=request,
                        failure_origin=failure_origin,
                        terminal=True,
                    )
                else:
                    no_edit_error = str(
                        getattr(agent, "_last_validation_error", None)
                        or "Repair Agent made no valid edit"
                    )
                    history.append(
                        {
                            "attempt": attempt,
                            "kind": failure_origin,
                            "source_path": "",
                            "error": no_edit_error,
                        }
                    )
                    terminal = attempt >= max_repair_attempts
                    record.update(
                        outcome=(
                            "repair_exhausted" if terminal else "repair_failed"
                        ),
                        success=False,
                        binary_path="",
                        repair_attempt=attempt,
                        repair_attempts=updated_counts,
                        repair_history=history,
                        repair_request=request,
                        failure_origin=failure_origin,
                        terminal=terminal,
                        error=no_edit_error,
                    )
                    if terminal and failure_origin == "compile" and existing is None:
                        final_source = store.copy_file_or_validate(
                            source,
                            store.source_path(driver_id, "compile-failed.cc"),
                        )
                        canonical = {
                            "driver_id": driver_id,
                            "outcome": "failed",
                            "attempts": attempt,
                            "generated_source": str(
                                Path(
                                    generated_record["generated_source"]
                                ).resolve()
                            ),
                            "source_path": str(final_source),
                            "binary_path": "",
                            "error": repair_error,
                            "agent_usage": driver_agent_usage_summary(
                                store,
                                driver_id,
                            ),
                        }
                        store.write_json_or_validate(
                            store.stage_result_path("compile_repair", driver_id),
                            canonical,
                        )
                        record["source_path"] = str(final_source)
    except Exception as exc:
        record = _compile_action_infrastructure(
            driver_id,
            "compile_repair",
            source_value,
            f"compile stage infrastructure error: {exc}",
            repair_attempt=max(repair_counts.values()),
        )
        record["repair_attempts"] = repair_counts
        record["repair_history"] = list(failed_attempts)
        record["repair_request"] = request
    finally:
        close = getattr(agent, "close", None)
        if callable(close):
            close()
    store.write_json(action_dir / "result.json", record)
    return record


def _repair_history(
    history: Sequence[Mapping[str, Any]],
    *,
    kind: str,
) -> list[dict[str, Any]]:
    result = []
    for entry in history:
        entry_kind = str(entry.get("kind") or "compile")
        if entry_kind != kind:
            continue
        source_path = str(entry.get("source_path") or "")
        fixed_code = (
            Path(source_path).read_text(encoding="utf-8", errors="replace")
            if source_path and Path(source_path).is_file()
            else None
        )
        result.append(
            {
                "attempt": int(entry["attempt"]),
                "fixed_code": fixed_code,
                "compile_error": str(entry.get("error") or ""),
            }
        )
    return result
