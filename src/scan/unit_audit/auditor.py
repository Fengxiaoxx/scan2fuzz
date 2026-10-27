"""One OpenCode session per slice: prompts in, parsed findings out."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger

from src.core import get_project_root
from src.experiment import RunArtifactStore
from src.llm.agent_utils.json_parser import extract_json_object
from src.llm.agent_utils.log_manager import (
    write_agent_transcript,
    write_unit_audit_final_log,
    write_unit_audit_initial_log,
)
from src.llm.opencode_query import OPENCODE_BUILTIN_FILE_TOOLS, OpenCodeQueryClient
from src.llm.usage import _safe_subject_component, record_agent_call
from src.scan.unit_audit.schema import AuditFinding, parse_findings
from src.scan.unit_audit.slicing import Slice

# The largest slices take about 1000 s; a slower one should fail as a timeout.
TURN_TIMEOUT_SECONDS = 2400
TOOLS = OPENCODE_BUILTIN_FILE_TOOLS


@dataclass
class SliceAuditRequest:
    slice_: Slice
    number: int
    source_root: Path
    system_prompt: str
    user_prompt: str
    session_dir: Path


@dataclass
class SliceAuditOutcome:
    """A non-empty `error` means the slice was not audited."""

    number: int
    file: str
    start: int
    end: int
    findings: list[AuditFinding] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=dict)
    seconds: float = 0.0
    error: str = ""
    reused: bool = False  # restored from an earlier attempt of the same run

    def to_dict(self) -> dict[str, Any]:
        return {
            "slice": self.number,
            "file": self.file,
            "start": self.start,
            "end": self.end,
            "finding_count": len(self.findings),
            "usage": self.usage,
            "seconds": round(self.seconds, 1),
            **({"error": self.error} if self.error else {}),
            **({"reused": True} if self.reused else {}),
        }


class OpenCodeSliceAuditor:
    def __init__(self, library_name: str, model: str, *, workers: int = 1) -> None:
        self.library_name = library_name
        self.model = model
        self.workers = workers

    def audit(self, request: SliceAuditRequest) -> SliceAuditOutcome:
        """Never raises: a failed slice is recorded in its outcome and the others go on.

        Like the doc and driver agents, each call leaves attempt-NN.log (prompts, thinking,
        tool calls, raw reply, parsed findings) and agent.jsonl beside its calls.jsonl.
        The outcome is kept as outcome.json, so rerunning the same run's scan audits
        only the slices that have not succeeded yet.
        """
        slice_ = request.slice_
        subject = f"{slice_.file}:{slice_.start}"
        store = RunArtifactStore.from_environment(get_project_root(), self.library_name)
        log_dir = store.usage_path("scan", subject=_safe_subject_component(subject)).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        outcome_file = log_dir / "outcome.json"
        digest = _request_digest(request, self.model)
        reused = _succeeded_outcome(outcome_file, digest, request.number)
        if reused is not None:
            return reused
        outcome = SliceAuditOutcome(request.number, slice_.file, slice_.start, slice_.end)
        attempt = 1 + sum(1 for _ in log_dir.glob("attempt-*.log"))
        log_file = str(log_dir / f"attempt-{attempt:02d}.log")
        write_unit_audit_initial_log(
            log_file,
            self.library_name,
            f"{slice_.file}:{slice_.start}-{slice_.end}",
            self.model,
            request.system_prompt,
            request.user_prompt,
        )
        # The session lives at a neutral path while it runs: OpenCode lists its own
        # directories in permission-denied messages, and the real one names the run and slice.
        live_session = Path(tempfile.mkdtemp(prefix="opencode-"))
        client = OpenCodeQueryClient(
            str(request.source_root),
            client_name="trace2fuzz_unit_audit",
            client_title="Trace2Fuzz Unit Audit",
            session_dir=str(live_session),
            new_session=True,
            timeout_seconds=TURN_TIMEOUT_SECONDS,
            api_key_concurrency=self.workers,
            confine_reads=True,
        )
        started = time.monotonic()
        execution = None
        raw_response = ""
        try:
            execution = client.run(
                prompt=request.user_prompt,
                system_prompt=request.system_prompt,
                model=self.model,
                mcp_config={"mcp": {}},
                configured_tools=list(TOOLS),
                transcript_path=str(log_dir / "agent.jsonl"),
            )
            raw_response = execution.result_text or ""
            outcome.usage = execution.usage or {}
            write_agent_transcript(log_file, execution.transcript)
            payload = extract_json_object(raw_response)
            if payload is None:
                raise ValueError("slice reply carried no JSON object")
            outcome.findings = parse_findings(payload, file=slice_.file, units=slice_.units)
        except Exception as exc:
            outcome.error = f"{type(exc).__name__}: {exc}"
        finally:
            outcome.seconds = time.monotonic() - started
            client.close()
            record_agent_call(
                self.library_name,
                agent="unit_audit_slice",
                stage="scan",
                model=self.model,
                call_index=request.number,
                configured_tools=list(TOOLS),
                result=execution,
                error=outcome.error,
                artifact_path=log_file,
                subject_id=subject,
                subject_kind="unit_audit_slice",
            )
            write_unit_audit_final_log(
                log_file, raw_response, [asdict(finding) for finding in outcome.findings], outcome.error
            )
            outcome_file.write_text(json.dumps({
                "request_digest": digest,
                **outcome.to_dict(),
                "findings": [asdict(finding) for finding in outcome.findings],
            }, ensure_ascii=False, indent=2), encoding="utf-8")
            # Sessions are diagnostics, not audit results. OpenCode can still
            # change its installed dependencies while a cross-device copy runs.
            try:
                if request.session_dir.exists():
                    shutil.rmtree(request.session_dir)
                request.session_dir.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(
                    live_session,
                    request.session_dir,
                    symlinks=True,
                    ignore=shutil.ignore_patterns("node_modules"),
                )
            except OSError as exc:
                logger.warning(
                    "slice {:03d}: session archive failed ({}); audit outcome was saved",
                    request.number,
                    f"{type(exc).__name__}: {str(exc)[:240]}",
                )
            finally:
                shutil.rmtree(live_session, ignore_errors=True)
        return outcome


def _request_digest(request: SliceAuditRequest, model: str) -> str:
    """Identity of one slice audit: the same slice, prompts and model mean the same request."""
    slice_ = request.slice_
    payload = [slice_.file, slice_.start, slice_.end, request.system_prompt, request.user_prompt, model]
    return hashlib.sha256(json.dumps(payload).encode()).hexdigest()


def _succeeded_outcome(path: Path, digest: str, number: int) -> SliceAuditOutcome | None:
    """The outcome of an earlier successful attempt at exactly this request, if any."""
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("request_digest") != digest or data.get("error"):
        return None
    return SliceAuditOutcome(
        # Slice indices can shift when the source set changes. The digest still
        # identifies the same slice content, but reporting uses this run's index.
        number=number,
        file=data["file"],
        start=data["start"],
        end=data["end"],
        findings=[AuditFinding(**finding) for finding in data["findings"]],
        usage=data["usage"],
        seconds=data["seconds"],
        reused=True,
    )
