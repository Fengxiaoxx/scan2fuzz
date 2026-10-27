"""Run Trace2Fuzz agent turns through a local OpenCode server."""

from __future__ import annotations

import json
import fcntl
import math
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from src.llm.provider_config import ModelProviderConfig
from src.llm.api_key_pool import parse_api_keys, shared_api_key_pool, KeyLease, key_fingerprint
from src.llm.provider_transport import ProviderTransport


OPENCODE_BUILTIN_FILE_TOOLS = ("read", "grep", "glob")
OPENCODE_BUILTIN_WEB_TOOLS = ("webfetch", "websearch")
OPENCODE_BUILTIN_EXEC_TOOLS = ("bash",)
OPENCODE_BUILTIN_EDIT_TOOLS = ("write", "edit")
OPENCODE_BUILTIN_CODE_TOOLS = (
    "bash",
    "read",
    "write",
    "edit",
    "grep",
    "glob",
)
OPENCODE_BUILTIN_TOOLS = (
    OPENCODE_BUILTIN_FILE_TOOLS
    + OPENCODE_BUILTIN_WEB_TOOLS
    + OPENCODE_BUILTIN_EXEC_TOOLS
    + OPENCODE_BUILTIN_EDIT_TOOLS
)
OPENCODE_AGENT_NAME = "build"
OPENCODE_AGENT_OPTIONS = {
    "thinking": {"type": "enabled"},
    "reasoningEffort": "high",
}
def chatgpt_login_file() -> Path:
    """Where `opencode auth login` keeps its credentials for the user running the pipeline."""
    data_home = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data_home) / "opencode" / "auth.json"


def chatgpt_reasoning_variant() -> str:
    """The model variant requested for each prompt, which is how the OpenCode client sets reasoning.

    Which variants exist depends on the model (gpt-5.6 and gpt-6 models add "max", gpt-6 has no
    "none"), so the runtime checks the request against the model's own list. OPENCODE_REASONING_EFFORT
    names it: high by default, the effort the other providers use; "off" asks for "none".
    """
    effort = os.environ.get("OPENCODE_REASONING_EFFORT", "").strip().lower() or "high"
    return "none" if effort == "off" else effort


def _checked_temperature(value: float) -> float:
    if not math.isfinite(value) or value < 0:
        raise ValueError("OpenCode temperature must be a finite nonnegative number")
    return value


def temperature_from_environment(environ: Optional[Mapping[str, str]] = None) -> Optional[float]:
    """The sampling temperature a call uses when it does not name one: OPENCODE_TEMPERATURE.

    Unset or empty keeps the provider's own default. A value that is not a finite
    nonnegative number is refused rather than silently ignored, like one passed to
    run(); a call that names its own temperature keeps it.
    """
    raw = (os.environ if environ is None else environ).get("OPENCODE_TEMPERATURE", "").strip()
    if not raw:
        return None
    try:
        return _checked_temperature(float(raw))
    except ValueError:
        raise ValueError(
            f"OPENCODE_TEMPERATURE must be a finite nonnegative number, got {raw!r}"
        ) from None

_FILE_TOOL_COMPAT_NAMES = {
    "bash": "Bash",
    "read": "Read",
    "write": "Write",
    "grep": "Grep",
    "glob": "Glob",
    "edit": "Edit",
    "webfetch": "WebFetch",
    "websearch": "WebSearch",
    "mcp__t2f__Read": "Read",
    "mcp__t2f__Grep": "Grep",
    "mcp__t2f__Glob": "Glob",
}


def _find_opencode_worktree(cwd: Path) -> Path:
    """Mirror OpenCode's nearest-Git-worktree path basis for permissions."""
    resolved = cwd.resolve()
    for directory in (resolved, *resolved.parents):
        if (directory / ".git").exists():
            return directory
    return resolved


@dataclass
class OpenCodeQueryResult:
    """OpenCode output shaped like the result consumed by existing agents."""

    result_text: str
    raw_result: str
    stop_reason: str
    duration_ms: int = 0
    usage: Optional[Dict[str, Any]] = None
    model_usage: Optional[Dict[str, Any]] = None
    is_error: bool = False
    result_message_received: bool = False
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    transcript: List[Dict[str, Any]] = field(default_factory=list)
    user_message_id: str = ""


class OpenCodeQueryClient:
    """Run isolated turns, optionally resuming a persisted OpenCode session."""

    def __init__(
        self,
        cwd: str,
        *,
        client_name: str = "trace2fuzz_agent",
        client_title: str = "Trace2Fuzz Agent",
        provider_config: Optional[ModelProviderConfig] = None,
        timeout_seconds: Optional[int] = None,
        api_key_concurrency: Optional[int] = None,
        session_dir: Optional[str] = None,
        new_session: bool = False,
        editable_file: Optional[str] = None,
        readable_roots: Optional[Sequence[str]] = None,
        confine_reads: bool = False,
    ) -> None:
        self.cwd = str(Path(cwd).resolve())
        self.client_name = client_name
        self.client_title = client_title
        self.provider_config = provider_config or ModelProviderConfig.from_env()
        # The original query client did not impose a per-turn time budget.
        # Only apply a deadline when the caller explicitly configures one.
        if timeout_seconds is None:
            configured_timeout = os.environ.get("OPENCODE_TIMEOUT_SEC", "").strip()
            timeout_seconds = int(configured_timeout) if configured_timeout else None
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("OpenCode timeout_seconds must be positive when configured")
        if (
            api_key_concurrency is not None
            and (
                type(api_key_concurrency) is not int
                or api_key_concurrency < 1
            )
        ):
            raise ValueError("OpenCode api_key_concurrency must be a positive integer")
        self.timeout_seconds = timeout_seconds
        self.api_key_concurrency = api_key_concurrency
        self._slot_cancelled = threading.Event()
        self.session_dir = Path(session_dir).resolve() if session_dir else None
        self.new_session = new_session
        self.editable_file = self._resolve_editable_file(editable_file)
        self.readable_roots = tuple(
            Path(root).resolve(strict=True) for root in (readable_roots or ())
        )
        if any(not root.is_dir() for root in self.readable_roots):
            raise ValueError("readable_roots must contain directories")
        self.confine_reads = confine_reads

    @staticmethod
    def _resolve_editable_file(path: Optional[str]) -> Optional[Path]:
        if path is None:
            return None
        candidate = Path(path)
        if candidate.is_symlink():
            raise ValueError(f"editable_file must not be a symlink: {candidate}")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file():
            raise ValueError(f"editable_file must be a regular file: {resolved}")
        return resolved

    @property
    def has_session(self) -> bool:
        if not self.session_dir or self.new_session:
            return False
        session_file = self.session_dir / "session.json"
        if not session_file.is_file():
            return False
        try:
            saved = json.loads(session_file.read_text(encoding="utf-8"))
            return saved.get("identity", {}).get("cwd") == self.cwd
        except (OSError, ValueError, TypeError):
            return False

    def run(
        self,
        *,
        prompt: str,
        system_prompt: str,
        model: str,
        mcp_config: Mapping[str, Any],
        configured_tools: Sequence[str],
        temperature: Optional[float] = None,
        transcript_path: Optional[str] = None,
        fork_before_message_id: Optional[str] = None,
    ) -> OpenCodeQueryResult:
        from src.llm.journal import append_record

        call_id = uuid.uuid4().hex
        path = Path(transcript_path) if transcript_path else None
        key_events: list[dict] = []

        def on_key_event(event: dict) -> None:
            key_events.append(event)
            if path is not None:
                append_record(path, {**event, "call_id": call_id})

        if path is not None:
            append_record(path, {"type": "request", "call_id": call_id,
                "model": model, "system_prompt": system_prompt, "user_prompt": prompt,
                "configured_tools": configured_tool_names_for_logs(configured_tools),
                "temperature": temperature, "continuation": self.has_session})
        try:
            result = self._run(prompt=prompt, system_prompt=system_prompt, model=model,
                mcp_config=mcp_config, configured_tools=configured_tools, temperature=temperature,
                on_key_event=on_key_event, fork_before_message_id=fork_before_message_id)
        except Exception as exc:
            exc.agent_call_id = call_id
            partial = getattr(exc, "agent_result", None)
            if partial is not None:
                partial.call_id = call_id
                partial.key_events = key_events
            if path is not None:
                append_record(path, {"type": "error", "call_id": call_id, "error": str(exc),
                    "session_id": getattr(partial, "session_id", ""),
                    "transcript": getattr(partial, "transcript", []),
                    "message_usage": getattr(partial, "message_usage", []),
                    "partial": True})
            raise
        result.call_id = call_id
        result.key_events = key_events
        if path is not None:
            append_record(path, {"type": "response", "call_id": call_id,
                "session_id": getattr(result, "session_id", ""), "stop_reason": result.stop_reason,
                "user_message_id": result.user_message_id,
                "transcript": result.transcript, "output": result.result_text,
                "message_usage": getattr(result, "message_usage", []), "usage": result.usage,
                "reasoning_status": "returned" if any(item.get("type") == "thinking"
                    for item in result.transcript) else "not_returned"})
        return result

    def _run(
        self,
        *,
        prompt: str,
        system_prompt: str,
        model: str,
        mcp_config: Mapping[str, Any],
        configured_tools: Sequence[str],
        temperature: Optional[float] = None,
        on_key_event: Optional[Callable[[dict], None]] = None,
        fork_before_message_id: Optional[str] = None,
    ) -> OpenCodeQueryResult:
        if temperature is not None:
            temperature = _checked_temperature(float(temperature))
        else:
            temperature = temperature_from_environment()
        if self.session_dir is not None:
            self.session_dir.mkdir(parents=True, exist_ok=True)
        context = (nullcontext(str(self.session_dir)) if self.session_dir else
                   tempfile.TemporaryDirectory(prefix="opencode-"))
        with context as temp, (Path(temp) / "turn.lock").open("a") as lock:
            # Workflow workers may be different processes, but a session has one writer.
            fcntl.flock(lock, fcntl.LOCK_EX)
            session_file = Path(temp) / "session.json"
            identity = {"cwd": self.cwd, "model": model,
                        "temperature": temperature,
                        "provider": self.provider_config.provider_id}
            saved_session_id = None
            fork_boundary_message_id = None
            preferred_key_index = None
            saved = {}
            if self.has_session:
                saved = json.loads(session_file.read_text(encoding="utf-8"))
                if saved["identity"] != identity:
                    raise ValueError("OpenCode session configuration does not match")
                saved_session_id = saved["session_id"]
                preferred_key_index = saved.get("key_index")
                fork_boundary_message_id = saved.get("fork_boundary_message_id")

            raw_keys = os.environ.get(self.provider_config.api_key_env, "")
            keys = parse_api_keys(raw_keys) if raw_keys else ()
            if preferred_key_index is not None:
                if (
                    type(preferred_key_index) is not int
                    or not 0 <= preferred_key_index < len(keys)
                    or saved.get("key_fingerprint") != key_fingerprint(keys[preferred_key_index])
                ):
                    raise ValueError(
                        "Cannot verify saved session API key binding; restore the original "
                        "key configuration or explicitly start a new session. Legacy sessions "
                        "without a key fingerprint require a new session."
                    )
            lease = None
            if len(keys) > 1:
                pool = shared_api_key_pool(
                    self.provider_config.provider_id,
                    self.provider_config.base_url,
                    keys,
                    concurrency=self.api_key_concurrency,
                )
                lease = pool.acquire(
                    preferred_index=preferred_key_index,
                    timeout=self.timeout_seconds if self.timeout_seconds is not None else 60.0,
                    cancelled=self._slot_cancelled,
                )

            try:
                runtime = _OpenCodeRuntime(
                    cwd=self.cwd,
                    temp_root=Path(temp),
                    title=self.client_title,
                    provider=self.provider_config,
                    model=model,
                    timeout_seconds=self.timeout_seconds,
                    temperature=temperature,
                    editable_file=self.editable_file,
                    readable_roots=self.readable_roots,
                    confine_reads=self.confine_reads,
                    configured_tools=configured_tools,
                    on_key_event=on_key_event,
                    lease=lease,
                )
                if saved_session_id:
                    runtime.session_id = saved_session_id
                try:
                    runtime.start()
                    if fork_before_message_id:
                        if not saved_session_id:
                            raise ValueError("cannot fork an absent OpenCode session")
                        if fork_boundary_message_id != fork_before_message_id:
                            runtime.fork_before_message(fork_before_message_id)
                            fork_boundary_message_id = fork_before_message_id
                    runtime.add_mcp_servers(mcp_config, configured_tools)
                    started = time.monotonic()
                    response = runtime.prompt(
                        prompt=prompt,
                        system_prompt=system_prompt,
                        configured_tools=configured_tools,
                    )
                    duration_ms = int((time.monotonic() - started) * 1000)
                except Exception as exc:
                    partial = getattr(exc, "opencode_response", None)
                    if partial is not None:
                        execution = normalize_opencode_response(partial, model=model,
                            duration_ms=int((time.monotonic() - started) * 1000))
                        normalize_tool_names_for_logs(execution, configured_tools=configured_tools)
                        execution.session_id = runtime.session_id
                        exc.agent_result = execution
                    raise
                finally:
                    runtime.close()
                    if self.session_dir and runtime.session_id:
                        temporary = session_file.with_suffix(".tmp")
                        data = {"identity": identity, "session_id": runtime.session_id}
                        if fork_boundary_message_id:
                            data["fork_boundary_message_id"] = fork_boundary_message_id
                        if lease is not None:
                            data["key_index"] = lease.index
                            data["key_fingerprint"] = key_fingerprint(lease.key)
                        elif keys:
                            data["key_index"] = 0
                            data["key_fingerprint"] = key_fingerprint(keys[0])
                        temporary.write_text(json.dumps(data), encoding="utf-8")
                        temporary.replace(session_file)
                        self.new_session = False
            finally:
                if lease is not None:
                    lease.release()
        result = normalize_opencode_response(
            response,
            model=model,
            duration_ms=duration_ms,
        )
        normalize_tool_names_for_logs(result, configured_tools=configured_tools)
        result.session_id = runtime.session_id
        return result

    def close(self) -> None:
        """Cancel pending slot acquisition; each turn closes its own server."""
        self._slot_cancelled.set()


class _OpenCodeRuntime:
    def __init__(
        self,
        *,
        cwd: str,
        temp_root: Path,
        title: str,
        provider: ModelProviderConfig,
        model: str,
        timeout_seconds: Optional[int],
        temperature: Optional[float] = None,
        editable_file: Optional[Path] = None,
        readable_roots: Sequence[Path] = (),
        confine_reads: bool = False,
        configured_tools: Sequence[str] = (),
        on_key_event: Optional[Callable[[dict], None]] = None,
        lease: Optional[KeyLease] = None,
    ) -> None:
        self.cwd = cwd
        self.temp_root = temp_root
        self.title = title
        self.provider = provider
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.temperature = temperature
        self.editable_file = editable_file
        self.readable_roots = tuple(readable_roots)
        self.confine_reads = confine_reads
        self.configured_tools = tuple(configured_tools)
        self.lease = lease
        self.port = _reserve_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.process: Optional[subprocess.Popen[bytes]] = None
        self.log_path = temp_root / "opencode-server.log"
        self._log_file: Any = None
        self._tmp_dir: Optional[str] = None
        self.session_id = ""
        self.on_key_event = on_key_event
        self._transport: Optional[ProviderTransport] = None
        self._prompt_thread: Optional[threading.Thread] = None
        self._login_link: Optional[Path] = None
        self._variant: Optional[str] = None

    def start(self) -> None:
        binary = os.environ.get("OPENCODE_BINARY", "opencode")
        executable = shutil.which(binary)
        if not executable:
            raise RuntimeError(f"OpenCode executable not found: {binary}")

        credential = None
        if not self.provider.uses_chatgpt_login:
            keys = parse_api_keys(os.environ.get(self.provider.api_key_env, ""))
            credential = keys[0]
            if len(keys) > 1:
                key_to_use = self.lease.key if self.lease else keys[0]
                key_index = self.lease.index if self.lease else 0
                on_rate_limit = self.lease.mark_cooling_down if self.lease else None
                self._transport = ProviderTransport(
                    self.provider.base_url,
                    pool=self.lease.pool if self.lease else None,
                    key=key_to_use,
                    key_index=key_index,
                    on_rate_limit=on_rate_limit,
                    timeout=self.timeout_seconds,
                    on_key_event=self.on_key_event,
                    lease=self.lease,
                )
                self._transport.start()
                credential = self._transport.token

        config_home = self.temp_root / "config"
        data_home = self.temp_root / "data"
        state_home = self.temp_root / "state"
        cache_home = self.temp_root / "cache"
        config_dir = config_home / "opencode"
        config_dir.mkdir(parents=True, exist_ok=True)
        for directory in (data_home, state_home, cache_home):
            directory.mkdir(parents=True, exist_ok=True)
        (config_dir / "opencode.json").write_text(
            json.dumps(self._config(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        if self.provider.uses_chatgpt_login:
            self._link_chatgpt_login(data_home)

        environment = os.environ.copy()
        # Do not mutate the parent environment: workers share it. OpenCode gets
        # a single credential (or the loopback token), never the JSON key list.
        if credential is not None:
            environment[self.provider.api_key_env] = credential
        # OpenCode unpacks its native file-search library (5.5 MB) into TMPDIR on
        # every start and never removes it; a private TMPDIR goes away in close().
        # Neutral names: OpenCode lists these paths in its permission-denied messages.
        self._tmp_dir = tempfile.mkdtemp(prefix="opencode-tmp-")
        environment.update(
            {
                "XDG_CONFIG_HOME": str(config_home),
                "XDG_DATA_HOME": str(data_home),
                "XDG_STATE_HOME": str(state_home),
                "XDG_CACHE_HOME": str(cache_home),
                "TMPDIR": self._tmp_dir,
            }
        )
        self._log_file = self.log_path.open("wb")
        self.process = subprocess.Popen(
            [
                executable,
                "serve",
                "--pure",
                "--hostname",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--print-logs",
                "--log-level",
                "WARN",
            ],
            cwd=self.cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 45
        last_error = ""
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(self._startup_error("OpenCode server exited"))
            try:
                health = self.request("GET", "/global/health", timeout=2)
                if health.get("healthy") is True:
                    break
            except Exception as exc:
                last_error = str(exc)
            time.sleep(0.2)
        else:
            raise RuntimeError(self._startup_error(f"OpenCode server timeout: {last_error}"))
        if self.provider.uses_chatgpt_login:
            self._variant = self._checked_variant()

    def _checked_variant(self) -> str:
        """The requested reasoning variant, if this model has it.

        OpenCode quietly sends its default effort for a variant the model lacks (gpt-5.5 with "max"
        goes out as "medium"), so the request is checked against the model's own variants here.
        """
        requested = chatgpt_reasoning_variant()
        providers = self.request("GET", "/provider", query={"directory": self.cwd})
        models = next((p["models"] for p in providers["all"] if p["id"] == self.provider.provider_id), {})
        if self.model not in models:
            raise ValueError(f"the ChatGPT login does not offer {self.model}; it offers: {', '.join(sorted(models))}")
        variants = list(models[self.model].get("variants") or {})
        if requested not in variants:
            raise ValueError(
                f"{self.model} has no reasoning variant {requested!r}; its variants: {', '.join(variants)}"
            )
        return requested

    def _link_chatgpt_login(self, data_home: Path) -> None:
        """Give this isolated OpenCode the ChatGPT login saved by `opencode auth login`.

        A link rather than a copy: OpenCode rewrites auth.json in place when it refreshes the
        tokens, so through the link every concurrent session keeps the current refresh token.
        close() removes the link, because the session directory is kept with the run's reports.
        """
        shared = chatgpt_login_file()
        login = json.loads(shared.read_text(encoding="utf-8")).get("openai", {}) if shared.is_file() else {}
        if login.get("type") != "oauth":
            raise RuntimeError(
                f"no ChatGPT login for OpenAI in {shared}: run `opencode auth login` and choose "
                "OpenAI, then a ChatGPT Pro/Plus method"
            )
        link = data_home / "opencode" / "auth.json"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(shared)
        self._login_link = link

    def add_mcp_servers(
        self,
        mcp_config: Mapping[str, Any],
        configured_tools: Sequence[str],
    ) -> None:
        raw_servers = mcp_config.get("mcp")
        if not isinstance(raw_servers, Mapping):
            raise ValueError("OpenCode agent requires an explicit MCP configuration")
        remaining = {
            name for name in configured_tools if name.startswith("mcp__")
        }
        unsupported = set(configured_tools) - remaining - set(
            OPENCODE_BUILTIN_TOOLS
        )
        if unsupported:
            raise ValueError(f"unsupported OpenCode tools: {sorted(unsupported)}")
        for server_name, raw_server in raw_servers.items():
            if not isinstance(raw_server, Mapping):
                raise ValueError(f"invalid MCP server configuration: {server_name}")
            bare_tools = raw_server.get("enabled_tools")
            if not isinstance(bare_tools, list):
                raise ValueError(f"MCP server {server_name} requires enabled_tools")
            prefix = f"mcp__{server_name}__"
            selected = [name for name in bare_tools if prefix + name in remaining]
            remaining.difference_update(prefix + name for name in selected)
            if not selected:
                continue
            server_type = str(raw_server.get("type") or "local").lower()
            timeout_ms = int(raw_server.get("tool_timeout_sec", 300)) * 1000
            if server_type == "remote":
                url = str(raw_server.get("url") or "").strip()
                if not url.startswith(("http://", "https://")):
                    raise ValueError(
                        f"MCP server {server_name} requires an absolute remote URL"
                    )
                config = {
                    "type": "remote",
                    "url": url,
                    "headers": {
                        str(key): str(value)
                        for key, value in (raw_server.get("headers") or {}).items()
                    },
                    "oauth": False,
                    "enabled": True,
                    "timeout": timeout_ms,
                }
            elif server_type in {"local", "stdio"}:
                command = [str(raw_server["command"])] + [
                    str(item) for item in raw_server.get("args", [])
                ]
                config = {
                    "type": "local",
                    "command": command,
                    "cwd": str(raw_server.get("cwd") or self.cwd),
                    "environment": {
                        str(key): str(value)
                        for key, value in (raw_server.get("env") or {}).items()
                    },
                    "enabled": True,
                    "timeout": timeout_ms,
                }
            else:
                raise ValueError(
                    f"unsupported MCP server type for {server_name}: {server_type}"
                )
            result = self.request(
                "POST",
                "/mcp",
                query={"directory": self.cwd},
                body={"name": str(server_name), "config": config},
            )
            status = result.get(str(server_name), result.get("status", {}))
            if isinstance(status, Mapping) and status.get("status") not in {
                None,
                "connected",
            }:
                raise RuntimeError(f"MCP server {server_name} failed: {status}")
        if remaining:
            raise ValueError(f"configured tools are not provided by MCP: {sorted(remaining)}")

    def prompt(
        self,
        *,
        prompt: str,
        system_prompt: str,
        configured_tools: Sequence[str],
    ) -> Mapping[str, Any]:
        previous_ids = set()
        if self.session_id:
            previous = self.request("GET", f"/session/{quote(self.session_id)}/message",
                                    query={"directory": self.cwd})
            previous_ids = {message["info"]["id"] for message in previous}
        else:
            self._create_session()
        # The global config denies unconfigured tools. Do not send a wildcard
        # denial here: OpenCode also applies it to external_directory and would
        # override the path-specific source/candidate permissions.
        tools = {_opencode_tool_name(name): True for name in configured_tools}
        return self._send_prompt(prompt, system_prompt, tools, previous_ids)

    def _create_session(self) -> None:
        body: dict[str, Any] = {
            "title": self.title,
            "model": {"id": self.model, "providerID": self.provider.provider_id},
        }
        session = self.request(
            "POST",
            "/session",
            query={"directory": self.cwd},
            body=body,
        )
        self.session_id = str(session["id"])

    def fork_before_message(self, message_id: str) -> None:
        """Continue from the conversation before one failed user turn."""
        if not self.session_id or not message_id:
            raise ValueError("fork requires a session and user message ID")
        session = self.request(
            "POST",
            f"/session/{quote(self.session_id)}/fork",
            query={"directory": self.cwd},
            body={"messageID": message_id},
        )
        new_id = session.get("id") if isinstance(session, Mapping) else None
        if not isinstance(new_id, str) or not new_id or new_id == self.session_id:
            raise ValueError("OpenCode fork returned no new session ID")
        self.session_id = new_id

    def _send_prompt(self, prompt, system_prompt, tools, previous_ids):
        body = {
            "model": {
                "providerID": self.provider.provider_id,
                "modelID": self.model,
            },
            "agent": OPENCODE_AGENT_NAME,
            "system": system_prompt,
            "tools": tools,
            "parts": [{"type": "text", "text": prompt}],
        }
        if self._variant is not None:
            body["variant"] = self._variant
        try:
            response = self._prompt_request(
                "POST",
                f"/session/{quote(self.session_id)}/message",
                query={"directory": self.cwd},
                body=body,
                timeout=self.timeout_seconds,
            )
            history = self.request(
                "GET",
                f"/session/{quote(self.session_id)}/message",
                query={"directory": self.cwd},
            )
            enriched = dict(response)
            enriched["history"] = [message for message in history
                                   if message.get("info", {}).get("id") not in previous_ids]
            self._restore_tool_output_text(enriched)
            return enriched
        except Exception as exc:
            try:
                self.request(
                    "POST",
                    f"/session/{quote(self.session_id)}/abort",
                    query={"directory": self.cwd},
                    body={},
                    timeout=5,
                )
            except Exception:
                pass
            try:
                history = self.request("GET", f"/session/{quote(self.session_id)}/message",
                                       query={"directory": self.cwd}, timeout=5)
                error = {"name": "TransportError", "message": str(exc)}
                partial = {"info": {"error": error},
                           "parts": [], "history": [message for message in history
                               if message.get("info", {}).get("id") not in previous_ids]}
                self._restore_tool_output_text(partial)
                exc.opencode_response = partial
            except Exception:
                pass
            raise

    def _prompt_request(self, *args, **kwargs):
        if self._transport is None:
            return self.request(*args, **kwargs)
        # Propagate local transport failures while OpenCode's prompt is blocked.
        completed = threading.Event()
        outcome: dict[str, Any] = {}

        def send() -> None:
            try:
                outcome["response"] = self.request(*args, **kwargs)
            except Exception as exc:
                outcome["error"] = exc
            finally:
                completed.set()

        self._prompt_thread = threading.Thread(target=send, name="opencode-prompt", daemon=True)
        self._prompt_thread.start()
        while not completed.wait(0.1):
            if self._transport.failure is not None:
                raise self._transport.failure
        if self._transport.failure is not None:
            raise self._transport.failure
        if "error" in outcome:
            raise outcome["error"]
        return outcome["response"]

    def _restore_tool_output_text(self, response: Mapping[str, Any]) -> None:
        """Recover full textual MCP results before the isolated runtime is removed.

        OpenCode can persist a truncated display string plus the path to the
        original output. The old query contract exposed the complete tool text.
        This only restores returned telemetry; it does not change the model's
        context, tool execution, or the persisted OpenCode session.
        """
        messages = [response, *(response.get("history") or [])]
        runtime_root = self.temp_root.resolve()
        for message in messages:
            if not isinstance(message, Mapping):
                continue
            for part in message.get("parts") or []:
                if not isinstance(part, Mapping) or part.get("type") != "tool":
                    continue
                state = part.get("state")
                if not isinstance(state, dict) or state.get("status") != "completed":
                    continue
                metadata = state.get("metadata")
                if not isinstance(metadata, Mapping) or not metadata.get("truncated"):
                    continue
                output_path = metadata.get("outputPath")
                if not isinstance(output_path, str) or not output_path:
                    # Native OpenCode tools can mark bounded results as
                    # truncated. That is the requested tool result, not an
                    # archived MCP output; preserve it without reading more.
                    if part.get("tool") in OPENCODE_BUILTIN_TOOLS:
                        continue
                    raise RuntimeError("OpenCode truncated a tool result without its full output path")
                path = Path(output_path).resolve()
                if not path.is_relative_to(runtime_root):
                    raise RuntimeError("OpenCode full tool output is outside the isolated runtime")
                state["output"] = path.read_text(encoding="utf-8", errors="replace")

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Mapping[str, str]] = None,
        body: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = 30,
    ) -> Any:
        url = self.base_url + path
        if query:
            url += "?" + "&".join(
                f"{quote(str(key))}={quote(str(value))}" for key, value in query.items()
            )
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(
            url,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                payload = response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenCode HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError) as exc:
            raise RuntimeError(f"OpenCode request failed: {exc}") from exc
        if not payload:
            return {}
        return json.loads(payload)

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
        process, self.process = self.process, None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None
        link, self._login_link = self._login_link, None
        if link is not None:
            link.unlink(missing_ok=True)
        tmp_dir, self._tmp_dir = self._tmp_dir, None
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        if self._prompt_thread is not None:
            self._prompt_thread.join(timeout=5)

    def _config(self) -> dict[str, Any]:
        if self.provider.uses_chatgpt_login:
            config = self._chatgpt_login_config()
        else:
            config = self._custom_provider_config()
        permission: dict[str, Any] = {"*": "deny"}
        for tool in self.configured_tools:
            permission[_opencode_tool_name(tool)] = "allow"
        if self.editable_file is not None:
            path = str(self.editable_file)
            edit_patterns = {"*": "deny", path: "allow"}
            worktree = _find_opencode_worktree(Path(self.cwd))
            relative_path = os.path.relpath(self.editable_file, worktree)
            edit_patterns[relative_path] = "allow"

            # OpenCode checks external access against the parent-directory glob,
            # not the full file path. Each Agent candidate lives alone in its
            # session/work directory, so this grants access to that isolated
            # work area without exposing the rest of the session.
            candidate_directory = str(self.editable_file.parent / "*")
            external_patterns = {"*": "deny", candidate_directory: "allow"}
            for root in self.readable_roots:
                external_patterns[str(root)] = "allow"
                external_patterns[str(root / "*")] = "allow"
                external_patterns[str(root / "**")] = "allow"
            permission["edit"] = edit_patterns
            permission["external_directory"] = external_patterns
        elif self.confine_reads:
            # A read-only session that may see nothing outside its working directory.
            permission["external_directory"] = {"*": "deny"}
        config["permission"] = permission
        return config

    def _chatgpt_login_config(self) -> dict[str, Any]:
        """OpenCode's own OpenAI provider and login, configured as the OpenCode client uses them.

        No provider block and no reasoning options here: the reasoning effort travels with each
        prompt as the model's variant (chatgpt_reasoning_variant), as the OpenCode client sends it.
        """
        agent_options: dict[str, Any] = {}
        if self.temperature is not None:
            agent_options["temperature"] = self.temperature
        return {
            "$schema": "https://opencode.ai/config.json",
            "model": f"{self.provider.provider_id}/{self.model}",
            "share": "disabled",
            "autoupdate": False,
            "agent": {
                OPENCODE_AGENT_NAME: agent_options,
            },
        }

    def _custom_provider_config(self) -> dict[str, Any]:
        if not self.provider.is_custom:
            raise ValueError(
                "OpenCode integration requires an explicit custom provider configuration"
            )
        agent_options = dict(OPENCODE_AGENT_OPTIONS)
        # OPENCODE_REASONING_EFFORT overrides the reasoning budget (low/medium/high);
        # "off" disables thinking. Used to measure the speed/quality trade-off.
        effort = os.environ.get("OPENCODE_REASONING_EFFORT", "").strip().lower()
        if effort == "off":
            agent_options["thinking"] = {"type": "disabled"}
            agent_options.pop("reasoningEffort", None)
        elif effort in {"low", "medium", "high"}:
            agent_options["reasoningEffort"] = effort
        model_options: dict[str, Any] = {"name": self.model}
        temperature = getattr(self, "temperature", None)
        if temperature is not None:
            agent_options["temperature"] = temperature
            model_options["temperature"] = True
        return {
            "$schema": "https://opencode.ai/config.json",
            "model": f"{self.provider.provider_id}/{self.model}",
            "provider": {
                self.provider.provider_id: {
                    "npm": "@ai-sdk/openai-compatible",
                    "name": self.provider.provider_id,
                    "options": {
                        "baseURL": self._transport.base_url if self._transport else self.provider.base_url,
                        "apiKey": f"{{env:{self.provider.api_key_env}}}",
                    },
                    "models": {self.model: model_options},
                }
            },
            "share": "disabled",
            "autoupdate": False,
            "agent": {
                OPENCODE_AGENT_NAME: agent_options,
            },
        }

    def _startup_error(self, prefix: str) -> str:
        if self._log_file is not None:
            self._log_file.flush()
        try:
            detail = self.log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            detail = ""
        return f"{prefix}\n{detail}".strip()


def configured_tool_names_for_logs(tool_names: Sequence[str]) -> list[str]:
    return [_FILE_TOOL_COMPAT_NAMES.get(name, name) for name in tool_names]


def normalize_tool_names_for_logs(
    result: Any, *, configured_tools: Optional[Sequence[str]] = None
) -> None:
    aliases: dict[str, str] = {}
    if configured_tools is not None:
        for configured in configured_tools:
            logged = _FILE_TOOL_COMPAT_NAMES.get(configured, configured)
            aliases[configured] = logged
            aliases[_opencode_tool_name(configured)] = logged
    allowed = set(aliases.values()) if configured_tools is not None else None
    for collection_name in ("tool_calls", "transcript"):
        entries = getattr(result, collection_name, []) or []
        retained = []
        for item in entries:
            if isinstance(item, dict):
                name = str(item.get("name") or "")
                if name in aliases:
                    item["name"] = aliases[name]
                elif name in _FILE_TOOL_COMPAT_NAMES:
                    item["name"] = _FILE_TOOL_COMPAT_NAMES[name]
            is_tool = collection_name == "tool_calls" or (
                isinstance(item, dict) and item.get("type") == "tool_call"
            )
            if allowed is not None and is_tool and (
                not isinstance(item, dict) or item.get("name") not in allowed
            ):
                continue
            retained.append(item)
        setattr(result, collection_name, retained)


def normalize_opencode_response(
    response: Mapping[str, Any],
    *,
    model: str,
    duration_ms: int,
) -> OpenCodeQueryResult:
    info = response.get("info") if isinstance(response, Mapping) else None
    parts = response.get("parts") if isinstance(response, Mapping) else None
    info = info if isinstance(info, Mapping) else {}
    parts = parts if isinstance(parts, list) else []
    history = response.get("history") if isinstance(response, Mapping) else None
    user_message_ids = [
        str(message["info"].get("id") or "")
        for message in history or []
        if isinstance(message, Mapping)
        and isinstance(message.get("info"), Mapping)
        and message["info"].get("role") == "user"
    ]
    assistant_messages = [
        message
        for message in history or []
        if isinstance(message, Mapping)
        and isinstance(message.get("info"), Mapping)
        and message["info"].get("role") == "assistant"
    ]
    # History endpoints can include the same message more than once. Keep its
    # newest snapshot once, without counting its tokens or tools twice.
    messages_by_id = {}
    for index, message in enumerate(assistant_messages):
        key = message["info"].get("id") or ("anonymous", index)
        messages_by_id[key] = message
    assistant_messages = list(messages_by_id.values())
    transcript_parts = [
        part
        for message in assistant_messages
        for part in (
            message.get("parts") if isinstance(message.get("parts"), list) else []
        )
    ] or parts
    transcript: list[dict[str, Any]] = []
    tool_calls: list[dict[str, Any]] = []
    # The result is the final reply, not every text emitted during the turn.
    # Collect it directly so a missing part ID cannot leak progress text into
    # the caller's JSON/code parser.
    text_parts = [
        str(part["text"])
        for part in parts
        if isinstance(part, Mapping) and part.get("type") == "text" and part.get("text")
    ]
    seen_parts = {}
    for index, part in enumerate(transcript_parts):
        if not isinstance(part, Mapping):
            continue
        key = ("tool", part.get("callID")) if part.get("type") == "tool" and part.get("callID") else part.get("id") or ("anonymous", index)
        seen_parts[key] = part
    for part in seen_parts.values():
        if not isinstance(part, Mapping):
            continue
        part_type = part.get("type")
        if part_type == "text":
            content = str(part.get("text") or "")
            if content:
                transcript.append({"type": "text", "content": content})
        elif part_type == "reasoning":
            content = str(part.get("text") or "")
            if content:
                transcript.append({"type": "thinking", "content": content})
        elif part_type == "tool":
            entry = _tool_entry(part)
            transcript.append({
                "type": "tool_call",
                "id": entry["id"],
                "turn_index": 1,
                "name": entry["name"],
                "input": entry["input"],
                "output": entry["output_text"],
                "is_error": entry["is_error"],
                "result_received": entry["result_received"],
            })
            tool_calls.append(entry)

    token_sources = [
        message["info"].get("tokens")
        for message in assistant_messages
        if isinstance(message["info"].get("tokens"), Mapping)
    ]
    if not token_sources and isinstance(info.get("tokens"), Mapping):
        token_sources = [info["tokens"]]
    usage = {
        # OpenCode stores uncached input and non-reasoning output separately;
        # these totals add the cached input and the reasoning output back in.
        "input_tokens": sum(
            int(tokens.get("input", 0) or 0)
            + sum(int((tokens.get("cache") or {}).get(field, 0) or 0)
                  for field in ("read", "write"))
            for tokens in token_sources
        ),
        "output_tokens": sum(
            int(tokens.get("output", 0) or 0) + int(tokens.get("reasoning", 0) or 0)
            for tokens in token_sources
        ),
        "cache_read_input_tokens": sum(
            int((tokens.get("cache") or {}).get("read", 0) or 0)
            for tokens in token_sources
            if isinstance(tokens.get("cache"), Mapping)
        ),
    } if token_sources else None
    # The stop reason is the turn's status, not the provider's finish_reason:
    # an earlier failed step is not a failed turn if the final reply recovered.
    error = info.get("error")
    if isinstance(error, Mapping) and error.get("name") == "MessageAbortedError":
        stop_reason = "interrupted"
    elif error or info.get("finish") == "error" or not info:
        stop_reason = "failed"
    else:
        stop_reason = "completed"
    result_text = "\n".join(text_parts)
    result = OpenCodeQueryResult(
        result_text=result_text,
        raw_result=result_text,
        stop_reason=stop_reason,
        duration_ms=duration_ms,
        usage=usage,
        model_usage={
            model: {
                "inputTokens": usage["input_tokens"],
                "outputTokens": usage["output_tokens"],
                "cacheReadInputTokens": usage["cache_read_input_tokens"],
            }
        } if usage is not None else None,
        is_error=stop_reason != "completed",
        result_message_received=bool(info),
        tool_calls=tool_calls,
        transcript=transcript,
        user_message_id=next((value for value in user_message_ids if value), ""),
    )
    # Per-message telemetry rides on the result as an attribute, outside the
    # dataclass fields.
    result.message_usage = [
        {
            "message_id": message["info"].get("id"),
            "model": message["info"].get("modelID", model),
            "provider": message["info"].get("providerID"),
            "tokens": message["info"].get("tokens"),
            "error": message["info"].get("error"),
        }
        for message in (assistant_messages or [{"info": info}])
    ]
    return result


def _tool_entry(part: Mapping[str, Any]) -> dict[str, Any]:
    state = part.get("state") if isinstance(part.get("state"), Mapping) else {}
    status = str(state.get("status") or "")
    output = str(state.get("output") or state.get("error") or "")
    result_received = status in {"completed", "error"}
    if status == "completed":
        # OpenCode's persisted tool state exposes only text. Our MCP tools all
        # return one text block, so wrap it back into the MCP result envelope
        # without parsing or rewriting it.
        raw_output: Any = {
            "content": [{"type": "text", "text": output}],
            "isError": False,
        }
    elif status == "error":
        raw_output = {"message": output}
    else:
        raw_output = None
    name = _legacy_tool_name(str(part.get("tool") or ""))
    return {
        "id": str(part.get("callID") or part.get("id") or ""),
        "name": name,
        "input": state.get("input") or {},
        "output": raw_output,
        "output_text": output,
        "is_error": status == "error",
        "result_received": result_received,
    }


def _opencode_tool_name(name: str) -> str:
    if name in OPENCODE_BUILTIN_TOOLS:
        return name
    if not name.startswith("mcp__") or "__" not in name[5:]:
        raise ValueError(f"invalid Trace2Fuzz MCP tool name: {name}")
    server, tool = name[5:].split("__", 1)
    return _sanitize(server) + "_" + _sanitize(tool)


def _legacy_tool_name(name: str) -> str:
    if name in _FILE_TOOL_COMPAT_NAMES:
        return _FILE_TOOL_COMPAT_NAMES[name]
    prefix = _sanitize("t2f") + "_"
    if name.startswith(prefix):
        return "mcp__t2f__" + name[len(prefix) :]
    return name


def _sanitize(value: str) -> str:
    return "".join(char if char.isalnum() or char in "_-" else "_" for char in value)


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
