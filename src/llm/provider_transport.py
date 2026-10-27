"""Loopback transport that performs in-place retries on HTTP 429 and provider hiccups.

Request bodies and successful response bytes pass through unchanged.
When HTTP 429 occurs, it respects Retry-After, marks cooldown, and waits in-place
before retrying on the same key. A Retry-After beyond an hour means the key's quota
is used up: the request moves to another healthy key, or fails when none is left,
instead of waiting out the reset. A failure before any byte reaches OpenCode (no
connection, a 5xx, a stream that breaks before its first chunk) is retried in place
too; a stream that breaks after that ends only its own connection.
"""

from __future__ import annotations

import email.utils
import gzip
import hmac
import http.client
import json
import math
import secrets
import threading
import uuid
import zlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from loguru import logger

from src.llm.api_key_pool import ApiKeyPool, KeyLease


_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}
# Provider hiccups retried in place while OpenCode has received nothing yet.
_TRANSIENT_STATUS = {500, 502, 503, 504}
_MAX_TRANSIENT_RETRIES = 6
# A rate limit that lasts longer than this is a used-up quota, not a pause worth sitting out.
_MAX_IN_PLACE_WAIT = 3600.0
# A key that answered 429 through every retry is left alone this long by new sessions, though
# no Retry-After said when it comes back.
_EXHAUSTED_COOLDOWN = 1800.0
_UPSTREAM_ERRORS = (OSError, http.client.HTTPException)


def _parse_retry_after(header_value: Optional[str], attempt: int) -> float:
    if header_value:
        cleaned = header_value.strip()
        try:
            val = float(cleaned)
            if not math.isfinite(val):
                raise ValueError("Non-finite Retry-After")
            return max(0.01, val)
        except ValueError:
            try:
                parsed_date = email.utils.parsedate_to_datetime(cleaned)
                diff = (parsed_date - datetime.now(timezone.utc)).total_seconds()
                if diff > 0:
                    return diff
            except Exception:
                pass
    base = min(60.0, 2.0 * (2 ** (attempt - 1)))
    return base + secrets.randbelow(1000) / 1000.0


def _describe_429(exc: HTTPError) -> str:
    """What the provider said with a 429: a used-up quota usually names which limit and when it resets."""
    headers = {name: value[:80] for name, value in exc.headers.items() if name.lower() not in ("date", "connection")}
    try:
        raw = exc.read(4096)
        encoding = exc.headers.get("Content-Encoding", "").lower()
        if "gzip" in encoding:
            raw = gzip.decompress(raw)
        elif "deflate" in encoding:
            raw = zlib.decompress(raw)
        body = " ".join(raw.decode("utf-8", "replace").split())[:400]
    except (OSError, EOFError, zlib.error):
        body = "(unreadable)"
    return f"headers={headers} body={body}"


def _read_chunk(response) -> bytes:
    """The next piece of the reply; a fixed-length reply cut short is a broken stream too."""
    chunk = response.read1(64 * 1024)
    remaining = getattr(response, "length", None)  # an HTTPError body may carry none
    if not chunk and remaining:
        raise http.client.IncompleteRead(b"", remaining)
    return chunk


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _reply(handler: BaseHTTPRequestHandler, status: int, message: str) -> None:
    body = json.dumps({"error": {"message": message}}).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class ProviderTransport:
    """One OpenCode runtime's transport on a leased key, retrying 429s and provider hiccups in place."""

    def __init__(
        self,
        base_url: str,
        pool: Optional[ApiKeyPool] = None,
        *,
        key: Optional[str] = None,
        key_index: int = 0,
        on_rate_limit: Optional[Callable[[float], None]] = None,
        timeout: Optional[float] = None,
        on_key_event: Optional[Callable[[dict], None]] = None,
        lease: Optional[KeyLease] = None,
    ) -> None:
        self._url = base_url.rstrip("/") + "/chat/completions"
        self.pool = pool
        self.lease = lease  # lets a request leave a key whose quota is used up
        if key is not None:
            self.key = key
            self.key_index = key_index
        elif pool is not None:
            self.key = pool.get_key(key_index)
            self.key_index = key_index
            if on_rate_limit is None:
                on_rate_limit = lambda wait_sec: pool.mark_cooling_down(key_index, wait_sec)
        else:
            raise ValueError("ProviderTransport requires either key or pool")

        if pool is not None and on_rate_limit is None:
            on_rate_limit = lambda wait_sec: pool.mark_cooling_down(key_index, wait_sec)

        self.on_rate_limit = on_rate_limit
        self.timeout = timeout
        self.on_key_event = on_key_event
        self.token = secrets.token_urlsafe(32)
        self.failure: Optional[Exception] = None
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._stopped = threading.Event()

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("Provider transport is not running")
        return f"http://127.0.0.1:{self._server.server_port}/v1"

    def start(self) -> None:
        self._stopped.clear()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            # HTTP/1.1 so a streamed reply can be chunked: a cut stream then arrives
            # without its terminating chunk, which OpenCode sees as an error.
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_POST(self):
                if self.path != "/v1/chat/completions":
                    _reply(self, 404, "Unsupported model endpoint")
                    return
                if not hmac.compare_digest(
                    self.headers.get("Authorization", ""), "Bearer " + owner.token
                ):
                    _reply(self, 401, "Invalid local transport credential")
                    return
                try:
                    length = int(self.headers.get("Content-Length", "-1"))
                    if length < 0 or self.headers.get("Transfer-Encoding"):
                        raise ValueError
                except ValueError:
                    _reply(self, 400, "A Content-Length request body is required")
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    _reply(self, 400, "Incomplete request body")
                    return
                try:
                    owner._forward(self, body)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # The OpenCode session was closed; never replay its request.
                except Exception as exc:
                    owner.failure = exc
                    self.close_connection = True

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.1},
            name="provider-transport",
            daemon=True,
        )
        self._thread.start()

    def _forward(self, handler: BaseHTTPRequestHandler, body: bytes) -> None:
        blocked_headers = _HOP_HEADERS | {"host", "authorization", "content-length"}
        blocked_headers.update(
            name.strip().lower() for name in handler.headers.get("Connection", "").split(",")
        )
        headers = {
            name: value
            for name, value in handler.headers.items()
            if name.lower() not in blocked_headers
        }
        request_id = uuid.uuid4().hex
        attempt = 0
        max_429_retries = 5
        transient = 0
        while not self._stopped.is_set():
            # Existing sessions must respect cooldown extensions by other requests.
            if self.pool is not None:
                remaining = self.pool.cooldown_remaining(self.key_index)
                if remaining > 0:
                    self._stopped.wait(min(remaining, 0.1))
                    continue
            attempt += 1
            request = Request(
                self._url,
                data=body,
                headers={**headers, "Authorization": "Bearer " + self.key},
            )
            try:
                response = build_opener(_NoRedirect()).open(request, timeout=self.timeout)
            except HTTPError as exc:
                if exc.code in _TRANSIENT_STATUS and transient < _MAX_TRANSIENT_RETRIES:
                    transient += 1
                    exc.close()
                    self._retry_transient(request_id, transient, "status", f"HTTP {exc.code}")
                    continue
                if exc.code != 429:
                    response = exc
                else:
                    retry_after_str = exc.headers.get("Retry-After") if exc.headers else None
                    wait_sec = _parse_retry_after(retry_after_str, attempt)
                    if attempt == 1:  # never passed on to OpenCode, so reading the body is safe
                        logger.warning("Model HTTP 429 for key {} said: {}", self.key_index + 1, _describe_429(exc))
                    if self.on_rate_limit is not None:
                        self.on_rate_limit(wait_sec)
                    left_key = self.key_index
                    # A Retry-After beyond an hour names a used-up quota; a key that keeps
                    # answering 429 through every retry is one too, though it names no reset.
                    exhausted = wait_sec > _MAX_IN_PLACE_WAIT or attempt > max_429_retries
                    if exhausted:
                        exc.close()
                        if self.on_rate_limit is not None:
                            self.on_rate_limit(max(wait_sec, _EXHAUSTED_COOLDOWN))
                    switched = exhausted and self.lease is not None and self.lease.switch(self._stopped)
                    if switched:
                        self.key, self.key_index = self.lease.key, self.lease.index
                    event = {
                        "type": "provider_rate_limit",
                        "recorded_at": datetime.now(timezone.utc).isoformat(),
                        "request_id": request_id,
                        "attempt": attempt,
                        "status_code": 429,
                        "key_index": left_key + 1,
                        "next_key_index": self.key_index + 1,
                        "key_count": self.pool.count if self.pool else 1,
                        "wait_seconds": wait_sec,
                        "retry_exhausted": exhausted and not switched,
                    }
                    if self.on_key_event is not None:
                        self.on_key_event(event)
                    if exhausted:
                        if not switched:
                            reason = (
                                f"is rate limited for {wait_sec:.0f}s"
                                if wait_sec > _MAX_IN_PLACE_WAIT
                                else "kept answering HTTP 429"
                            )
                            raise RuntimeError(f"API key {left_key + 1} {reason} and no other key is available")
                        logger.warning(
                            "Model HTTP 429 for key {}: {}, serving the request from key {} instead",
                            left_key + 1,
                            f"Retry-After {wait_sec:.0f}s" if wait_sec > _MAX_IN_PLACE_WAIT else "429 on every retry",
                            self.key_index + 1,
                        )
                        attempt = 0
                        continue
                    exc.close()
                    logger.warning(
                        "Model HTTP 429 for key {}: waiting {:.1f}s in-place before retry (attempt {}/{})",
                        self.key_index + 1,
                        wait_sec,
                        attempt,
                        max_429_retries,
                    )
                    self._stopped.wait(wait_sec)
                    continue
            except _UPSTREAM_ERRORS as exc:
                if transient < _MAX_TRANSIENT_RETRIES:
                    transient += 1
                    self._retry_transient(request_id, transient, "connect", exc)
                    continue
                # Let OpenCode apply its existing upstream-error retry policy.
                _reply(handler, 502, f"Model provider connection failed: {exc}")
                return

            with response:
                # Read ahead before any header goes out: a stream that breaks before its
                # first chunk can still be retried here, unseen by the OpenCode session.
                try:
                    chunk = _read_chunk(response)
                except _UPSTREAM_ERRORS as exc:
                    if transient < _MAX_TRANSIENT_RETRIES:
                        transient += 1
                        self._retry_transient(request_id, transient, "first_chunk", exc)
                        continue
                    _reply(handler, 502, f"Model provider stream failed: {exc}")
                    return
                handler.send_response(response.status)
                blocked = _HOP_HEADERS | {
                    name.strip().lower()
                    for name in response.headers.get("Connection", "").split(",")
                }
                framed = response.headers.get("Content-Length") is None
                for name, value in response.headers.items():
                    if name.lower() not in blocked:
                        handler.send_header(name, value)
                if framed:
                    handler.send_header("Transfer-Encoding", "chunked")
                handler.end_headers()
                while chunk:
                    handler.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk) if framed else chunk)
                    handler.wfile.flush()
                    try:
                        chunk = _read_chunk(response)
                    except _UPSTREAM_ERRORS as exc:
                        # Part of the reply already reached OpenCode: end only this
                        # connection so OpenCode retries it, never abort the session.
                        self._record_transient(request_id, transient + 1, "stream", exc, retrying=False)
                        handler.close_connection = True
                        return
                if framed:
                    handler.wfile.write(b"0\r\n\r\n")
                    handler.wfile.flush()
            return

    def _record_transient(
        self, request_id: str, attempt: int, phase: str, error: object, *, retrying: bool
    ) -> None:
        logger.warning(
            "Model provider {} failure for key {} ({}): {}",
            phase,
            self.key_index + 1,
            f"retry {attempt}/{_MAX_TRANSIENT_RETRIES} in place" if retrying else "left to OpenCode",
            error,
        )
        if self.on_key_event is not None:
            self.on_key_event({
                "type": "provider_transient_failure",
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
                "phase": phase,
                "attempt": attempt,
                "key_index": self.key_index + 1,
                "error": str(error)[:500],
                "retrying_in_place": retrying,
            })

    def _retry_transient(self, request_id: str, attempt: int, phase: str, error: object) -> None:
        self._record_transient(request_id, attempt, phase, error, retrying=True)
        self._stopped.wait(_parse_retry_after(None, attempt))

    def close(self) -> None:
        self._stopped.set()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join()
            self._thread = None
