"""API key slot pool that spreads LLM calls evenly over the keys, with in-place cooldown."""

from __future__ import annotations

import json
import hashlib
import math
import time
from concurrent.futures import CancelledError
from threading import Condition, Event, Lock
from typing import Optional


def parse_api_keys(value: str) -> tuple[str, ...]:
    """Accept the existing single credential or a JSON array of credentials."""
    value = value.strip()
    if value.startswith("["):
        try:
            keys = json.loads(value)
        except ValueError:
            raise ValueError("LLM_API_KEY must be a valid JSON list of keys") from None
    else:
        keys = [value]
    if not keys or any(not isinstance(key, str) or not key.strip() for key in keys):
        raise ValueError("LLM_API_KEY must contain at least one non-empty key")
    keys = tuple(key.strip() for key in keys)
    if any("\r" in key or "\n" in key for key in keys):
        raise ValueError("LLM_API_KEY keys must not contain line breaks")
    if len(set(keys)) != len(keys):
        raise ValueError("LLM_API_KEY contains duplicate keys")
    return keys


def calculate_capacities(keys_count: int, concurrency: int) -> list[int]:
    """Per-key slot limit: every key's even share of the concurrency, rounded up.

    The pool also caps its total at the concurrency, so the shares never add up to
    more than that; rounding up keeps every key usable when there are more keys
    than concurrent calls.
    """
    if keys_count <= 0:
        raise ValueError("At least one API key is required")
    return [math.ceil(max(1, concurrency) / keys_count)] * keys_count


_process_concurrency: Optional[int] = None


def configure_concurrency(concurrency: int) -> None:
    """Fix this process's simultaneous LLM calls: each stage CLI passes its --concurrency."""
    global _process_concurrency
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency < 1:
        raise ValueError("concurrency must be a positive integer")
    _process_concurrency = concurrency


def resolve_concurrency(explicit: Optional[int] = None) -> int:
    if explicit is not None and explicit > 0:
        return explicit
    if _process_concurrency is not None:
        return _process_concurrency
    from src.core.config import DEFAULT_CONCURRENCY
    return DEFAULT_CONCURRENCY


class KeyLease:
    """A slot leased from the pool for one agent execution turn."""

    def __init__(self, pool: "ApiKeyPool", index: int, key: str) -> None:
        self.pool = pool
        self.index = index
        self.key = key
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._released = True
            self.pool.release(self.index)

    def mark_cooling_down(self, duration: float) -> None:
        self.pool.mark_cooling_down(self.index, duration)

    def switch(self, cancelled: Optional[Event] = None, wait: float = 1800.0) -> bool:
        """Move to another healthy key, giving up the slot on the one in use.

        A healthy key whose slots are all busy is waited for, up to `wait` seconds: its calls
        finish and free one. Returns False at once when every key is cooling down, and
        after `wait` when none frees a slot; the lease then holds nothing and its later
        release is a no-op.
        """
        self.release()
        if all(self.pool.is_cooling_down(i) for i in range(self.pool.count)):
            return False
        try:
            replacement = self.pool.acquire(cancelled=cancelled, timeout=wait)
        except TimeoutError:
            return False
        self.index, self.key, self._released = replacement.index, replacement.key, False
        return True

    def __enter__(self) -> "KeyLease":
        return self

    def __exit__(self, *args) -> None:
        self.release()


class ApiKeyPool:
    """Thread-safe key pool: at most `concurrency` calls, spread evenly over the keys."""

    def __init__(self, keys: tuple[str, ...], concurrency: Optional[int] = None) -> None:
        self._keys = keys
        self._concurrency = resolve_concurrency(concurrency)
        self._capacities = calculate_capacities(len(keys), self._concurrency)
        self._active = [0] * len(keys)
        self._last_leased = [0] * len(keys)
        self._leases = 0
        self._cool_down_until = [0.0] * len(keys)
        self._lock = Lock()
        self._cond = Condition(self._lock)

    @property
    def count(self) -> int:
        return len(self._keys)

    @property
    def concurrency(self) -> int:
        return self._concurrency

    @property
    def capacities(self) -> tuple[int, ...]:
        return tuple(self._capacities)

    @property
    def active_counts(self) -> tuple[int, ...]:
        with self._lock:
            return tuple(self._active)

    def get_key(self, index: int) -> str:
        return self._keys[index % self.count]

    def acquire(
        self,
        preferred_index: Optional[int] = None,
        timeout: Optional[float] = 60.0,
        cancelled: Optional[Event] = None,
    ) -> KeyLease:
        """Lease the healthy key with the fewest active calls.

        Ties go to the session's own key (preferred_index), then to the key leased
        least recently, so light load still rotates over every key. Balance comes
        first: a call never waits for one particular key while another is free.
        """
        if preferred_index is not None:
            if type(preferred_index) is not int or not 0 <= preferred_index < self.count:
                raise ValueError("Saved API key index is invalid")
        if timeout is not None and (not math.isfinite(timeout) or timeout < 0):
            raise ValueError("Slot timeout must be finite and nonnegative")
        deadline = (time.monotonic() + timeout) if timeout is not None else None
        with self._lock:
            while True:
                if cancelled is not None and cancelled.is_set():
                    raise CancelledError("API key slot wait cancelled")
                now = time.monotonic()
                target_index = None
                candidates = [
                    i
                    for i in range(self.count)
                    if (
                        now >= self._cool_down_until[i]
                        and self._active[i] < self._capacities[i]
                    )
                ]
                if candidates and sum(self._active) < self._concurrency:
                    least = min(self._active[i] for i in candidates)
                    balanced = [i for i in candidates if self._active[i] == least]
                    target_index = (
                        preferred_index
                        if preferred_index in balanced
                        else min(balanced, key=lambda i: self._last_leased[i])
                    )

                if target_index is not None:
                    self._active[target_index] += 1
                    self._leases += 1
                    self._last_leased[target_index] = self._leases
                    return KeyLease(self, target_index, self._keys[target_index])

                wait_time = None
                future_cooldowns = [
                    self._cool_down_until[i] - now
                    for i in range(self.count)
                    if self._cool_down_until[i] > now
                ]
                if future_cooldowns:
                    wait_time = min(future_cooldowns)

                if deadline is not None:
                    remaining = deadline - now
                    if remaining <= 0:
                        raise TimeoutError("Timed out waiting for an available API key slot")
                    wait_time = remaining if wait_time is None else min(wait_time, remaining)

                self._cond.wait(timeout=min(wait_time, 0.1) if wait_time is not None else 0.1)

    def release(self, index: int) -> None:
        with self._lock:
            if 0 <= index < self.count and self._active[index] > 0:
                self._active[index] -= 1
            self._cond.notify_all()

    def mark_cooling_down(self, index: int, duration: float) -> None:
        if not math.isfinite(duration) or duration < 0:
            raise ValueError("Cooldown must be finite and nonnegative")
        with self._lock:
            if 0 <= index < self.count:
                now = time.monotonic()
                self._cool_down_until[index] = max(self._cool_down_until[index], now + duration)
            self._cond.notify_all()

    def is_cooling_down(self, index: int) -> bool:
        with self._lock:
            if 0 <= index < self.count:
                return time.monotonic() < self._cool_down_until[index]
            return False

    def cooldown_remaining(self, index: int) -> float:
        with self._lock:
            return max(0.0, self._cool_down_until[index] - time.monotonic())


def key_fingerprint(key: str) -> str:
    """Persist a credential identity without storing the credential itself."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


_pools: dict[tuple[str, str, tuple[str, ...]], ApiKeyPool] = {}
_pools_lock = Lock()


def shared_api_key_pool(
    provider: str,
    base_url: str,
    keys: tuple[str, ...],
    concurrency: Optional[int] = None,
) -> ApiKeyPool:
    """Share accounting and cooldowns; reject conflicting limits in this process.

    The first caller establishes the capacity for this provider and ordered
    credential group. A subsequent call cannot change it or create a second
    pool, even when all leases are released: cooldowns may still be active.
    """
    effective_concurrency = resolve_concurrency(concurrency)
    identity = (provider, base_url, keys)
    with _pools_lock:
        pool = _pools.get(identity)
        if pool is None:
            pool = ApiKeyPool(keys, concurrency=effective_concurrency)
            _pools[identity] = pool
        elif pool.concurrency != effective_concurrency:
            raise ValueError(
                "Conflicting API key concurrency in this process: "
                f"existing={pool.concurrency}, requested={effective_concurrency}. "
                "Use the same concurrency for callers sharing these credentials."
            )
        return pool
