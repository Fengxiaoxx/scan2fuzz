"""Deterministic shortest-path ranking for target API candidates."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from typing import Any


def shortest_witness_path(
    successors: Mapping[str, Iterable[str]], source: str, target: str
) -> tuple[str, ...]:
    """Return the lexically deterministic shortest call path."""
    if source == target:
        return (source,)

    parents: dict[str, str | None] = {source: None}
    queue = deque([source])
    while queue:
        caller = queue.popleft()
        for callee in sorted(successors.get(caller, ())):
            if callee in parents:
                continue
            parents[callee] = caller
            if callee == target:
                path = [target]
                node = target
                while parents[node] is not None:
                    node = parents[node]
                    path.append(node)
                return tuple(reversed(path))
            queue.append(callee)

    raise ValueError(f"no call path from {source} to {target}")


def rank_by_path_length(candidates: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order candidates by shortest chain, then ABI symbol."""
    return sorted(candidates, key=lambda item: (item["path_length"], item["abi_symbol"]))
