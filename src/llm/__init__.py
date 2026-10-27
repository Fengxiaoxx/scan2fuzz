"""
LLM-facing helpers and orchestration support.
"""

from src.llm.provider_config import ModelProviderConfig, resolve_model_name
from src.llm.usage import (
    collect_agent_usage_metrics,
    driver_agent_usage_summary,
    record_agent_call,
    summarize_agent_calls,
)

__all__ = [
    "OpenCodeQueryClient",
    "OpenCodeQueryResult",
    "ModelProviderConfig",
    "resolve_model_name",
    "collect_agent_usage_metrics",
    "driver_agent_usage_summary",
    "record_agent_call",
    "summarize_agent_calls",
]


def __getattr__(name: str):
    """Load the OpenCode transport only when a caller requests it."""
    if name in {"OpenCodeQueryClient", "OpenCodeQueryResult"}:
        from src.llm.opencode_query import OpenCodeQueryClient, OpenCodeQueryResult

        return {
            "OpenCodeQueryClient": OpenCodeQueryClient,
            "OpenCodeQueryResult": OpenCodeQueryResult,
        }[name]
    raise AttributeError(name)
