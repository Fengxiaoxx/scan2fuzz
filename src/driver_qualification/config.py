"""Validated configuration access for driver qualification."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def get_qualification_seconds(config: Mapping[str, Any], key: str) -> int:
    """Return a required duration from the qualification configuration."""
    qualification = config.get("driver_qualification")
    if not isinstance(qualification, Mapping):
        raise ValueError("driver_qualification configuration is required")

    value = qualification.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"driver_qualification.{key} must be a positive integer"
        )
    return value
