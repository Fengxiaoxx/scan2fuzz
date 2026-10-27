"""Project filesystem location."""

from pathlib import Path


# Project root is two levels above this file (src/core/file_utils.py).
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def get_project_root() -> Path:
    """Return absolute project root"""
    return PROJECT_ROOT

