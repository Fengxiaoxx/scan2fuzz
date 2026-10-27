"""
Core data structures, configuration, and filesystem helpers.
"""

from src.core.code_utils import (
    normalize_language,
    extract_code_from_markdown,
    generate_git_diff,
)
from src.core.config import (
    DEFAULT_CONCURRENCY,
    load_library_config,
    build_include_paths,
    build_compile_flags,
)
from src.core.driver_names import make_driver_id, resolve_driver_identity
from src.core.file_utils import get_project_root
from src.core.targets import Target, TargetParser

__all__ = [
    "normalize_language",
    "extract_code_from_markdown",
    "generate_git_diff",
    "DEFAULT_CONCURRENCY",
    "load_library_config",
    "build_include_paths",
    "build_compile_flags",
    "get_project_root",
    "make_driver_id",
    "resolve_driver_identity",
    "Target",
    "TargetParser",
]
