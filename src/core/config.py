#!/usr/bin/env python3
"""
Configuration Loader - Centralized config reading utility
"""

import os
import yaml
from pathlib import Path
from pathlib import PurePosixPath
from typing import List


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONCURRENCY = 4  # default of every LLM-facing --concurrency; builds use all CPUs
COMPILE_CONFIG_KEYS = {
    "analysis_library",
    "sanitize_library",
    "coverage_library",
    "additional_libs",
}
CONFIG_KEYS = {
    "language",
    "compile_config",
    "driver_qualification",
}
OPTIONAL_CONFIG_KEYS = {"public_api", "unit_audit"}
DRIVER_QUALIFICATION_KEYS = {"chunk_seconds", "max_total_time"}
PUBLIC_API_KEYS = {
    "entry_headers",
    "c_standard",
    "cpp_standard",
    "include_dirs",
    "include_transitive_declarations",
}
UNIT_AUDIT_KEYS = {"exclude_installed_header_prefixes"}
BUILD_VARIANTS = {"analysis", "sanitize", "coverage", "aflpp"}


def _require_positive_integer(
    config: dict,
    key: str,
    config_path: Path,
    *,
    label: str | None = None,
) -> int:
    value = config.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"{label or key} must be a positive integer: {config_path}"
        )
    return value


def load_library_config(library: str) -> dict:
    """
    Load configuration for a specific library

    Args:
        library: Library name (e.g., 'cjson', 'libaom')

    Returns:
        Validated library configuration
    """
    frozen_run = "RUN_DIR" in os.environ or "RUN_ID" in os.environ
    if frozen_run:
        from src.experiment import RunArtifactStore

        store = RunArtifactStore.from_environment(PROJECT_ROOT, library)
        config_path = store.safe_path("config/config.yaml")
    else:
        config_path = PROJECT_ROOT / "info_lib" / library / "config.yaml"

    if not config_path.is_file():
        raise FileNotFoundError(f"library config not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict):
        raise ValueError(f"library config must be a YAML mapping: {config_path}")

    # Concurrency is a per-stage --concurrency parameter now; the frozen configs
    # of earlier runs still carry it and stay readable.
    config.pop("concurrency", None)
    config.pop("llm_concurrency", None)
    qualification = config.get("driver_qualification")
    if isinstance(qualification, dict):
        qualification.pop("workers", None)

    if not CONFIG_KEYS.issubset(config) or set(config) - (
        CONFIG_KEYS | OPTIONAL_CONFIG_KEYS
    ):
        raise ValueError(
            "library config must contain required keys "
            f"{sorted(CONFIG_KEYS)} and optional keys {sorted(OPTIONAL_CONFIG_KEYS)}: "
            f"{config_path}"
        )

    if config["language"] not in {"c", "cpp"}:
        raise ValueError(f"language must be 'c' or 'cpp': {config_path}")

    compile_config = config.get("compile_config")
    if not isinstance(compile_config, dict):
        raise ValueError(f"compile_config must be a YAML mapping: {config_path}")
    if set(compile_config) != COMPILE_CONFIG_KEYS:
        raise ValueError(
            f"compile_config must contain exactly {sorted(COMPILE_CONFIG_KEYS)}: "
            f"{config_path}"
        )
    for key in ("analysis_library", "sanitize_library", "coverage_library"):
        if not isinstance(compile_config[key], str):
            raise ValueError(f"compile_config.{key} must be a string: {config_path}")
    additional_libs = compile_config["additional_libs"]
    if not isinstance(additional_libs, list) or not all(
        isinstance(value, str) and value for value in additional_libs
    ):
        raise ValueError(
            f"compile_config.additional_libs must be a list of strings: "
            f"{config_path}"
        )

    qualification = config.get("driver_qualification")
    if (
        not isinstance(qualification, dict)
        or set(qualification) != DRIVER_QUALIFICATION_KEYS
    ):
        raise ValueError(
            "driver_qualification must contain exactly "
            f"{sorted(DRIVER_QUALIFICATION_KEYS)}: "
            f"{config_path}"
        )
    for key in DRIVER_QUALIFICATION_KEYS:
        _require_positive_integer(
            qualification,
            key,
            config_path,
            label=f"driver_qualification.{key}",
        )

    unit_audit = config.get("unit_audit")
    if unit_audit is not None:
        if not isinstance(unit_audit, dict) or set(unit_audit) != UNIT_AUDIT_KEYS:
            raise ValueError(
                f"unit_audit must contain exactly {sorted(UNIT_AUDIT_KEYS)}: {config_path}"
            )
        prefixes = unit_audit["exclude_installed_header_prefixes"]
        if not isinstance(prefixes, list) or not all(
            isinstance(prefix, str)
            and prefix.endswith("/")
            and not prefix.startswith("/")
            and all(part not in ("", ".", "..") for part in prefix[:-1].split("/"))
            for prefix in prefixes
        ):
            raise ValueError(
                "unit_audit.exclude_installed_header_prefixes must be relative "
                f"include directory prefixes: {config_path}"
            )

    public_api = config.get("public_api")
    if public_api is not None:
        # Old run snapshots can contain this removed extraction option. Their
        # scan/preprocess artifacts are already frozen; driver rounds use those
        # artifacts and do not need to reinterpret the old option.
        if (
            frozen_run
            and isinstance(public_api, dict)
            and "header_templates" in public_api
        ):
            if not isinstance(public_api["header_templates"], bool):
                raise ValueError(
                    f"public_api.header_templates must be boolean: {config_path}"
                )
            public_api.pop("header_templates")
        if not isinstance(public_api, dict) or set(public_api) - PUBLIC_API_KEYS:
            raise ValueError(
                f"public_api may contain only {sorted(PUBLIC_API_KEYS)}: {config_path}"
            )
        entry_headers = public_api.get("entry_headers")
        if not isinstance(entry_headers, list) or not entry_headers or not all(
            isinstance(header, str) and header for header in entry_headers
        ):
            raise ValueError(
                f"public_api.entry_headers must be a non-empty list of strings: "
                f"{config_path}"
            )
        c_standard = public_api.get("c_standard", "c11")
        if c_standard not in {"c11", "gnu11"}:
            raise ValueError(
                f"public_api.c_standard must be c11 or gnu11: {config_path}"
            )
        cpp_standard = public_api.get("cpp_standard", "c++17")
        if cpp_standard not in {"c++17", "c++20", "c++23"}:
            raise ValueError(
                "public_api.cpp_standard must be c++17, c++20, or c++23: "
                f"{config_path}"
            )
        include_transitive = public_api.get(
            "include_transitive_declarations", True
        )
        if not isinstance(include_transitive, bool):
            raise ValueError(
                "public_api.include_transitive_declarations must be boolean: "
                f"{config_path}"
            )
        include_dirs = public_api.get("include_dirs", [])
        if not isinstance(include_dirs, list) or not all(
            isinstance(value, str) and value for value in include_dirs
        ):
            raise ValueError(
                f"public_api.include_dirs must be a list of strings: {config_path}"
            )
        for value in include_dirs:
            relative = PurePosixPath(value)
            if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                raise ValueError(
                    "public_api.include_dirs entries must be normalized relative "
                    f"paths: {config_path}"
                )
    return config


def build_include_paths(
    library_name: str, variant: str, *, run_dir: Path | None = None
) -> List[str]:
    """
    Build include paths for library headers

    New runs compile against the frozen installed public headers only. Legacy
    runs without that scan artifact retain the original source/build includes.

    Args:
        library_name: Library name (e.g., 'cjson', 'libaom')
        variant: Build variant whose generated headers must match the linked library

    Returns:
        List of include flags (e.g., ['-Itest_lib/libaom', '-Itest_lib/libaom/build_sanitize'])
    """
    if variant not in BUILD_VARIANTS:
        raise ValueError(f"unknown build variant: {variant}")

    include_flags = []
    test_lib_path = PROJECT_ROOT / "test_lib" / library_name

    selected_run_dir = run_dir or os.environ.get("RUN_DIR")
    if selected_run_dir:
        scan_dir = Path(selected_run_dir) / "stages" / "scan"
        frozen_include = scan_dir / "public-install" / "include"
        if frozen_include.is_dir():
            include_roots = [frozen_include]
            config = load_library_config(library_name)
            for relative in config.get("public_api", {}).get("include_dirs", []):
                candidate = (frozen_include / relative).resolve(strict=True)
                candidate.relative_to(frozen_include.resolve(strict=True))
                if not candidate.is_dir():
                    raise NotADirectoryError(candidate)
                include_roots.append(candidate)
            return [f"-I{path}" for path in include_roots]
        if (scan_dir / "build-result.json").is_file():
            raise FileNotFoundError(
                f"run-frozen public include directory is missing: {frozen_include}"
            )

    if test_lib_path.exists():
        # Source root (for API headers)
        include_flags.append(f"-I{test_lib_path}")

        # Public headers directory (commonly named include/) — needed when a
        # header in src/ transitively includes a public header by its bare name.
        public_include = test_lib_path / "include"
        if public_include.exists():
            include_flags.append(f"-I{public_include}")

        config = load_library_config(library_name)
        for relative in config.get("public_api", {}).get("include_dirs", []):
            candidate = test_lib_path / relative
            if candidate.is_dir():
                include_flags.append(f"-I{candidate}")

        # Build directory (for generated config headers like config/aom_config.h)
        # This is needed because headers may transitively include "config/..." files
        build_path = test_lib_path / f"build_{variant}"
        if build_path.exists():
            include_flags.append(f"-I{build_path}")

        # Autoconf and CMake commonly place generated public headers here
        # (for example c-ares' ares_build.h).
        generated_include = build_path / "include"
        if generated_include.is_dir():
            include_flags.append(f"-I{generated_include}")

        installed_include = build_path / "work" / "include"
        if installed_include.exists():
            include_flags.append(f"-I{installed_include}")

    return include_flags


def build_compile_flags(
    library_name: str,
    *,
    library_variant: str = "sanitize",
    run_dir: Path | None = None,
) -> str:
    """
    Build compilation flags from library config

    Args:
        library_name: Library name (e.g., 'cjson', 'libaom')
        library_variant: The reachability sanitizer archive or a separate
            AFL++ sanitizer archive used only by final comparison fuzzing.

    Returns:
        Compilation flags string
    """
    config = load_library_config(library_name)

    if library_variant not in {"sanitize", "aflpp"}:
        raise ValueError(f"unknown library variant: {library_variant}")
    compile_config = config['compile_config']

    parts = []

    # Add include paths
    parts.extend(build_include_paths(library_name, library_variant, run_dir=run_dir))

    # Library file
    sanitize_library = compile_config['sanitize_library']
    if library_variant == "aflpp" and sanitize_library:
        library_path = Path(sanitize_library)
        if "build_sanitize" not in library_path.parts:
            raise ValueError(
                f"sanitize_library has no build_sanitize directory: {sanitize_library}"
            )
        sanitize_library = str(Path(*(
            f"build_{library_variant}" if part == "build_sanitize" else part
            for part in library_path.parts
        )))
    if sanitize_library:
        parts.append(sanitize_library)

    # Additional libs
    additional_libs = compile_config['additional_libs']
    if additional_libs:
        parts.extend(additional_libs)

    return " ".join(parts)
