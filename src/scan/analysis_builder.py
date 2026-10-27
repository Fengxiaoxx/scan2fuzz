"""Create the shared build artifacts required by the scan stage."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from src.scan.bitcode_builder import (
    BuildLogParser,
    build_target_bitcode,
    get_target_sources,
)


def _resolve_tool(*candidates: str) -> str:
    for candidate in candidates:
        if os.path.isabs(candidate):
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
            continue
        resolved = shutil.which(candidate)
        if resolved is not None:
            return resolved
    raise FileNotFoundError(f"Unable to locate tool from candidates: {candidates}")

class AnalysisBuilder:
    """Create the CodeQL database, build trace, and linked bitcode."""

    def __init__(
        self,
        library_name: str,
        test_lib_dir: str,
        info_lib_dir: str,
        build_script: str,
        analysis_library: str,
        codeql_log_file: str,
    ):
        if not isinstance(analysis_library, str) or not analysis_library.strip():
            raise ValueError("compile_config.analysis_library is required")
        if not isinstance(codeql_log_file, str) or not codeql_log_file.strip():
            raise ValueError("codeql_log_file is required")
        self.library_name = library_name
        self.test_lib_dir = os.path.abspath(test_lib_dir)
        self.info_lib_dir = os.path.abspath(info_lib_dir)
        self.build_script = os.path.abspath(build_script)
        self.expected_link_target = Path(analysis_library).name
        self.selected_link_target: Optional[Path] = None
        self.build_dir = os.path.join(self.test_lib_dir, "build_analysis")
        self.compile_db_path = os.path.join(self.build_dir, "compile_commands.json")
        self.database_path = os.path.join(
            self.info_lib_dir, "external", "database"
        )
        self.codeql_log_file = os.path.abspath(codeql_log_file)
        self.build_trace_file = os.path.join(self.info_lib_dir, "build", "build.log")
        self.build_hook_dir = os.path.join(self.info_lib_dir, "build", "hooks")
        self.bitcode_root = os.path.join(self.info_lib_dir, "build")
        self.public_install_dir = os.path.join(
            self.info_lib_dir, "build", "public-install"
        )
        self.public_headers_dir = os.path.join(self.public_install_dir, "include")

    def _build_wrapper_script(self, tool_name: str, target_path: str) -> str:
        return (
            "#!/bin/sh\n"
            f'if [ -d "{self.info_lib_dir}" ]; then\n'
            f'  echo "$(realpath .)|autofuzz_splitter|{tool_name} $@" >> "{self.build_trace_file}"\n'
            "fi\n"
            f'exec {target_path} "$@"\n'
        )

    def _prepare_build_hooks(self) -> Dict[str, str]:
        os.makedirs(self.build_hook_dir, exist_ok=True)
        Path(self.build_trace_file).write_text("")

        real_tools = {
            "clang": _resolve_tool("clang", "/usr/bin/clang", "/usr/lib/llvm-15/bin/clang", "/usr/lib/llvm-18/bin/clang"),
            "clang++": _resolve_tool("clang++", "/usr/bin/clang++", "/usr/lib/llvm-15/bin/clang++", "/usr/lib/llvm-18/bin/clang++"),
            "llvm-ar": _resolve_tool("llvm-ar", "/usr/bin/llvm-ar", "/usr/lib/llvm-15/bin/llvm-ar", "/usr/lib/llvm-18/bin/llvm-ar"),
            "yasm": _resolve_tool("yasm", "/usr/bin/yasm"),
        }
        # Some current libraries require a newer, explicitly versioned LLVM
        # toolchain (for example, Poppler's C++23 build uses clang-18).  Hook
        # those names too so their compile/link commands reach the bitcode log.
        for tool_name, candidates in {
            "clang-18": ("clang-18", "/usr/bin/clang-18", "/usr/lib/llvm-18/bin/clang"),
            "clang++-18": ("clang++-18", "/usr/bin/clang++-18", "/usr/lib/llvm-18/bin/clang++"),
            "llvm-ar-18": ("llvm-ar-18", "/usr/bin/llvm-ar-18", "/usr/lib/llvm-18/bin/llvm-ar"),
        }.items():
            try:
                real_tools[tool_name] = _resolve_tool(*candidates)
            except FileNotFoundError:
                pass

        for tool_name, target_path in real_tools.items():
            wrapper_path = Path(self.build_hook_dir) / tool_name
            wrapper_path.write_text(self._build_wrapper_script(tool_name, target_path))
            wrapper_path.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = f"{self.build_hook_dir}:{env.get('PATH', '')}"
        env["CC"] = "clang"
        env["CXX"] = "clang++"
        env["AR"] = "llvm-ar"
        return env

    def _detect_primary_link_target(self) -> Optional[str]:
        if not os.path.exists(self.build_trace_file) or os.path.getsize(self.build_trace_file) == 0:
            logger.error("Build log missing or empty")
            return None

        parser = BuildLogParser(Path(self.build_trace_file))
        _srcs, _compiles, links, _assems = parser.parse()
        if not links:
            logger.error(f"No link/archive targets found in {self.build_trace_file}")
            return None

        candidates = [
            path for path in links if path.name == self.expected_link_target
        ]
        if not candidates and self.expected_link_target.endswith(".so"):
            versioned_prefix = f"{self.expected_link_target}."
            candidates = [
                path for path in links if path.name.startswith(versioned_prefix)
            ]
        if len(candidates) != 1:
            logger.error(
                "Expected exactly one link target for {} but found {}. "
                "Available targets: {}",
                self.expected_link_target,
                len(candidates),
                ", ".join(sorted(str(path) for path in links)),
            )
            return None

        selected = candidates[0]
        self.selected_link_target = selected.resolve(strict=True)
        logger.info(f"Selected link target for bitcode extraction: {selected}")
        return selected.name

    def create_linked_bitcode(self) -> Optional[str]:
        """Build a linked .bc file from the captured build log."""
        try:
            target = self._detect_primary_link_target()
            if target is None:
                return None

            for directory in ("bc", "bc_parts"):
                output = Path(self.bitcode_root) / directory
                if output.exists():
                    shutil.rmtree(output)

            linked, parts = build_target_bitcode(
                Path(self.build_trace_file),
                target,
                Path(self.bitcode_root),
            )
            logger.success(f"Linked bitcode generated at {linked}")
            logger.info(f"Linked bitcode built from {len(parts)} object bitcode files")
            return str(linked)
        except Exception as exc:
            logger.error(f"Failed to generate linked bitcode: {exc}")
            return None

    def create_codeql_database(self) -> bool:
        """Create CodeQL database (which also builds the library)."""
        if os.path.exists(self.database_path):
            logger.info("Removing the previous CodeQL database")
            shutil.rmtree(self.database_path)
        if os.path.exists(self.public_install_dir):
            shutil.rmtree(self.public_install_dir)

        logger.info("Creating CodeQL database...")

        os.makedirs(self.build_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.codeql_log_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.database_path), exist_ok=True)

        # CodeQL runs the command in the source root; the script runs from where
        # it lives, so a library's own build.sh (libpcap has one) is never touched.
        command = [
            "codeql",
            "database",
            "create",
            self.database_path,
            "--language=cpp",
            f"--source-root=test_lib/{self.library_name}",
            "--command",
            shlex.join(["bash", self.build_script, "analysis"]),
        ]

        logger.debug("Command: {}", " ".join(command))

        try:
            env = self._prepare_build_hooks()
            env["BUILD_CONTRACT"] = "1"
            env["INSTALL_PREFIX"] = self.public_install_dir
            with open(self.codeql_log_file, "w") as log_file:
                result = subprocess.run(
                    command,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=".",
                    env=env,
                )

            if result.returncode != 0:
                logger.error(f"CodeQL database creation failed (see {self.codeql_log_file})")
                return False

            if not os.path.exists(self.database_path):
                logger.error("CodeQL database not created")
                return False

            if not os.path.exists(self.compile_db_path):
                logger.error("compile_commands.json not generated")
                return False

            try:
                public_headers = self.get_public_header_files()
            except (OSError, ValueError) as exc:
                logger.error(f"Public header installation is invalid: {exc}")
                return False
            if not public_headers:
                logger.error(
                    "Analysis build installed no public headers under {}",
                    self.public_headers_dir,
                )
                return False

            logger.success(f"CodeQL database created at {self.database_path}")
            logger.success("Build completed (compile_commands.json generated)")
            logger.success(
                "Installed {} public header files at {}",
                len(public_headers),
                self.public_headers_dir,
            )
            logger.success(f"Build log captured at {self.build_trace_file}")
            return True

        except Exception as exc:
            logger.error(f"CodeQL database creation error: {exc}")
            return False

    def get_public_header_files(self) -> List[Path]:
        """Return the analysis build's authoritative installed header files."""
        root = Path(self.public_headers_dir)
        if not root.is_dir():
            raise ValueError(f"public include directory is missing: {root}")

        resolved_root = root.resolve(strict=True)
        files: List[Path] = []
        for candidate in sorted(root.rglob("*")):
            if candidate.is_symlink():
                resolved = candidate.resolve(strict=True)
                try:
                    resolved.relative_to(resolved_root)
                except ValueError as exc:
                    raise ValueError(
                        f"public header symlink escapes install prefix: {candidate}"
                    ) from exc
            if candidate.is_file():
                files.append(candidate)
        return files

    def get_linked_source_files(self) -> List[str]:
        """Return source files that participate in building the primary link target (.a/.so)."""
        if not os.path.exists(self.build_trace_file) or os.path.getsize(self.build_trace_file) == 0:
            logger.error("Build log missing or empty; linked source scope is unavailable")
            return []

        target = self._detect_primary_link_target()
        if target is None:
            logger.error("No link target detected; linked source scope is unavailable")
            return []

        sources = get_target_sources(Path(self.build_trace_file), target)
        missing = sorted(str(path) for path in sources if not path.is_file())
        if missing:
            logger.error(
                "Linked source files are missing: {}", ", ".join(missing)
            )
            return []
        result = sorted({str(path) for path in sources})
        logger.info(f"Found {len(result)} source files participating in link target")
        return result
