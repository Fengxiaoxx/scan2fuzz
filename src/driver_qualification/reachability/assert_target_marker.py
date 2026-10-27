"""Build a reach-only replacement object for targets on ``assert`` lines."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.core import get_project_root


_ASSERT_LINE = re.compile(r"^\s*assert\s*\(")
_CPP_SUFFIXES = frozenset({".cc", ".cpp", ".cxx"})


@dataclass(frozen=True)
class AssertTargetMarker:
    """Artifacts used to measure one assert target during coverage replay."""

    object_path: Path
    hit_path: Path


def _target_source(
    project_root: Path,
    library: str,
    target: str,
) -> tuple[Path, int] | None:
    try:
        target_file, line_text = target.rsplit(":", 1)
        line = int(line_text)
    except (ValueError, TypeError):
        return None
    if line <= 0:
        return None

    try:
        source_root = (project_root / "test_lib" / library).resolve(strict=True)
        source = Path(target_file)
        if not source.is_absolute():
            source = source_root / source
        source = source.resolve(strict=True)
    except OSError:
        return None
    try:
        source.relative_to(source_root)
    except ValueError:
        return None
    return source, line


def _is_assert_target(source: Path, line: int) -> bool:
    lines = source.read_text(encoding="utf-8").splitlines()
    return line <= len(lines) and bool(_ASSERT_LINE.match(lines[line - 1]))


def _compile_entry(database: Path, source: Path) -> dict[str, Any]:
    entries = json.loads(database.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError(f"coverage compile database must be an array: {database}")

    matches = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        file_path = entry.get("file")
        directory = entry.get("directory")
        if not isinstance(file_path, str) or not isinstance(directory, str):
            continue
        candidate = Path(file_path)
        if not candidate.is_absolute():
            candidate = Path(directory) / candidate
        if candidate.resolve() == source:
            matches.append(entry)
    if len(matches) != 1:
        raise ValueError(
            f"expected one coverage compile command for {source}, found {len(matches)}"
        )
    return matches[0]


def _instrumented_source(
    source: Path,
    line: int,
    marker_name: str,
    hit_path: Path,
) -> str:
    original = source.read_text(encoding="utf-8").splitlines(keepends=True)
    source_literal = json.dumps(str(source))
    hit_literal = json.dumps(str(hit_path))
    helper = f"""\
#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace {{
void {marker_name}() noexcept {{
  static std::atomic_flag recorded = ATOMIC_FLAG_INIT;
  if (recorded.test_and_set(std::memory_order_relaxed)) return;
  const int saved_errno = errno;
  const int fd = ::open({hit_literal}, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd >= 0) ::close(fd);
  errno = saved_errno;
}}
}}  // namespace

#line 1 {source_literal}
"""
    marker = (
        f"#line {line} {source_literal}\n"
        f"{marker_name}();\n"
        f"#line {line} {source_literal}\n"
    )
    return helper + "".join(original[: line - 1]) + marker + "".join(original[line - 1 :])


def _compile_command(
    entry: dict[str, Any],
    overlay_path: Path,
    object_path: Path,
) -> tuple[list[str], Path]:
    directory = Path(str(entry["directory"]))
    arguments = entry.get("arguments")
    if isinstance(arguments, list) and all(isinstance(arg, str) for arg in arguments):
        command = list(arguments)
    else:
        raw_command = entry.get("command")
        if not isinstance(raw_command, str):
            raise ValueError("coverage compile command has neither arguments nor command")
        command = shlex.split(raw_command)

    rewritten: list[str] = []
    skip_output = False
    for argument in command:
        if skip_output:
            skip_output = False
            continue
        if argument == "-o":
            skip_output = True
            continue
        if argument.startswith("-o") and len(argument) > 2:
            continue

        rewritten.append(argument)

    if "-c" not in rewritten:
        rewritten.append("-c")
    rewritten.extend(["-ivfsoverlay", str(overlay_path), "-o", str(object_path)])
    return rewritten, directory


def prepare_assert_target_marker(
    library: str,
    target: str,
    workdir: str,
    *,
    project_root: Path | None = None,
) -> AssertTargetMarker | None:
    """Return marker artifacts only when the exact target line starts with assert."""
    root = (project_root or get_project_root()).resolve()
    resolved = _target_source(root, library, target)
    if resolved is None:
        return None
    source, line = resolved
    if source.suffix not in _CPP_SUFFIXES or not _is_assert_target(source, line):
        return None

    marker_dir = Path(workdir) / "assert-target-marker"
    marker_dir.mkdir(parents=True, exist_ok=True)
    hit_path = marker_dir / "hit"
    digest = hashlib.sha256(
        source.read_bytes() + f"\0{line}\0{hit_path}".encode()
    ).hexdigest()[:12]
    marker_name = f"__trace2fuzz_assert_target_{digest}"
    instrumented_source = marker_dir / f"{source.stem}-{digest}{source.suffix}"
    overlay_path = marker_dir / f"{source.stem}-{digest}.overlay.json"
    object_path = marker_dir / f"{source.stem}-{digest}.o"
    build_log = marker_dir / "build.log"

    instrumented_source.write_text(
        _instrumented_source(source, line, marker_name, hit_path),
        encoding="utf-8",
    )
    overlay_path.write_text(
        json.dumps(
            {
                "version": 0,
                "roots": [
                    {
                        "type": "file",
                        "name": str(source),
                        "external-contents": str(instrumented_source),
                        "use-external-name": "false",
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    database = root / "test_lib" / library / "build_coverage" / "compile_commands.json"
    entry = _compile_entry(database, source)
    command, directory = _compile_command(entry, overlay_path, object_path)
    result = subprocess.run(
        command,
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=180,
    )
    build_log.write_text(
        result.stdout + ("\n--- stderr ---\n" + result.stderr if result.stderr else ""),
        encoding="utf-8",
    )
    if result.returncode != 0 or not object_path.is_file():
        raise RuntimeError(
            f"assert target marker compilation failed for {target}; see {build_log}"
        )
    return AssertTargetMarker(object_path=object_path, hit_path=hit_path)
