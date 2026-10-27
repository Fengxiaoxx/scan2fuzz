"""Classify deterministic coverage source-resolution failures."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from src.core.llvm_cov import COV


_DIE = re.compile(r"^0x[0-9a-f]+: DW_TAG_\w+")
_DWARF_VALUE = re.compile(r'\("([^"]+)"\)')
_SECTION = re.compile(r"^\s*\[\s*\d+\]\s+(\S+)\s+")


def _llvm_tool(name: str) -> str | None:
    """Prefer the same LLVM version used for coverage export."""
    version = COV.rsplit("-", 1)[-1]
    candidates = [f"{name}-{version}", name]
    candidates.extend(f"{name}-{other}" for other in ("18", "17", "16", "14"))
    for candidate in dict.fromkeys(candidates):
        executable = shutil.which(candidate)
        if executable:
            return executable
    return None


def _member_source_identity(
    archive: Path,
    member: str,
    expected_source: str,
) -> tuple[bool, str]:
    """Require coverage sections and an exact DWARF source for one member."""
    readelf = _llvm_tool("llvm-readelf")
    dwarfdump = _llvm_tool("llvm-dwarfdump")
    if readelf is None or dwarfdump is None:
        return False, "matching LLVM object-inspection tools are unavailable"
    try:
        extracted = subprocess.run(
            ["ar", "p", str(archive), member],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if extracted.returncode != 0 or not extracted.stdout:
            return False, "could not extract the archive member"
        with tempfile.TemporaryDirectory(prefix="reachability-object-") as temporary:
            object_path = Path(temporary) / "target.o"
            object_path.write_bytes(extracted.stdout)
            sections = subprocess.run(
                [readelf, "--sections", "--wide", str(object_path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if sections.returncode != 0:
                return False, "could not inspect the archive member's ELF sections"
            section_names = {
                match.group(1)
                for line in sections.stdout.splitlines()
                if (match := _SECTION.match(line)) is not None
            }
            missing = {"__llvm_covmap", "__llvm_covfun"} - section_names
            if missing:
                return (
                    False,
                    "archive member lacks coverage sections "
                    + ", ".join(sorted(missing)),
                )
            dump = subprocess.run(
                [dwarfdump, f"--name={expected_source}", str(object_path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        if dump.returncode != 0:
            return False, "could not inspect the archive member's DWARF identity"
    except (OSError, subprocess.TimeoutExpired):
        return False, "could not inspect the archive member"

    name = ""
    comp_dir = ""
    in_compile_unit = False
    for line in dump.stdout.splitlines():
        if _DIE.match(line):
            if in_compile_unit and name:
                source = name if os.path.isabs(name) else os.path.join(comp_dir, name)
                if os.path.normpath(source) == os.path.normpath(expected_source):
                    return True, ""
            in_compile_unit = "DW_TAG_compile_unit" in line
            name = ""
            comp_dir = ""
        elif in_compile_unit:
            value = _DWARF_VALUE.search(line)
            if value and "DW_AT_name" in line:
                name = value.group(1)
            elif value and "DW_AT_comp_dir" in line:
                comp_dir = value.group(1)
    if in_compile_unit and name:
        source = name if os.path.isabs(name) else os.path.join(comp_dir, name)
        if os.path.normpath(source) == os.path.normpath(expected_source):
            return True, ""
    return False, f"no matching DWARF compile-unit identity for {expected_source}"


def classify_source_resolution_failure(
    diagnostic_path: Path,
    coverage_library: Path,
    target: str,
) -> tuple[str, str] | None:
    """Separate an unlinked candidate from a missing coverage-build object.

    A unique archive member with coverage sections and a DWARF compile unit
    identifying the expected source indicates that it was built for coverage
    but omitted from the linked driver. Ambiguous or unverifiable members
    remain build problems so a candidate is never rejected on a basename match.
    """
    try:
        diagnostic = json.loads(diagnostic_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(diagnostic, dict) or diagnostic.get("phase") != "source_resolution":
        return None

    error = str(diagnostic.get("error") or "coverage source resolution failed")
    source = target.rsplit(":", 1)[0]
    expected_prefix = (
        f"analysis source path is absent from coverage data: {source} (expected "
    )
    expected_source = (
        error[len(expected_prefix):-1]
        if error.startswith(expected_prefix) and error.endswith(")")
        else ""
    )
    if Path(source).suffix in {".h", ".hh", ".hpp", ".hxx", ".inc"}:
        return (
            "coverage_source_unavailable",
            f"{error}. Header coverage comes from translation units that include "
            "the header; inspect the candidate's include paths and coverage "
            "mapping before changing the coverage library.",
        )
    if expected_source and Path(expected_source).is_absolute() and coverage_library.suffix == ".a":
        try:
            listing = subprocess.run(
                ["ar", "t", str(coverage_library)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            listing = None
        if listing is not None and listing.returncode == 0:
            object_name = f"{Path(source).name}.o"
            members = [
                member.strip()
                for member in listing.stdout.splitlines()
                if Path(member.strip()).name == object_name
            ]
            if len(members) == 1:
                matching, reason = _member_source_identity(
                    coverage_library, members[0], expected_source
                )
                if matching:
                    return (
                        "target_source_unlinked",
                        f"{error}. The coverage archive contains one {object_name} "
                        f"compiled from {expected_source}, but the candidate's "
                        "coverage binary has no target-source coverage. Check "
                        "whether feature guards or driver calls compiled out "
                        "the path to the target.",
                    )
                reason = f"The archive member {members[0]} {reason}"
            elif members:
                reason = f"The archive contains {len(members)} ambiguous {object_name} members"
            else:
                reason = f"The archive has no {object_name}"
            return (
                "coverage_source_unavailable",
                f"{error}. {reason} in {coverage_library}; rebuild or verify the "
                "coverage library against the revision used for target analysis.",
            )

    return (
        "coverage_source_unavailable",
        f"{error}. Inspect the configured coverage library "
        f"{coverage_library} and its source paths before resuming this target.",
    )
