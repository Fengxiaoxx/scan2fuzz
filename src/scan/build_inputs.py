"""Recover linked compile inputs and installed public files for a library.

The link trace selects object files. Compiler depfiles select each object's
inputs. The install tree selects files published to consumers. Missing depfiles
are an incomplete build record, not permission to scan every source file.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path

from src.scan.bitcode_builder import BuildCommand, _target_compile_commands


_CONTINUATION = re.compile(r"\\\r?\n")
_HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx"})
_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".c++"})


def _depfile_for(command: BuildCommand) -> Path:
    """Use an explicit -MF path, or an existing conventional depfile."""
    args = shlex.split(command.cmd)
    for index, arg in enumerate(args):
        if arg == "-MF" and index + 1 < len(args):
            return command.abspath(Path(args[index + 1]))
        if arg.startswith("-MF") and len(arg) > 3:
            return command.abspath(Path(arg[3:]))
    output = command.output()
    object_depfile = Path(str(output) + ".d")
    if object_depfile.is_file():
        return object_depfile
    # libvpx emits source-named depfiles (foo.c.d) beside foo.c.o.
    source_depfile = output.with_suffix(".d")
    if source_depfile.is_file():
        return source_depfile
    return object_depfile


def _read_depfile(path: Path, working_directory: Path) -> set[Path]:
    """Parse the first Make dependency rule, ignoring optional -MP phony rules."""
    text = _CONTINUATION.sub(" ", path.read_text(encoding="utf-8"))
    first_rule = text.splitlines()[0] if text else ""
    if ":" not in first_rule:
        raise ValueError(f"depfile has no dependency rule: {path}")
    dependencies = shlex.split(first_rule.split(":", 1)[1])
    if not dependencies:
        raise ValueError(f"depfile has no inputs: {path}")
    return {
        (Path(name) if Path(name).is_absolute() else working_directory / name).resolve()
        for name in dependencies
    }


def collect_linked_build_inputs(
    build_log: Path,
    link_target: str,
    source_root: Path,
    installed_include_root: Path | None = None,
) -> dict:
    """Return linked inputs plus the public install surface when requested.

    Raises on any missing object/depfile, so the result never masquerades as a
    complete source scope when a build system did not emit dependencies.
    """
    source_root = source_root.resolve(strict=True)
    target, commands = _target_compile_commands(build_log, link_target)
    records = []
    missing = []
    all_inputs: set[str] = set()
    for command in commands:
        obj = command.output()
        depfile = _depfile_for(command)
        if not depfile.is_file():
            missing.append(str(depfile))
            continue
        dependencies = _read_depfile(depfile, command.path)
        declared_sources = set(command.sources(real=True))
        if not declared_sources <= dependencies:
            raise ValueError(f"depfile omits compiler source for {obj}: {depfile}")
        project_inputs = sorted(
            path.relative_to(source_root).as_posix()
            for path in dependencies
            if path.is_relative_to(source_root)
        )
        all_inputs.update(project_inputs)
        records.append(
            {
                "object": str(obj),
                "depfile": str(depfile),
                "sources": sorted(str(path) for path in declared_sources),
                "project_inputs": project_inputs,
            }
        )
    if missing:
        raise FileNotFoundError(
            f"{len(missing)} of {len(commands)} linked objects lack depfiles; "
            f"first missing: {missing[0]}"
        )
    result = {
        "link_target": str(target),
        "source_root": str(source_root),
        "objects": records,
        "project_sources": sorted(
            name for name in all_inputs if Path(name).suffix.lower() in _SOURCE_SUFFIXES
        ),
        "project_headers": sorted(
            name for name in all_inputs if Path(name).suffix.lower() in _HEADER_SUFFIXES
        ),
        "project_other_inputs": sorted(
            name
            for name in all_inputs
            if Path(name).suffix.lower() not in _SOURCE_SUFFIXES | _HEADER_SUFFIXES
        ),
    }
    if installed_include_root is not None:
        installed_include_root = installed_include_root.resolve(strict=True)
        if not installed_include_root.is_dir():
            raise ValueError(f"installed include root is not a directory: {installed_include_root}")
        installed = []
        for path in sorted(installed_include_root.rglob("*")):
            if not path.is_file():
                continue
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(installed_include_root):
                raise ValueError(f"installed file escapes include root: {path}")
            include_name = path.relative_to(installed_include_root).as_posix()
            # These are ordinary installation layouts, not library-name rules.
            # If neither source copy matches, retain the installed file itself.
            source_path = None
            for candidate in (source_root / include_name, source_root / "include" / include_name):
                if candidate.is_file() and candidate.read_bytes() == path.read_bytes():
                    source_path = candidate.resolve()
                    break
            installed.append(
                {
                    "include": include_name,
                    "installed_path": str(path),
                    "source_path": str(source_path) if source_path else None,
                }
            )
        result["installed_public_files"] = installed
        result["scan_file_paths"] = sorted(
            {str(source_root / name) for name in all_inputs}
            | {item["source_path"] or item["installed_path"] for item in installed}
        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_log", type=Path)
    parser.add_argument("link_target")
    parser.add_argument("source_root", type=Path)
    parser.add_argument("--installed-include-root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = collect_linked_build_inputs(
        args.build_log, args.link_target, args.source_root, args.installed_include_root
    )
    summary = {
        "link_target": result["link_target"],
        "linked_objects": len(result["objects"]),
        "project_sources": len(result["project_sources"]),
        "project_headers": len(result["project_headers"]),
        "project_other_inputs": len(result["project_other_inputs"]),
    }
    if args.installed_include_root is not None:
        summary["installed_public_files"] = len(result["installed_public_files"])
        summary["installed_source_mapped"] = sum(
            item["source_path"] is not None for item in result["installed_public_files"]
        )
        summary["scan_files"] = len(result["scan_file_paths"])
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
