"""Find every function definition and its line range with tree-sitter."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Node, Parser

C_SUFFIXES = frozenset({".c", ".h"})
CPP_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".incl_cpp"})
LANGUAGE_DEPENDENT_SUFFIXES = frozenset({".inc", ".inl", ".ipp", ".tcc"})
HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx"})
SOURCE_SUFFIXES = C_SUFFIXES | CPP_SUFFIXES | LANGUAGE_DEPENDENT_SUFFIXES

_NAME_TYPES = frozenset(
    {"identifier", "field_identifier", "qualified_identifier", "operator_name",
     "destructor_name", "type_identifier"}
)

# These Abseil macros expand to an optional inline namespace. Without macro
# expansion, tree-sitter can mistake the following namespace and all its
# contents for one function definition. Mask only standalone marker lines and
# preserve their byte length so source locations remain exact.
_ABSL_NAMESPACE_MARKER = re.compile(
    rb"(?m)^([ \t]*)(ABSL_NAMESPACE_(?:BEGIN|END))(?=[ \t]*(?://[^\r\n]*)?\r?$)"
)


@dataclass(frozen=True)
class Unit:
    """One function definition, located by file and 1-based inclusive lines."""

    file: str
    name: str
    start_line: int
    end_line: int

    @property
    def lines(self) -> int:
        return self.end_line - self.start_line + 1


def _parser_for(suffix: str, language: str = "c") -> Parser:
    if suffix == ".h" or suffix in LANGUAGE_DEPENDENT_SUFFIXES:
        # A .h belongs to the library's language: C++ headers carry templates,
        # references and operator overloads that the C grammar misparses.
        if language.strip().lower() in {"cpp", "c++", "cxx", "cc"}:
            return Parser(Language(tree_sitter_cpp.language()))
        return Parser(Language(tree_sitter_c.language()))
    if suffix in C_SUFFIXES:
        return Parser(Language(tree_sitter_c.language()))
    if suffix in CPP_SUFFIXES:
        return Parser(Language(tree_sitter_cpp.language()))
    raise ValueError(f"no grammar for source suffix: {suffix!r}")


def _declarator_name(node: Node | None) -> str | None:
    """Follow the declarator chain (e.g. reference_declarator -> function_declarator) to the name."""
    while node is not None:
        if node.type in _NAME_TYPES:
            return node.text.decode("utf-8", "replace")
        child = node.child_by_field_name("declarator")
        if child is None:
            # reference_declarator (and similar wrappers) carry no declarator
            # field; their named child is e.g. function_declarator.
            child = next(
                (c for c in node.named_children if c.type.endswith("_declarator")),
                None,
            )
        node = child
    return None


def _mask_namespace_markers(source: bytes) -> bytes:
    return _ABSL_NAMESPACE_MARKER.sub(
        lambda match: match.group(1) + b" " * len(match.group(2)), source
    )


def enumerate_file(path: Path, *, relative_to: Path, language: str = "c") -> list[Unit]:
    tree = _parser_for(path.suffix.lower(), language).parse(
        _mask_namespace_markers(path.read_bytes())
    )
    relative = path.resolve().relative_to(relative_to.resolve()).as_posix()

    units: list[Unit] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            name = _declarator_name(node.child_by_field_name("declarator"))
            if name:
                units.append(
                    Unit(
                        file=relative,
                        name=name,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                    )
                )
            # Nested definitions (lambdas, local classes) belong to the
            # enclosing function's range, so stop descending here.
            continue
        stack.extend(node.children)
    return units


def enumerate_units(source_files: list[str], *, source_root: str, language: str = "c") -> list[Unit]:
    """Units of the caller's files, sorted; files without a C/C++ suffix are skipped."""
    root = Path(source_root)
    units: list[Unit] = []
    for entry in source_files:
        path = Path(entry)
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        units.extend(enumerate_file(path, relative_to=root, language=language))
    units.sort(key=lambda unit: (unit.file, unit.start_line))
    return units


def enumerate_library_units(source_files: list[str], *, source_root: str, language: str = "c") -> list[Unit]:
    """Link-target sources plus the library's own headers.

    The build trace lists only translation units, so header-defined code (inline
    functions, class and function templates) would never be enumerated; for C++
    libraries that is where much of the code lives. Headers are therefore added
    explicitly, skipping the pipeline's own build directories.
    """
    root = Path(source_root)
    skip_parts = {"build_analysis", "build_sanitize", "build_coverage", ".git"}
    headers = sorted(
        str(path)
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in HEADER_SUFFIXES
        and not skip_parts.intersection(path.parts)
    )
    return enumerate_units([*source_files, *headers], source_root=source_root, language=language)
