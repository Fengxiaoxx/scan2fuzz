"""Extract the strict public function API from an installed library and headers."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

import clang.cindex
from clang.cindex import (
    AccessSpecifier,
    Cursor,
    CursorKind,
    Diagnostic,
    Index,
    LinkageKind,
    TypeKind,
)


_FUNCTION_KINDS = {
    CursorKind.FUNCTION_DECL,
    CursorKind.CXX_METHOD,
    CursorKind.CONSTRUCTOR,
    CursorKind.DESTRUCTOR,
}
_MEMBER_FUNCTION_KINDS = {
    CursorKind.CXX_METHOD,
    CursorKind.CONSTRUCTOR,
    CursorKind.DESTRUCTOR,
}
_HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
_ELF_FUNCTION_TYPES = {"FUNC", "IFUNC", "GNU_IFUNC"}
_ELF_BINDINGS = {"GLOBAL", "WEAK"}
_ELF_VISIBILITIES = {"DEFAULT", "PROTECTED"}
_EXTERNAL_LINKAGES = {LinkageKind.EXTERNAL}
if hasattr(LinkageKind, "UNIQUE_EXTERNAL"):
    _EXTERNAL_LINKAGES.add(LinkageKind.UNIQUE_EXTERNAL)
_STANDARD_PREAMBLE = "#include <stddef.h>\n#include <stdio.h>\n"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _headers_digest(headers: Sequence[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for header in headers:
        relative = header.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(_sha256_file(header)))
        digest.update(b"\0")
    return digest.hexdigest()


def _split_symbol_version(raw_symbol: str) -> tuple[str, str | None, str | None]:
    if "@@" in raw_symbol:
        abi_symbol, version = raw_symbol.split("@@", 1)
        return abi_symbol, version, "default"
    if "@" in raw_symbol:
        abi_symbol, version = raw_symbol.split("@", 1)
        return abi_symbol, version, "nondefault"
    return raw_symbol, None, None


def _extract_exports(analysis_library: Path) -> List[dict]:
    try:
        result = subprocess.run(
            ["readelf", "--dyn-syms", "--wide", str(analysis_library)],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ValueError("readelf is required for public API extraction") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ValueError(f"readelf failed for {analysis_library}: {detail}")

    exports: List[dict] = []
    seen = set()
    for line in result.stdout.splitlines():
        fields = line.split(None, 7)
        if len(fields) != 8 or not fields[0].rstrip(":").isdigit():
            continue
        _number, _value, _size, symbol_type, binding, visibility, index, name = fields
        raw_symbol = name.split(None, 1)[0]
        if (
            symbol_type not in _ELF_FUNCTION_TYPES
            or binding not in _ELF_BINDINGS
            or visibility not in _ELF_VISIBILITIES
            or index == "UND"
        ):
            continue

        abi_symbol, version, version_kind = _split_symbol_version(raw_symbol)
        if not abi_symbol:
            raise ValueError(f"export has an empty ABI symbol: {line.strip()}")
        key = (raw_symbol, symbol_type, binding, visibility, index)
        if key in seen:
            continue
        seen.add(key)
        exports.append(
            {
                "raw_symbol": raw_symbol,
                "abi_symbol": abi_symbol,
                "version": version,
                "version_kind": version_kind,
                "type": symbol_type,
                "binding": binding,
                "visibility": visibility,
                "section_index": index,
            }
        )

    if not exports:
        raise ValueError(f"no defined dynamic function exports found in {analysis_library}")
    return sorted(exports, key=lambda item: (item["abi_symbol"], item["raw_symbol"]))


def _installed_headers(headers_root: Path) -> List[Path]:
    headers: List[Path] = []
    for candidate in sorted(headers_root.rglob("*")):
        if not candidate.is_file():
            continue
        if candidate.suffix.lower() not in _HEADER_SUFFIXES:
            raise ValueError(f"installed include file has an unsupported suffix: {candidate}")
        try:
            candidate.resolve(strict=True).relative_to(headers_root)
        except ValueError as exc:
            raise ValueError(f"installed header escapes headers_root: {candidate}") from exc
        headers.append(candidate)
    if not headers:
        raise ValueError(f"no installed headers found under {headers_root}")
    return headers


def _qualified_name(cursor: Cursor) -> str:
    components = [cursor.spelling]
    parent = cursor.semantic_parent
    while parent is not None and parent.kind != CursorKind.TRANSLATION_UNIT:
        if parent.spelling:
            components.append(parent.spelling)
        parent = parent.semantic_parent
    return "::".join(reversed(components))


def _path_within_root(path: str, root: Path) -> Path | None:
    try:
        return Path(path).resolve(strict=True).relative_to(root)
    except (FileNotFoundError, OSError, ValueError):
        return None


def _declaration_record(
    cursor: Cursor, include_header: Path, declaration_header: Path
) -> dict:
    mangled_name = (cursor.mangled_name or "").strip()
    display_name = (cursor.spelling or "").strip()
    qualified_name = _qualified_name(cursor).strip()
    type_signature = (cursor.type.spelling or "").strip()
    signature = _format_signature(cursor)
    include = include_header.as_posix()
    declaration_header_name = declaration_header.as_posix()
    if not all(
        (
            mangled_name,
            display_name,
            qualified_name,
            signature,
            type_signature,
            include,
            declaration_header_name,
        )
    ):
        raise ValueError(
            "installed function declaration is missing a required field: "
            f"{include}:{cursor.location.line}:{cursor.location.column}"
        )
    return {
        "abi_symbol": mangled_name,
        "mangled_name": mangled_name,
        "display_name": display_name,
        "qualified_name": qualified_name,
        "signature": signature,
        "type_signature": type_signature,
        "include": include,
        "kind": cursor.kind.name,
        "line": cursor.location.line,
        "column": cursor.location.column,
        "linkage": cursor.linkage.name,
    }


def _format_signature(cursor: Cursor) -> str:
    arguments = []
    for argument in cursor.get_arguments():
        argument_type = (argument.type.spelling or "").strip()
        argument_name = (argument.spelling or "").strip()
        arguments.append(
            f"{argument_type} {argument_name}".strip()
        )
    if (
        cursor.type.kind == TypeKind.FUNCTIONPROTO
        and cursor.type.is_function_variadic()
    ):
        arguments.append("...")
    if (
        not arguments
        and cursor.kind == CursorKind.FUNCTION_DECL
        and cursor.type.kind == TypeKind.FUNCTIONPROTO
    ):
        arguments.append("void")
    parameters = ", ".join(arguments)
    name = (cursor.spelling or "").strip()
    if cursor.kind in {CursorKind.CONSTRUCTOR, CursorKind.DESTRUCTOR}:
        return f"{name}({parameters})"
    result_type = (cursor.result_type.spelling or "").strip()
    return f"{result_type} {name}({parameters})".strip()


def _diagnostic_text(diagnostic: Diagnostic) -> str:
    location = diagnostic.location
    file_name = location.file.name if location.file is not None else "<unknown>"
    return f"{file_name}:{location.line}:{location.column}: {diagnostic.spelling}"


def _source_language(header: Path, language: str) -> str:
    if language == "cpp" or header.suffix.lower() in {".hh", ".hpp", ".hxx", ".inl"}:
        return "c++"
    return "c"


def _parse_header_probe(
    index: Index,
    headers_root: Path,
    include_dirs: Sequence[Path],
    source_language: str,
    includes: Sequence[Path],
    label: str,
    c_standard: str,
    cpp_standard: str,
) -> clang.cindex.TranslationUnit:
    standard = f"-std={cpp_standard}" if source_language == "c++" else f"-std={c_standard}"
    arguments = ["-x", source_language, standard]
    arguments.extend(_system_include_arguments(source_language))
    arguments.extend(f"-I{path}" for path in include_dirs)
    extension = "cc" if source_language == "c++" else "c"
    probe_path = headers_root / f".trace2fuzz-public-api-{label}.{extension}"
    probe_source = _STANDARD_PREAMBLE + "".join(
        f"#include <{header.relative_to(headers_root).as_posix()}>\n"
        for header in includes
    )
    try:
        translation_unit = index.parse(
            str(probe_path),
            args=arguments,
            unsaved_files=[(str(probe_path), probe_source)],
            options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
        )
    except clang.cindex.TranslationUnitLoadError as exc:
        raise ValueError(f"unable to parse public header probe {label}: {exc}") from exc

    errors = [
        _diagnostic_text(diagnostic)
        for diagnostic in translation_unit.diagnostics
        if diagnostic.severity >= Diagnostic.Error
    ]
    if errors:
        raise ValueError(
            f"unable to parse public header probe {label}: " + " | ".join(errors)
        )
    return translation_unit


def _records_from_translation_unit(
    translation_unit: clang.cindex.TranslationUnit,
    headers_root: Path,
    include_header: Path,
    use_entry_header: bool,
) -> List[dict]:
    records: Dict[tuple, dict] = {}
    for cursor in translation_unit.cursor.walk_preorder():
        if cursor.kind not in _FUNCTION_KINDS or cursor.location.file is None:
            continue
        if (
            cursor.kind in _MEMBER_FUNCTION_KINDS
            and cursor.access_specifier != AccessSpecifier.PUBLIC
        ):
            continue
        if cursor.linkage not in _EXTERNAL_LINKAGES:
            continue
        if not (cursor.mangled_name or "").strip():
            continue
        declaration_header = _path_within_root(cursor.location.file.name, headers_root)
        if declaration_header is None:
            continue
        record = _declaration_record(
            cursor,
            include_header if use_entry_header else declaration_header,
            declaration_header,
        )
        if use_entry_header and include_header != declaration_header:
            record["declaration_header"] = declaration_header.as_posix()
        key = (
            record["abi_symbol"],
            record["include"],
            record.get("declaration_header", record["include"]),
            record["line"],
            record["column"],
        )
        records[key] = record
    return list(records.values())


def _extract_declarations(
    headers: Sequence[Path],
    headers_root: Path,
    language: str,
    entry_headers: Sequence[str] | None,
    additional_include_dirs: Sequence[Path],
    c_standard: str,
    cpp_standard: str,
    include_transitive_declarations: bool = True,
) -> List[dict]:
    include_dirs = [headers_root, *additional_include_dirs]
    use_entry_headers = entry_headers is not None
    if use_entry_headers:
        headers_by_include = {
            header.relative_to(headers_root).as_posix(): header for header in headers
        }
        unknown = sorted(set(entry_headers) - set(headers_by_include))
        if unknown:
            raise ValueError(
                "configured public API entry headers are not installed: "
                + ", ".join(unknown)
            )
        selected_headers = [headers_by_include[header] for header in entry_headers]
    else:
        selected_headers = list(headers)

    headers_by_language: Dict[str, List[Path]] = defaultdict(list)
    for header in selected_headers:
        headers_by_language[_source_language(header, language)].append(header)

    index = Index.create()
    entry_declarations: Dict[tuple, dict] = {}
    for source_language, language_headers in sorted(headers_by_language.items()):
        for header in language_headers:
            try:
                translation_unit = _parse_header_probe(
                    index,
                    headers_root,
                    include_dirs,
                    source_language,
                    [header],
                    header.relative_to(headers_root).as_posix().replace("/", "-"),
                    c_standard,
                    cpp_standard,
                )
            except ValueError:
                raise
            entry_header = header.relative_to(headers_root)
            for record in _records_from_translation_unit(
                translation_unit, headers_root, entry_header, use_entry_headers
            ):
                if (
                    use_entry_headers
                    and not include_transitive_declarations
                    and "declaration_header" in record
                ):
                    continue
                key = (
                    record["abi_symbol"],
                    record["include"],
                    record.get("declaration_header", record["include"]),
                    record["line"],
                    record["column"],
                )
                entry_declarations[key] = record

    declarations = sorted(
        entry_declarations.values(),
        key=lambda item: (
            item["abi_symbol"],
            item["include"],
            item.get("declaration_header", item["include"]),
            item["line"],
            item["column"],
        ),
    )
    if not declarations:
        raise ValueError(f"no function declarations found under {headers_root}")
    return declarations


def _system_include_arguments(source_language: str) -> List[str]:
    """Return the active Clang driver's authoritative system include paths."""
    compiler = "clang++" if source_language == "c++" else "clang"
    try:
        result = subprocess.run(
            [compiler, "-E", "-x", source_language, "-", "-v"],
            input="",
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ValueError(f"{compiler} is required for public header parsing") from exc
    if result.returncode != 0:
        raise ValueError(f"failed to query {compiler} system include paths")

    paths = []
    collecting = False
    for line in result.stderr.splitlines():
        stripped = line.strip()
        if stripped == "#include <...> search starts here:":
            collecting = True
            continue
        if stripped == "End of search list.":
            break
        if collecting and stripped:
            path = stripped.removesuffix(" (framework directory)")
            if Path(path).is_dir():
                paths.append(path)
    if not paths:
        raise ValueError(f"{compiler} reported no system include paths")
    arguments = []
    for path in paths:
        arguments.extend(("-isystem", path))
    return arguments


def _group_by(records: Iterable[dict], key: str) -> Dict[str, List[dict]]:
    grouped: Dict[str, List[dict]] = defaultdict(list)
    for record in records:
        grouped[record[key]].append(record)
    return dict(grouped)


def _build_api_record(
    abi_symbol: str, exports: Sequence[dict], declarations: Sequence[dict]
) -> dict:
    identity_fields = ("display_name", "qualified_name", "type_signature")
    for field in identity_fields:
        values = {declaration[field] for declaration in declarations}
        # A destructor declared without an exception specification can be
        # reported by libclang as either ``void ()`` or ``void () noexcept``
        # depending on the entry header's include context.  The ELF ABI symbol
        # and the declaration itself are identical, so do not turn this parser
        # presentation difference into a false public-API conflict.
        if field == "type_signature":
            values = {value.removesuffix(" noexcept") for value in values}
        if len(values) != 1:
            raise ValueError(
                f"conflicting installed declarations for ABI symbol {abi_symbol}: {field}"
            )
    primary = declarations[0]
    result = {
        "api_id": f"abi:{abi_symbol}",
        "abi_symbol": abi_symbol,
        "display_name": primary["display_name"],
        "qualified_name": primary["qualified_name"],
        "signature": primary["signature"],
        "type_signature": primary["type_signature"],
        "include": primary["include"],
        "exports": list(exports),
        "declarations": list(declarations),
    }
    if "declaration_header" in primary:
        result["declaration_header"] = primary["declaration_header"]
    return result


def extract_public_api(
    analysis_library: Path,
    headers_root: Path,
    language: str,
    output_path: Path,
    *,
    entry_headers: Sequence[str] | None = None,
    include_dirs: Sequence[str] | None = None,
    c_standard: str = "c11",
    cpp_standard: str = "c++17",
    include_transitive_declarations: bool = True,
) -> dict:
    """Extract, validate, persist, and return the strict installed public API."""
    try:
        analysis_library = Path(analysis_library).resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ValueError(f"analysis library does not exist: {analysis_library}") from exc
    try:
        headers_root = Path(headers_root).resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ValueError(f"headers root does not exist: {headers_root}") from exc
    output_path = Path(output_path)
    if not analysis_library.is_file():
        raise ValueError(f"analysis library is not a file: {analysis_library}")
    if not headers_root.is_dir():
        raise ValueError(f"headers root is not a directory: {headers_root}")
    if language not in {"c", "cpp"}:
        raise ValueError("language must be 'c' or 'cpp'")
    if c_standard not in {"c11", "gnu11"}:
        raise ValueError("c_standard must be c11 or gnu11")
    if cpp_standard not in {"c++17", "c++20", "c++23"}:
        raise ValueError("cpp_standard must be c++17, c++20, or c++23")
    if not isinstance(include_transitive_declarations, bool):
        raise ValueError("include_transitive_declarations must be boolean")
    if entry_headers is not None and (
        not entry_headers
        or not all(isinstance(header, str) and header for header in entry_headers)
    ):
        raise ValueError("entry_headers must be a non-empty sequence of strings")
    if include_dirs is not None and (
        not isinstance(include_dirs, Sequence)
        or isinstance(include_dirs, (str, bytes))
        or not all(isinstance(path, str) and path for path in include_dirs)
    ):
        raise ValueError("include_dirs must be a sequence of relative paths")

    resolved_include_dirs = []
    for relative in include_dirs or []:
        candidate = (headers_root / relative).resolve(strict=True)
        try:
            candidate.relative_to(headers_root)
        except ValueError as exc:
            raise ValueError(f"public include directory escapes headers root: {relative}") from exc
        if not candidate.is_dir():
            raise ValueError(f"public include directory is not a directory: {relative}")
        resolved_include_dirs.append(candidate)

    headers = _installed_headers(headers_root)
    exports = _extract_exports(analysis_library)
    declarations = _extract_declarations(
        headers,
        headers_root,
        language,
        entry_headers,
        resolved_include_dirs,
        c_standard,
        cpp_standard,
        include_transitive_declarations,
    )
    exports_by_symbol = _group_by(exports, "abi_symbol")
    declarations_by_symbol = _group_by(declarations, "abi_symbol")
    public_symbols = sorted(exports_by_symbol.keys() & declarations_by_symbol.keys())
    if not public_symbols:
        raise ValueError("public API intersection is empty")

    apis = [
        _build_api_record(
            symbol, exports_by_symbol[symbol], declarations_by_symbol[symbol]
        )
        for symbol in public_symbols
    ]
    header_manifest = [
        {
            "include": header.relative_to(headers_root).as_posix(),
            "sha256": _sha256_file(header),
        }
        for header in headers
    ]
    result = {
        "schema_version": 1,
        "inputs": {
            "analysis_library": {
                "path": str(analysis_library),
                "sha256": _sha256_file(analysis_library),
            },
            "headers_root": {
                "path": str(headers_root),
                "sha256": _headers_digest(headers, headers_root),
                "header_count": len(headers),
                "headers": header_manifest,
            },
            "language": language,
            "cpp_standard": cpp_standard,
            "include_dirs": [
                path.relative_to(headers_root).as_posix()
                for path in resolved_include_dirs
            ],
            "parser": {
                "clang": _compiler_identity("clang"),
                "clang++": _compiler_identity("clang++"),
                "libclang": {
                    "library_file": str(clang.cindex.Config.library_file or ""),
                    "library_path": str(clang.cindex.Config.library_path or ""),
                },
                "standard_preamble": _STANDARD_PREAMBLE.splitlines(),
            },
        },
        "apis": apis,
        "unmatched_exports": [
            record for record in exports if record["abi_symbol"] not in public_symbols
        ],
        "header_only_declarations": [
            record
            for record in declarations
            if record["abi_symbol"] not in public_symbols
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    return result


def _compiler_identity(command: str) -> dict:
    path = shutil.which(command)
    if path is None:
        raise ValueError(f"{command} is required for public header parsing")
    resolved = Path(path).resolve(strict=True)
    result = subprocess.run(
        [str(resolved), "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise ValueError(f"failed to query {command} version")
    return {
        "path": str(resolved),
        "sha256": _sha256_file(resolved),
        "version": result.stdout.splitlines()[0],
    }
