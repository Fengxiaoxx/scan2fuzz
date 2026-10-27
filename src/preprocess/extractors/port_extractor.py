"""
PortExtractor — static per-function port enumeration via Python libclang.

(Formerly collapsed each function to a single first-match subject_type; it now
enumerates EVERY port so the fact-base builder can reason about handle flow.)

For each public API function, enumerates every port — the return value plus each
parameter — with the structural facts needed to reason about handle flow:

  - port:          "return", the parameter name, or "argN" if unnamed
  - type:          normalized base type name (qualifiers / struct keyword stripped,
                   opaque void* typedefs such as cmsHTRANSFORM / CURL preserved)
  - is_handle:     True if the port is a non-builtin pointer or an opaque void*
                   typedef (an opaque resource object), else False
  - pointer_depth: 0 for a value, 1 for T*, 2 for T**, …
  - is_return:     True for the return value, False for parameters

From the ports it also derives, by one pure structural rule (see
``derive_handle_flow``), each function's produced and consumed handle TYPES:
a handle leaves via the return value or a ``T**`` out-parameter (produce) and
enters by-value as a ``T*`` parameter (consume); non-handle ports are ignored.
It does NOT decide acquire/use/release ownership — that stays with the LLM's
handle_lifecycle label (e.g. the rare in-place-init case ``inflateInit``, where
a consumed handle is actually acquired).

A function is kept only if it is a real public API: its ``cursor.mangled_name``
is in the export set (api_symbols.txt) AND its linkage is EXTERNAL. The linkage
gate rejects an internal ``static`` function that happens to share a name with a
public API (in C its mangled name is the bare name, so the export-set test alone
would let it through).

"Non-builtin" means: not an intrinsic C type (int, char, float, void…).

Results are cached to info_lib/<lib>/raw/classify/api_ports.json, keyed by the
canonical mangled ID:
    {mangled: {"name", "mangled", "coord": {file, line, col},
               "ports": [...], "produces": [...], "consumes": [...]}}
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from typing import Dict, List, Optional, Set

import shlex

import clang.cindex
from clang.cindex import CursorKind, LinkageKind, TypeKind
from loguru import logger


PROJECT_ROOT = Path(__file__).resolve().parents[3]

_FUNCTION_KINDS = {
    CursorKind.FUNCTION_DECL,
    CursorKind.CXX_METHOD,
    CursorKind.CONSTRUCTOR,
    CursorKind.DESTRUCTOR,
}

_INTERNAL_ALIAS_SUFFIX = "__internal_alias"

# Flags that must be dropped before passing args to libclang
_SKIP_FLAGS = {"-c", "-E", "-MD", "-MMD", "-MP"}
_SKIP_WITH_NEXT = {"-o", "-MF", "-MT", "-MQ"}


def _clang_resource_dir() -> Path:
    result = subprocess.run(
        ["clang", "-print-resource-dir"],
        check=True,
        capture_output=True,
        text=True,
    )
    resource_dir = Path(result.stdout.strip()).resolve(strict=True)
    if not (resource_dir / "include" / "stddef.h").is_file():
        raise FileNotFoundError(
            f"Clang resource headers are incomplete: {resource_dir}"
        )
    return resource_dir


def _filter_args(args: List[str], source: str, cwd: Optional[str] = None) -> List[str]:
    """
    Remove flags that are meaningless or harmful when passed to libclang
    for AST parsing (output flags, dependency generation, source path itself).

    ``cwd`` should be the build directory the compile command was issued from,
    so relative source paths (e.g. ``../../src/cmsio1.c``) can be resolved
    against the absolute ``source`` path.
    """
    source_abs = os.path.realpath(source)
    result: List[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _SKIP_FLAGS:
            i += 1
            continue
        if arg in _SKIP_WITH_NEXT:
            i += 2
            continue
        candidate = arg if os.path.isabs(arg) else os.path.join(cwd or "", arg)
        if os.path.realpath(candidate) == source_abs:
            i += 1
            continue
        result.append(arg)
        i += 1
    return result

# TypeKinds that represent C builtin scalar types.
_BUILTIN_KINDS: Set[TypeKind] = {
    TypeKind.VOID,
    TypeKind.BOOL,
    TypeKind.CHAR_U,
    TypeKind.UCHAR,
    TypeKind.CHAR16,
    TypeKind.CHAR32,
    TypeKind.USHORT,
    TypeKind.UINT,
    TypeKind.ULONG,
    TypeKind.ULONGLONG,
    TypeKind.UINT128,
    TypeKind.CHAR_S,
    TypeKind.SCHAR,
    TypeKind.WCHAR,
    TypeKind.SHORT,
    TypeKind.INT,
    TypeKind.LONG,
    TypeKind.LONGLONG,
    TypeKind.INT128,
    TypeKind.FLOAT,
    TypeKind.DOUBLE,
    TypeKind.LONGDOUBLE,
    TypeKind.FLOAT128,
}


# ---------------------------------------------------------------------------
# Type helpers
# ---------------------------------------------------------------------------

def _base_canonical(t: clang.cindex.Type) -> clang.cindex.Type:
    """
    Get the innermost canonical type, stripping pointers and qualifiers.
    For T*, T**, const T* etc., returns the canonical T.
    """
    c = t.get_canonical()
    while c.kind == TypeKind.POINTER:
        c = c.get_pointee().get_canonical()
    return c


def _is_builtin(t: clang.cindex.Type) -> bool:
    """True if the base (de-pointed) canonical type is a C builtin scalar."""
    return _base_canonical(t).kind in _BUILTIN_KINDS


def _base_type_name(t: clang.cindex.Type) -> str:
    """
    Human-readable name of the base type, preserving the SOURCE-level typedef
    spelling (the name signatures and the LLM use), with pointers, qualifiers
    and struct/class prefixes stripped.

    Uses the SUGARED type — pointers are stripped via get_pointee() on the
    sugared type, which libclang keeps sugared — so a struct-backed handle
    typedef keeps its typedef name instead of collapsing to the bare struct tag
    (the old `_base_canonical(t).spelling` returned the tag, which no caller /
    LLM queries by, breaking find_api for every struct-backed handle):
      cmsIOHANDLER *        → "cmsIOHANDLER"   (was "_cms_io_handler")
      cmsContext            → "cmsContext"     (typedef hides the pointer)
      cJSON **              → "cJSON"
      const cJSON *         → "cJSON"
      const char *          → "char"
      struct _cms_io_handler *  → "_cms_io_handler"  (raw-struct spelling kept as-is)
    is_handle / pointer_depth are decided separately on the canonical type.
    """
    cur = t
    while cur.kind == TypeKind.POINTER:  # strip pointers on the SUGARED type
        cur = cur.get_pointee()
    name = cur.spelling
    # strip const/volatile qualifiers
    for qualifier in ("const ", "volatile ", "restrict "):
        if name.startswith(qualifier):
            name = name[len(qualifier):]
    # strip struct/class/union/enum keyword
    for prefix in ("struct ", "class ", "union ", "enum "):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _opaque_handle_name(t: clang.cindex.Type) -> Optional[str]:
    """
    If ``t`` is an opaque ``pointer-to-void`` typedef, return the typedef name;
    otherwise None.

    Recognizes two styles:
      Style 1 (lcms): ``typedef void *cmsHTRANSFORM``. The typedef itself hides
        the pointer; ``t.spelling`` is the typedef name (no ``*``), and
        ``t.get_canonical()`` is ``void *``.
      Style 2 (curl): ``typedef void CURL;`` used as ``CURL *``. ``t`` is a
        pointer; ``t.get_pointee().spelling`` is the typedef name (not
        literally ``void``).
    """
    can = t.get_canonical()
    if can.kind != TypeKind.POINTER:
        return None
    if can.get_pointee().kind != TypeKind.VOID:
        return None

    def _strip(name: str) -> str:
        for q in ("const ", "volatile ", "restrict "):
            if name.startswith(q):
                name = name[len(q):]
        return name

    # Style 1: typedef hides the pointer (spelling has no '*').
    raw = t.spelling.strip()
    if raw and raw != "void *" and "*" not in raw:
        stripped = _strip(raw)
        if stripped and stripped != "void":
            return stripped

    # Style 2: pointer to a typedef-of-void (pointee name is not literal 'void').
    # Guard against raw ``const void *`` / ``volatile void *`` falling through
    # to a bogus ``"void"`` subject_type after qualifiers are stripped.
    pt_spelling = t.get_pointee().spelling.strip()
    if pt_spelling and pt_spelling != "void":
        stripped = _strip(pt_spelling)
        if stripped and stripped != "void":
            return stripped

    return None


def _pointer_depth(t: clang.cindex.Type) -> int:
    """Number of pointer levels in the canonical type (0=value, 1=T*, 2=T**)."""
    c = t.get_canonical()
    depth = 0
    while c.kind == TypeKind.POINTER:
        depth += 1
        c = c.get_pointee().get_canonical()
    return depth


# ---------------------------------------------------------------------------
# Per-TU extraction
# ---------------------------------------------------------------------------

def _extract_from_tu(
    tu: clang.cindex.TranslationUnit,
    library_root: str,
    export_symbols: Optional[Set[str]],
    compilation_directory: Optional[str] = None,
) -> Dict[str, dict]:
    """
    Walk the AST of one translation unit and return, per public-API definition
    found within the library root, keyed by the mangled ID:
        {mangled: {"name", "mangled", "coord", "ports", "produces", "consumes"}}.

    A definition is a public API iff its linkage is EXTERNAL and its mangled name
    is in ``export_symbols`` (the linkage gate rejects internal ``static`` name
    twins). If ``export_symbols`` is None, every external definition is kept.
    """
    result: Dict[str, dict] = {}

    for cursor in tu.cursor.walk_preorder():
        try:
            cursor_kind = cursor.kind
        except ValueError:
            # The bundled Python bindings can lag libclang's C++ AST enum set.
            # Unknown nodes cannot be one of the function kinds extracted here.
            continue
        if cursor_kind not in _FUNCTION_KINDS:
            continue
        if not cursor.is_definition():
            continue
        if cursor.linkage != LinkageKind.EXTERNAL:
            continue

        mangled = cursor.mangled_name
        if not mangled:
            continue
        public_symbol = mangled
        if export_symbols is not None and public_symbol not in export_symbols:
            if not public_symbol.endswith(_INTERNAL_ALIAS_SUFFIX):
                continue
            public_symbol = public_symbol.removesuffix(_INTERNAL_ALIAS_SUFFIX)
            if public_symbol not in export_symbols:
                continue

        # Definition must live inside the library root.
        loc = cursor.location
        if not loc or not loc.file:
            continue
        file_path = os.path.normpath(loc.file.name)
        if not os.path.isabs(file_path):
            file_path = os.path.normpath(
                os.path.join(compilation_directory or os.getcwd(), file_path)
            )
        try:
            rel = os.path.relpath(file_path, library_root)
        except ValueError:
            continue
        if rel.startswith(".."):
            continue

        ports = _ports_for(cursor)
        result[public_symbol] = {
            "name": public_symbol,
            "mangled": public_symbol,
            "coord": {"file": rel, "line": loc.line, "col": loc.column},
            "ports": ports,
            **derive_handle_flow(ports),
        }

    return result


def _port_record(port: str, t: clang.cindex.Type, is_return: bool) -> Dict[str, object]:
    """Structural facts for one port (the return value or one parameter).

    ``is_handle`` is True for an opaque pointer-to-void typedef (``cmsHTRANSFORM``,
    ``CURL *``) or a non-builtin pointer (``cJSON *``, ``cJSON **``) — i.e. an
    opaque resource object. The opaque-typedef branch mirrors the former Rule
    1b/3b: ``_is_builtin`` strips canonical pointers down to ``void`` and would
    otherwise treat such a typedef as a non-handle and lose its name.

    No produce/consume or acquire/use/release judgement is made here — this is
    pure structure.
    """
    opaque = _opaque_handle_name(t)
    if opaque:
        type_name = opaque
        is_handle = True
    else:
        type_name = _base_type_name(t)
        # A function pointer (callback param) has canonical POINTER kind with a
        # FUNCTION* base; it is NOT a resource handle, so exclude it — otherwise
        # callbacks pollute produces/consumes with bogus function-signature types.
        is_fn_ptr = _base_canonical(t).kind in (
            TypeKind.FUNCTIONPROTO,
            TypeKind.FUNCTIONNOPROTO,
        )
        is_handle = (
            (not _is_builtin(t))
            and t.get_canonical().kind == TypeKind.POINTER
            and not is_fn_ptr
        )
    return {
        "port": port,
        "type": type_name,
        "is_handle": is_handle,
        "pointer_depth": _pointer_depth(t),
        "is_return": is_return,
    }


def _ports_for(func_cursor: clang.cindex.Cursor) -> List[Dict[str, object]]:
    """Enumerate every port of a function: the return value plus each parameter.

    Replaces the former first-match subject_type rule — instead of collapsing to
    one primary type, this keeps the full structural signature so the fact-base
    builder can derive producer/consumer handle flow from the ports (combined
    with the LLM's handle_lifecycle label).
    """
    ports: List[Dict[str, object]] = []

    ret_type = func_cursor.result_type
    if (
        func_cursor.kind not in {CursorKind.CONSTRUCTOR, CursorKind.DESTRUCTOR}
        and ret_type.get_canonical().kind != TypeKind.VOID
    ):
        ports.append(_port_record("return", ret_type, is_return=True))

    for i, param in enumerate(func_cursor.get_arguments()):
        name = param.spelling or f"arg{i}"
        ports.append(_port_record(name, param.type, is_return=False))

    return ports


def derive_handle_flow(ports: List[Dict[str, object]]) -> Dict[str, list]:
    """Produced / consumed handle types, derived purely from the ports.

    One structural rule, no body inspection and no LLM:
      - produce: a handle leaves the function — the return value, or a ``T**``
        out-parameter the function writes through (``pointer_depth >= 2``).
      - consume: a handle enters by value — a ``T*`` parameter the caller
        already holds (``pointer_depth == 1``, not the return).
    Non-handle ports (scalars, strings, by-value structs) are ignored. Each
    entry keeps ``port`` so the type stays bound to a specific parameter.
    """
    produces = [
        {"port": p["port"], "type": p["type"]}
        for p in ports
        if p["is_handle"] and (p["is_return"] or p["pointer_depth"] >= 2)
    ]
    consumes = [
        {"port": p["port"], "type": p["type"]}
        for p in ports
        if p["is_handle"] and not p["is_return"] and p["pointer_depth"] == 1
    ]
    return {"produces": produces, "consumes": consumes}


# ---------------------------------------------------------------------------
# Main extractor class
# ---------------------------------------------------------------------------

class PortExtractor:
    """
    Enumerate structural ports for every API function using Python libclang.

    No external binary required. The caller supplies the run-frozen
    compile_commands.json.
    """

    CACHE_FILENAME = "api_ports.json"

    def __init__(
        self,
        library_name: str,
        compile_commands_path: Path,
        force_recompute: bool = False,
    ):
        self.library_name = library_name
        self.info_lib_dir = PROJECT_ROOT / "info_lib" / library_name
        self.lib_dir = PROJECT_ROOT / "test_lib" / library_name
        self.compile_commands_path = Path(compile_commands_path).resolve(strict=True)
        self.force_recompute = force_recompute
        self._classify_dir = self.info_lib_dir / "raw" / "classify"
        self._cache_path = self._classify_dir / self.CACHE_FILENAME

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self) -> Dict[str, dict]:
        """
        Return the public-API records keyed by mangled ID (see module docstring):
        {mangled: {"name", "mangled", "coord", "ports", "produces", "consumes"}}.
        Results are cached in info_lib/<lib>/raw/classify/api_ports.json.
        """
        if not self.force_recompute and self._cache_path.exists():
            logger.info(f"Loading cached API ports from {self._cache_path}")
            return json.loads(self._cache_path.read_text())

        export_symbols = self._load_export_symbols()
        cc_path = self.compile_commands_path

        logger.info(
            f"Extracting API ports for {self.library_name} "
            f"using {cc_path}"
        )

        entries = json.loads(cc_path.read_text())

        merged: Dict[str, dict] = {}
        index = clang.cindex.Index.create()
        seen: Set[tuple[str, str, tuple[str, ...]]] = set()
        resource_dir = _clang_resource_dir()

        for entry in entries:
            source = entry.get("file", "")
            if not source:
                continue
            source = os.path.normpath(source)

            # Get compile args from the entry
            arguments = entry.get("arguments")
            if arguments:
                args = list(arguments[1:])  # drop the compiler executable
            else:
                cmd_str = entry.get("command", "")
                args = shlex.split(cmd_str)[1:] if cmd_str else []

            entry_dir = entry.get("directory", "")
            args = _filter_args(args, source, cwd=entry_dir)
            if not any(arg.startswith("-resource-dir") for arg in args):
                args.append(f"-resource-dir={resource_dir}")
            source_path = (
                source
                if os.path.isabs(source)
                else os.path.join(entry_dir, source)
            )
            parse_key = (
                os.path.realpath(source_path),
                os.path.realpath(entry_dir),
                tuple(args),
            )
            if parse_key in seen:
                continue
            seen.add(parse_key)

            # Switch cwd to the build directory so relative include paths
            # (e.g. ``-I../../include``) resolve correctly during parsing.
            saved_cwd = os.getcwd()
            try:
                if entry_dir and os.path.isdir(entry_dir):
                    os.chdir(entry_dir)
                tu = index.parse(source, args=args)
            except Exception as exc:
                logger.warning(f"Failed to parse {source}: {exc}")
                continue
            finally:
                os.chdir(saved_cwd)

            result = _extract_from_tu(
                tu, str(self.lib_dir), export_symbols, compilation_directory=entry_dir
            )
            for mangled, record in result.items():
                existing = merged.get(mangled)
                if existing is not None and existing != record:
                    raise ValueError(
                        "inconsistent API port records for "
                        f"{mangled}: {existing!r} != {record!r}"
                    )
                merged[mangled] = record

        logger.info(
            f"API ports computed for {len(merged)} functions "
            f"(library: {self.library_name})"
        )
        self._classify_dir.mkdir(parents=True, exist_ok=True)
        self._cache_path.write_text(json.dumps(merged, indent=2, sort_keys=True))
        return merged

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_export_symbols(self) -> Optional[Set[str]]:
        """Load the canonical ABI symbols accepted by public-interface analysis."""
        path = self.info_lib_dir / "txt" / "api_symbols.txt"
        if not path.is_file():
            raise FileNotFoundError(f"canonical API symbol list is missing: {path}")
        symbols = {
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        if not symbols:
            raise ValueError(f"canonical API symbol list is empty: {path}")
        return symbols
