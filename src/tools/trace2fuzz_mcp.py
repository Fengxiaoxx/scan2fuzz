"""Provider-neutral Trace2Fuzz tools exposed through standard MCP."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from fnmatch import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from mcp import types
from mcp.server import Server

from src.core import get_project_root


TRACE2FUZZ_MCP_SERVER_NAME = "t2f"
LSP_TOOL_NAMES = (
    "get_source",
    "goto_definition",
    "callees",
    "callers",
    "types_used",
)
FILE_TOOL_NAMES = ("Read", "Grep", "Glob")

def _object_schema(
    properties: Mapping[str, dict[str, Any]],
    required: Sequence[str],
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": dict(properties),
        "required": list(required),
        "additionalProperties": False,
    }


_STRING = {"type": "string"}
_BOOLEAN = {"type": "boolean"}
_NONNEGATIVE_INTEGER = {"type": "integer", "minimum": 0}
_POSITIVE_INTEGER = {"type": "integer", "minimum": 1}
_COORD_SCHEMA = _object_schema(
    {"file": _STRING, "line": _POSITIVE_INTEGER, "col": _POSITIVE_INTEGER},
    ("file", "line", "col"),
)


def _resolve_editable_file(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError(f"editable_file must not be a symlink: {candidate}")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"editable_file must be a regular file: {resolved}")
    return resolved


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    read_only: bool = True
    destructive: bool = False

    def as_mcp_tool(self, library_name: str) -> types.Tool:
        return types.Tool(
            name=self.name,
            description=self.description.format(library_name=library_name),
            inputSchema=self.input_schema,
            annotations=types.ToolAnnotations(
                readOnlyHint=self.read_only,
                destructiveHint=self.destructive,
                idempotentHint=self.read_only,
                openWorldHint=False,
            ),
        )


@dataclass(frozen=True)
class ToolExecutionResult:
    text: str
    is_error: bool = False

    def as_mcp_result(self) -> types.CallToolResult:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=self.text)],
            isError=self.is_error,
        )


TOOL_SPECS: dict[str, ToolSpec] = {
    "Read": ToolSpec(
        name="Read",
        description=(
            "Read a UTF-8 source file from the current library or the isolated "
            "driver workspace. Lines are returned with 1-based line numbers."
        ),
        input_schema=_object_schema(
            {
                "file_path": _STRING,
                "offset": _NONNEGATIVE_INTEGER,
                "limit": _POSITIVE_INTEGER,
            },
            ("file_path",),
        ),
    ),
    "Grep": ToolSpec(
        name="Grep",
        description=(
            "Search source files in the current library or isolated driver "
            "workspace using a regular expression."
        ),
        input_schema=_object_schema(
            {
                "pattern": _STRING,
                "path": _STRING,
                "glob": _STRING,
                "type": _STRING,
                "output_mode": {
                    "type": "string",
                    "enum": ["content", "files_with_matches", "count"],
                },
                "-i": _BOOLEAN,
                "-n": _BOOLEAN,
                "-A": _NONNEGATIVE_INTEGER,
                "-B": _NONNEGATIVE_INTEGER,
                "-C": _NONNEGATIVE_INTEGER,
                "head_limit": _POSITIVE_INTEGER,
                "offset": _NONNEGATIVE_INTEGER,
                "multiline": _BOOLEAN,
            },
            ("pattern",),
        ),
    ),
    "Glob": ToolSpec(
        name="Glob",
        description=(
            "Find files by glob pattern in the current library or isolated "
            "driver workspace."
        ),
        input_schema=_object_schema(
            {"pattern": _STRING, "path": _STRING},
            ("pattern",),
        ),
    ),
    "edit_driver": ToolSpec(
        name="edit_driver",
        description="Replace one unique string in the isolated driver candidate.",
        input_schema=_object_schema(
            {"old_string": _STRING, "new_string": _STRING},
            ("old_string", "new_string"),
        ),
        read_only=False,
        destructive=True,
    ),
    "search_function": ToolSpec(
        name="search_function",
        description="Search {library_name} functions by functionality description.",
        input_schema=_object_schema({"query": _STRING}, ("query",)),
    ),
    "find_api": ToolSpec(
        name="find_api",
        description=(
            "Find the most relevant {library_name} API for creating, using, or releasing "
            "a handle. Combines lifecycle and handle-type filtering with semantic "
            "ranking to select up to three candidates in relevance order.\n\n"
            "When you need to identify an API for a desired operation, use this tool "
            "first rather than searching source files for candidate APIs. Describe "
            "the operation in natural language; you do not need to know the API name. "
            "Then use source browsing tools to inspect the returned candidates and "
            "confirm their usage.\n\n"
            "Provide handle_lifecycle (acquire_handle, use_handle, or release_handle), "
            "handle_type, and a brief nl_description of the desired operation.\n\n"
            "Example: To find how to release an existing cJSON object, use:\n"
            '{{"handle_lifecycle": "release_handle", "handle_type": "cJSON", '
            '"nl_description": "Delete a cJSON object and free its child nodes"}}\n\n'
            "Returns a list of up to three APIs, each with only header_file, "
            "signature, source, and coord. Returns an empty list when no API matches."
        ),
        input_schema=_object_schema(
            {
                "handle_lifecycle": _STRING,
                "handle_type": _STRING,
                "nl_description": _STRING,
            },
            ("handle_lifecycle", "handle_type", "nl_description"),
        ),
    ),
    "find_drivers": ToolSpec(
        name="find_drivers",
        description=(
            "Get one example {library_name} fuzz driver (the library's own bundled "
            "upstream fuzzer source) to use as a template. Pass target_function = the API "
            "you are writing a driver for; returns the bundled fuzzer that best matches — "
            "one that calls target_function if available, otherwise the richest example. "
            "Returns the matching driver's full source code to use as a template "
            "(or a short note if the library bundles no fuzzer)."
        ),
        input_schema=_object_schema(
            {"target_function": _STRING},
            ("target_function",),
        ),
    ),
    "compile_driver": ToolSpec(
        name="compile_driver",
        description=(
            "Compile a {library_name} fuzz driver file with the project's clang flags. "
            "Pass the absolute driver_file path. Returns {{success: bool, error: str, "
            "command: str, output_file: str}}. Use this inside a fix-and-recompile loop: "
            "edit the driver with edit_driver, call compile_driver, inspect error if "
            "success is false, iterate. Stop iterating once success is true."
        ),
        input_schema=_object_schema(
            {"driver_file": _STRING},
            ("driver_file",),
        ),
        read_only=False,
    ),
    "get_source": ToolSpec(
        name="get_source",
        description=(
            "When you already have a function or type definition coordinate and need to "
            "inspect its full implementation or declaration. Pass the definition coordinate, "
            "not a call/use site (file, line, col; 1-based, on the symbol name). Returns JSON "
            "with name, location, and source. If you only have a use site, call "
            "goto_definition first."
        ),
        input_schema=_COORD_SCHEMA,
    ),
    "goto_definition": ToolSpec(
        name="goto_definition",
        description=(
            "When you have a symbol at a use site and need to find where it is defined. Pass "
            "the use-site coordinate on the type or function name (file, line, col; 1-based). "
            "Returns JSON with name, definition location, and source."
        ),
        input_schema=_COORD_SCHEMA,
    ),
    "callees": ToolSpec(
        name="callees",
        description=(
            "When you need to know which functions a specific function directly calls. Pass "
            "the function's definition coordinate, not a call/use site (file, line, col; "
            "1-based, on the function name). Returns a JSON array of directly called functions."
        ),
        input_schema=_COORD_SCHEMA,
    ),
    "callers": ToolSpec(
        name="callers",
        description=(
            "When you need to know which functions directly call a specific function. Pass "
            "the function's definition coordinate, not a call/use site (file, line, col; "
            "1-based, on the function name). Returns a JSON array of direct callers."
        ),
        input_schema=_COORD_SCHEMA,
    ),
    "types_used": ToolSpec(
        name="types_used",
        description=(
            "When you need to know which types are referenced inside a specific function. Pass "
            "the function's definition coordinate (file, line, col; 1-based, on the function "
            "name). Returns a JSON array of {{name, kind, line, col}}; pass one of those type "
            "coordinates to goto_definition to inspect the type."
        ),
        input_schema=_COORD_SCHEMA,
    ),
}


class Trace2FuzzToolRegistry:
    """Lazily initialized implementations for one library and tool subset."""

    def __init__(
        self,
        library_name: str,
        tool_names: Sequence[str],
        *,
        editable_file: Optional[str] = None,
    ) -> None:
        if not library_name:
            raise ValueError("library_name must not be empty")
        if not tool_names:
            raise ValueError("at least one tool must be enabled")
        unknown = sorted(set(tool_names) - set(TOOL_SPECS))
        if unknown:
            raise ValueError(f"unknown Trace2Fuzz tools: {unknown}")
        if len(set(tool_names)) != len(tool_names):
            raise ValueError("tool_names must not contain duplicates")

        self.library_name = library_name
        self.tool_names = tuple(tool_names)
        self._instances: dict[str, Any] = {}
        self.project_root = Path(get_project_root()).resolve()
        self.library_root = (self.project_root / "test_lib" / library_name).resolve()
        self.editable_path = (
            _resolve_editable_file(editable_file) if editable_file else None
        )
        if "edit_driver" in self.tool_names and self.editable_path is None:
            raise ValueError("edit_driver requires --editable-file")

    @property
    def specs(self) -> list[ToolSpec]:
        return [TOOL_SPECS[name] for name in self.tool_names]

    async def call(
        self, name: str, arguments: Mapping[str, Any]
    ) -> ToolExecutionResult:
        if name not in self.tool_names:
            return ToolExecutionResult(f"tool is not enabled: {name}", is_error=True)
        try:
            handler = getattr(self, f"_call_{name}")
            return handler(dict(arguments))
        except Exception as exc:
            return ToolExecutionResult(
                json.dumps({"error": str(exc)}, ensure_ascii=False),
                is_error=True,
            )

    def _instance(self, name: str, factory: Any) -> Any:
        if name not in self._instances:
            self._instances[name] = factory()
        return self._instances[name]

    def _resolve_read_path(self, raw_path: str) -> Path:
        requested = Path(raw_path or ".")
        if requested.is_absolute():
            candidates = [requested]
        else:
            candidates = [
                self.library_root / requested,
                self.project_root / requested,
            ]
        candidate = next((path for path in candidates if path.exists()), candidates[0])
        resolved = candidate.resolve(strict=True)
        roots = [self.library_root]
        if self.editable_path is not None:
            roots.append(self.editable_path.parent)
        if not any(resolved == root or root in resolved.parents for root in roots):
            raise ValueError(f"path is outside the allowed source roots: {resolved}")
        return resolved

    @staticmethod
    def _display_path(path: Path, project_root: Path) -> str:
        try:
            return str(path.relative_to(project_root))
        except ValueError:
            return str(path)

    def _call_Read(self, arguments: dict[str, Any]) -> ToolExecutionResult:
        path = self._resolve_read_path(arguments["file_path"])
        if not path.is_file():
            return ToolExecutionResult(f"not a regular file: {path}", is_error=True)
        offset = int(arguments.get("offset", 0) or 0)
        limit = min(int(arguments.get("limit", 2000) or 2000), 5000)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        selected = lines[offset : offset + limit]
        if not selected:
            return ToolExecutionResult("(empty file or offset beyond end)")
        return ToolExecutionResult(
            "\n".join(
                f"{line_number:6d}\t{line}"
                for line_number, line in enumerate(selected, start=offset + 1)
            )
        )

    def _call_Glob(self, arguments: dict[str, Any]) -> ToolExecutionResult:
        base = self._resolve_read_path(arguments.get("path") or ".")
        if not base.is_dir():
            return ToolExecutionResult(f"not a directory: {base}", is_error=True)
        matches = [
            path.resolve()
            for path in base.glob(arguments["pattern"])
            if path.is_file() and not path.is_symlink()
        ]
        rendered = [
            self._display_path(path, self.project_root)
            for path in sorted(set(matches))[:1000]
        ]
        return ToolExecutionResult("\n".join(rendered) if rendered else "No files found")

    def _call_Grep(self, arguments: dict[str, Any]) -> ToolExecutionResult:
        base = self._resolve_read_path(arguments.get("path") or ".")
        flags = re.IGNORECASE if arguments.get("-i") else 0
        pattern = re.compile(arguments["pattern"], flags)
        file_glob = str(arguments.get("glob") or "")
        file_type = str(arguments.get("type") or "")
        type_globs = {
            "c": ("*.c", "*.h"),
            "cpp": ("*.cc", "*.cpp", "*.cxx", "*.h", "*.hh", "*.hpp"),
        }.get(file_type, ())
        if base.is_file():
            files = [base]
        else:
            files = [
                path
                for path in base.rglob("*")
                if path.is_file() and not path.is_symlink()
            ]

        matched: list[tuple[Path, list[tuple[int, str]]]] = []
        for path in files:
            relative = str(path.relative_to(base)) if base.is_dir() else path.name
            if file_glob and not (
                fnmatch(relative, file_glob) or fnmatch(path.name, file_glob)
            ):
                continue
            if type_globs and not any(fnmatch(path.name, item) for item in type_globs):
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            hits = [
                (line_number, line)
                for line_number, line in enumerate(lines, start=1)
                if pattern.search(line)
            ]
            if hits:
                matched.append((path.resolve(), hits))

        output_mode = arguments.get("output_mode") or "files_with_matches"
        rendered: list[str] = []
        if output_mode == "files_with_matches":
            rendered = [
                self._display_path(path, self.project_root) for path, _ in matched
            ]
        elif output_mode == "count":
            rendered = [
                f"{self._display_path(path, self.project_root)}:{len(hits)}"
                for path, hits in matched
            ]
        else:
            for path, hits in matched:
                display = self._display_path(path, self.project_root)
                rendered.extend(f"{display}:{number}:{line}" for number, line in hits)

        offset = int(arguments.get("offset", 0) or 0)
        head_limit = min(int(arguments.get("head_limit", 1000) or 1000), 5000)
        rendered = rendered[offset : offset + head_limit]
        return ToolExecutionResult("\n".join(rendered) if rendered else "No matches found")

    def _call_edit_driver(self, arguments: dict[str, Any]) -> ToolExecutionResult:
        assert self.editable_path is not None
        old = arguments["old_string"]
        new = arguments["new_string"]
        if not old:
            return ToolExecutionResult("old_string must not be empty", is_error=True)
        current = self.editable_path.read_text(encoding="utf-8")
        count = current.count(old)
        if count != 1:
            return ToolExecutionResult(
                f"old_string must match exactly once; found {count}",
                is_error=True,
            )
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.editable_path.name}.",
            suffix=".tmp",
            dir=self.editable_path.parent,
            text=True,
        )
        try:
            with os.fdopen(
                descriptor, "w", encoding="utf-8", newline="\n"
            ) as stream:
                stream.write(current.replace(old, new, 1))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.editable_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return ToolExecutionResult("driver candidate updated")

    def _call_search_function(
        self, arguments: dict[str, Any]
    ) -> ToolExecutionResult:
        from src.tools.semantic_search import SemanticFunctionSearcher

        searcher = self._instance(
            "semantic_search",
            lambda: SemanticFunctionSearcher(self.library_name),
        )
        return ToolExecutionResult(searcher.search(arguments["query"]))

    def _call_find_api(self, arguments: dict[str, Any]) -> ToolExecutionResult:
        from src.tools.fact_base_query import FactBaseQuery

        fact_base = self._instance(
            "fact_base",
            lambda: FactBaseQuery(self.library_name),
        )
        result = fact_base.query(
            arguments["handle_lifecycle"],
            arguments["handle_type"],
            arguments["nl_description"],
        )
        return ToolExecutionResult(
            json.dumps(result, ensure_ascii=False, indent=2)
        )

    def _call_find_drivers(
        self, arguments: dict[str, Any]
    ) -> ToolExecutionResult:
        from src.tools.driver_query import DriverQuery

        drivers = self._instance(
            "drivers",
            lambda: DriverQuery(self.library_name),
        )
        result = drivers.find(arguments["target_function"])
        if not result.get("found"):
            return ToolExecutionResult(
                "No bundled example fuzz driver found for this library."
            )
        return ToolExecutionResult(result["source"])

    def _call_compile_driver(
        self, arguments: dict[str, Any]
    ) -> ToolExecutionResult:
        from src.tools.compiler import compile_driver

        requested = Path(arguments["driver_file"]).resolve(strict=True)
        if self.editable_path is not None and requested != self.editable_path:
            return ToolExecutionResult(
                f"compile_driver is restricted to {self.editable_path}",
                is_error=True,
            )
        result = compile_driver(str(requested), self.library_name)
        return ToolExecutionResult(
            json.dumps(
                {
                    "success": bool(result.get("success", False)),
                    "error": result.get("error", "")
                    or result.get("stderr", ""),
                    "command": result.get("compile_command", ""),
                    "output_file": result.get("binary_file", "") or "",
                },
                ensure_ascii=False,
                indent=2,
            )
        )

    def _lsp_call(
        self, method: str, arguments: dict[str, Any]
    ) -> ToolExecutionResult:
        from src.tools.lsp_resolver import LspResolver

        resolver = self._instance(
            "lsp",
            lambda: LspResolver(self.library_name),
        )
        try:
            return ToolExecutionResult(getattr(resolver, method)(arguments))
        except Exception as exc:
            return ToolExecutionResult(
                json.dumps(
                    {"error": f"LSP unavailable: {exc}"},
                    ensure_ascii=False,
                ),
                is_error=True,
            )

    def _call_get_source(self, arguments: dict[str, Any]) -> ToolExecutionResult:
        return self._lsp_call("get_source", arguments)

    def _call_goto_definition(
        self, arguments: dict[str, Any]
    ) -> ToolExecutionResult:
        return self._lsp_call("goto_definition", arguments)

    def _call_callees(self, arguments: dict[str, Any]) -> ToolExecutionResult:
        return self._lsp_call("callees", arguments)

    def _call_callers(self, arguments: dict[str, Any]) -> ToolExecutionResult:
        return self._lsp_call("callers", arguments)

    def _call_types_used(self, arguments: dict[str, Any]) -> ToolExecutionResult:
        return self._lsp_call("types_used", arguments)


def create_standard_mcp_server(registry: Trace2FuzzToolRegistry) -> Server:
    """Create a standard MCP server consumable by any MCP client."""
    server = Server(TRACE2FUZZ_MCP_SERVER_NAME)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            spec.as_mcp_tool(registry.library_name)
            for spec in registry.specs
        ]

    @server.call_tool()
    async def call_tool(
        name: str, arguments: dict[str, Any]
    ) -> types.CallToolResult:
        return (await registry.call(name, arguments)).as_mcp_result()

    return server


def select_tool_names(
    *,
    include_file_tools: bool = False,
    include_search_function: bool = True,
    include_compile_driver: bool = False,
    include_lsp: bool = False,
    include_fact_base: bool = False,
    include_drivers: bool = False,
    editable_file: Optional[str] = None,
) -> list[str]:
    names: list[str] = []
    if include_file_tools:
        names.extend(FILE_TOOL_NAMES)
    if editable_file is not None:
        names.append("edit_driver")
    if include_search_function:
        names.append("search_function")
    if include_fact_base:
        names.append("find_api")
    if include_drivers:
        names.append("find_drivers")
    if include_compile_driver:
        names.append("compile_driver")
    if include_lsp:
        names.extend(LSP_TOOL_NAMES)
    return names


@dataclass(frozen=True)
class Trace2FuzzMcpBundle:
    """Standard stdio configuration plus runtime-specific configurations."""

    server_name: str
    server_config: dict[str, Any]
    runtime_server_config: dict[str, Any]
    tool_names: list[str]
    bare_tool_names: list[str]

    def opencode_config(self) -> dict[str, Any]:
        server = dict(self.runtime_server_config)
        return {"mcp": {self.server_name: server}}


def create_trace2fuzz_mcp_bundle(
    library_name: str,
    *,
    include_file_tools: bool = False,
    include_search_function: bool = True,
    include_compile_driver: bool = False,
    include_lsp: bool = False,
    include_fact_base: bool = False,
    include_drivers: bool = False,
    editable_file: Optional[str] = None,
    python_executable: Optional[str] = None,
) -> Trace2FuzzMcpBundle:
    """Build stdio launch settings for one Trace2Fuzz tool subset."""
    bare_names = select_tool_names(
        include_file_tools=include_file_tools,
        include_search_function=include_search_function,
        include_compile_driver=include_compile_driver,
        include_lsp=include_lsp,
        include_fact_base=include_fact_base,
        include_drivers=include_drivers,
        editable_file=editable_file,
    )
    if not bare_names:
        raise ValueError("at least one Trace2Fuzz MCP tool must be enabled")

    root = str(Path(get_project_root()).resolve())
    command = python_executable or sys.executable
    editable_path = (
        _resolve_editable_file(editable_file) if editable_file else None
    )
    args = [
        "-m",
        "src.tools.mcp_stdio_server",
        "--library",
        library_name,
        "--tools",
        *bare_names,
    ]
    if editable_path is not None:
        args.extend(["--editable-file", str(editable_path)])

    child_env = {"PYTHONPATH": root}
    env_keys = ["RUN_DIR", "RUN_ID"]
    for key in env_keys:
        value = os.environ.get(key)
        if value:
            child_env[key] = value

    stdio_config: dict[str, Any] = {
        "type": "stdio",
        "command": command,
        "args": args,
        "env": child_env,
    }
    runtime_server_config: dict[str, Any] = {
        "command": command,
        "args": args,
        "cwd": root,
        "env": child_env,
        "enabled_tools": bare_names,
        "required": True,
        "startup_timeout_sec": 30,
        "tool_timeout_sec": 300,
    }
    return Trace2FuzzMcpBundle(
        server_name=TRACE2FUZZ_MCP_SERVER_NAME,
        server_config=stdio_config,
        runtime_server_config=runtime_server_config,
        tool_names=[
            f"mcp__{TRACE2FUZZ_MCP_SERVER_NAME}__{name}" for name in bare_names
        ],
        bare_tool_names=bare_names,
    )
