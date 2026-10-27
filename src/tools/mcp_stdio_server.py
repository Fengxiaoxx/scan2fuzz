"""Standard stdio MCP server for Trace2Fuzz's custom tools."""

from __future__ import annotations

import argparse
import os
import sys

import anyio
from mcp.server.stdio import stdio_server

from src.tools.trace2fuzz_mcp import (
    TOOL_SPECS,
    Trace2FuzzToolRegistry,
    create_standard_mcp_server,
)


PROFILES = {
    "doc": ["get_source", "goto_definition", "callees", "callers", "types_used"],
    "driver": [
        "find_api",
        "find_drivers",
        "get_source",
        "goto_definition",
        "callees",
        "callers",
        "types_used",
    ],
    "compile": [
        "Read",
        "Grep",
        "Glob",
        "edit_driver",
        "compile_driver",
        "get_source",
        "goto_definition",
        "callees",
        "callers",
        "types_used",
    ],
    "search": ["search_function"],
}


def _infer_library(explicit: str | None) -> str:
    """Resolve the library name from --library, T2F_MCP_LIBRARY, or cwd."""
    if explicit:
        return explicit
    env = os.getenv("T2F_MCP_LIBRARY", "").strip()
    if env:
        return env
    # Infer from cwd when it sits under .../test_lib/<lib>[/...].
    parts = os.path.abspath(os.getcwd()).split(os.sep)
    if "test_lib" in parts:
        i = parts.index("test_lib")
        if i + 1 < len(parts):
            return parts[i + 1]
    raise SystemExit(
        "library not given: pass --library <name>, set T2F_MCP_LIBRARY, "
        "or run from inside test_lib/<lib>/"
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mcp_stdio_server",
        description="Trace2Fuzz tools as a standard stdio MCP server",
    )
    p.add_argument("--library", "-l", default=None, help="library name (e.g. lcms)")
    p.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="driver",
        help="predefined tool subset (default: driver)",
    )
    p.add_argument(
        "--tools",
        nargs="+",
        choices=sorted(TOOL_SPECS),
        help="explicit tool subset; overrides --profile",
    )
    p.add_argument(
        "--editable-file",
        help="single driver path available to edit_driver/compile_driver",
    )
    return p.parse_args(argv)


async def _serve(server: object) -> None:
    init_opts = server.create_initialization_options()  # type: ignore[attr-defined]
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, init_opts)  # type: ignore[attr-defined]


def main(argv: list[str] | None = None) -> None:
    ns = _parse_args(sys.argv[1:] if argv is None else argv)
    library = _infer_library(ns.library)
    tool_names = list(ns.tools or PROFILES[ns.profile])
    registry = Trace2FuzzToolRegistry(
        library,
        tool_names,
        editable_file=ns.editable_file,
    )
    server = create_standard_mcp_server(registry)
    anyio.run(_serve, server)


if __name__ == "__main__":
    main()
