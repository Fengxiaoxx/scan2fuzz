from __future__ import annotations

import argparse
import logging
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

LOGGER = logging.getLogger(__name__)
_SPLITTER = "|autofuzz_splitter|"


@dataclass
class BuildCommand:
    cmd: str
    path: Path = Path()

    def __post_init__(self) -> None:
        self.path = self.path.absolute()

    def is_link(self) -> bool:
        return (" -c " not in self.cmd) and (not self.cmd.endswith("-c"))

    def is_assemble(self) -> bool:
        tool = _split_command_preserving_macro_quotes(self.cmd)[0]
        if "yasm" in tool:
            return True

        output = re.search(r"(-o )(.+?)( |$)", self.cmd)
        if output is not None and re.search(r"[\w._/-]+?\.l?(s)", output.group(0)):
            return True

        return any(token.endswith('.S') for token in _split_command_preserving_macro_quotes(self.cmd))

    def abspath(self, src: Path) -> Path:
        if src.is_absolute():
            return src.resolve()
        return (self.path / src).resolve()

    def output(self, real: bool = True) -> Path:
        result = ""
        if match := re.search(r"(-o )(.+?)( |$)", self.cmd):
            result = match.group(2)
        elif match := re.search(r"[\w._/-]+?\.l?a", self.cmd):
            result = match.group(0)
        elif match := re.search(r"[\w._/-]+?\.l?(c|cpp|cc|cxx)", self.cmd):
            result = match.group(0)
            result = result[: result.rfind('.')]
            result = result + '.o'
        result_path = Path(result)
        return self.abspath(result_path) if real else result_path

    def is_archive(self) -> bool:
        tool = Path(_split_command_preserving_macro_quotes(self.cmd)[0]).name
        return re.fullmatch(r"(llvm-)?ar(-\d+)?", tool) is not None

    def whole_archives(self) -> List[Path]:
        """Static archives this command links whole (-Wl,--whole-archive).

        A whole archive is part of the target itself; an archive linked the
        ordinary way is a dependency that only resolves symbols.
        """
        whole = False
        result: List[Path] = []
        for token in _split_command_preserving_macro_quotes(self.cmd)[1:]:
            if token == "-Wl,--whole-archive":
                whole = True
            elif token == "-Wl,--no-whole-archive":
                whole = False
            elif whole and token.endswith(".a"):
                result.append(self.abspath(Path(token)))
        return result

    def objects(self) -> List[Path]:
        tokens = _split_command_preserving_macro_quotes(self.cmd)
        if self.is_link():
            result = {
                token for token in tokens if token.endswith(('.o', '.lo'))
            }
        else:
            try:
                idx = tokens.index('-o')
            except ValueError as exc:
                raise RuntimeError(f'Unable to find objects in ({self.cmd})') from exc
            result = {tokens[idx + 1]}
        return [self.abspath(Path(obj)) for obj in sorted(result)]

    def sources(self, real: bool = True) -> List[Path]:
        tokens = _split_command_preserving_macro_quotes(self.cmd)
        sources = [Path(token) for token in tokens if re.search(r'\.(c|cpp|cc|cxx)$', token)]
        if real:
            sources = [self.abspath(source) for source in sources]
        return sources


class BuildLogParser:
    def __init__(self, build_log_path: Path):
        self.build_log_path = build_log_path.resolve()
        if not self.build_log_path.exists():
            raise FileNotFoundError(self.build_log_path)

    def parse(
        self, real: bool = True
    ) -> Tuple[
        Dict[Path, BuildCommand],
        Dict[Path, BuildCommand],
        Dict[Path, BuildCommand],
        Dict[Path, BuildCommand],
    ]:
        lines = self.build_log_path.read_text().replace("\\\n", "").splitlines()

        compiles: List[BuildCommand] = []
        links: List[BuildCommand] = []
        assems: List[BuildCommand] = []
        for line in lines:
            if not line.strip():
                continue
            command = self.parse_command(line)
            if command.is_link():
                links.append(command)
            else:
                compiles.append(command)
            if command.is_assemble():
                assems.append(command)

        srcs: Dict[Path, BuildCommand] = {}
        for cmd in compiles:
            for src in cmd.sources(True):
                srcs[src] = cmd

        compile_map = {compile_cmd.output(real): compile_cmd for compile_cmd in compiles}
        link_map = {link_cmd.output(real): link_cmd for link_cmd in links}
        assem_map = {assem_cmd.output(real): assem_cmd for assem_cmd in assems}
        # Large archives are written by several appending commands (OpenSSL
        # adds libcrypto.a members in chunks); keep every writer.
        self.archive_writers: Dict[Path, List[BuildCommand]] = {}
        for link_cmd in links:
            if link_cmd.is_archive() and link_cmd.output().suffix == ".a":
                self.archive_writers.setdefault(link_cmd.output(), []).append(link_cmd)
        return srcs, compile_map, link_map, assem_map

    def parse_command(self, captured_command: str) -> BuildCommand:
        tokens = [
            token.strip()
            for token in captured_command.split(_SPLITTER)
            if token.strip()
        ]
        if len(tokens) != 2:
            raise ValueError(f"Invalid command line: {captured_command}")
        path = Path(tokens[0])
        command = normalize_command(tokens[1])
        return BuildCommand(command, path)


def _split_command_preserving_macro_quotes(cmd: str) -> List[str]:
    # Preserve quotes embedded inside macro definitions such as
    # -DTABLESDIR="/usr/local/share/liblouis/tables". shlex would strip
    # those quotes, which changes the C preprocessor value.
    pattern = re.compile(r"'(-D[^']*)'|-D[^\s=]+=\"[^\"]*\"|-D[^\s]+")
    macros: List[str] = []

    def repl(match: re.Match[str]) -> str:
        macros.append(match.group(1) or match.group(0))
        return f'__AUTOFUZZ_MACRO_{len(macros) - 1}__'

    protected = pattern.sub(repl, cmd)
    parts = shlex.split(protected)

    restored: List[str] = []
    for part in parts:
        if part.startswith('__AUTOFUZZ_MACRO_') and part.endswith('__'):
            try:
                idx = int(part[len('__AUTOFUZZ_MACRO_'):-2])
            except ValueError:
                restored.append(part)
                continue
            restored.append(macros[idx])
        else:
            restored.append(part)
    return restored


def normalize_command(cmd: str) -> str:
    cmd_pattern = re.compile(
        r"(ar|llvm-ar(?:-\d+)?|clang(?:\+\+)?(?:-\d+)?) "
    )
    unnecessary_opts = {
        "-O4",
        "-O3",
        "-O2",
        "-O1",
        "-Og",
        "-Os",
        "-Oz",
        "-Ofast",
        "-O0",
        "-O",
        "-DNDEBUG",
        "-fno-exceptions",
        "-std=gnu99",
    }

    match = cmd_pattern.search(cmd)
    if match is not None:
        cmd = cmd[match.start() :]
    tokens: List[str] = []
    for token in _split_command_preserving_macro_quotes(cmd):
        token = token.strip()
        if (
            not token
            or token in unnecessary_opts
            or token.startswith("-Werror")
            or token.startswith("-fsanitize")
        ):
            continue
        if token.startswith("&&"):
            tokens.clear()
            continue
        tokens.append(token)
    return shlex.join(tokens)


def rewrite_emit_command(
    command: BuildCommand, emit_type: str = "bc", extra_opts: str = "-O0 -g"
) -> str:
    emit_opt = "-emit-ast" if emit_type == "ast" else "-emit-llvm"
    cmd = re.compile(r"^(clang(?:\+\+)?(?:-\d+)?) ").sub(
        rf"\g<1> {emit_opt} ", command.cmd
    )
    return f"{cmd} {extra_opts}".strip()


def emit(
    command: BuildCommand,
    output_root: Path,
    emit_type: str = "bc",
    extra_opts: str = "-O0 -g",
) -> Path:
    output_root = output_root.resolve()
    cmd = rewrite_emit_command(
        command, emit_type=emit_type, extra_opts=extra_opts
    )

    output = command.output(False)
    toutput = Path(output)
    if toutput.is_absolute():
        try:
            toutput = toutput.relative_to(command.path)
        except ValueError:
            toutput = Path(*toutput.parts[1:])  # strip leading /

    emitted = output_root / f"{toutput}.{emit_type}"
    emitted.parent.mkdir(parents=True, exist_ok=True)

    cmd_tokens = shlex.split(cmd)
    if "-o" in cmd_tokens:
        idx = cmd_tokens.index("-o")
        cmd_tokens[idx + 1] = str(emitted)
    else:
        cmd_tokens.extend(["-o", str(emitted)])

    LOGGER.info("Emit %s from %s", emit_type, output)
    subprocess.run(cmd_tokens, cwd=command.path, check=True)
    if not emitted.exists():
        raise FileNotFoundError(emitted)
    return emitted


def emit_bc(
    command: BuildCommand, output_root: Path, extra_opts: str = "-O0 -g"
) -> Path:
    return emit(command, output_root, emit_type="bc", extra_opts=extra_opts)


def link_bitcode(
    bitcodes: Iterable[Path], output_path: Path, cwd: Path | None = None
) -> Path:
    bitcodes = [Path(bc).resolve() for bc in bitcodes]
    if not bitcodes:
        raise ValueError("No bitcode files to link")
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    linker = shutil.which("llvm-link-18")
    if linker is None:
        raise FileNotFoundError("llvm-link-18 is not available")
    cmd = [linker, *map(str, bitcodes), "-o", str(output_path)]
    subprocess.run(cmd, cwd=cwd, check=True)
    if not output_path.exists():
        raise FileNotFoundError(output_path)
    return output_path


def resolve_target(
    links: Dict[Path, BuildCommand], target: str
) -> Tuple[Path, BuildCommand]:
    target_name = Path(target).name
    candidates = [
        (path, cmd)
        for path, cmd in links.items()
        if path.name == target_name or str(path) == target
    ]
    if len(candidates) != 1:
        raise RuntimeError(
            f"Ambiguous target {target!r}: {[str(path) for path, _ in candidates]}"
        )
    return candidates[0]


def get_target_sources(
    build_log_path: Path,
    target: str,
) -> List[Path]:
    """Return source files that participate in building the given link target."""
    _target_path, compile_commands = _target_compile_commands(
        build_log_path, target
    )
    return [
        source
        for command in compile_commands
        for source in command.sources(real=True)
    ]


def _target_compile_commands(
    build_log_path: Path,
    target: str,
) -> Tuple[Path, List[BuildCommand]]:
    """Resolve every non-assembly object in one link target to its compiler command."""
    parser = BuildLogParser(build_log_path)
    _srcs, compiles, links, assems = parser.parse()
    target_path, link_cmd = resolve_target(links, target)

    objects = link_cmd.objects()
    for archive in link_cmd.whole_archives():
        writers = parser.archive_writers.get(archive)
        if not writers:
            raise RuntimeError(
                f"Link target {target_path} links archive {archive}, "
                "which the build log never writes"
            )
        objects.extend(obj for writer in writers for obj in writer.objects())

    commands: List[BuildCommand] = []
    missing: List[Path] = []
    for obj in dict.fromkeys(objects):
        if obj in assems:
            continue
        compile_cmd = compiles.get(obj)
        if compile_cmd is None and obj.suffix == ".lo":
            # zlib builds PIC objects as objs/<name>.o and then renames them to
            # <name>.lo before linking the shared library.
            compile_cmd = compiles.get(obj.parent / "objs" / f"{obj.stem}.o")
        if compile_cmd is None:
            missing.append(obj)
            continue
        commands.append(compile_cmd)

    if missing:
        raise RuntimeError(
            f"Link target {target_path} contains objects without compile commands: "
            + ", ".join(str(path) for path in missing)
        )
    if not commands:
        raise RuntimeError(f"Link target {target_path} has no C/C++ compile commands")
    return target_path, commands


def build_target_bitcode(
    build_log_path: Path,
    target: str,
    output_dir: Path,
    extra_opts: str = "-O0 -g",
) -> Tuple[Path, List[Path]]:
    target_path, compile_commands = _target_compile_commands(
        build_log_path, target
    )

    bc_dir = output_dir / "bc_parts" / target_path.name
    emitted = [
        emit_bc(command, bc_dir, extra_opts=extra_opts)
        for command in compile_commands
    ]

    linked_path = output_dir / "bc" / f"{target_path.name}.bc"
    linked = link_bitcode(emitted, linked_path, cwd=build_log_path.parent)
    return linked, emitted


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build-log-based bitcode builder"
    )
    parser.add_argument(
        "--build-log",
        required=True,
        type=Path,
        help=(
            "Build log captured in trace format: "
            "<cwd>|autofuzz_splitter|<command>"
        ),
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Link/archive target basename to extract, e.g. libcjson.a",
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Directory to store emitted and linked bitcode",
    )
    parser.add_argument(
        "--extra-opts",
        default="-O0 -g",
        help="Extra compiler options appended while emitting bitcode",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    linked, parts = build_target_bitcode(
        args.build_log,
        args.target,
        args.out_dir,
        extra_opts=args.extra_opts,
    )
    print(linked)
    print(f"linked {len(parts)} bitcode files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
