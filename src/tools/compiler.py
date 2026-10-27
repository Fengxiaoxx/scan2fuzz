"""
Compiler Tool - Compile driver code for LLM agents and workflows
"""

import hashlib
import json
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Dict
from src.core import build_compile_flags, get_project_root, load_library_config


_BASE_FLAGS = (
    "-O1 -g -fno-omit-frame-pointer -fno-pie -no-pie "
    "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION "
    "-fsanitize=fuzzer,address,undefined "
    "-fsanitize-address-use-after-scope"
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sanitizer_library_path(library_name: str) -> Path:
    configured = Path(
        load_library_config(library_name)["compile_config"]["sanitize_library"]
    )
    return (
        configured if configured.is_absolute()
        else get_project_root() / configured
    ).resolve(strict=True)


def compile_driver_signature(
    driver_file: str,
    library_name: str,
    *,
    compile_flags: str | None = None,
) -> str:
    """Identify the compiler and flags independently of source/output paths."""
    compiler = "clang++" if driver_file.endswith(('.cc', '.cpp', '.cxx', '.C')) else "clang"
    executable = shutil.which(compiler)
    if not executable:
        raise FileNotFoundError(f"compiler is unavailable: {compiler}")
    version = subprocess.run(
        [executable, "--version"],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    ).stdout.splitlines()[0]
    payload = [
        str(Path(executable).resolve()),
        version,
        "-std=c++17" if compiler == "clang++" else "",
        *shlex.split(_BASE_FLAGS),
        *shlex.split(
            build_compile_flags(library_name)
            if compile_flags is None else compile_flags
        ),
    ]
    return hashlib.sha256(json.dumps(payload).encode("utf-8")).hexdigest()


def compile_driver(
    driver_file: str,
    library_name: str,
    *,
    output_path: str | None = None,
) -> Dict:
    """
    Compile a driver file

    Args:
        driver_file: Path to driver source file
        library_name: Name of the library

    Returns:
        Dictionary with compilation result
    """
    source = Path(driver_file).resolve(strict=True)
    output_file = Path(output_path).resolve() if output_path else source.with_suffix(".out")
    if output_path:
        if output_file.exists():
            raise FileExistsError(f"relink output already exists: {output_file}")
        output_file.parent.mkdir(parents=True, exist_ok=True)
    elif output_file.exists():
        output_file.unlink()

    # Select compiler based on file extension
    if driver_file.endswith(('.cc', '.cpp', '.cxx', '.C')):
        compiler = "clang++"
    else:
        compiler = "clang"

    # Build command
    compile_flags = build_compile_flags(library_name)
    compiler_signature = compile_driver_signature(
        str(source), library_name, compile_flags=compile_flags
    )
    sanitizer_library = sanitizer_library_path(library_name)
    sanitizer_sha256 = file_sha256(sanitizer_library)
    source_sha256 = file_sha256(source)
    command_args = [
        compiler,
        *(["-std=c++17"] if compiler == "clang++" else []),
        *shlex.split(_BASE_FLAGS),
        "-o",
        str(output_file),
        str(source),
    ]
    if compile_flags:
        command_args.extend(shlex.split(compile_flags))
    command = shlex.join(command_args)

    # A compiler non-zero exit is a candidate failure. Process execution
    # failures are infrastructure errors and must remain distinguishable.
    try:
        result = subprocess.run(
            command_args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=60
        )

        success = result.returncode == 0
        if file_sha256(sanitizer_library) != sanitizer_sha256:
            raise RuntimeError("sanitizer library changed while compiling the driver")
        if file_sha256(source) != source_sha256:
            raise RuntimeError("driver source changed while compiling the driver")

        provenance = (
            {
                "binary_path": str(output_file),
                "binary_sha256": file_sha256(output_file),
                "source_sha256": source_sha256,
                "sanitizer_library": str(sanitizer_library),
                "sanitizer_sha256": sanitizer_sha256,
                "compile_flags": compile_flags,
                "compiler_signature": compiler_signature,
                "compile_command": command,
            }
            if success and output_file.is_file()
            else None
        )

        return {
            'success': success,
            'returncode': result.returncode,
            'binary_file': str(output_file) if success else None,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'compile_command': command,
            'binary_provenance': provenance,
        }

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Compilation timeout after 60 seconds") from exc
    except Exception as e:
        raise RuntimeError(f"Compiler execution error: {e}") from e
