"""Concrete adapters wiring the monitor to THIS project (clang++, libFuzzer,
the library config). Project-specific code lives ONLY here; the core
(progress/stall/monitor) imports none of it.

`refine` has no default on purpose -- that is the LLM agent step, which the
caller injects. Everything else (build, fuzz, diagnose, chain extraction) is
provided so the fuzz->probe->stall half is runnable out of the box.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable, List, Mapping, Optional, Sequence, Tuple

from src.core import (build_include_paths, get_project_root, load_library_config,
                      resolve_driver_identity)
from src.core.llvm_cov import compile_coverage_binary
from src.driver_qualification.runtime import PersistentFuzzSession

from .monitor import BuildBinary

PROJECT_ROOT = get_project_root()

try:
    from .progress import ChainStep as _ProgressChainStep
except ImportError:
    _ProgressChainStep = None


def _maybe_int(value: Any) -> Any:
    if value is None or isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def _make_chain_step(data: Mapping[str, Any]) -> Any:
    step = dict(data)
    if "line" in step:
        step["line"] = _maybe_int(step.get("line"))
    if "col" in step:
        step["col"] = _maybe_int(step.get("col"))

    if _ProgressChainStep is not None:
        fields = {
            key: step[key]
            for key in ("fn", "file", "line", "col", "symbol")
            if key in step
        }
        try:
            return _ProgressChainStep(**fields)
        except TypeError:
            pass
    return step


def chain_step_fn(step: Any) -> str:
    if isinstance(step, str):
        return step
    if isinstance(step, Mapping):
        value = step.get("fn") or step.get("name")
        return str(value) if value else ""
    value = getattr(step, "fn", None) or getattr(step, "name", None)
    return str(value) if value else str(step)


def resolve_target(lib: str, driver_name: str) -> Optional[Tuple[str, List[Any]]]:
    """Resolve a driver to its exact candidate-plan target and chain."""
    api_id, marker = resolve_driver_identity(lib, driver_name)
    if marker is None:
        return None
    from src.driver_generation.inputs import resolve_work_item

    item = resolve_work_item(lib, api_id, marker)
    target = item["target"]
    chain = [
        _make_chain_step(step)
        for step in target["chain"]
        if step.get("fn")
    ]
    return f"{target['file']}:{target['line']}", chain


def make_adapters(lib: str, *, corpus_dir: str,
                  workdir: str = "/tmp/reachability_monitor",
                  chunk_seconds: int = 60,
                  replacement_objects: Sequence[str] = (),
                  artifact_dir: Optional[str] = None,
                  output_path: Optional[str] = None,
                  runtime_env: Optional[Mapping[str, str]] = None,
                  fuzzer_args: Sequence[str] = (),
                  on_fuzzer_start: Optional[Callable[[int], None]] = None,
                  on_fuzzer_stop: Optional[Callable[[], None]] = None,
                  ) -> Tuple[BuildBinary, PersistentFuzzSession]:
    """Build the coverage compiler and persistent SAN fuzz session.

    build_cov(driver_src) -> coverage binary (cached by source content).
    fuzz_session.checkpoint(runtime_binary) -> immutable corpus snapshot.
    """
    cc = load_library_config(lib)["compile_config"]
    cov_lib = Path(cc["coverage_library"])
    if not cov_lib.is_absolute():
        cov_lib = PROJECT_ROOT / cov_lib
    includes = build_include_paths(lib, "coverage")
    extra_libs = cc.get("additional_libs", [])
    Path(workdir).mkdir(parents=True, exist_ok=True)
    Path(corpus_dir).mkdir(parents=True, exist_ok=True)
    if artifact_dir:
        Path(artifact_dir).mkdir(parents=True, exist_ok=True)

    def build_cov(driver_src: str) -> Optional[str]:
        digest = hashlib.sha1(Path(driver_src).read_bytes())
        for object_path in replacement_objects:
            digest.update(Path(object_path).read_bytes())
        h = digest.hexdigest()[:12]
        out = Path(workdir) / f"cov_{h}.out"
        if out.exists():
            return str(out)
        return compile_coverage_binary(
            driver_src,
            str(out),
            includes,
            str(cov_lib),
            extra_libs,
            replacement_objects=list(replacement_objects),
        )

    fuzz_session = PersistentFuzzSession(
        corpus_dir=corpus_dir,
        workdir=workdir,
        checkpoint_seconds=chunk_seconds,
        artifact_dir=artifact_dir,
        output_path=output_path,
        env=runtime_env,
        fuzzer_args=fuzzer_args,
        on_fuzzer_start=on_fuzzer_start,
        on_fuzzer_stop=on_fuzzer_stop,
    )
    return build_cov, fuzz_session
