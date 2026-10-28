"""Run the final ASan+UBSan AFL++ campaign as a resumable pipeline stage."""

from __future__ import annotations

import argparse
from pathlib import Path
import shlex
import subprocess

from src.cli.common import positive_int
from src.cli.run_context import stage_run
from src.core import build_compile_flags
from src.experiment import finalize_run
from src.fuzz_run import RunOptions, run_fuzz


STAGE = "fuzz_run"


def _prepare_library(store) -> None:
    """Build missing pinned AFL++ tools and the ASan+UBSan static library."""
    subprocess.run(
        ["bash", str(store.project_root / "src" / "fuzz_run" / "setup_aflpp.sh")],
        cwd=store.project_root,
        check=True,
    )

    variant = "aflpp"
    flags = shlex.split(build_compile_flags(store.library, library_variant=variant))
    archives = [
        store.project_root / flag
        for flag in flags
        if not flag.startswith("-") and f"build_{variant}" in Path(flag).parts
    ]
    if not archives:
        raise ValueError(f"{store.library} has no {variant} static library in compile flags")
    if all(archive.is_file() for archive in archives):
        return

    source = store.project_root / "test_lib" / store.library
    recipe = store.project_root / "info_lib" / store.library / "build.sh"
    if not source.is_dir() or not recipe.is_file():
        raise FileNotFoundError(f"missing source or build recipe for {store.library}")
    log = store.safe_path(f"stages/{STAGE}/build-{variant}.log")
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as output:
        output.write(f"Building {store.library} {variant}\n")
        output.flush()
        result = subprocess.run(
            ["bash", str(recipe), variant],
            cwd=source,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(f"{variant} library build failed; see {log}")
    if any(not archive.is_file() for archive in archives):
        raise RuntimeError(f"{variant} build did not create all required archives; see {log}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library")
    parser.add_argument("--run-id")
    parser.add_argument("--driver", action="append", default=[])
    parser.add_argument("--repetitions", type=positive_int, default=10)
    parser.add_argument("--seconds-per-run", type=positive_int, default=86400)
    parser.add_argument("--concurrency", type=positive_int, default=4)
    parser.add_argument("--timeout-ms", type=positive_int, default=5000)
    args = parser.parse_args()

    with stage_run(args.library, STAGE, run_id=args.run_id) as store:
        targets = store.read_json(store.stage_result_path("driver_rounds")).get("targets")
        if not isinstance(targets, list):
            raise ValueError("driver_rounds result has no target list")
        if not any(isinstance(target, dict) and target.get("state") == "REACHED"
                   for target in targets):
            store.write_json(store.stage_result_path(STAGE), {
                "schema_version": 1,
                "status": "skipped",
                "reason": "no_fuzzable_drivers",
                "campaign": None,
            })
            finalize_run(store)
            print("Final AFL++ fuzz skipped: no REACHED drivers", flush=True)
            return 0

        settings = {
            "schema_version": 1,
            "library": args.library,
            "run_id": store.run_id,
            "drivers": args.driver,
            "repetitions": args.repetitions,
            "seconds_per_run": args.seconds_per_run,
            "concurrency": args.concurrency,
            "timeout_ms": args.timeout_ms,
            "profile": "asan_ubsan",
        }
        plan_path = store.safe_path(f"stages/{STAGE}/plan.json")
        if plan_path.is_file():
            if store.read_json(f"stages/{STAGE}/plan.json") != settings:
                raise ValueError("fuzz_run settings differ from the pending stage plan")
        else:
            store.write_json(f"stages/{STAGE}/plan.json", settings)

        relative = f"stages/{STAGE}/campaign.json"
        checkpoint = store.safe_path(relative)
        if checkpoint.is_file():
            summary = store.read_json(relative)
            if summary.get("status") != "completed":
                raise ValueError(f"invalid completed campaign checkpoint: {checkpoint}")
        else:
            _prepare_library(store)
            summary = run_fuzz(RunOptions(
                project_root=store.project_root,
                library=args.library,
                run_id=store.run_id,
                drivers=tuple(args.driver),
                repetitions=args.repetitions,
                seconds_per_run=args.seconds_per_run,
                concurrency=args.concurrency,
                timeout_ms=args.timeout_ms,
            ))
            if summary["status"] != "completed":
                print(f"Final AFL++: {summary['status']}; retry this stage", flush=True)
                return 1
            store.write_json(relative, summary)
        campaign = {
            "status": summary["status"],
            "output_dir": summary["output_dir"],
            "driver_count": summary["driver_count"],
            "seed_count": summary["seed_count"],
        }
        print(f"Final AFL++: completed ({summary['output_dir']})", flush=True)

        store.write_json(store.stage_result_path(STAGE), {
            "schema_version": 1,
            "status": "completed",
            "settings": settings,
            "campaign": campaign,
        })
        finalize_run(store)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
