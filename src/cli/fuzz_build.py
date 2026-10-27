"""Build merged AFL++ driver binaries without starting a fuzz campaign."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets

from src.cli.fuzz_run_stage import _prepare_library
from src.experiment.store import RunArtifactStore
from src.fuzz_run.runner import (
    RunOptions,
    _build_merged,
    _load_drivers,
    _sha256,
    _write_initial_corpus,
    _write_merged_sources,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--driver", action="append", default=[])
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    run_dir = root / "workspace" / args.library / "runs" / args.run_id
    store = RunArtifactStore.from_environment(
        root, args.library, {"RUN_DIR": str(run_dir), "RUN_ID": args.run_id}
    )
    invocation = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    invocation += "-" + secrets.token_hex(4)

    options = RunOptions(
        project_root=root,
        library=args.library,
        run_id=args.run_id,
        drivers=tuple(args.driver),
    )
    options.validate()
    drivers = _load_drivers(options)
    if len(drivers) > 256:
        raise ValueError("the one-byte selector supports at most 256 drivers")
    print(f"Preparing {args.library} ASan+UBSan: {len(drivers)} REACHED drivers", flush=True)
    _prepare_library(store)

    work = root / "workspace" / args.library / "fuzz_builds" / args.run_id / invocation
    work.mkdir(parents=True, exist_ok=False)
    entry, names = _write_merged_sources(drivers, work)
    merged = _build_merged(options, work, entry)
    seed_count = _write_initial_corpus(drivers, work / "corpus")
    manifest = {
        "schema_version": 1,
        "library": args.library,
        "run_id": args.run_id,
        "profile": "asan_ubsan",
        "merged_driver": str(merged),
        "merged_driver_sha256": _sha256(merged),
        "driver_count": len(names),
        "driver_selectors": [
            {"index": index, "driver_id": driver.driver_id}
            for index, driver in enumerate(drivers)
        ],
        "seed_mode": "selector_only",
        "seed_count": seed_count,
    }
    (work / "build.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Built ASan+UBSan: {merged}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
