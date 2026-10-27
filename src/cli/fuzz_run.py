"""Build and run merged Trace2Fuzz AFL++ campaigns from selector-only seeds."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.cli.common import positive_int
from src.fuzz_run import RunOptions, run_fuzz


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library")
    parser.add_argument("--run-id", required=True, help="run containing the selected drivers")
    parser.add_argument(
        "--repetitions",
        type=positive_int,
        default=10,
        help="number of independent AFL++ campaigns (default: 10)",
    )
    parser.add_argument("--driver", action="append", default=[], help="run only this driver (repeatable)")
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=4,
        help="parallel campaigns (default: 4)",
    )
    parser.add_argument(
        "--seconds-per-run",
        type=positive_int,
        default=86400,
        help="seconds per campaign (default: 86400)",
    )
    parser.add_argument(
        "--timeout-ms",
        type=positive_int,
        default=5000,
        help="per-input timeout in milliseconds (default: 5000)",
    )
    parser.add_argument(
        "--detect-leaks", action="store_true",
        help="run an AFL++ LSan check after every input (slower)",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[2]

    options = RunOptions(
        project_root=project_root,
        library=args.library,
        run_id=args.run_id,
        drivers=tuple(args.driver),
        concurrency=args.concurrency,
        repetitions=args.repetitions,
        seconds_per_run=args.seconds_per_run,
        timeout_ms=args.timeout_ms,
        detect_leaks=args.detect_leaks,
    )
    summary = run_fuzz(options)
    print(f"AFL++ run: {summary['status']} ({summary['output_dir']})", flush=True)
    return 0 if summary["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
