"""CLI for the target-centric driver state machines."""

from __future__ import annotations

import argparse
import traceback
from contextlib import nullcontext
from functools import partial
from typing import Dict

from loguru import logger

from src.cli.common import (
    add_concurrency_argument,
    add_fuzz_concurrency_argument,
    apply_concurrency,
    configure_logger,
    suppress_async_cleanup_warnings,
)
from src.cli.run_context import stage_run
from src.driver_rounds.workflow import DriverRoundWorkflow
from src.experiment import finalize_run


def _driver_rounds_dashboard(store, library: str, args):
    try:
        from src.ui import (
            DriverRoundsStageProvider,
            driver_rounds_dashboard_spec,
            stage_dashboard_process,
        )

        return stage_dashboard_process(
            partial(
                DriverRoundsStageProvider,
                store.run_dir,
                store.run_id,
                library,
                args.max_generation_failures,
                args.max_repair_attempts,
                args.max_refine_attempts,
            ),
            driver_rounds_dashboard_spec(library),
        )
    except Exception:
        return nullcontext()


def _candidate_rejections(values: list[str]) -> Dict[str, int]:
    rejections: Dict[str, int] = {}
    for value in values:
        marker, separator, raw_index = value.partition("=")
        if not separator or not marker or not raw_index.isdigit():
            raise argparse.ArgumentTypeError(
                "--reject-candidate requires TARGET_MARKER=ONE_BASED_INDEX"
            )
        index = int(raw_index)
        if index <= 0:
            raise argparse.ArgumentTypeError(
                "--reject-candidate index must be positive"
            )
        if marker in rejections:
            raise argparse.ArgumentTypeError(
                f"duplicate --reject-candidate target: {marker}"
            )
        rejections[marker] = index - 1
    return rejections


def main() -> int:
    suppress_async_cleanup_warnings()
    configure_logger(detailed=True)
    parser = argparse.ArgumentParser(
        description="Independently advance every target to its next driver action"
    )
    parser.add_argument("library")
    parser.add_argument("--run-id", help="existing experiment run")
    parser.add_argument(
        "--max-generation-failures",
        type=int,
        default=5,
        help="failed Generator actions allowed per candidate (default: 5)",
    )
    parser.add_argument(
        "--max-infrastructure-retries",
        type=int,
        default=5,
        help=(
            "transient retries allowed per target phase in one command "
            "(default: 5)"
        ),
    )
    parser.add_argument(
        "--max-repair-attempts",
        type=int,
        default=5,
        help=(
            "Repair attempts allowed per diagnostic type and candidate "
            "(5 compile + 5 runtime by default)"
        ),
    )
    parser.add_argument(
        "--max-refine-attempts",
        type=int,
        default=5,
        help="reachability Refiner actions allowed per candidate (default: 5)",
    )
    parser.add_argument(
        "--reject-candidate",
        action="append",
        default=[],
        metavar="TARGET=INDEX",
        help=(
            "mark one exact current candidate as a manually confirmed static "
            "false positive before scheduling; repeat for multiple targets"
        ),
    )
    add_concurrency_argument(parser)
    add_fuzz_concurrency_argument(parser)
    args = parser.parse_args()
    apply_concurrency(args.concurrency)

    try:
        rejected_candidates = _candidate_rejections(args.reject_candidate)
        with stage_run(
            args.library,
            "driver_rounds",
            run_id=args.run_id,
        ) as store:
            print(f"Run artifacts: {store.run_dir}", flush=True)
            print(
                f"Concurrency: {args.concurrency} LLM actions, "
                f"{args.fuzz_concurrency} reachability fuzzers",
                flush=True,
            )
            with _driver_rounds_dashboard(store, args.library, args):
                result = DriverRoundWorkflow(
                    args.library,
                    store,
                    max_generation_failures=args.max_generation_failures,
                    max_infrastructure_retries=args.max_infrastructure_retries,
                    max_repair_attempts=args.max_repair_attempts,
                    max_refine_attempts=args.max_refine_attempts,
                    concurrency=args.concurrency,
                    fuzz_concurrency=args.fuzz_concurrency,
                ).run(candidate_rejections=rejected_candidates)
            finalize_run(store, result["status"])
            summary = result["summary"]
            logger.info(
                "Driver rounds complete: {}/{} targets reached; "
                "{} crashed; {} exhausted; {} unresolved; "
                "{} infrastructure retries",
                summary["reached"],
                summary["targets"],
                summary["crashed"],
                summary["exhausted"],
                summary["unresolved_static"],
                summary["infrastructure_attempts"],
            )
            return 0 if result["success"] else 1
    except KeyboardInterrupt:
        logger.warning("\nInterrupted by user")
        return 130
    except Exception as exc:
        logger.error(f"Driver rounds failed: {exc}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
