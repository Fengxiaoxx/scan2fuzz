"""
CLI entrypoint for preprocessing workflows.
"""

from __future__ import annotations

import argparse

from src.cli.common import (
    add_concurrency_argument,
    apply_concurrency,
    configure_logger,
    suppress_async_cleanup_warnings,
)
from src.cli.run_context import stage_run


def main() -> int:
    suppress_async_cleanup_warnings()

    parser = argparse.ArgumentParser(
        description="Preprocessing workflow for library analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 -m src.cli.preprocess lcms --run-id <run_id>
  python3 -m src.cli.preprocess lcms --run-id <run_id> --debug

Immutable run output:
  - workspace/{library}/runs/{run_id}/stages/preprocess/result.json
  - workspace/{library}/runs/{run_id}/stages/preprocess/api-docs/
  - workspace/{library}/runs/{run_id}/stages/preprocess/fact_base.json
  - workspace/{library}/runs/{run_id}/stages/preprocess/drivers.json
  - workspace/{library}/runs/{run_id}/stages/preprocess/faiss-index/
  - workspace/{library}/runs/{run_id}/stages/preprocess/candidate_plan.json
        """,
    )
    parser.add_argument("library", help="Library name (e.g., libaom)")
    parser.add_argument("--run-id", help="experiment run containing scan output")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    add_concurrency_argument(parser)
    args = parser.parse_args()
    apply_concurrency(args.concurrency)

    configure_logger(debug=args.debug)
    with stage_run(
        args.library,
        "preprocess",
        run_id=args.run_id,
    ) as store:
        from src.preprocess.workflow import PreprocessWorkflow

        print(f"Run artifacts: {store.run_dir}", flush=True)
        workflow = PreprocessWorkflow(args.library, concurrency=args.concurrency)
        return 0 if workflow.run() else 1


if __name__ == "__main__":
    raise SystemExit(main())
