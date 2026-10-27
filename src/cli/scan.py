"""
CLI entrypoint for shared builds and one selected library alert backend.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from src.cli.run_context import stage_run
from src.cli.common import add_concurrency_argument, apply_concurrency, configure_logger
from src.core import get_project_root, load_library_config
from src.experiment import RunArtifactStore, finalize_run
from src.scan.backend import AlertBackend
from src.scan.workflow import ScanWorkflow


def snapshot_scan_outputs(
    store: RunArtifactStore,
    library: str,
    workflow: ScanWorkflow,
) -> int:
    """Freeze scan outputs consumed by later stages."""
    if workflow.scan_status != "completed":
        raise ValueError("cannot publish targets from an incomplete scan")
    info = get_project_root() / "info_lib" / library
    outputs = {
        info / "txt" / "targets.txt": "stages/scan/targets.txt",
        **workflow.scan_artifacts,
        info / "external" / "scan" / "findings.json": (
            "stages/scan/findings.json"
        ),
        info / "raw" / "reachability" / "call_graph.direct.csv": (
            "stages/scan/reachability/call_graph.direct.csv"
        ),
        info / "raw" / "reachability" / "function_locations.csv": (
            "stages/scan/reachability/function_locations.csv"
        ),
        info / "raw" / "reachability" / "scope.json": (
            "stages/scan/reachability/scope.json"
        ),
        info / "raw" / "reachability" / "include-edges.csv": (
            "stages/scan/reachability/include-edges.csv"
        ),
        info / "raw" / "reachability" / "provenance-edges.csv": (
            "stages/scan/reachability/provenance-edges.csv"
        ),
        info / "raw" / "reachability" / "provenance-edges.jsonl": (
            "stages/scan/reachability/provenance-edges.jsonl"
        ),
        info / "raw" / "reachability" / "result.json": (
            "stages/scan/reachability/result.json"
        ),
        info / "raw" / "reachability" / "direct-extractor.log": (
            "stages/scan/reachability/direct-extractor.log"
        ),
        info / "raw" / "reachability" / "function-location-extractor.log": (
            "stages/scan/reachability/function-location-extractor.log"
        ),
        info / "raw" / "reachability" / "include-edges.bqrs": (
            "stages/scan/reachability/include-edges.bqrs"
        ),
        info / "raw" / "reachability" / "include-edges.log": (
            "stages/scan/reachability/include-edges.log"
        ),
        info / "raw" / "reachability" / "provenance-edges.bqrs": (
            "stages/scan/reachability/provenance-edges.bqrs"
        ),
        info / "raw" / "reachability" / "provenance-edges.log": (
            "stages/scan/reachability/provenance-edges.log"
        ),
        Path(workflow.analysis_builder.compile_db_path): (
            "stages/scan/compile_commands.json"
        ),
        Path(workflow.analysis_builder.build_trace_file): (
            "stages/scan/build-trace.log"
        ),
        Path(workflow.analysis_builder.codeql_log_file): (
            "stages/scan/codeql-database-build.log"
        ),
    }
    if workflow.linked_bitcode is None:
        raise ValueError("scan completed without linked bitcode")
    outputs[Path(workflow.linked_bitcode)] = "stages/scan/linked.bc"

    analysis_library = load_library_config(library)["compile_config"][
        "analysis_library"
    ]
    analysis_library_path = Path(analysis_library)
    if not analysis_library_path.is_absolute():
        analysis_library_path = get_project_root() / analysis_library_path
    selected_link_target = workflow.analysis_builder.selected_link_target
    if selected_link_target is None:
        raise ValueError("scan completed without a selected analysis link target")
    analysis_library_path = analysis_library_path.resolve(strict=True)
    selected_link_target = selected_link_target.resolve(strict=True)
    if analysis_library_path != selected_link_target:
        raise ValueError(
            "configured analysis_library does not resolve to the selected link target: "
            f"configured={analysis_library_path}, selected={selected_link_target}"
        )
    analysis_library_path = selected_link_target
    analysis_library_artifact = (
        f"stages/scan/analysis-library/{analysis_library_path.name}"
    )
    outputs[analysis_library_path] = analysis_library_artifact

    public_headers = []
    public_headers_root = Path(workflow.analysis_builder.public_headers_dir)
    for source in workflow.analysis_builder.get_public_header_files():
        relative = source.relative_to(public_headers_root)
        destination = Path("stages/scan/public-install/include") / relative
        outputs[source] = destination.as_posix()
        public_headers.append(
            {
                "path": destination.as_posix(),
                "include": relative.as_posix(),
                "sha256": _sha256(source),
            }
        )
    for source, destination in outputs.items():
        store.copy_file_or_validate(source, destination)

    build_result_path = "stages/scan/build-result.json"
    store.write_json(
        build_result_path,
        {
            "schema_version": 1,
            "analysis_library": analysis_library_artifact,
            "analysis_library_sha256": _sha256(analysis_library_path),
            "public_headers_root": "stages/scan/public-install/include",
            "public_headers": public_headers,
        },
    )

    targets = (info / "txt" / "targets.txt").read_text(encoding="utf-8")
    target_count = sum(1 for line in targets.splitlines() if line.strip())
    store.write_json(
        store.stage_result_path("scan"),
        {
            "status": "completed",
            "target_count": target_count,
            "outputs": [*outputs.values(), build_result_path],
        },
    )
    return target_count


def snapshot_incomplete_scan_outputs(
    store: RunArtifactStore,
    workflow: ScanWorkflow,
) -> None:
    """Preserve current diagnostics, never stale targets or a zero-target claim."""
    if workflow.scan_status not in ("partial", "failed"):
        raise ValueError("expected an incomplete scan")
    for source, destination in workflow.scan_artifacts.items():
        store.copy_file_or_validate(source, destination)
    store.write_json(
        store.stage_result_path("scan"),
        {
            "status": workflow.scan_status,
            "success": False,
            "target_count": None,
            "outputs": list(workflow.scan_artifacts.values()),
        },
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _select_backend(
    library: str,
    name: str,
    *,
    workers: int,
) -> AlertBackend:
    """Construct exactly one backend; their outputs are never combined here."""
    if name == "codeql-infer":
        from src.scan.static_backend import CodeQLInferBackend

        return CodeQLInferBackend()
    if name == "unit-audit":
        from src.scan.unit_audit.backend import UnitAuditBackend

        return UnitAuditBackend(library, workers=workers)
    raise ValueError(f"Unknown alert backend: {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Shared analysis build followed by one C/C++ alert backend",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 -m src.cli.scan lcms
  python3 -m src.cli.scan lcms --debug

Immutable run output:
  - workspace/{library}/runs/{run_id}/stages/scan/result.json
  - workspace/{library}/runs/{run_id}/stages/scan/targets.txt
  - backend-specific scan reports, such as codeql.sarif, infer-report.json,
    or unit-audit-findings.json
  - workspace/{library}/runs/{run_id}/stages/scan/findings.json
  - workspace/{library}/runs/{run_id}/stages/scan/reachability/result.json
        """,
    )
    parser.add_argument("library", help="Library name (e.g., cJSON)")
    parser.add_argument("--run-id", help="existing incomplete experiment run")
    parser.add_argument(
        "--alert-backend",
        choices=("codeql-infer", "unit-audit"),
        default="unit-audit",
        help="Choose exactly one alert backend (default: unit-audit)",
    )
    add_concurrency_argument(parser)
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)
    apply_concurrency(args.concurrency)

    configure_logger(debug=args.debug)
    with stage_run(
        args.library,
        "scan",
        run_id=args.run_id,
        create=True,
    ) as store:
        print(f"Run ID: {store.run_id}", flush=True)
        print(f"Run artifacts: {store.run_dir}", flush=True)
        alert_backend = _select_backend(
            args.library,
            args.alert_backend,
            workers=args.concurrency,
        )
        workflow = ScanWorkflow(
            args.library,
            build_script=str(store.safe_path("config/build.sh")),
            codeql_log_file=str(
                store.safe_path("stages/scan/codeql-database-build.log")
            ),
            alert_backend=alert_backend,
        )
        if not workflow.run():
            snapshot_incomplete_scan_outputs(store, workflow)
            return 1
        target_count = snapshot_scan_outputs(store, args.library, workflow)
        if target_count == 0:
            finalize_run(store, "no_targets")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
