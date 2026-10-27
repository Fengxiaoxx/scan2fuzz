"""Prepare shared analysis inputs, run one alert backend, then publish results."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from loguru import logger

from src.core import load_library_config, normalize_language
from src.scan.analysis_builder import AnalysisBuilder
from src.scan.backend import AlertBackend, ScanContext
from src.scan.evidence import write_scan_evidence
from src.scan.target_generator import TargetGenerator
from src.preprocess.reachability.scan_graph import ReachabilityScanBuilder


class ScanWorkflow:
    """Build once and invoke the selected, mutually exclusive alert backend."""

    def __init__(
        self,
        library_name: str,
        *,
        build_script: Optional[str] = None,
        codeql_log_file: str,
        alert_backend: AlertBackend,
    ):
        self.library_name = library_name
        self.test_lib_dir = f"test_lib/{library_name}"
        self.info_lib_dir = f"info_lib/{library_name}"
        self.txt_dir = f"{self.info_lib_dir}/txt"
        self.build_script = build_script or f"{self.info_lib_dir}/build.sh"
        self.scan_reports_dir = f"{self.info_lib_dir}/external/scan"
        self.targets_file = f"{self.txt_dir}/targets.txt"
        self.findings_file = f"{self.scan_reports_dir}/findings.json"
        config = load_library_config(library_name)
        self.language = normalize_language(config.get("language", "C"))

        self.analysis_builder = AnalysisBuilder(
            library_name,
            self.test_lib_dir,
            self.info_lib_dir,
            self.build_script,
            config["compile_config"]["analysis_library"],
            codeql_log_file,
        )
        self.alert_backend = alert_backend
        self.scan_artifacts: dict[Path, str] = {}
        self.scan_status = "failed"
        self.target_generator = TargetGenerator(self.targets_file, self.test_lib_dir)
        self.linked_bitcode: Optional[str] = None
        self.reachability_dir = os.path.join(
            self.info_lib_dir, "raw", "reachability"
        )

    # ------------------------------------------------------------------
    # Public entrypoint
    # ------------------------------------------------------------------

    def run(self) -> bool:
        """Prepare inputs, execute one backend, and publish only complete output."""
        logger.info(f"Scanning {self.library_name}...")
        self.scan_artifacts = {}
        self.scan_status = "failed"
        self.linked_bitcode = None

        if not self.check_prerequisites():
            return False
        os.makedirs(self.txt_dir, exist_ok=True)

        context = self._prepare_analysis()
        if context is None:
            return False
        try:
            result = self.alert_backend.scan(context)
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            logger.error(f"Selected alert backend failed: {exc}")
            return False
        if result is None:
            return False
        self.scan_artifacts = result.artifacts
        if result.status != "completed":
            self.scan_status = result.status
            logger.error(
                "Scan result is {}; preserving diagnostics without publishing targets",
                result.status,
            )
            return False
        if not self.target_generator.generate_groups(result.target_groups):
            return False

        try:
            write_scan_evidence(
                self.findings_file, result.reports, self.target_generator
            )
        except (OSError, TypeError, ValueError) as exc:
            logger.error(f"Failed to preserve scan evidence: {exc}")
            return False
        self.scan_status = "completed"

        logger.success("Scan completed!")
        return True

    # ------------------------------------------------------------------
    # Sub-steps (called in order from `run`)
    # ------------------------------------------------------------------

    def _prepare_analysis(self) -> ScanContext | None:
        """Finish shared builds before entering either alert backend.

        CodeQL database creation and reachability queries are build inputs;
        CodeQL/Infer alert analysis belongs to the selected backend. The Agent
        backend owns its whole profile/search/pattern/scan sequence.
        """
        if not self._build_codeql_database():
            return None
        if not self._build_linked_bitcode():
            return None
        if not self._build_reachability_graphs():
            return None

        source_files = self.analysis_builder.get_linked_source_files()
        if not source_files:
            logger.error("No source files found")
            return None
        selected_link_target = self.analysis_builder.selected_link_target
        if selected_link_target is None:
            logger.error("No link target selected")
            return None
        return ScanContext(
            source_root=self.test_lib_dir,
            reports_dir=self.scan_reports_dir,
            database_path=self.analysis_builder.database_path,
            compile_db_path=self.analysis_builder.compile_db_path,
            source_files=source_files,
            language=self.language,
            build_trace_path=self.analysis_builder.build_trace_file,
            link_target=str(selected_link_target),
            public_include_dir=self.analysis_builder.public_headers_dir,
        )

    def check_prerequisites(self) -> bool:
        """Check shared build requirements and the selected alert backend."""
        if not os.path.exists(self.test_lib_dir):
            logger.error(f"Library directory not found: {self.test_lib_dir}")
            return False

        if not os.path.exists(self.info_lib_dir):
            os.makedirs(self.info_lib_dir, exist_ok=True)

        if not os.path.exists(self.build_script):
            logger.error(f"Build script not found: {self.build_script}")
            return False

        if shutil.which("codeql") is None:
            logger.error("CodeQL not found in PATH")
            return False

        return self.alert_backend.check_prerequisites()

    def _build_codeql_database(self) -> bool:
        """Build the CodeQL and compilation databases, then configure clangd."""
        if not self.analysis_builder.create_codeql_database():
            return False
        self._write_clangd_config()
        return True

    def _build_linked_bitcode(self) -> bool:
        self.linked_bitcode = self.analysis_builder.create_linked_bitcode()
        if self.linked_bitcode is None:
            logger.error("Linked bitcode generation failed")
            return False
        return True

    def _build_reachability_graphs(self) -> bool:
        """Build identity-preserving direct and provenance call evidence."""
        if self.linked_bitcode is None:
            logger.error("Current scan produced no linked bitcode")
            return False
        selected = self.analysis_builder.selected_link_target
        if selected is None:
            logger.error("Current scan selected no analysis link target")
            return False
        try:
            summary = ReachabilityScanBuilder(
                source_root=Path(self.test_lib_dir),
                database=Path(self.analysis_builder.database_path),
                build_trace=Path(self.analysis_builder.build_trace_file),
                link_target=selected.name,
                linked_bitcode=Path(self.linked_bitcode),
                output_dir=Path(self.reachability_dir),
            ).build()
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            logger.error(f"Reachability graph construction failed: {exc}")
            return False
        logger.success(
            "Reachability evidence built: {} direct/provenance rows in {} files",
            summary["query"]["strict_rows"],
            summary["scope_file_count"],
        )
        return True

    def _write_clangd_config(self) -> None:
        """Write a .clangd file pointing clangd at the CodeQL compilation database."""
        clangd_path = os.path.join(self.test_lib_dir, ".clangd")
        with open(clangd_path, "w", encoding="utf-8") as f:
            f.write("CompileFlags:\n  CompilationDatabase: build_analysis\n")
        logger.info(f"Wrote clangd config to {clangd_path}")
