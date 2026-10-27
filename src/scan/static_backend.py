"""The existing CodeQL + Infer alert pipeline, behind the backend boundary."""

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import List

from loguru import logger

from src.scan.backend import ScanContext, ScanResult
from src.scan.codeql_scanner import CodeQLReportParseError, CodeQLScanner
from src.scan.infer_scanner import InferReportParseError, InferScanner


class CodeQLInferBackend:
    """Preserve execution order, all-scanners-required policy and precedence."""

    def check_prerequisites(self) -> bool:
        for tool, name in (("codeql", "CodeQL"), ("infer", "Infer")):
            if shutil.which(tool) is None:
                logger.error(f"{name} not found in PATH")
                return False
        return True

    def scan(self, context: ScanContext) -> ScanResult | None:
        codeql = CodeQLScanner(
            context.database_path, context.reports_dir, context.source_root
        )
        infer = InferScanner(context.compile_db_path, context.reports_dir)
        codeql_ok = codeql.run()
        infer_ok = self._run_infer(infer, context)
        if not codeql_ok or not infer_ok:
            logger.error("CodeQL and Infer must both complete successfully")
            return None
        try:
            codeql_targets = codeql.parse_report(context.source_files)
            infer_targets = infer.parse_report()
        except (CodeQLReportParseError, InferReportParseError) as exc:
            logger.error(f"Scan report parsing failed: {exc}")
            return None
        if infer.evidence is None or codeql.evidence is None:
            logger.error("successful scan has no diagnostic evidence")
            return None
        return ScanResult(
            target_groups={"Infer": infer_targets, "CodeQL": codeql_targets},
            reports=[infer.evidence, codeql.evidence],
            artifacts={
                Path(codeql.codeql_report_path).absolute(): "stages/scan/codeql.sarif",
                Path(codeql.codeql_log_path).absolute(): "stages/scan/codeql.log",
                Path(infer.infer_report_path).absolute(): "stages/scan/infer-report.json",
            },
        )

    def _run_infer(self, scanner: InferScanner, context: ScanContext) -> bool:
        try:
            filtered = self._make_filtered_compile_db(
                context.compile_db_path, context.source_files
            )
        except (OSError, ValueError) as exc:
            logger.error(f"Failed to create linked-source compile database: {exc}")
            return False
        try:
            return scanner.run(filtered)
        finally:
            os.remove(filtered)

    @staticmethod
    def _make_filtered_compile_db(compile_db_path: str, source_files: List[str]) -> str:
        """Write a filtered compile_commands.json containing only the given source files."""
        if not os.path.exists(compile_db_path):
            raise FileNotFoundError(
                f"compile_commands.json not found: {compile_db_path}"
            )

        source_set = {os.path.abspath(path) for path in source_files}
        if not source_set:
            raise ValueError("linked source list is empty")

        temp_path = None
        try:
            with open(compile_db_path) as f:
                entries = json.load(f)

            if not isinstance(entries, list):
                raise ValueError("compile_commands.json root must be an array")

            filtered = []
            matched_sources = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError(
                        "compile_commands.json entries must be objects"
                    )
                file_path = entry.get("file")
                if not isinstance(file_path, str) or not file_path:
                    raise ValueError(
                        "compile_commands.json entry has no source file"
                    )
                if not os.path.isabs(file_path):
                    directory = entry.get("directory")
                    if not isinstance(directory, str) or not directory:
                        raise ValueError(
                            "relative compile command source has no directory"
                        )
                    file_path = os.path.join(directory, file_path)
                resolved_source = os.path.abspath(file_path)
                if resolved_source in source_set:
                    filtered.append(entry)
                    matched_sources.add(resolved_source)

            missing_sources = sorted(source_set - matched_sources)
            if missing_sources:
                raise ValueError(
                    "linked sources missing from compile_commands.json: "
                    + ", ".join(missing_sources)
                )

            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            )
            temp_path = tmp.name
            try:
                json.dump(filtered, tmp)
            finally:
                tmp.close()
            return temp_path
        except Exception:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
            raise

