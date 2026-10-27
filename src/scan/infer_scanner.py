"""
Infer scanner and report parser
"""

import os
import subprocess
from collections import Counter
from typing import List, Optional

from loguru import logger

from src.core import Target
from src.scan.evidence import ReportEvidence
from src.scan.finding_policy import keep_infer_type


class InferReportParseError(RuntimeError):
    """Raised when an Infer report cannot be parsed."""


class InferScanner:
    """Infer static analysis scanner"""

    def __init__(self, compile_db_path: str, scan_reports_dir: str):
        self.compile_db_path = compile_db_path
        self.scan_reports_dir = scan_reports_dir
        self.infer_output_dir = f"{scan_reports_dir}/infer"
        self.infer_report_path = f"{self.infer_output_dir}/report.json"
        self.evidence: Optional[ReportEvidence] = None

    def run(self, compile_db_path: str = None) -> bool:
        """Run Infer static analysis"""
        logger.info("Running Infer analysis...")

        db = compile_db_path or self.compile_db_path
        if not os.path.exists(db):
            logger.error(f"compile_commands.json not found: {db}")
            return False

        # Ensure report directory exists
        os.makedirs(self.scan_reports_dir, exist_ok=True)

        # Drop any stale report so a crashed run can't be mistaken for success.
        if os.path.exists(self.infer_report_path):
            os.remove(self.infer_report_path)

        try:
            # Run Infer with fuzzing-focused checkers
            # Disable DEAD_STORE as it's not relevant for fuzzing
            result = subprocess.run([
                "infer", "run",
                "--compilation-database", db,
                "-o", self.infer_output_dir,
                "--keep-going",
                "--disable-issue-type", "DEAD_STORE",  # Disable dead store warnings
            ], capture_output=True, text=True, timeout=600)

            if result.returncode != 0:
                logger.error(
                    f"Infer exited with code {result.returncode}: {result.stderr.strip()}"
                )
                return False

            if os.path.exists(self.infer_report_path):
                return True
            else:
                logger.error("Infer report not generated")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Infer timeout (600s)")
            return False
        except Exception as e:
            logger.error(f"Infer failed: {e}")
            return False

    def parse_report(self) -> List[Target]:
        """Parse Infer JSON report"""
        self.evidence = None
        if not os.path.exists(self.infer_report_path):
            raise InferReportParseError(
                f"Infer report not found: {self.infer_report_path}"
            )

        targets = []
        excluded_types = Counter()

        try:
            issues, evidence = ReportEvidence.load(
                self.infer_report_path,
                analyzer="infer",
                artifact="stages/scan/infer-report.json",
            )

            if not isinstance(issues, list):
                raise ValueError("Infer report root must be a JSON array")

            for issue_index, issue in enumerate(issues):
                if not isinstance(issue, dict):
                    raise ValueError("Infer report issues must be JSON objects")
                finding = evidence.add(
                    f"/{issue_index}", issue.get("bug_type", "UNKNOWN"), issue
                )
                severity = issue.get('severity')

                # Only findings emitted as issues are candidates for target generation.
                if severity not in ['ERROR', 'WARNING']:
                    finding.exclusion_reason = "unsupported_severity"
                    continue

                file_path = issue.get('file', '')
                line_no = issue.get('line', 0)
                bug_type = issue.get('bug_type', 'UNKNOWN')
                qualifier = issue.get('qualifier', '')

                if not keep_infer_type(bug_type):
                    excluded_types[bug_type] += 1
                    finding.exclusion_reason = "sanitizer_unrelated_type"
                    continue

                if not file_path or not line_no:
                    finding.exclusion_reason = "missing_file_or_line"
                    continue

                # Use bug_type or qualifier as description
                description = qualifier if qualifier else bug_type

                targets.append(Target(
                    file_path=file_path,
                    line_no=line_no,
                    severity=severity,
                    description=description
                ))
                finding.target = targets[-1]

            if excluded_types:
                summary = ", ".join(
                    f"{bug_type}={count}"
                    for bug_type, count in sorted(excluded_types.items())
                )
                logger.info(
                    f"Excluded {sum(excluded_types.values())} sanitizer-unrelated "
                    f"Infer findings: {summary}"
                )
            logger.info(f"Parsed {len(targets)} Infer targets")
            self.evidence = evidence
            return targets

        except Exception as e:
            logger.error(f"Failed to parse Infer report: {e}")
            raise InferReportParseError(
                f"Failed to parse Infer report: {self.infer_report_path}"
            ) from e
