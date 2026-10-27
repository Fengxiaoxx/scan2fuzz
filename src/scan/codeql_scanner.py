"""
CodeQL vulnerability scanner and SARIF parser.
"""

import os
import subprocess
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

from loguru import logger

from src.core import Target
from src.scan.evidence import ReportEvidence
from src.scan.finding_policy import keep_codeql_rule


class CodeQLReportParseError(RuntimeError):
    """Raised when a CodeQL SARIF report cannot be parsed."""


class CodeQLScanner:
    """Runs CodeQL security queries and converts SARIF findings to targets."""

    QUERY_SUITE = "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls"
    SOURCE_EXTENSIONS = (".c", ".cc", ".cpp", ".cxx")
    HEADER_EXTENSIONS = (".h", ".hh", ".hpp", ".hxx")

    def __init__(self, codeql_db: str, scan_reports_dir: str, source_root: str):
        self.codeql_db = os.path.abspath(codeql_db)
        self.scan_reports_dir = scan_reports_dir
        self.source_root = os.path.abspath(source_root)
        self.codeql_report_path = os.path.join(scan_reports_dir, "codeql.sarif")
        self.codeql_log_path = os.path.join(scan_reports_dir, "codeql.log")
        self.evidence: Optional[ReportEvidence] = None

    def run(self) -> bool:
        """Run CodeQL C/C++ security analysis against an existing database."""
        logger.info("Running CodeQL security analysis...")

        if not os.path.exists(self.codeql_db):
            logger.error(f"CodeQL database not found: {self.codeql_db}")
            return False

        os.makedirs(self.scan_reports_dir, exist_ok=True)
        if os.path.exists(self.codeql_report_path):
            os.remove(self.codeql_report_path)

        command = [
            "codeql",
            "database",
            "analyze",
            self.codeql_db,
            self.QUERY_SUITE,
            "--format=sarif-latest",
            f"--output={self.codeql_report_path}",
            "--threads=0",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=1200,
            )

            with open(self.codeql_log_path, "w", encoding="utf-8") as log_file:
                log_file.write(result.stdout)
                if result.stderr:
                    log_file.write("\n--- stderr ---\n")
                    log_file.write(result.stderr)

            if result.returncode != 0:
                logger.error(f"CodeQL analysis failed (see {self.codeql_log_path})")
                return False

            if not os.path.exists(self.codeql_report_path):
                logger.error("CodeQL SARIF report not generated")
                return False

            logger.success(f"CodeQL report generated at {self.codeql_report_path}")
            return True

        except subprocess.TimeoutExpired:
            logger.error("CodeQL analysis timeout (1200s)")
            return False
        except Exception as exc:
            logger.error(f"CodeQL analysis failed: {exc}")
            return False

    def parse_report(self, linked_source_files: Optional[List[str]] = None) -> List[Target]:
        """Parse CodeQL SARIF report into targets.

        When linked_source_files is provided, source-file findings are limited
        to the translation units that contribute to the selected link target.
        Header findings are accepted only when the header lives in a directory
        that contains one of those linked translation units.
        """
        self.evidence = None
        if not os.path.exists(self.codeql_report_path):
            raise CodeQLReportParseError(
                f"CodeQL report not found: {self.codeql_report_path}"
            )

        allowed_files, allowed_header_dirs = self._build_allowed_sets(linked_source_files)
        targets: List[Target] = []
        excluded_rules = Counter()

        try:
            sarif, evidence = ReportEvidence.load(
                self.codeql_report_path,
                analyzer="codeql",
                artifact="stages/scan/codeql.sarif",
            )

            if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
                raise ValueError("CodeQL SARIF report must contain a runs array")

            evidence.metadata = {
                "sarif_version": sarif.get("version"),
                "source_root": self.source_root,
                "runs": [],
            }
            for run_index, run in enumerate(sarif["runs"]):
                if not isinstance(run, dict):
                    raise ValueError("CodeQL SARIF runs must be JSON objects")
                rules = self._rules_by_id(run)
                original_uri_bases = run.get("originalUriBaseIds", {})
                driver = run.get("tool", {}).get("driver", {})
                evidence.metadata["runs"].append(
                    {
                        "index": run_index,
                        "driver": {
                            key: value for key, value in driver.items() if key != "rules"
                        },
                        "originalUriBaseIds": original_uri_bases,
                        "columnKind": run.get("columnKind"),
                    }
                )
                results = run.get("results", [])
                if not isinstance(results, list):
                    raise ValueError("CodeQL SARIF results must be a JSON array")

                for result_index, result in enumerate(results):
                    if not isinstance(result, dict):
                        raise ValueError("CodeQL SARIF results must be JSON objects")
                    rule_id = result.get("ruleId") or result.get("rule", {}).get("id", "")
                    rule = rules.get(rule_id, {})
                    properties = rule.get("properties", {})
                    finding = evidence.add(
                        f"/runs/{run_index}/results/{result_index}",
                        rule_id,
                        result,
                        rule,
                    )

                    if properties.get("kind") not in {"problem", "path-problem"}:
                        finding.exclusion_reason = "unsupported_rule_kind"
                        continue

                    if not keep_codeql_rule(rule_id):
                        excluded_rules[rule_id] += 1
                        finding.exclusion_reason = "sanitizer_unrelated_rule"
                        continue

                    location = self._primary_location(result)
                    if location is None:
                        finding.exclusion_reason = "missing_primary_location"
                        continue

                    file_path, line_no = self._location_to_path(location, original_uri_bases)
                    if not file_path or not line_no:
                        finding.exclusion_reason = "missing_file_or_line"
                        continue

                    if not self._is_allowed_file(file_path, allowed_files, allowed_header_dirs):
                        finding.exclusion_reason = "outside_linked_source_scope"
                        continue

                    targets.append(
                        Target(
                            file_path=file_path,
                            line_no=line_no,
                            severity=self._severity(result, properties),
                            description=self._description(rule_id, rule, result),
                        )
                    )
                    finding.target = targets[-1]

            if excluded_rules:
                summary = ", ".join(
                    f"{rule_id}={count}"
                    for rule_id, count in sorted(excluded_rules.items())
                )
                logger.info(
                    f"Excluded {sum(excluded_rules.values())} sanitizer-unrelated "
                    f"CodeQL findings: {summary}"
                )
            logger.info(f"Parsed {len(targets)} CodeQL targets")
            self.evidence = evidence
            return targets

        except Exception as exc:
            logger.error(f"Failed to parse CodeQL report: {exc}")
            raise CodeQLReportParseError(
                f"Failed to parse CodeQL report: {self.codeql_report_path}"
            ) from exc

    def _build_allowed_sets(
        self, linked_source_files: Optional[List[str]]
    ) -> Tuple[Optional[Set[str]], Set[str]]:
        if not linked_source_files:
            return None, set()

        allowed_files = {
            os.path.abspath(path)
            for path in linked_source_files
            if path
        }
        allowed_header_dirs = {
            os.path.dirname(path)
            for path in allowed_files
            if path.endswith(self.SOURCE_EXTENSIONS)
        }
        return allowed_files, allowed_header_dirs

    def _rules_by_id(self, run: Dict) -> Dict[str, Dict]:
        return {
            rule.get("id"): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
            if rule.get("id")
        }

    def _primary_location(self, result: Dict) -> Optional[Dict]:
        locations = result.get("locations") or []
        if not locations:
            return None
        return locations[0].get("physicalLocation")

    def _location_to_path(self, location: Dict, original_uri_bases: Dict) -> Tuple[Optional[str], Optional[int]]:
        artifact = location.get("artifactLocation", {})
        uri = artifact.get("uri")
        if not uri:
            return None, None

        file_path = self._resolve_uri(uri, artifact.get("uriBaseId"), original_uri_bases)
        line_no = location.get("region", {}).get("startLine")
        if not isinstance(line_no, int):
            return None, None

        return file_path, line_no

    def _resolve_uri(self, uri: str, uri_base_id: Optional[str], original_uri_bases: Dict) -> str:
        decoded = unquote(uri)
        parsed = urlparse(decoded)

        if parsed.scheme == "file":
            return os.path.abspath(parsed.path)

        if os.path.isabs(decoded):
            return os.path.abspath(decoded)

        base = self.source_root
        if uri_base_id and uri_base_id in original_uri_bases:
            base_uri = original_uri_bases[uri_base_id].get("uri", "")
            base_parsed = urlparse(base_uri)
            if base_parsed.scheme == "file":
                base = base_parsed.path
            elif base_uri:
                base = base_uri

        return os.path.abspath(os.path.join(base, decoded))

    def _is_allowed_file(
        self,
        file_path: str,
        allowed_files: Optional[Set[str]],
        allowed_header_dirs: Set[str],
    ) -> bool:
        if allowed_files is None:
            return True

        normalized = os.path.abspath(file_path)
        if normalized in allowed_files:
            return True

        if normalized.endswith(self.HEADER_EXTENSIONS):
            return os.path.dirname(normalized) in allowed_header_dirs

        return False

    def _severity(self, result: Dict, properties: Dict) -> str:
        problem_severity = properties.get("problem.severity")
        if problem_severity:
            return problem_severity.upper()

        level = result.get("level")
        if level:
            return level.upper()

        return "WARNING"

    def _description(self, rule_id: str, rule: Dict, result: Dict) -> str:
        message = result.get("message", {}).get("text", "").strip()
        name = rule.get("name") or rule_id
        if message:
            return f"CodeQL {rule_id}: {message}"
        return f"CodeQL {rule_id}: {name}"
