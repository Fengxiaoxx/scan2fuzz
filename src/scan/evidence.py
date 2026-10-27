"""Run-scoped diagnostic evidence, separate from the legacy target interface.

Native analyzer result objects are retained without flattening their paths or
interpreting diagnostic steps as runtime facts. Nothing downstream consumes
this sidecar: targets.txt remains the sole target-selection input.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.targets import Target, TargetParser
from src.scan.target_generator import TargetGenerator


@dataclass
class FindingEvidence:
    json_pointer: str
    rule_id: str
    result: dict[str, Any]
    rule: dict[str, Any] | None = None
    # The existing generator normalizes this same object in place. Do not use
    # its merged description/severity in place of the original result above.
    target: Target | None = None
    exclusion_reason: str | None = None


@dataclass
class ReportEvidence:
    analyzer: str
    artifact: str
    sha256: str
    metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[FindingEvidence] = field(default_factory=list)

    @classmethod
    def load(
        cls, path: str, *, analyzer: str, artifact: str
    ) -> tuple[Any, ReportEvidence]:
        # Hash exactly the bytes being parsed, not a later read of the report.
        payload = Path(path).read_bytes()
        return json.loads(payload), cls(
            analyzer=analyzer,
            artifact=artifact,
            sha256=hashlib.sha256(payload).hexdigest(),
        )

    def add(
        self,
        json_pointer: str,
        rule_id: str,
        result: dict[str, Any],
        rule: dict[str, Any] | None = None,
    ) -> FindingEvidence:
        finding = FindingEvidence(json_pointer, rule_id, result, rule)
        self.findings.append(finding)
        return finding


def build_scan_evidence(
    reports: list[ReportEvidence], generator: TargetGenerator
) -> dict[str, Any]:
    """Link findings to the *written* targets, without selecting new targets.

    Call only after generate() succeeds. The legacy parser and file order also
    determine downstream target markers; their behavior is not reimplemented
    or changed here. Location grouping is a task identity, not a finding ID.
    """
    targets = TargetParser.parse_file(generator.targets_file)
    target_records = []
    by_location = {}
    for ordinal, target in enumerate(targets, 1):
        record = {
            "target_id": f"{target.file_path}:{target.line_no}",
            "marker": f"TARGET_{ordinal:04d}",
            "file": target.file_path,
            "line": target.line_no,
            "finding_ids": [],
        }
        key = (target.file_path, target.line_no)
        if key in by_location:
            raise ValueError(f"duplicate written target: {record['target_id']}")
        by_location[key] = record
        target_records.append(record)

    finding_records = []
    finding_ids = set()
    for report in reports:
        for finding in report.findings:
            # A fingerprint or file:line alone need not identify one finding.
            # This identity is exact within the immutable report snapshot.
            finding_id = (
                f"{report.analyzer}:{report.sha256}:{finding.json_pointer}"
            )
            if finding_id in finding_ids:
                raise ValueError(f"duplicate finding identity: {finding_id}")
            finding_ids.add(finding_id)
            reason = finding.exclusion_reason
            target_record = None
            if finding.target is not None:
                if reason is not None:
                    raise ValueError("finding is both selected and excluded")
                target = finding.target
                reason = generator._exclusion_reason(target.file_path)
                if reason is None:
                    target_record = by_location.get(
                        (target.file_path, target.line_no)
                    )
                    if target_record is None:
                        raise ValueError("selected finding has no written target")
                    target_record["finding_ids"].append(finding_id)
            elif reason is None:
                raise ValueError("finding has no recorded selection decision")

            finding_records.append(
                {
                    "finding_id": finding_id,
                    "analyzer": report.analyzer,
                    "rule_id": finding.rule_id,
                    "report_ref": {
                        "artifact": report.artifact,
                        "sha256": report.sha256,
                        "json_pointer": finding.json_pointer,
                    },
                    "rule": finding.rule,
                    "result": finding.result,
                    "selection": {
                        "status": (
                            "selected" if target_record is not None else "excluded"
                        ),
                        "reason": reason,
                        "target_id": (
                            target_record["target_id"]
                            if target_record is not None else None
                        ),
                    },
                }
            )

    if any(not target["finding_ids"] for target in target_records):
        raise ValueError("written target has no original finding evidence")
    selected_count = sum(
        record["selection"]["status"] == "selected" for record in finding_records
    )
    return {
        "schema_version": 1,
        "reports": [
            {
                "analyzer": report.analyzer,
                "artifact": report.artifact,
                "sha256": report.sha256,
                "metadata": report.metadata,
            }
            for report in reports
        ],
        "findings": finding_records,
        "targets": target_records,
        "summary": {
            "finding_count": len(finding_records),
            "selected_finding_count": selected_count,
            "excluded_finding_count": len(finding_records) - selected_count,
            "target_count": len(target_records),
        },
    }


def write_scan_evidence(
    path: str, reports: list[ReportEvidence], generator: TargetGenerator
) -> None:
    """Atomically replace the working sidecar; CLI later freezes it in the run."""
    document = build_scan_evidence(reports, generator)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=Path(path).absolute().parent,
            prefix=".findings.",
            delete=False,
        ) as handle:
            temporary_path = handle.name
            json.dump(document, handle, ensure_ascii=False, allow_nan=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            os.unlink(temporary_path)
