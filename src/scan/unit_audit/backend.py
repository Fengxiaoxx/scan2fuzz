"""Unit-audit alert backend: slice the library, audit every slice, publish every finding.

Findings are not ranked or cut: the auditor's own grades flipped between runs for
the same bug, so every finding becomes a target.
"""

from __future__ import annotations

import json
import os
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path

from dotenv import load_dotenv
from loguru import logger

from src.core.config import load_library_config
from src.core.targets import Target
from src.llm.provider_config import resolve_model_name
from src.scan.backend import ScanContext, ScanResult
from src.scan.build_inputs import collect_linked_build_inputs
from src.scan.evidence import ReportEvidence
from src.scan.source_tree import require_clean_tree
from src.scan.unit_audit.auditor import OpenCodeSliceAuditor, SliceAuditRequest
from src.scan.unit_audit.prompt import build_system_prompt, build_user_prompt
from src.scan.unit_audit.slicing import DEFAULT_SLICE_LINES, build_slices, render_source
from src.scan.unit_audit.source_copy import copy_tracked_sources
from src.scan.unit_audit.units import SOURCE_SUFFIXES, enumerate_file, enumerate_units

DEFAULT_UNIT_AUDIT_MODEL = "deepseek-v4-flash"
REPORT_ARTIFACT = "stages/scan/unit-audit-findings.json"
# Each round after the first audits again only the slices that failed in the round before;
# slices still failing after the last round are dropped and the scan goes on without them.
MAX_AUDIT_ROUNDS = 5


class UnitAuditBackend:
    def __init__(
        self,
        library_name: str,
        *,
        slice_lines: int = DEFAULT_SLICE_LINES,
        workers: int,
        auditor=None,
    ) -> None:
        if workers < 1:
            raise ValueError("workers must be at least 1")
        self.library_name = library_name
        self.slice_lines = slice_lines
        self.workers = workers
        load_dotenv()  # here rather than at import, so importing is side-effect free
        self.model = resolve_model_name("UNIT_AUDIT_MODEL", DEFAULT_UNIT_AUDIT_MODEL)
        self._auditor = auditor  # tests pass a stand-in with an audit(request) method

    def check_prerequisites(self) -> bool:
        binary = os.environ.get("OPENCODE_BINARY", "opencode")
        if shutil.which(binary) is None:
            logger.error(f"OpenCode executable not found: {binary}")
            return False
        return True

    def scan(self, context: ScanContext) -> ScanResult | None:
        source_root = Path(context.source_root).resolve(strict=True)
        require_clean_tree(source_root)
        reports_dir = Path(context.reports_dir) / "unit-audit"
        reports_dir.mkdir(parents=True, exist_ok=True)

        if not (context.build_trace_path and context.link_target and context.public_include_dir):
            raise ValueError("Unit audit requires the build trace, link target, and installed include tree")
        scope = collect_linked_build_inputs(
            Path(context.build_trace_path),
            context.link_target,
            source_root,
            Path(context.public_include_dir),
        )
        excluded_prefixes = load_library_config(self.library_name).get(
            "unit_audit", {}
        ).get("exclude_installed_header_prefixes", [])
        # Generated installed headers may have no matching checkout file. They
        # are still in the scope inventory; reject any function definitions
        # until their source locations can be mapped for target generation.
        include_root = Path(context.public_include_dir).resolve(strict=True)
        for installed in scope["installed_public_files"]:
            # Headers installed only to satisfy public-header dependencies are
            # not part of this library's audit target.
            if any(installed["include"].startswith(prefix) for prefix in excluded_prefixes):
                continue
            if installed["source_path"] is not None:
                continue
            path = Path(installed["installed_path"])
            if path.suffix.lower() in SOURCE_SUFFIXES and enumerate_file(
                path, relative_to=include_root, language=context.language
            ):
                raise ValueError(f"installed code has no source location: {path}")
        audit_files = [
            path for path in scope["scan_file_paths"]
            if Path(path).is_relative_to(source_root)
        ]
        units = enumerate_units(
            audit_files, source_root=str(source_root), language=context.language
        )
        logger.info(
            "Unit audit scope: {} linked inputs, {} installed files, {} unique files",
            len(scope["project_sources"])
            + len(scope["project_headers"])
            + len(scope["project_other_inputs"]),
            len(scope["installed_public_files"]),
            len(scope["scan_file_paths"]),
        )
        if not units:
            logger.error("Unit audit found no function units to read")
            return None
        slices = build_slices(units, self.slice_lines)
        logger.info("Unit audit: {} units in {} slices, model={}", len(units), len(slices), self.model)

        system_prompt = build_system_prompt()
        # Sessions read a neutral copy of tracked code plus selected generated
        # inputs; slicing and rendered source use identical checkout files.
        audit_copy = copy_tracked_sources(source_root, build_inputs=audit_files)
        requests = [
            SliceAuditRequest(
                slice_=slice_,
                number=number,
                source_root=audit_copy.root,
                system_prompt=system_prompt,
                user_prompt=build_user_prompt(slice_, source=render_source(source_root, slice_)),
                session_dir=reports_dir / f"slice-{number:03d}" / "session",
            )
            for number, slice_ in enumerate(slices, 1)
        ]
        auditor = self._auditor or OpenCodeSliceAuditor(
            self.library_name, self.model, workers=self.workers
        )
        by_number = {}
        pending = requests
        for audit_round in range(1, MAX_AUDIT_ROUNDS + 1):
            if audit_round > 1:
                logger.warning(
                    "Unit audit round {}/{}: auditing {} failed slices again",
                    audit_round,
                    MAX_AUDIT_ROUNDS,
                    len(pending),
                )
            # One line per slice as soon as it is done: a full audit runs for hours.
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                futures = [pool.submit(auditor.audit, request) for request in pending]
                for done, future in enumerate(as_completed(futures), 1):
                    outcome = future.result()
                    by_number[outcome.number] = outcome
                    logger.info(
                        "slice {:03d}/{:03d} done ({} of {}): {}:{}-{} -> {} findings, {:.0f}s{}",
                        outcome.number,
                        len(requests),
                        done,
                        len(pending),
                        outcome.file,
                        outcome.start,
                        outcome.end,
                        len(outcome.findings),
                        outcome.seconds,
                        f" ERROR {outcome.error}" if outcome.error else " (reused)" if outcome.reused else "",
                    )
            pending = [request for request in pending if by_number[request.number].error]
            if not pending:
                break
        shutil.rmtree(audit_copy.root.parent)
        outcomes = sorted(by_number.values(), key=lambda outcome: outcome.number)

        findings = sorted(
            (finding for outcome in outcomes for finding in outcome.findings),
            key=lambda finding: (finding.file, finding.line),
        )
        failed = [outcome for outcome in outcomes if outcome.error]
        counts = {
            "slice_count": len(outcomes),
            "failed_slice_count": len(failed),
            "reused_slice_count": sum(1 for outcome in outcomes if outcome.reused),
            "finding_count": len(findings),
        }

        report_path = reports_dir / "unit-audit-findings.json"
        report = {
            "library": self.library_name,
            "model": self.model,
            "audit_source": {"commit": audit_copy.commit, "tracked_files": audit_copy.tracked_files},
            **counts,
            "usage": {
                key: sum(outcome.usage.get(key) or 0 for outcome in outcomes)
                for key in ("input_tokens", "output_tokens", "cache_read_input_tokens")
            },
            "model_seconds_sum": round(sum(outcome.seconds for outcome in outcomes), 1),
            "findings": [asdict(finding) for finding in findings],
            "slices": [outcome.to_dict() for outcome in outcomes],
        }
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

        _, evidence = ReportEvidence.load(str(report_path), analyzer="UnitAudit", artifact=REPORT_ARTIFACT)
        targets: list[Target] = []
        for index, finding in enumerate(findings):
            record = evidence.add(f"/findings/{index}", "UnitAudit", asdict(finding))
            record.target = Target(
                file_path=finding.file,
                line_no=finding.line,
                severity="WARNING",
                description=finding.target_description(),
            )
            targets.append(record.target)
        evidence.metadata = {
            "source_root": context.source_root,
            "model": self.model,
            **counts,
            "published_target_count": len(targets),
        }
        if failed:
            logger.warning(
                "Unit audit dropped {} of {} slices that still failed after {} rounds ({})",
                len(failed),
                len(outcomes),
                MAX_AUDIT_ROUNDS,
                ", ".join(f"{o.file}:{o.start}-{o.end}" for o in failed),
            )
        logger.info("Unit audit published {} of {} findings as targets", len(targets), len(findings))

        # Per-slice logs are written straight into the run (stages/scan/subjects/*/logs).
        return ScanResult(
            target_groups={"UnitAudit": targets},
            reports=[evidence],
            artifacts={report_path.absolute(): REPORT_ARTIFACT},
        )
