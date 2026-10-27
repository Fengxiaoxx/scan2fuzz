"""Unit Audit findings accepted by the downstream target publisher."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

from src.core.targets import Target, TargetParser
from src.driver_generation.inputs import work_item
from src.preprocess.reachability.candidate_plan import (
    CandidatePlanBuilder, _audit_path, _audit_vulnerability_type,
)
from src.scan.unit_audit.schema import AuditFinding, parse_findings


class UnitAuditSchemaTests(unittest.TestCase):
    def test_minimal_finding_keeps_the_public_api_path(self):
        payload = {
            "findings": [{
                "function": "parse_value",
                "line": 20,
                "vulnerability_type": "heap-buffer-overflow",
                "entry_api": "parse_document",
                "call_path": [
                    {"function": "parse_document", "file": "src/parser.c", "line": 5},
                    {"function": "parse_value", "file": "src/parser.c", "line": 20},
                ],
                "evidence": "src/parser.c:20 reads beyond the validated buffer length; ASan detects the read.",
            }]
        }
        units = (SimpleNamespace(
            file="src/parser.c", name="parse_value", start_line=10, end_line=30
        ),)

        findings = parse_findings(payload, file="src/parser.c", units=units)

        self.assertEqual(len(findings), 1)
        self.assertEqual(set(asdict(findings[0])), {
            "file", "function", "line", "vulnerability_type", "entry_api", "call_path", "evidence"
        })
        self.assertEqual(findings[0].evidence, payload["findings"][0]["evidence"])
        target = Target("src/parser.c", 20, "WARNING", findings[0].target_description())
        loaded = TargetParser.parse_line(target.to_string())
        self.assertIsNotNone(loaded)
        self.assertEqual(
            _audit_vulnerability_type(loaded.description), "heap-buffer-overflow"
        )
        self.assertEqual(
            _audit_path(loaded.description, apis={"parse_document"}),
            (payload["findings"][0]["call_path"], "used"),
        )
        self.assertNotIn("reads beyond", findings[0].target_description())

        del payload["findings"][0]["evidence"]
        with self.assertRaisesRegex(ValueError, "evidence"):
            parse_findings(payload, file="src/parser.c", units=units)

    def test_merged_findings_keep_type_with_the_selected_call_path(self):
        first = (
            "parse_value (vulnerability_type: heap-buffer-overflow; entry: parse_document; "
            "path: parse_document@src/parser.c:5 -> parse_value@src/parser.c:20)"
        )
        second = (
            "parse_value (vulnerability_type: memory leak; entry: load_document; "
            "path: load_document@src/parser.c:8 -> parse_value@src/parser.c:20)"
        )
        description = f"{first} | {second}"

        self.assertEqual(_audit_vulnerability_type(description), "memory leak")
        path, status = _audit_path(description, apis={"parse_document", "load_document"})
        self.assertEqual(status, "used")
        self.assertEqual(path[0]["function"], "load_document")

    def test_vulnerability_type_reaches_generation_work_item(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src" / "parser.c"
            source.parent.mkdir()
            source.write_text("\n" * 30, encoding="utf-8")
            finding = AuditFinding(
                file="src/parser.c",
                function="parse_value",
                line=20,
                vulnerability_type="heap-buffer-overflow",
                entry_api="parse_document",
                call_path=[
                    {"function": "parse_document", "file": "src/parser.c", "line": 5},
                    {"function": "parse_value", "file": "src/parser.c", "line": 20},
                ],
                evidence="The read exceeds the checked buffer length.",
            )
            targets = root / "targets.txt"
            targets.write_text(
                Target(finding.file, finding.line, "WARNING", finding.target_description()).to_string() + "\n",
                encoding="utf-8",
            )
            commands = root / "compile_commands.json"
            commands.write_text(json.dumps([{"directory": str(root), "file": "src/parser.c"}]), encoding="utf-8")
            locations = root / "function_locations.csv"
            locations.write_text(
                "name,mangled,file_path,start_line,end_line,anchor_line,anchor_col\n"
                "parse_document,parse_document,src/parser.c,1,9,1,1\n"
                "parse_value,parse_value,src/parser.c,10,30,10,1\n",
                encoding="utf-8",
            )
            graph = root / "graph.csv"
            graph.write_text("caller_name,callee_name\nparse_document,parse_value\n", encoding="utf-8")
            api = root / "public_api.json"
            api.write_text(json.dumps({"apis": [{
                "api_id": "abi:parse_document",
                "abi_symbol": "parse_document",
                "display_name": "parse_document",
                "qualified_name": "parse_document",
                "signature": "void parse_document(void)",
                "include": "<parser.h>",
            }]}), encoding="utf-8")

            plan = CandidatePlanBuilder(
                library="example",
                source_root=root,
                targets_file=targets,
                compile_commands=commands,
                function_locations=locations,
                graph_high=graph,
                graph_all=graph,
                public_api=api,
            ).build(root / "candidate_plan.json")

            target = plan["targets"][0]
            self.assertEqual(target["vulnerability_type"], "heap-buffer-overflow")
            self.assertEqual(target["audit_path"], "used")
            self.assertEqual(work_item(target, 0)["vulnerability_type"], "heap-buffer-overflow")


if __name__ == "__main__":
    unittest.main()
