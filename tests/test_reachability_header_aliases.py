"""Installed copies of a public header share target-line coverage."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.driver_qualification.reachability.progress import (
    CoverageSourceAbsentError,
    CoverageSourceResolver,
    probe,
)


class HeaderCoverageAliasTests(unittest.TestCase):
    def test_missing_source_path_resolves_identical_installed_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            original = source_root / "include" / "fixed_array.h"
            installed = root / "install" / "include" / "fixed_array.h"
            original.parent.mkdir(parents=True)
            installed.parent.mkdir(parents=True)
            original.write_text("int target() { return 1; }\n")
            installed.write_bytes(original.read_bytes())
            data = {"data": [{"files": [{"filename": str(installed)}]}]}

            resolver = CoverageSourceResolver(data, str(source_root))
            self.assertEqual(resolver.resolve("include/fixed_array.h"), str(installed))
            self.assertEqual(
                resolver.audit()["resolutions"][0]["method"],
                "identical_header_copy",
            )

            installed.write_text("int target() { return 200; }\n")
            with self.assertRaises(CoverageSourceAbsentError):
                CoverageSourceResolver(data, str(source_root)).resolve(
                    "include/fixed_array.h"
                )

    def test_byte_identical_installed_header_counts_toward_source_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            original = source_root / "include" / "civil_time_detail.h"
            installed = root / "install" / "include" / "civil_time_detail.h"
            original.parent.mkdir(parents=True)
            installed.parent.mkdir(parents=True)
            content = "\n" * 181 + "return fields(y + delta);\n"
            original.write_text(content)
            installed.write_text(content)

            def coverage(count):
                return {"data": [{"files": [
                    {"filename": str(original), "segments": [
                        [182, 1, 0, True, True, False],
                        [183, 1, 0, False, True, False],
                    ]},
                    {"filename": str(installed), "segments": [
                        [182, 1, count, True, True, False],
                        [183, 1, 0, False, True, False],
                    ]},
                ], "functions": []}]}

            audit = root / "resolution.json"
            with patch(
                "src.driver_qualification.reachability.progress.replay_and_export",
                return_value=coverage(17),
            ):
                result = probe(
                    "unused", "unused", "include/civil_time_detail.h:182", [],
                    workdir=str(root), source_root=str(source_root),
                    resolution_audit_path=str(audit),
                )
            self.assertEqual(result.hit, 17)
            self.assertEqual(
                set(json.loads(audit.read_text())["target_equivalent_files"]),
                {str(original), str(installed)},
            )

            installed.write_text(content + "// changed version\n")
            with patch(
                "src.driver_qualification.reachability.progress.replay_and_export",
                return_value=coverage(17),
            ):
                result = probe(
                    "unused", "unused", "include/civil_time_detail.h:182", [],
                    workdir=str(root), source_root=str(source_root),
                )
            self.assertEqual(result.hit, 0)


if __name__ == "__main__":
    unittest.main()
