"""Focused checks for the coverage context sent to Driver Refiner."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.driver_qualification.reachability.diagnose import make_region_diagnose
from src.driver_qualification.reachability.progress import ChainStep, Progress


SOURCE = """int entry(void) {
  return middle();
}
int middle(void) {
  return target();
}
int target(void) {
  if (guard())
    return risky();
  return 0;
}
"""


class ReachReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "source.c"
        self.source.write_text(SOURCE, encoding="utf-8")
        self.chain = [
            ChainStep("entry", str(self.source), 1, symbol="entry"),
            ChainStep("middle", str(self.source), 4, symbol="middle"),
            ChainStep("target", str(self.source), 7, symbol="target"),
        ]

    def function(
        self, name: str, first: int, last: int, count: int,
        *, path: Path | None = None, zero_line: int | None = None,
    ) -> dict:
        regions = [[first, 1, last, 2, count, 0, 0, 0]]
        if zero_line is not None:
            regions.append([zero_line, 1, zero_line, 40, 0, 0, 0, 0])
        return {
            "name": name,
            "count": count,
            "filenames": [str(path or self.source)],
            "regions": regions,
        }

    def report(self, functions: list[dict], progress: Progress | None) -> str:
        data = {"data": [{"functions": functions, "files": []}]}
        diagnose = make_region_diagnose(
            "lcms", f"{self.source}:9", self.chain,
            lambda _: "coverage-binary", self.temp.name,
            workdir=self.temp.name,
        )
        with patch(
            "src.driver_qualification.reachability.diagnose.replay_and_export",
            return_value=data,
        ):
            return diagnose("driver.cc", progress)

    def test_enclosing_function_is_preferred_and_printed_in_full(self) -> None:
        report = self.report([
            self.function("entry", 1, 3, 3),
            self.function("middle", 4, 6, 3),
            self.function("target", 7, 11, 2, zero_line=9),
        ], Progress(0, 3, "target", 3))
        self.assertIn("Specified code line", report)
        self.assertIn("Line-by-line source coverage for target (source.c:7-11)", report)
        self.assertIn("int target(void) {", report)
        self.assertIn("  return 0;", report)
        self.assertRegex(report, r"(?m)^\s*9\s+0\s+return risky\(\);")
        self.assertNotIn("int entry(void)", report)
        self.assertNotIn("int middle(void)", report)
        self.assertNotIn("Reach chain", report)
        self.assertNotIn("Frontier", report)
        self.assertNotIn("BRANCH", report)

    def test_nearest_covered_chain_function_is_selected_without_depth(self) -> None:
        report = self.report([
            self.function("entry", 1, 3, 3),
            self.function("middle", 4, 6, 2),
            self.function("target", 7, 11, 0),
        ], Progress(0, 1, "entry", 3))
        self.assertIn("Line-by-line source coverage for middle (source.c:4-6)", report)
        self.assertIn("  return target();", report)
        self.assertNotIn("int entry(void)", report)
        self.assertNotIn("int target(void)", report)

    def test_noncontiguous_chain_coverage_still_selects_nearest_function(self) -> None:
        report = self.report([
            self.function("entry", 1, 3, 0),
            self.function("middle", 4, 6, 2),
            self.function("target", 7, 11, 0),
        ], Progress(0, 0, "", 3))
        self.assertIn("Line-by-line source coverage for middle (source.c:4-6)", report)

    def test_same_name_in_another_file_does_not_count_as_enclosing_function(self) -> None:
        other = Path(self.temp.name) / "other" / "source.c"
        other.parent.mkdir()
        other.write_text(SOURCE, encoding="utf-8")
        report = self.report([
            self.function("middle", 4, 6, 2),
            self.function("target", 7, 11, 0),
            self.function("target", 7, 11, 9, path=other),
        ], None)
        self.assertIn("Line-by-line source coverage for middle (source.c:4-6)", report)
        self.assertNotIn("int target(void)", report)

    def test_no_reliable_covered_function_has_short_fallback(self) -> None:
        report = self.report([
            self.function("entry", 1, 3, 0),
            self.function("middle", 4, 6, 0),
            self.function("target", 7, 11, 0),
        ], Progress(0, 0, "", 3))
        self.assertIn("not covered in this bounded run", report)
        self.assertIn("No reliably matched source for a covered function was found", report)
        self.assertNotIn("Reach chain", report)
        self.assertNotIn("Frontier", report)
        self.assertNotIn("int entry(void)", report)

    def test_report_uses_file_line_counts_over_function_region_counts(self) -> None:
        data = {"data": [{
            "functions": [self.function("target", 7, 11, 2)],
            "files": [{
                "filename": str(self.source),
                "segments": [
                    [7, 1, 2, True, True, False],
                    [8, 1, 0, True, True, False],
                    [9, 1, 0, True, True, False],
                    [10, 1, 2, True, True, False],
                    [12, 1, 0, False, False, False],
                ],
            }],
        }]}
        diagnose = make_region_diagnose(
            "lcms", f"{self.source}:9", self.chain,
            lambda _: "coverage-binary", self.temp.name,
            workdir=self.temp.name,
        )
        with patch(
            "src.driver_qualification.reachability.diagnose.replay_and_export",
            return_value=data,
        ):
            report = diagnose("driver.cc", None)
        self.assertRegex(report, r"(?m)^\s*9\s+0\s+return risky\(\);")

    def test_function_source_includes_signature_before_first_coverage_region(self) -> None:
        self.source.write_text("""int entry(void) {
  return middle();
}
int middle(void) {
  return target(0, 0);
}
int target(
    int value,
    int flags)
{
  if (guard())
    return risky();
  return value + flags;
}
""", encoding="utf-8")
        chain = [
            ChainStep("entry", str(self.source), 1, symbol="entry"),
            ChainStep("middle", str(self.source), 4, symbol="middle"),
            ChainStep("target", str(self.source), 7, symbol="target"),
        ]
        data = {"data": [{"functions": [
            self.function("entry", 1, 3, 3),
            self.function("middle", 4, 6, 3),
            # llvm-cov's first region begins at the opening brace, after
            # the declaration recorded by the static-analysis chain.
            self.function("target", 10, 14, 2, zero_line=12),
        ], "files": []}]}
        diagnose = make_region_diagnose(
            "lcms", f"{self.source}:12", chain,
            lambda _: "coverage-binary", self.temp.name,
            workdir=self.temp.name,
        )
        with patch(
            "src.driver_qualification.reachability.diagnose.replay_and_export",
            return_value=data,
        ):
            report = diagnose("driver.cc", None)
        self.assertIn("Line-by-line source coverage for target (source.c:7-14)", report)
        self.assertIn("int target(", report)
        self.assertIn("    int value,", report)
        self.assertIn("    int flags)", report)
        self.assertRegex(report, r"(?m)^\s*12\s+0\s+return risky\(\);")

    def test_coverage_build_path_maps_to_analysis_target_function(self) -> None:
        report = self._report_with_separate_build_paths(target_count=2)
        self.assertIn("Line-by-line source coverage for target (generated.c:7-11)", report)
        self.assertIn("int target(void) {", report)
        self.assertNotIn("int middle(void)", report)

    def test_coverage_build_path_maps_to_nearest_covered_upstream(self) -> None:
        report = self._report_with_separate_build_paths(target_count=0)
        self.assertIn("Line-by-line source coverage for middle (generated.c:4-6)", report)
        self.assertIn("  return target();", report)
        self.assertNotIn("int target(void)", report)

    def _report_with_separate_build_paths(self, *, target_count: int) -> str:
        source_root = Path(self.temp.name) / "library"
        analysis = source_root / "build_analysis" / "generated.c"
        coverage = source_root / "build_coverage" / "generated.c"
        analysis.parent.mkdir(parents=True)
        coverage.parent.mkdir(parents=True)
        analysis.write_text(SOURCE, encoding="utf-8")
        coverage.write_text(SOURCE, encoding="utf-8")
        chain = [
            ChainStep("entry", str(analysis), 1, symbol="entry"),
            ChainStep("middle", str(analysis), 4, symbol="middle"),
            ChainStep("target", str(analysis), 7, symbol="target"),
        ]
        data = {"data": [{"functions": [
            self.function("entry", 1, 3, 3, path=coverage),
            self.function("middle", 4, 6, 2, path=coverage),
            self.function("target", 7, 11, target_count, path=coverage, zero_line=9),
        ], "files": []}]}
        diagnose = make_region_diagnose(
            "lcms", f"{analysis}:9", chain,
            lambda _: "coverage-binary", self.temp.name,
            workdir=self.temp.name,
            source_root=str(source_root),
        )
        with patch(
            "src.driver_qualification.reachability.diagnose.replay_and_export",
            return_value=data,
        ):
            return diagnose("driver.cc", None)


if __name__ == "__main__":
    unittest.main()
