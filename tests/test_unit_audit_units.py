"""Header grammar selection and declarator naming in unit enumeration."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.scan.unit_audit.slicing import build_slices
from src.scan.unit_audit.units import enumerate_file

CPP_HEADER = """\
struct Box {
  Box& operator=(const Box& other) {
    value = other.value;
    return *this;
  }
  int value;
};

int& ref_ret() {
  static int x;
  return x;
}

int add(int a, int b) { return a + b; }
"""

ABSEIL_HEADER = """\
namespace absl {
ABSL_NAMESPACE_BEGIN
namespace internal {
int first() { return 1; }
int target(int value) {
  return value + first();
}
}  // namespace internal
ABSL_NAMESPACE_END
}  // namespace absl
"""


class UnitEnumerationTests(unittest.TestCase):
    def _units(self, language: str):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "sample.h"
            header.write_text(CPP_HEADER)
            return enumerate_file(header, relative_to=root, language=language)

    def test_cpp_header_uses_the_library_language(self):
        cpp = {u.name: (u.start_line, u.end_line) for u in self._units("C++")}
        c = {u.name: (u.start_line, u.end_line) for u in self._units("C")}

        self.assertEqual(cpp["operator="], (2, 5))
        self.assertEqual(cpp["ref_ret"], (9, 12))
        self.assertEqual(cpp["add"], (14, 14))
        # The C grammar cannot parse C++ member operators, so those
        # definitions vanish when a .h is read as C.
        self.assertNotIn("operator=", c)
        self.assertIn("add", c)

    def test_reference_declarator_reaches_the_function_name(self):
        # reference_declarator carries no `declarator` field; the name is found
        # through its named *_declarator child instead of stopping there.
        names = sorted(u.name for u in self._units("C++"))
        self.assertEqual(names, ["add", "operator=", "ref_ret"])

    def test_listing_carries_the_names_into_the_prompt(self):
        listing = "\n".join(s.listing() for s in build_slices(self._units("C++")))
        self.assertIn("- operator= (lines 2-5)", listing)
        self.assertIn("- ref_ret (lines 9-12)", listing)

    def test_abseil_namespace_markers_preserve_nested_functions_and_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "sample.h"
            header.write_text(ABSEIL_HEADER)
            units = enumerate_file(header, relative_to=root, language="C++")

        self.assertEqual(
            sorted((unit.name, unit.start_line, unit.end_line) for unit in units),
            [("first", 4, 4), ("target", 5, 7)],
        )
        listing = "\n".join(slice_.listing() for slice_ in build_slices(units))
        self.assertIn("- target (lines 5-7)", listing)
        self.assertNotIn("internal (lines", listing)

    def test_compiler_included_code_fragments_are_enumerated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("fragment.inc", "fragment.incl_cpp"):
                path = root / name
                path.write_text("inline int included() { return 7; }\n")
                units = enumerate_file(path, relative_to=root, language="C++")
                self.assertEqual([(unit.name, unit.start_line) for unit in units], [("included", 1)])


if __name__ == "__main__":
    unittest.main()
