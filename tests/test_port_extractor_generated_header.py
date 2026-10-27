"""Resolve AST locations in generated headers against their build directory."""

import os
import tempfile
import unittest
from pathlib import Path

from clang import cindex

from src.preprocess.extractors.port_extractor import _extract_from_tu


class GeneratedHeaderPortsTests(unittest.TestCase):
    def test_relative_header_definition_uses_compilation_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            source_dir = root / "src"
            build.mkdir()
            source_dir.mkdir()
            (build / "generated.h").write_text(
                "int example_api(const char *name) { return name != 0; }\n",
                encoding="utf-8",
            )
            source = source_dir / "example.c"
            source.write_text('#include "generated.h"\n', encoding="utf-8")

            original = Path.cwd()
            try:
                os.chdir(build)
                tu = cindex.Index.create().parse(str(source), args=["-I."])
            finally:
                os.chdir(original)

            self.assertFalse(list(tu.diagnostics))
            ports = _extract_from_tu(
                tu, str(root), {"example_api"}, compilation_directory=str(build)
            )
            self.assertEqual(ports["example_api"]["coord"]["file"], "build/generated.h")


if __name__ == "__main__":
    unittest.main()
