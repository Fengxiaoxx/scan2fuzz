"""Compiler depfiles define linked build scope without walking the source tree."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.scan.bitcode_builder import BuildCommand
from src.scan.build_inputs import _depfile_for, _read_depfile, collect_linked_build_inputs


class BuildInputsTests(unittest.TestCase):
    def test_explicit_depfile_and_make_continuations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            depfile = root / "obj" / "inputs.d"
            depfile.parent.mkdir()
            depfile.write_text(
                "obj/file.o: src/file.cc include/a.h \\\n"
                " include/path\\ with\\ spaces.h\n"
                "include/a.h:\n",
                encoding="utf-8",
            )
            command = BuildCommand(
                "clang++ -MMD -MF obj/inputs.d -c src/file.cc -o obj/file.o",
                root,
            )
            self.assertEqual(_depfile_for(command), depfile)
            self.assertEqual(
                _read_depfile(depfile, root),
                {
                    (root / "src/file.cc").resolve(),
                    (root / "include/a.h").resolve(),
                    (root / "include/path with spaces.h").resolve(),
                },
            )

    def test_default_depfile_follows_object_name(self):
        with tempfile.TemporaryDirectory() as directory:
            command = BuildCommand("clang -c a.c -o obj/a.c.o", Path(directory))
            self.assertEqual(
                _depfile_for(command), Path(directory) / "obj/a.c.o.d"
            )

    def test_installed_header_is_selected_without_compile_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            installed = root / "install" / "include"
            (source / "lib").mkdir(parents=True)
            (installed / "lib").mkdir(parents=True)
            (source / "lib" / "a.cc").write_text("int a() { return 1; }\n")
            public_header = source / "lib" / "public.h"
            public_header.write_text("inline int b() { return 2; }\n")
            (installed / "lib" / "public.h").write_bytes(public_header.read_bytes())
            command = BuildCommand("clang++ -c lib/a.cc -o a.o", source)
            (source / "a.o.d").write_text("a.o: lib/a.cc\n")

            with patch(
                "src.scan.build_inputs._target_compile_commands",
                return_value=(source / "libexample.so", [command]),
            ):
                result = collect_linked_build_inputs(
                    root / "build.log", "libexample.so", source, installed
                )

            self.assertEqual(result["project_headers"], [])
            self.assertEqual(
                result["installed_public_files"][0]["source_path"],
                str(public_header),
            )
            self.assertIn(str(public_header), result["scan_file_paths"])


if __name__ == "__main__":
    unittest.main()
