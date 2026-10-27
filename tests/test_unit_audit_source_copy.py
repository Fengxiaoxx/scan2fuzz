"""The audit copy includes selected generated inputs without copying whole build trees."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from src.scan.unit_audit.source_copy import copy_tracked_sources


class SourceCopyTests(unittest.TestCase):
    def test_selected_generated_input_is_available_to_auditor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "library"
            root.mkdir()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "source.cc").write_text("int f() { return 1; }\n")
            subprocess.run(["git", "-C", str(root), "add", "source.cc"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "-c", "user.name=Test", "-c",
                 "user.email=test@example.invalid", "commit", "-qm", "initial"],
                check=True,
            )
            generated = root / "build_analysis" / "generated.h"
            generated.parent.mkdir()
            generated.write_text("inline int g() { return 2; }\n")
            (generated.parent / "unselected.h").write_text("unused\n")

            copied = copy_tracked_sources(root, build_inputs=[str(generated)])
            try:
                self.assertTrue((copied.root / "source.cc").is_file())
                self.assertEqual(
                    (copied.root / "build_analysis" / "generated.h").read_text(),
                    generated.read_text(),
                )
                self.assertFalse((copied.root / "build_analysis" / "unselected.h").exists())
            finally:
                shutil.rmtree(copied.root.parent)


if __name__ == "__main__":
    unittest.main()
