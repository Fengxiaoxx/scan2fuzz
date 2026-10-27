"""The frozen build must match, regardless of compile command ordering."""

import json
import tempfile
import unittest
from pathlib import Path

from src.preprocess.workflow import _same_compilation_database


class CompilationDatabaseComparisonTests(unittest.TestCase):
    def test_order_does_not_change_build_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current = root / "current.json"
            frozen = root / "frozen.json"
            commands = [
                {"directory": "/build", "file": "a.cc", "command": "clang++ -O2 -c a.cc"},
                {"directory": "/build", "file": "b.cc", "command": "clang++ -O2 -c b.cc"},
            ]
            frozen.write_text(json.dumps(commands), encoding="utf-8")
            current.write_text(json.dumps(list(reversed(commands))), encoding="utf-8")
            self.assertTrue(_same_compilation_database(current, frozen))

            commands[0]["command"] = "clang++ -O0 -c a.cc"
            current.write_text(json.dumps(commands), encoding="utf-8")
            self.assertFalse(_same_compilation_database(current, frozen))


if __name__ == "__main__":
    unittest.main()
