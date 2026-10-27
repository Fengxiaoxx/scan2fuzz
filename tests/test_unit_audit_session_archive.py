"""A session snapshot is optional evidence, not the result of a slice audit."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.scan.unit_audit.auditor import OpenCodeSliceAuditor, SliceAuditRequest
from src.scan.unit_audit.slicing import Slice
from src.scan.unit_audit.units import Unit


class UnitAuditSessionArchiveTests(unittest.TestCase):
    def test_failed_session_archive_keeps_result_and_next_slice_running(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = root / "live-sessions"
            sessions.mkdir()
            usage_root = root / "usage"
            store = SimpleNamespace(
                usage_path=lambda stage, subject: usage_root / subject / "logs" / "calls.jsonl"
            )
            model_calls: list[str] = []
            closed: list[Path] = []

            class FakeClient:
                def __init__(self, *args, session_dir: str, **kwargs):
                    self.session_dir = Path(session_dir)
                    (self.session_dir / "config").mkdir()
                    (self.session_dir / "config" / "opencode.json").write_text("{}")
                    (self.session_dir / "config" / "node_modules" / "effect").mkdir(parents=True)
                    (self.session_dir / "config" / "node_modules" / "effect" / "moving.js").write_text("x")

                def run(self, *, prompt: str, **kwargs):
                    model_calls.append(prompt)
                    findings = ([{
                        "function": "parse_value",
                        "line": 2,
                        "vulnerability_type": "heap-buffer-overflow",
                        "entry_api": "parse_value",
                        "call_path": [{"function": "parse_value", "file": "first.c", "line": 2}],
                        "evidence": "The read may exceed the buffer.",
                    }] if prompt == "first" else [])
                    return SimpleNamespace(
                        result_text=json.dumps({"findings": findings}),
                        usage={"input_tokens": 5, "output_tokens": 3},
                        transcript=[],
                    )

                def close(self):
                    closed.append(self.session_dir)

            def request(number: int, file: str, function: str, prompt: str):
                return SliceAuditRequest(
                    slice_=Slice(file, 1, 3, (Unit(file, function, 1, 3),)),
                    number=number,
                    source_root=root,
                    system_prompt="audit the source",
                    user_prompt=prompt,
                    session_dir=root / "reports" / f"slice-{number:03d}" / "session",
                )

            first = request(1, "first.c", "parse_value", "first")
            second = request(2, "second.c", "other_value", "second")
            original_copytree = shutil.copytree
            original_mkdtemp = tempfile.mkdtemp
            copy_calls = 0

            def flaky_copytree(source, destination, *args, **kwargs):
                nonlocal copy_calls
                copy_calls += 1
                if copy_calls == 1:
                    Path(destination).mkdir(parents=True)
                    raise shutil.Error([(str(source), str(destination), "No such file or directory")])
                return original_copytree(source, destination, *args, **kwargs)

            def local_mkdtemp(*, prefix):
                return original_mkdtemp(prefix=prefix, dir=sessions)

            with patch("src.scan.unit_audit.auditor.RunArtifactStore.from_environment", return_value=store), \
                 patch("src.scan.unit_audit.auditor.OpenCodeQueryClient", FakeClient), \
                 patch("src.scan.unit_audit.auditor.record_agent_call"), \
                 patch("src.scan.unit_audit.auditor.tempfile.mkdtemp", side_effect=local_mkdtemp), \
                 patch("src.scan.unit_audit.auditor.shutil.copytree", side_effect=flaky_copytree):
                auditor = OpenCodeSliceAuditor("example", "test-model")
                first_outcome = auditor.audit(first)
                second_outcome = auditor.audit(second)
                reused = auditor.audit(first)

            self.assertEqual(first_outcome.error, "")
            self.assertEqual(len(first_outcome.findings), 1)
            self.assertEqual(first_outcome.findings[0].function, "parse_value")
            self.assertEqual(second_outcome.error, "")
            self.assertTrue(reused.reused)
            self.assertEqual(model_calls, ["first", "second"])
            self.assertEqual(len(closed), 2)
            self.assertTrue(second.session_dir.is_dir())
            self.assertTrue((second.session_dir / "config" / "opencode.json").is_file())
            self.assertFalse((second.session_dir / "config" / "node_modules").exists())

            saved = list(usage_root.rglob("outcome.json"))
            self.assertEqual(len(saved), 2)
            first_saved = next(json.loads(path.read_text()) for path in saved if "first.c" in path.read_text())
            self.assertNotIn("error", first_saved)
            self.assertEqual(first_saved["finding_count"], 1)
            self.assertEqual(first_saved["findings"][0]["function"], "parse_value")


if __name__ == "__main__":
    unittest.main()
