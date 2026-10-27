"""Cached slice content can keep its result when the slice order changes."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.scan.unit_audit.auditor import (
    OpenCodeSliceAuditor,
    SliceAuditRequest,
    _request_digest,
)
from src.scan.unit_audit.slicing import Slice
from src.scan.unit_audit.units import Unit


class UnitAuditCacheNumberTests(unittest.TestCase):
    def test_reused_outcome_takes_current_request_number(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_dir = root / "logs"
            log_dir.mkdir()
            request = SliceAuditRequest(
                slice_=Slice("sample.c", 10, 20, (Unit("sample.c", "parse", 10, 20),)),
                number=240,
                source_root=root,
                system_prompt="audit",
                user_prompt="source",
                session_dir=root / "session",
            )
            (log_dir / "outcome.json").write_text(json.dumps({
                "request_digest": _request_digest(request, "test-model"),
                "slice": 236,
                "file": "sample.c",
                "start": 10,
                "end": 20,
                "findings": [],
                "usage": {"input_tokens": 3},
                "seconds": 1.0,
            }))
            store = SimpleNamespace(usage_path=lambda stage, subject: log_dir / "calls.jsonl")

            with patch("src.scan.unit_audit.auditor.RunArtifactStore.from_environment", return_value=store), \
                 patch("src.scan.unit_audit.auditor.OpenCodeQueryClient") as client:
                outcome = OpenCodeSliceAuditor("example", "test-model").audit(request)

            self.assertTrue(outcome.reused)
            self.assertEqual(outcome.number, 240)
            self.assertEqual(outcome.file, "sample.c")
            self.assertEqual(outcome.usage["input_tokens"], 3)
            client.assert_not_called()


if __name__ == "__main__":
    unittest.main()
