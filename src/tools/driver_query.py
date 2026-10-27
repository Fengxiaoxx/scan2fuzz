"""
find_drivers: pick one source-bundled example fuzz driver to show the generator.

Selection over the current run's immutable drivers.json snapshot:
  - 0 drivers              -> {"found": false}
  - exactly 1 driver       -> return it
  - many, some call target -> return the caller with the most apis_used (richest)
  - many, none call target -> return the driver with the most apis_used
                              (richest = most idioms; deterministic, not random)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from src.core import get_project_root
from src.experiment import RunArtifactStore


class DriverQuery:
    """Select an example driver from the source-bundled corpus by target function."""

    def __init__(self, library_name: str):
        store = RunArtifactStore.from_environment(get_project_root(), library_name)
        self.path = store.safe_path("stages/preprocess/drivers.json")
        self._corpus: Optional[List[Dict[str, Any]]] = None

    @property
    def corpus(self) -> List[Dict[str, Any]]:
        if self._corpus is None:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(value, list):
                raise ValueError("driver corpus must be a JSON array")
            self._corpus = value
        return self._corpus

    def find(self, target_function: str) -> Dict[str, Any]:
        drivers = self.corpus
        if not drivers:
            return {"found": False}
        if len(drivers) == 1:
            d = drivers[0]
            return self._project(d, target_function in d.get("apis_used", []))

        callers = [d for d in drivers if target_function in d.get("apis_used", [])]
        pool = callers or drivers
        chosen = max(pool, key=lambda d: len(d.get("apis_used", [])))
        return self._project(chosen, bool(callers))

    @staticmethod
    def _project(d: Dict[str, Any], calls_target: bool) -> Dict[str, Any]:
        return {
            "found": True,
            "path": d.get("path", ""),
            "apis_used": d.get("apis_used", []),
            "calls_target": calls_target,
            "source": d.get("source", ""),
        }
