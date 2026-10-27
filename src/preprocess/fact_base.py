"""
Assemble the per-library API fact base.

Merges the STRUCTURAL layer (api_ports.json, from PortExtractor: produces/consumes
handle types + coord, keyed by mangled) with the SEMANTIC layer (api/docs/*.json,
from the LSP doc agent: signature, summary, handle_lifecycle, constraints, source)
into one queryable record per API. Agents query this fact base through find_api.

Output: info_lib/<lib>/api/fact_base.json -- {mangled: record}, each record:

    {
      "mangled", "name", "signature", "coord": {file, line, col}, "summary",
      "handle_lifecycle": ["<acquire|use|release>_handle" | "none"],  # function-level (doc agent)
      "produces": ["<handle type>", ...],   # handle types leaving (return / T** out-param)
      "consumes": ["<handle type>", ...],   # handle types entering (T* by value)
      "constraints": [{param, value_kind}], # SCALAR params only -- handles live in produces/consumes
      "header_file", "source"
    }

Join key: mangled. The doc files are named <name>.json; for C libraries name == mangled.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from loguru import logger
from src.experiment import RunArtifactStore


class FactBaseBuilder:
    """Merge api_ports.json (structural) + api/docs/*.json (semantic) -> fact_base.json."""

    def __init__(
        self,
        library_name: str,
        artifact_store: RunArtifactStore,
        info_root: str = "info_lib",
    ):
        info = Path(info_root) / library_name
        self.ports_path = info / "raw" / "classify" / "api_ports.json"
        self.out_path = info / "api" / "fact_base.json"
        self.artifact_store = artifact_store
        self.doc_index = artifact_store.read_json(
            "stages/preprocess/api-doc-index.json"
        )
        if not isinstance(self.doc_index, dict):
            raise ValueError("API document index must be an object")

    def build(self) -> Dict[str, Any]:
        ports: Dict[str, Any] = json.loads(self.ports_path.read_text(encoding="utf-8"))

        fact_base: Dict[str, Dict[str, Any]] = {}
        with_doc = 0
        for mangled, p in ports.items():
            api_id = f"abi:{mangled}"
            name = p.get("name", mangled)
            doc = self._load_doc(api_id)
            with_doc += bool(doc)

            # Handle params already live in produces/consumes; keep only scalar constraints.
            handle_params = {
                port["port"]
                for port in p.get("ports", [])
                if port.get("is_handle") and not port.get("is_return")
            }
            constraints = [
                c for c in doc.get("constraints", []) if c.get("param") not in handle_params
            ]

            fact_base[api_id] = {
                "api_id": api_id,
                "mangled": mangled,
                "name": name,
                "qualified_name": doc["qualified_name"],
                "signature": doc.get("signature", ""),
                "coord": p.get("coord", {}),
                "summary": doc.get("summary", ""),
                "handle_lifecycle": self._as_list(doc.get("handle_lifecycle")),
                "produces": [h["type"] for h in p.get("produces", [])],
                "consumes": [h["type"] for h in p.get("consumes", [])],
                "constraints": constraints,
                "header_file": doc.get("header_file", ""),
                "source": doc.get("source", ""),
            }

        self.out_path.write_text(
            json.dumps(fact_base, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        summary = {
            "output": str(self.out_path),
            "api_count": len(fact_base),
            "with_doc": with_doc,
        }
        logger.info(
            f"fact_base: {summary['api_count']} APIs ({with_doc} with docs) -> {self.out_path}"
        )
        return summary

    def _load_doc(self, api_id: str) -> Dict[str, Any]:
        try:
            f = self.artifact_store.safe_path(self.doc_index[api_id])
        except KeyError as exc:
            raise FileNotFoundError(f"API document is not indexed: {api_id}") from exc
        if not f.is_file():
            raise FileNotFoundError(f"API document not found: {f}")
        try:
            value = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise ValueError(f"Unreadable API document: {f}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"API document must be a JSON object: {f}")
        return value

    @staticmethod
    def _as_list(value: Any) -> List[str]:
        if isinstance(value, str):
            return [value] if value else []
        return list(value) if value else []


def build_fact_base(
    library_name: str,
    artifact_store: RunArtifactStore,
    info_root: str = "info_lib",
) -> Dict[str, Any]:
    """Convenience entry point."""
    return FactBaseBuilder(library_name, artifact_store, info_root).build()
