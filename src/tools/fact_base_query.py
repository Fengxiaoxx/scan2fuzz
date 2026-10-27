"""
Faceted API lookup over the current run's immutable fact-base snapshot.

Query inputs (all required): (handle_lifecycle, handle_type, nl_description).

An API matches iff it carries the lifecycle label AND flows the handle type in
the direction implied by that lifecycle (the two facets are intersected):

    acquire_handle -> handle_type in produces
    release_handle -> handle_type in consumes
    use_handle     -> handle_type in produces OR consumes  (covers borrowed getters)

If one API survives, it is returned directly. If more than one survives, they
are re-ranked by FAISS semantic similarity to nl_description. Up to three
results are returned as a list, each with header_file, signature, source, coord.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from src.core import get_project_root
from src.experiment import RunArtifactStore

VALID_LIFECYCLES = ("acquire_handle", "use_handle", "release_handle")
MAX_CANDIDATES = 3


class FactBaseQuery:
    """Query the per-library fact base by (handle_lifecycle, handle_type, nl)."""

    def __init__(self, library_name: str):
        self.library_name = library_name
        self.run_store = RunArtifactStore.from_environment(
            get_project_root(), library_name
        )
        self.fact_base_path = self.run_store.safe_path(
            "stages/preprocess/fact_base.json"
        )
        self._fact_base: Optional[Dict[str, Any]] = None
        self._vector_tool = None  # lazy: only built when re-ranking is needed

    @property
    def fact_base(self) -> Dict[str, Any]:
        if self._fact_base is None:
            value = json.loads(self.fact_base_path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("fact base must be a JSON object")
            self._fact_base = value
        return self._fact_base

    def query(
        self, handle_lifecycle: str, handle_type: str, nl_description: str
    ) -> List[Dict[str, Any]]:
        if handle_lifecycle not in VALID_LIFECYCLES:
            raise ValueError(f"handle_lifecycle must be one of {list(VALID_LIFECYCLES)}")

        matches = [
            rec
            for rec in self.fact_base.values()
            if handle_lifecycle in rec.get("handle_lifecycle", [])
            and self._type_matches(rec, handle_lifecycle, handle_type)
        ]

        if len(matches) > 1:
            matches = self._rerank(matches, nl_description)

        return [self._project(rec) for rec in matches[:MAX_CANDIDATES]]

    @staticmethod
    def _type_matches(rec: Dict[str, Any], lifecycle: str, handle_type: str) -> bool:
        produces = rec.get("produces", [])
        consumes = rec.get("consumes", [])
        if lifecycle == "acquire_handle":
            return handle_type in produces
        if lifecycle == "release_handle":
            return handle_type in consumes
        return handle_type in produces or handle_type in consumes  # use_handle

    @staticmethod
    def _project(rec: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "header_file": rec.get("header_file", ""),
            "signature": rec.get("signature", ""),
            "source": rec.get("source", ""),
            "coord": rec.get("coord", {}),
        }

    def _rerank(
        self, matches: List[Dict[str, Any]], nl_description: str
    ) -> List[Dict[str, Any]]:
        """Order matches by FAISS similarity to nl_description (best first)."""
        order = {
            api_id: i
            for i, api_id in enumerate(self._semantic_order(nl_description))
        }
        missing = sorted(
            rec.get("api_id", "")
            for rec in matches
            if rec.get("api_id", "") not in order
        )
        if missing:
            raise ValueError(
                "FAISS index is missing fact-base APIs: " + ", ".join(missing)
            )
        return sorted(matches, key=lambda rec: order[rec["api_id"]])

    def _semantic_order(self, nl_description: str) -> List[str]:
        if self._vector_tool is None:
            from src.knowledge.vector_search import VectorSearchTool

            tool = VectorSearchTool(self.library_name)
            tool.load()
            self._vector_tool = tool
        results = self._vector_tool.vector_store.similarity_search_with_score(
            nl_description, k=len(self.fact_base)
        )
        return [doc.metadata.get("api_id", "") for doc, _ in results]
