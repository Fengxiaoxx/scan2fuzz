"""Run-scoped candidate and documentation inputs for driver stages."""

from __future__ import annotations

import json
from typing import Any, Dict

from src.core import get_project_root
from src.experiment import RunArtifactStore


def load_candidate_plan(
    library: str, store: RunArtifactStore | None = None
) -> Dict[str, Any]:
    store = store or RunArtifactStore.from_environment(get_project_root(), library)
    path = store.safe_path("stages/preprocess/candidate_plan.json")
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 8
        or not isinstance(value.get("targets"), list)
    ):
        raise ValueError(f"invalid candidate plan: {path}")
    return value


def work_item(target: Dict[str, Any], candidate_index: int) -> Dict[str, Any]:
    candidates = target.get("candidates")
    if not isinstance(candidates, list) or not 0 <= candidate_index < len(candidates):
        raise IndexError(
            f"candidate index {candidate_index} is invalid for {target.get('marker')}"
        )
    candidate = candidates[candidate_index]
    chain = candidate.get("chain")
    if not isinstance(chain, list) or not chain:
        raise ValueError(
            f"candidate has no call chain: {target.get('marker')}:{candidate_index}"
        )
    item = {
        "api_id": candidate["api_id"],
        "api": candidate["display_name"],
        "abi_symbol": candidate["abi_symbol"],
        "qualified_name": candidate["qualified_name"],
        "signature": candidate["signature"],
        "include": candidate["include"],
        "candidate_index": candidate_index,
        "candidate_count": len(candidates),
        "candidate_layer": candidate["layer"],
        "marker": target["marker"],
        "target_key": target["target_id"],
        "vulnerability_type": str(target.get("vulnerability_type") or ""),
        "target": {
            "target_key": target["target_id"],
            "marker": target["marker"],
            "file": target["file"],
            "line": target["line"],
            "severity": target["severity"],
            "description": target["description"],
            "chain": chain,
        },
    }
    expected_driver_id = candidate.get("driver_id")
    if not isinstance(expected_driver_id, str) or not expected_driver_id:
        raise ValueError(
            "candidate has no driver identity: "
            f"{target.get('marker')}:{candidate_index}"
        )
    item["driver_id"] = expected_driver_id
    return item


def resolve_work_item(
    library: str,
    api_id: str,
    marker: str,
    store: RunArtifactStore | None = None,
) -> Dict[str, Any]:
    """Resolve one exact API-target pair from the immutable candidate plan."""
    plan = load_candidate_plan(library, store)
    matches = []
    for target in plan["targets"]:
        if target.get("marker") != marker:
            continue
        for index, candidate in enumerate(target.get("candidates", [])):
            if candidate.get("api_id") == api_id:
                matches.append(work_item(target, index))
    if len(matches) != 1:
        raise KeyError(
            f"expected one candidate for {api_id}/{marker}, found {len(matches)}"
        )
    return matches[0]


def load_api_document(
    library: str,
    api_id: str,
    store: RunArtifactStore | None = None,
) -> Dict[str, Any]:
    store = store or RunArtifactStore.from_environment(get_project_root(), library)
    index = store.read_json("stages/preprocess/api-doc-index.json")
    if not isinstance(index, dict):
        raise ValueError("API document index must be a JSON object")
    if api_id not in index:
        raise KeyError(f"current run has no API documentation for {api_id}")
    document_path = store.safe_path(index[api_id])
    value = json.loads(document_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("api_id") != api_id:
        raise ValueError(f"invalid API documentation: {document_path}")
    return value
