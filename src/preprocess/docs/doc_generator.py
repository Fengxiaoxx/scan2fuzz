"""Generate one semantic document per canonical public API identity."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

from loguru import logger
from tqdm import tqdm

from src.experiment import RunArtifactStore
from src.preprocess.docs.lsp_doc_agent import LspDocAgent


_DOCUMENT_FIELDS = {
    "api_id": str,
    "abi_symbol": str,
    "function_name": str,
    "qualified_name": str,
    "signature": str,
    "handle_lifecycle": list,
    "summary": str,
    "constraints": list,
    "file_path": str,
    "header_file": str,
    "comment": str,
    "source": str,
}


def _doc_name(api_id: str) -> str:
    return hashlib.sha256(api_id.encode("utf-8")).hexdigest()[:20] + ".json"


def _load_public_apis(path: Path) -> Dict[str, Dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    apis = value.get("apis") if isinstance(value, dict) else None
    if not isinstance(apis, list) or not apis:
        raise ValueError(f"public API artifact contains no APIs: {path}")
    result = {str(api["api_id"]): dict(api) for api in apis}
    if len(result) != len(apis):
        raise ValueError("public API artifact contains duplicate identities")
    return result


def _load_locations(path: Path) -> Dict[str, Dict[str, Any]]:
    by_symbol: Dict[str, list[Dict[str, Any]]] = {}
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        for row in reader:
            symbol = row.get("mangled", "").strip()
            if not symbol:
                continue
            record = {
                "file_path": row.get("file_path", "").strip(),
                "start_line": int(row.get("start_line") or 0),
                "end_line": int(row.get("end_line") or 0),
                "character": int(row.get("anchor_col") or 1),
            }
            if record["file_path"] and record["start_line"] > 0:
                by_symbol.setdefault(symbol, []).append(record)
    return {
        symbol: min(
            records,
            key=lambda record: (
                record["end_line"] - record["start_line"],
                record["file_path"],
                record["start_line"],
            ),
        )
        for symbol, records in by_symbol.items()
    }


def _read_source(
    source_root: Path, file_path: str, start_line: int, end_line: int
) -> str:
    path = source_root / file_path
    if not path.is_file() or start_line <= 0 or end_line < start_line:
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[start_line - 1 : min(end_line, len(lines))])


def _validate_document(value: Any, api_id: str, path: Path) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"API document must be an object: {path}")
    for field, expected in _DOCUMENT_FIELDS.items():
        if not isinstance(value.get(field), expected):
            raise ValueError(f"invalid API document field {field!r}: {path}")
    if value["api_id"] != api_id:
        raise ValueError(f"API document identity mismatch: {path}")
    return value


def _materialize(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


def _process_one(
    api: Dict[str, Any],
    location: Dict[str, Any],
    source_root: Path,
    docs_dir: Path,
    agent: LspDocAgent,
    store: RunArtifactStore,
    artifact_path: str,
    max_attempts: int = 3,
) -> Tuple[str, bool]:
    api_id = str(api["api_id"])
    completed = store.safe_path(artifact_path)
    local_path = docs_dir / _doc_name(api_id)
    if completed.is_file():
        document = _validate_document(store.read_json(artifact_path), api_id, completed)
        _materialize(local_path, document)
        return api_id, True

    start = int(location.get("start_line") or 0)
    end = int(location.get("end_line") or 0)
    file_path = str(location.get("file_path") or "")
    source = _read_source(source_root, file_path, start, end)
    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            document = agent.analyze_function(
                str(api["qualified_name"]),
                api_id=api_id,
                abi_symbol=str(api["abi_symbol"]),
                display_name=str(api["display_name"]),
                file_hint=file_path,
                signature_hint=str(api["signature"]),
                header_file=str(api["include"]),
                comment="",
                source=source,
                start_line=start,
                end_line=end,
                character=int(location.get("character") or 1),
                attempt=attempt,
            )
            if document is None:
                raise RuntimeError("LspDocAgent returned no document")
            document = _validate_document(document, api_id, completed)
            store.write_json(artifact_path, document)
            _materialize(local_path, document)
            return api_id, True
        except Exception as exc:
            last_error = exc
            if attempt < max_attempts:
                time.sleep(min(2 ** (attempt - 1), 8))
    logger.error("LspDocAgent failed for {}: {}", api_id, last_error)
    return api_id, False


def generate_all_lsp(
    library: str,
    artifact_store: RunArtifactStore,
    artifact_index: Mapping[str, str],
    *,
    concurrency: int,
) -> Dict[str, int]:
    """Generate or restore every API document using ABI ids as all join keys."""
    if concurrency <= 0:
        raise ValueError("concurrency must be positive")
    info = Path("info_lib") / library
    apis = _load_public_apis(info / "api" / "public_api.json")
    if set(artifact_index) != set(apis):
        raise ValueError("API document index does not match public API identities")
    locations = _load_locations(info / "raw" / "csv" / "function_locations.csv")
    source_root = Path("test_lib") / library
    docs_dir = info / "api" / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    thread_local = threading.local()
    agents: list[LspDocAgent] = []
    agents_lock = threading.Lock()

    def agent() -> LspDocAgent:
        current = getattr(thread_local, "agent", None)
        if current is None:
            current = LspDocAgent(library)
            thread_local.agent = current
            with agents_lock:
                agents.append(current)
        return current

    reused = sum(
        artifact_store.safe_path(path).is_file() for path in artifact_index.values()
    )

    def task(api_id: str) -> Tuple[str, bool]:
        api = apis[api_id]
        return _process_one(
            api,
            locations.get(str(api["abi_symbol"]), {}),
            source_root,
            docs_dir,
            agent(),
            artifact_store,
            artifact_index[api_id],
        )

    failures = []
    try:
        with ThreadPoolExecutor(
            max_workers=max(1, min(concurrency, len(apis)))
        ) as pool:
            futures = [pool.submit(task, api_id) for api_id in sorted(apis)]
            with tqdm(
                total=len(futures),
                desc="Generating docs (LSP)",
                unit="api",
                dynamic_ncols=True,
                leave=True,
            ) as progress:
                for future in as_completed(futures):
                    api_id, success = future.result()
                    if not success:
                        failures.append(api_id)
                    progress.update()
    finally:
        for current in agents:
            current.close()
    if failures:
        raise RuntimeError(
            f"LspDocAgent failed for {len(failures)} API(s): "
            + ", ".join(sorted(failures))
        )
    return {"total": len(apis), "generated": len(apis) - reused, "reused": reused}
