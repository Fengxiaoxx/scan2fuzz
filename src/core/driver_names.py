"""Stable driver identifiers and run-scoped canonical identity lookup."""
import hashlib
import re
from pathlib import Path
from typing import Optional, Tuple


_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9._-]+", re.ASCII)
_HEADER_ID = re.compile(r"header:[0-9a-f]{20}", re.ASCII)


def _identity_symbol(api_id: str) -> str:
    if api_id.startswith("abi:") and len(api_id) > 4:
        return api_id[4:]
    if _HEADER_ID.fullmatch(api_id):
        return api_id[len("header:"):]
    raise ValueError(f"invalid API identity: {api_id!r}")


def make_driver_id(api_id: str, marker: str, display_name: str | None = None) -> str:
    """Build a stable driver id from an exported or frozen header identity."""
    if not _SAFE_COMPONENT.fullmatch(marker):
        raise ValueError(f"unsafe target marker: {marker!r}")
    symbol = _identity_symbol(api_id)
    if display_name == symbol and _SAFE_COMPONENT.fullmatch(symbol):
        component = symbol
    else:
        label = display_name or symbol
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", label, flags=re.ASCII).strip("._-")
        slug = slug or "api"
        digest = hashlib.sha256(api_id.encode("utf-8")).hexdigest()[:12]
        component = f"{slug[:64]}-{digest}"
    return f"{component}__{marker}"


def resolve_driver_identity(
    library: str,
    name: str,
) -> Tuple[str, Optional[str]]:
    """Resolve ``(api_id, marker)`` from an immutable per-driver record."""
    from src.core.file_utils import get_project_root
    from src.experiment import RunArtifactStore

    store = RunArtifactStore.from_environment(get_project_root(), library)
    path = Path(name)
    for candidate in [path.stem, *reversed(path.parts)]:
        if not _SAFE_COMPONENT.fullmatch(candidate):
            continue
        result_path = store.stage_result_path("driver_generation", candidate)
        if not result_path.is_file():
            continue
        record = store.read_json(result_path)
        if not isinstance(record, dict) or record.get("driver_id") != candidate:
            raise ValueError(f"invalid driver identity record: {result_path}")
        api_id = record.get("api_id")
        marker = record.get("marker")
        if not isinstance(api_id, str):
            raise ValueError(f"invalid API identity in {result_path}")
        try:
            _identity_symbol(api_id)
        except ValueError as exc:
            raise ValueError(f"invalid API identity in {result_path}") from exc
        if not isinstance(marker, str) or not _SAFE_COMPONENT.fullmatch(marker):
            raise ValueError(f"invalid target marker in {result_path}")
        return api_id, marker
    raise KeyError(f"source path contains no driver identity record: {name}")
