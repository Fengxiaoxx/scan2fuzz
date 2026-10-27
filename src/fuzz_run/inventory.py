"""Select reached drivers from a run result."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from src.experiment.store import artifact_driver_id


_DRIVER_ID = re.compile(r"[A-Za-z0-9._-]+", re.ASCII)


def _driver_id(value: Any) -> str:
    if not isinstance(value, str) or not _DRIVER_ID.fullmatch(value):
        raise ValueError("invalid fuzz driver ID")
    if value in {".", ".."}:
        raise ValueError("invalid fuzz driver ID")
    return value


@dataclass(frozen=True)
class FuzzableDriver:
    run_id: str
    run_dir: Path
    marker: str
    target_id: str
    driver_id: str
    source_path: Path
    attempt_path: Path
    hit_count: int
    state: str


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _target_records(run_dir: Path, library: str, run_id: str) -> list[dict[str, Any]]:
    """Load automatic results, journals, or a manual adjudication."""
    automatic = run_dir / "stages" / "driver_rounds" / "result.json"
    if automatic.is_file():
        result = _read_object(automatic)
        targets = result.get("targets")
        if not isinstance(targets, list):
            raise ValueError("driver_rounds result has no target list")
        return targets

    manifest_path = run_dir / "stages" / "driver_rounds" / "state-manifest.json"
    if manifest_path.is_file():
        manifest = _read_object(manifest_path)
        entries = manifest.get("targets")
        if (
            manifest.get("schema_version") != 1
            or manifest.get("library") != library
            or not isinstance(entries, list)
        ):
            raise ValueError(f"invalid driver-round state manifest: {manifest_path}")
        targets = []
        for entry in entries:
            marker = entry.get("marker") if isinstance(entry, dict) else None
            if not isinstance(marker, str):
                raise ValueError(f"invalid target entry in {manifest_path}")
            events = sorted(
                (manifest_path.parent / "targets" / marker / "events").glob(
                    "event-*.json"
                )
            )
            if not events:
                raise ValueError(f"target has no state journal: {marker}")
            event = _read_object(events[-1])
            target = event.get("target_state")
            if not isinstance(target, dict) or target.get("marker") != marker:
                raise ValueError(f"invalid final state journal: {events[-1]}")
            targets.append(target)
        return targets

    manual_path = run_dir / "stages" / "manual_adjudication" / "result.json"
    manual = _read_object(manual_path)
    if (
        manual.get("schema_version") != 1
        or manual.get("library") != library
        or manual.get("run_id") != run_id
        or manual.get("provenance") != "manual_coverage_adjudication"
    ):
        raise ValueError(f"invalid manual adjudication: {manual_path}")
    targets = manual.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("manual adjudication has no target list")
    for target in targets:
        evidence = target.get("manual_evidence") if isinstance(target, dict) else None
        reach = target.get("reach_feedback") if isinstance(target, dict) else None
        if (
            not isinstance(evidence, dict)
            or evidence.get("kind") != "independent_llvm_coverage"
            or not isinstance(reach, dict)
            or evidence.get("coverage_target_hits") != reach.get("hit")
            or evidence.get("sanitizer_smoke_status") != "passed"
        ):
            raise ValueError("manual REACHED target has incomplete evidence")
    return targets


def _resolve_run_path(project_root: Path, run_dir: Path, raw: Any) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ValueError("fuzz target is missing an artifact path")
    supplied = PurePosixPath(raw)
    anchor = PurePosixPath(run_dir.relative_to(project_root).as_posix())
    parts = supplied.parts
    anchor_parts = anchor.parts
    start = next(
        (
            index
            for index in range(len(parts) - len(anchor_parts) + 1)
            if parts[index : index + len(anchor_parts)] == anchor_parts
        ),
        None,
    )
    if start is None:
        candidate = run_dir / raw if not supplied.is_absolute() else Path(raw)
    else:
        candidate = project_root.joinpath(*parts[start:])
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(run_dir)
    except ValueError as exc:
        raise ValueError(f"run artifact path escapes the selected run: {raw}") from exc
    return resolved


def load_fuzzable_drivers(
    project_root: Path,
    library: str,
    run_id: str,
) -> tuple[Path, tuple[FuzzableDriver, ...]]:
    """Return a deterministic inventory backed by a completed run result."""
    root = project_root.resolve(strict=True)
    run_dir = (root / "workspace" / library / "runs" / run_id).resolve(strict=True)
    run_manifest = _read_object(run_dir / "run.json")
    if run_manifest.get("library") != library or run_manifest.get("run_id") != run_id:
        raise ValueError("run.json does not match requested library and run ID")

    targets = _target_records(run_dir, library, run_id)

    fuzzable: list[FuzzableDriver] = []
    for target in targets:
        if (
            not isinstance(target, dict)
            or target.get("state") != "REACHED"
        ):
            continue
        driver_id = _driver_id(target.get("selected_driver_id"))
        source_raw = target.get("stable_source_path") or target.get("source_path")
        reach = target.get("reach_feedback")
        source_path = _resolve_run_path(root, run_dir, source_raw)
        if not isinstance(reach, dict):
            raise ValueError(f"{target.get('marker')} has no reach evidence")
        hit_count = reach.get("hit")
        if (
            isinstance(hit_count, bool)
            or not isinstance(hit_count, int)
            or hit_count <= 0
        ):
            raise ValueError(f"{target.get('marker')} has no positive hit count")
        attempt_path = _resolve_run_path(root, run_dir, reach.get("attempt_dir"))
        if any(artifact_driver_id(run_dir, path) != driver_id
               for path in (source_path, attempt_path)):
            raise ValueError(f"{target.get('marker')} artifacts do not match {driver_id}")
        if not source_path.is_file() or not attempt_path.is_dir():
            raise ValueError(f"incomplete fuzz artifacts for {driver_id}")
        fuzzable.append(
            FuzzableDriver(
                run_id=run_id,
                run_dir=run_dir,
                marker=str(target.get("marker")),
                target_id=str(target.get("target_id")),
                driver_id=driver_id,
                source_path=source_path,
                attempt_path=attempt_path,
                hit_count=hit_count,
                state="REACHED",
            )
        )

    fuzzable.sort(key=lambda item: item.marker)
    if not fuzzable:
        raise ValueError(f"run has no REACHED targets: {library}/{run_id}")
    driver_ids = [item.driver_id for item in fuzzable]
    if len(driver_ids) != len(set(driver_ids)):
        raise ValueError("multiple fuzzable targets selected the same driver ID")
    return run_dir, tuple(fuzzable)
