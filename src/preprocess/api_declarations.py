"""Write driver-facing declarations from the frozen installed public API."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict

from loguru import logger

def build_public_api_declarations(
    library_name: str,
    public_api_path: Path,
) -> Dict[str, object]:
    """Build driver-facing declarations from the frozen installed interface."""
    data = json.loads(public_api_path.read_text(encoding="utf-8"))
    apis = data.get("apis") if isinstance(data, dict) else None
    if not isinstance(apis, list) or not apis:
        raise ValueError(f"public API artifact contains no APIs: {public_api_path}")

    rows = []
    identities = set()
    for api in apis:
        if not isinstance(api, dict):
            raise ValueError("public API entries must be objects")
        api_id = api.get("api_id")
        abi_symbol = api.get("abi_symbol")
        display_name = api.get("display_name")
        qualified_name = api.get("qualified_name")
        header = api.get("include")
        signature = api.get("signature")
        if not all(
            isinstance(value, str) and value
            for value in (
                api_id,
                abi_symbol,
                display_name,
                qualified_name,
                header,
                signature,
            )
        ):
            raise ValueError(f"incomplete public API declaration: {api!r}")
        if api_id in identities:
            raise ValueError(f"duplicate public API identity: {api_id}")
        identities.add(api_id)
        rows.append(
            {
                "api_id": api_id,
                "abi_symbol": abi_symbol,
                "display_name": display_name,
                "qualified_name": qualified_name,
                "header_file": header,
                "signature": signature,
            }
        )

    out_p = Path("info_lib") / library_name / "raw" / "csv" / "api_declarations.csv"
    out_p.parent.mkdir(parents=True, exist_ok=True)
    with out_p.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "api_id",
                "abi_symbol",
                "display_name",
                "qualified_name",
                "header_file",
                "signature",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)
    logger.success(f"api_declarations: {len(rows)} public APIs -> {out_p}")
    return {"output": str(out_p), "api_count": len(rows), "with_header": len(rows)}
