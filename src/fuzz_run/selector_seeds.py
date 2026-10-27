"""Create selector-only AFL++ corpora for merged fuzz drivers.

This file is also a standalone script so the same seed protocol can be used in
PromeFuzz and PromptFuzz containers without importing Trace2Fuzz packages.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re


_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]", re.ASCII)
_CASE = re.compile(
    r"\bcase\s+(\d+)\s*:\s*return\s+LLVMFuzzerTestOneInput_([A-Za-z0-9_]+)\s*\("
)


def driver_ids_from_entry(entry: Path, method: str) -> tuple[str, ...]:
    """Read the actual merged dispatcher instead of trusting a manual count."""
    source = entry.read_text(encoding="utf-8")
    cases = [(int(index), name) for index, name in _CASE.findall(source)]
    if not cases or [index for index, _ in cases] != list(range(len(cases))):
        raise ValueError(f"merged entry has missing or unordered driver cases: {entry}")
    if method == "promefuzz":
        modulus = re.search(r"switch\s*\(\s*driverIndex\s*%\s*(\d+)\s*\)", source)
        width = re.search(
            r"memcpy\s*\(\s*&driverIndex\s*,\s*selector\s*,\s*(\d+)\s*\)", source,
        )
        if (modulus is None or int(modulus.group(1)) != len(cases)
                or width is None or int(width.group(1)) not in {1, 2}
                or len(cases) > 1 << (8 * int(width.group(1)))):
            raise ValueError(f"unsupported PromeFuzz selector in {entry}")
    elif method == "promptfuzz":
        if "FDPConsumeIntegral(uint16_t, switch_id, fdp)" not in source:
            raise ValueError(f"unsupported PromptFuzz selector in {entry}")
    elif method == "trace2fuzz":
        modulus = re.search(r"switch\s*\(\s*data\[0\]\s*%\s*(\d+)\s*\)", source)
        if modulus is None or int(modulus.group(1)) != len(cases):
            raise ValueError(f"unsupported Trace2Fuzz selector in {entry}")
    else:
        raise ValueError(f"unknown method: {method}")
    return tuple(name for _, name in cases)


def selector_layout(entry: Path, method: str, driver_count: int) -> tuple[int, str]:
    """Return (selector width, byte order) for a merged entry's dispatcher."""
    if method == "promptfuzz":
        return 2, "big"
    if method == "trace2fuzz":
        return 1, "big"
    if method != "promefuzz":
        raise ValueError(f"unknown method: {method}")
    source = entry.read_text(encoding="utf-8")
    match = re.search(
        r"memcpy\s*\(\s*&driverIndex\s*,\s*selector\s*,\s*(\d+)\s*\)", source,
    )
    width = int(match.group(1)) if match else 1
    if width not in {1, 2}:
        raise ValueError(f"unsupported PromeFuzz selector width in {entry}")
    if driver_count > 1 << (8 * width):
        raise ValueError(f"driver count exceeds {width}-byte selector in {entry}")
    return width, "little" if width == 2 else "big"


def write_selector_seeds(
    corpus: Path, driver_ids: tuple[str, ...], *, selector_bytes: int, byteorder: str
) -> int:
    """Write exactly one selector and no payload for each driver."""
    if selector_bytes not in {1, 2} or byteorder not in {"big", "little"}:
        raise ValueError("unsupported selector format")
    if not 1 <= len(driver_ids) <= 1 << (selector_bytes * 8):
        raise ValueError("driver count exceeds selector capacity")
    if corpus.exists() and any(corpus.iterdir()):
        raise ValueError(f"seed directory is not empty: {corpus}")
    corpus.mkdir(parents=True, exist_ok=True)
    for index, driver_id in enumerate(driver_ids):
        safe_name = _SAFE_NAME.sub("_", driver_id)
        (corpus / f"selector_{index:05d}_{safe_name}").write_bytes(
            index.to_bytes(selector_bytes, byteorder)
        )
    return len(driver_ids)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--method", choices=("promefuzz", "promptfuzz", "trace2fuzz"), required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--count", type=int, help="number of cases in the merged dispatcher")
    source.add_argument("--entry", type=Path, help="read selector cases from the merged entry source")
    parser.add_argument("--output", type=Path, required=True, help="new or empty AFL++ input directory")
    args = parser.parse_args()
    driver_ids = (
        driver_ids_from_entry(args.entry, args.method)
        if args.entry else tuple(f"driver_{index}" for index in range(args.count))
    )
    if args.entry:
        selector_bytes, byteorder = selector_layout(
            args.entry, args.method, len(driver_ids),
        )
    else:
        selector_bytes = 2 if args.method == "promptfuzz" else 1
        byteorder = "big"
    count = write_selector_seeds(
        args.output,
        driver_ids,
        selector_bytes=selector_bytes,
        byteorder=byteorder,
    )
    print(f"{args.method}: wrote {count} selector-only seeds to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
