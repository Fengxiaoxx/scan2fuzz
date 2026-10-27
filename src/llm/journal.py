"""Lossless, atomic JSONL records for application-submitted agent turns."""

import fcntl
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def append_record(path: Path, record: dict, *, unique_key: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f"journal must not be a symlink: {path}")
    payload = (json.dumps({"recorded_at": datetime.now(timezone.utc).isoformat(), **record},
                          ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    # Lock the directory inode: replacement is atomic and process death releases
    # the lock without leaving a stale lock file that blocks a resumed run.
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    temporary = None
    try:
        fcntl.flock(directory, fcntl.LOCK_EX)
        if unique_key and record.get(unique_key) and path.is_file():
            with path.open(encoding="utf-8") as existing:
                for line in existing:
                    previous = json.loads(line)
                    if previous.get(unique_key) == record[unique_key]:
                        if {k: v for k, v in previous.items() if k != "recorded_at"} != {
                            k: v for k, v in record.items() if k != "recorded_at"
                        }:
                            raise ValueError(f"conflicting journal record: {record[unique_key]}")
                        return
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        with os.fdopen(descriptor, "wb") as destination:
            if path.exists():
                with path.open("rb") as source:
                    if source.seek(0, os.SEEK_END):
                        source.seek(-1, os.SEEK_END)
                        if source.read(1) != b"\n":
                            raise ValueError(f"incomplete journal: {path}")
                    source.seek(0)
                    shutil.copyfileobj(source, destination)
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
        os.fsync(directory)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
        os.close(directory)
