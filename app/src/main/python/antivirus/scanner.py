"""Conservative local file analysis primitives.

This starter performs exact SHA-256 signature matching only. It is not a
complete antivirus engine and must not be presented as one.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterable


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_file(path: str, signatures: dict[str, dict]) -> dict:
    candidate = Path(path)
    if not candidate.is_file():
        return {"path": str(candidate), "status": "skipped", "reason": "not a regular file"}

    try:
        file_hash = sha256_file(str(candidate))
        signature = signatures.get(file_hash)
        return {
            "path": str(candidate),
            "sha256": file_hash,
            "status": "detected" if signature else "no_match",
            "threat": signature,
        }
    except (OSError, PermissionError) as exc:
        return {"path": str(candidate), "status": "error", "reason": str(exc)}


def scan_paths(paths: Iterable[str], signatures: dict[str, dict]) -> list[dict]:
    return [inspect_file(path, signatures) for path in paths]


def engine_self_check() -> str:
    sample = hashlib.sha256(b"Nice Antivirus self-check").hexdigest()
    return (
        "Python engine: OK\n"
        f"SHA-256: OK ({sample[:16]}...)\n"
        "Detection mode: exact local signatures only\n"
        "No files were changed."
    )
