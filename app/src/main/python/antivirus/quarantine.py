"""Quarantine helpers are intentionally not wired to destructive actions yet.

Production quarantine should copy selected files into app-private storage,
record original URI/path and digest, verify copied bytes, and offer restore.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def fingerprint(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def quarantine_policy() -> dict:
    return {
        "enabled": False,
        "reason": "Storage Access Framework URI flow and restore UI must be implemented first.",
        "safety": "No file is deleted or moved by this starter.",
    }
