"""Safe cleanup candidate analysis. Never deletes files automatically."""
from __future__ import annotations

from pathlib import Path


def find_cleanup_candidates(paths: list[str]) -> list[dict]:
    findings = []
    for raw in paths:
        path = Path(raw)
        try:
            if path.is_file() and path.stat().st_size == 0:
                findings.append({
                    "path": str(path),
                    "reason": "empty file candidate",
                    "action": "review_before_delete",
                })
            elif path.is_dir() and not any(path.iterdir()):
                findings.append({
                    "path": str(path),
                    "reason": "empty directory candidate",
                    "action": "review_before_delete",
                })
        except OSError:
            continue
    return findings


def is_bin_file_safe_to_consider(path: str) -> bool:
    """A .bin extension alone is never grounds for deletion."""
    return Path(path).suffix.lower() == ".bin"
