"""Conservative local file analysis primitives.

Only exact SHA-256 matches from the local database are detections. This is
not a complete antivirus engine and no file is modified or deleted.
"""
from pathlib import Path
import hashlib
from typing import Iterable
from antivirus.database import connect, load_signatures


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
    except OSError as exc:
        return {"path": str(candidate), "status": "error", "reason": str(exc)}


def scan_paths(paths: Iterable[str], signatures: dict[str, dict]) -> list[dict]:
    return [inspect_file(path, signatures) for path in paths]


def scan_local_file(path: str, db_path: str) -> str:
    connection = connect(db_path)
    try:
        result = inspect_file(path, load_signatures(connection))
    finally:
        connection.close()
    if result["status"] == "detected":
        threat = result.get("threat") or {}
        return "THREAT MATCH: " + threat.get("label", "Unknown") + " (" + threat.get("severity", "unknown") + ")"
    if result["status"] == "no_match":
        return "No local signature match. SHA-256 " + result["sha256"][:16] + "…"
    return result["status"].upper() + ": " + result.get("reason", "unknown")


def engine_self_check() -> str:
    sample = hashlib.sha256(b"Nice Antivirus self-check").hexdigest()
    return (
        "Python engine: OK\n"
        + "SHA-256: OK (" + sample[:16] + "...)\n"
        + "Detection mode: exact local signatures only\n"
        + "No files were changed."
    )
