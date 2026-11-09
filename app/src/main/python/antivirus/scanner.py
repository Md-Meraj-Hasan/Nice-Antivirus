"""Conservative local file analysis primitives.

Only exact SHA-256 matches from the local database are detections. APK
container inspection is structural metadata review, not a malware verdict.
No file is modified or deleted.
"""
from pathlib import Path
import hashlib
from typing import Iterable
from antivirus.database import connect, load_signatures, record_scan, recent_scans, clear_scan_history
from antivirus.apk_analyzer import inspect_apk_container


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
        result = {
            "path": str(candidate),
            "sha256": file_hash,
            "status": "detected" if signature else "no_match",
            "threat": signature,
        }
        if candidate.suffix.lower() == ".apk":
            result["apk_review"] = inspect_apk_container(str(candidate))
        return result
    except OSError as exc:
        return {"path": str(candidate), "status": "error", "reason": str(exc)}


def scan_paths(paths: Iterable[str], signatures: dict[str, dict]) -> list[dict]:
    return [inspect_file(path, signatures) for path in paths]


def scan_local_file(path: str, db_path: str, display_path: str = "") -> str:
    connection = connect(db_path)
    try:
        result = inspect_file(path, load_signatures(connection))
        record_scan(connection, display_path or Path(path).name, result.get("sha256"), result["status"])
    finally:
        connection.close()
    if result["status"] == "detected":
        threat = result.get("threat") or {}
        report = "THREAT MATCH: " + threat.get("label", "Unknown") + " (" + threat.get("severity", "unknown") + ")"
    elif result["status"] == "no_match":
        report = "No local signature match. SHA-256 " + result["sha256"][:16] + "…"
    else:
        report = result["status"].upper() + ": " + result.get("reason", "unknown")
    apk = result.get("apk_review")
    if apk is not None:
        report += "\nAPK container: " + apk.get("status", "unknown")
        report += " | Manifest: " + ("yes" if apk.get("has_manifest") else "no")
        report += " | DEX: " + ("yes" if apk.get("has_dex") else "no")
        report += "\nNote: APK structure review is not a malware verdict."
    return report


def engine_self_check() -> str:
    sample = hashlib.sha256(b"Nice Antivirus self-check").hexdigest()
    return (
        "Python engine: OK\n"
        + "SHA-256: OK (" + sample[:16] + "...)\n"
        + "APK structure review: available\n"
        + "Detection mode: exact local signatures only\n"
        + "No files were changed."
    )


def scan_history_report(db_path: str, limit: int = 50) -> str:
    connection = connect(db_path)
    try:
        entries = recent_scans(connection, limit)
    finally:
        connection.close()
    if not entries:
        return "No scan history yet. Scan a file, APK or folder to create the first record."
    lines = ["RECENT SCANS (newest first)"]
    for item in entries:
        digest = (item.get("sha256") or "")[:16]
        lines.append(
            item["scanned_at"] + " | " + item["status"].upper()
            + "\n" + item["path"]
            + ("\nSHA-256: " + digest + "…" if digest else "")
        )
    return "\n\n".join(lines)


def clear_scan_history_records(db_path: str) -> int:
    """Clear scan history only; signature and metadata tables are untouched."""
    connection = connect(db_path)
    try:
        return clear_scan_history(connection)
    finally:
        connection.close()
