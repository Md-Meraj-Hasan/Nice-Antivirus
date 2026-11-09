"""Conservative local file analysis primitives.

Only exact SHA-256 matches from the local database are detections. APK
container inspection is structural metadata review, not a malware verdict.
No file is modified or deleted.
"""
from pathlib import Path
import hashlib
import json
from typing import Iterable
from antivirus.database import connect, load_signatures, record_scan, recent_scans, clear_scan_history
from antivirus.apk_analyzer import inspect_apk_container


_FILE_SIGNATURES = (
    (b"%PDF-", {".pdf"}, "PDF document"),
    (b"\x89PNG\r\n\x1a\n", {".png"}, "PNG image"),
    (b"\xff\xd8\xff", {".jpg", ".jpeg"}, "JPEG image"),
    (b"GIF87a", {".gif"}, "GIF image"),
    (b"GIF89a", {".gif"}, "GIF image"),
    (b"PK\x03\x04", {".zip", ".apk", ".docx", ".xlsx", ".pptx", ".jar"}, "ZIP-based archive"),
    (b"MZ", {".exe", ".dll"}, "Windows executable"),
    (b"\x7fELF", {".so", ".elf"}, "ELF executable"),
    (b"7z\xbc\xaf\x27\x1c", {".7z"}, "7-Zip archive"),
    (b"Rar!\x1a\x07", {".rar"}, "RAR archive"),
    (b"\x1f\x8b", {".gz"}, "GZIP archive"),
)


def inspect_file_type_mismatch(path: str) -> dict | None:
    """Compare a few well-known file headers with the filename extension.

    This is a manual-review hint only; it is not a malware verdict.
    """
    candidate = Path(path)
    try:
        with candidate.open("rb") as stream:
            header = stream.read(16)
    except OSError:
        return None
    if not header:
        return None
    for magic, allowed_extensions, detected_type in _FILE_SIGNATURES:
        if header.startswith(magic):
            extension = candidate.suffix.lower()
            if extension and extension not in allowed_extensions:
                return {
                    "status": "review",
                    "code": "file_extension_mismatch",
                    "detail": "File header looks like " + detected_type
                    + " but filename extension is " + extension + ".",
                    "detected_type": detected_type,
                    "extension": extension,
                    "note": "Filename and header mismatch is not proof of malware.",
                }
            return None
    return None


def inspect_archive_safety(path: str) -> dict | None:
    """Inspect ZIP metadata without extracting or executing archive contents."""
    candidate = Path(path)
    if candidate.suffix.lower() not in {".zip", ".jar", ".docx", ".xlsx", ".pptx"}:
        return None
    import stat
    import zipfile
    from collections import Counter

    try:
        with zipfile.ZipFile(candidate) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            indicators = []
            duplicates = [name for name, count in Counter(names).items() if count > 1]
            if duplicates:
                indicators.append({"code": "duplicate_entries", "count": len(duplicates),
                                   "detail": "Archive contains duplicate entry names."})
            if len(entries) > 10000:
                indicators.append({"code": "excessive_entry_count", "count": len(entries),
                                   "detail": "Archive contains more than 10,000 entries."})
            traversal = [
                name for name in names
                if name.startswith("/") or name.startswith(chr(92))
                or any(part == ".." for part in name.replace(chr(92), "/").split("/"))
            ]
            if traversal:
                indicators.append({"code": "path_traversal_names", "count": len(traversal),
                                   "detail": "Archive contains entries with absolute or parent-traversal paths."})
            encrypted = [entry for entry in entries if entry.flag_bits & 0x1]
            if encrypted:
                indicators.append({"code": "encrypted_entries", "count": len(encrypted),
                                   "detail": "Some archive entries are encrypted and cannot be inspected without a password."})
            symlinks = [
                entry.filename for entry in entries
                if stat.S_ISLNK((entry.external_attr >> 16) & 0xFFFF)
            ]
            if symlinks:
                indicators.append({"code": "symbolic_links", "count": len(symlinks),
                                   "detail": "Archive contains symbolic-link entries."})
            high_ratio = [
                entry for entry in entries
                if entry.file_size >= 10 * 1024 * 1024
                and entry.compress_size > 0
                and entry.file_size / entry.compress_size >= 1000
            ]
            if high_ratio:
                indicators.append({"code": "extreme_compression_ratio", "count": len(high_ratio),
                                   "detail": "Large entries have an extreme compression ratio."})
            return {
                "status": "review" if indicators else "no_structural_flags",
                "entry_count": len(entries),
                "review_indicators": indicators,
                "note": "ZIP metadata only; no extraction or execution. Indicators are not a malware verdict.",
            }
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return {"status": "invalid_or_unreadable", "review_indicators": [],
                "note": "Archive metadata could not be read; this is not a malware verdict."}


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
        type_review = inspect_file_type_mismatch(str(candidate))
        if type_review is not None:
            result["file_type_review"] = type_review
        if candidate.suffix.lower() == ".apk":
            result["apk_review"] = inspect_apk_container(str(candidate))
        else:
            archive_review = inspect_archive_safety(str(candidate))
            if archive_review is not None:
                result["archive_review"] = archive_review
        return result
    except OSError as exc:
        return {"path": str(candidate), "status": "error", "reason": str(exc)}


def scan_paths(paths: Iterable[str], signatures: dict[str, dict]) -> list[dict]:
    return [inspect_file(path, signatures) for path in paths]


def scan_local_file(path: str, db_path: str, display_path: str = "") -> str:
    connection = connect(db_path)
    try:
        result = inspect_file(path, load_signatures(connection))
        review_items = []
        for key, label in (
            ("file_type_review", "File type"),
            ("archive_review", "Archive"),
            ("apk_review", "APK structure"),
        ):
            review = result.get(key)
            if not isinstance(review, dict):
                continue
            indicators = review.get("review_indicators") or []
            if review.get("status") not in {"review", "invalid_or_unreadable"} and not indicators:
                continue
            review_items.append({
                "category": label,
                "status": review.get("status", "review"),
                "indicators": [
                    {"code": item.get("code", "review"), "detail": item.get("detail", "")}
                    for item in indicators if isinstance(item, dict)
                ],
                "detail": review.get("detail", ""),
            })
        review_summary = json.dumps(review_items, ensure_ascii=False, separators=(",", ":")) if review_items else ""
        record_scan(
            connection, display_path or Path(path).name, result.get("sha256"),
            result["status"], review_summary,
        )
    finally:
        connection.close()
    if result["status"] == "detected":
        threat = result.get("threat") or {}
        report = "THREAT MATCH: " + threat.get("label", "Unknown") + " (" + threat.get("severity", "unknown") + ")"
    elif result["status"] == "no_match":
        report = "No local signature match. SHA-256 " + result["sha256"][:16] + "…"
    else:
        report = result["status"].upper() + ": " + result.get("reason", "unknown")
    type_review = result.get("file_type_review")
    if type_review is not None:
        report += "\nFILE TYPE REVIEW: " + type_review["detail"]
        report += "\nNote: this mismatch is not a malware verdict."
    archive = result.get("archive_review")
    if archive is not None:
        report += "\\nARCHIVE REVIEW: " + archive.get("status", "unknown")
        for indicator in archive.get("review_indicators", []):
            report += "\\n- " + indicator["detail"]
        report += "\\nNote: archive metadata review is not a malware verdict."
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
        if item.get("review_summary"):
            try:
                reviews = json.loads(item["review_summary"])
            except (TypeError, ValueError):
                reviews = []
            for review in reviews:
                lines.append(
                    "MANUAL REVIEW: " + str(review.get("category", "File review"))
                    + " (" + str(review.get("status", "review")) + ")"
                )
                if review.get("detail"):
                    lines.append(str(review["detail"]))
                for indicator in review.get("indicators", []):
                    if indicator.get("detail"):
                        lines.append("- " + str(indicator["detail"]))
                lines.append("Review indicators are not a malware verdict.")
    return "\n\n".join(lines)


def clear_scan_history_records(db_path: str) -> int:
    """Clear scan history only; signature and metadata tables are untouched."""
    connection = connect(db_path)
    try:
        return clear_scan_history(connection)
    finally:
        connection.close()
