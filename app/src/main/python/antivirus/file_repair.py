"""Conservative, copy-only file diagnostics and repair helpers.

The engine never overwrites the input. Repairs are format-specific and only
performed when a safe structural operation is possible. Unknown formats are
reported as inspect-only rather than being modified blindly.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import zipfile
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_file(path: str) -> dict:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(str(source))
    size = source.stat().st_size
    suffix = source.suffix.lower()
    with source.open("rb") as stream:
        head = stream.read(32)
        stream.seek(max(0, size - 64))
        tail = stream.read(64)

    kind = "unknown"
    notes = []
    repairable = False
    if head.startswith(b"%PDF-"):
        kind = "PDF"
        repairable = True
        if b"%%EOF" not in tail:
            notes.append("PDF end marker is missing; a copy can be tested with a restored marker.")
    elif head.startswith(b"PK\\x03\\x04") or head.startswith(b"PK\\x05\\x06") or suffix in (".docx", ".xlsx", ".pptx", ".zip", ".apk"):
        kind = "ZIP-based container"
        repairable = True
        try:
            with zipfile.ZipFile(source, "r") as archive:
                bad = archive.testzip()
                if bad:
                    notes.append("CRC failure in entry: " + bad)
                else:
                    notes.append("ZIP directory and entry CRC checks passed.")
        except (OSError, zipfile.BadZipFile) as exc:
            notes.append("ZIP structure could not be fully read: " + str(exc))
    elif head.startswith(b"SQLite format 3\\x00") or suffix in (".sqlite", ".sqlite3", ".db"):
        kind = "SQLite database"
        repairable = True
        try:
            db = sqlite3.connect("file:" + str(source.resolve()) + "?mode=ro", uri=True)
            try:
                result = db.execute("PRAGMA quick_check").fetchone()
                notes.append("SQLite quick_check: " + str(result[0] if result else "no result"))
            finally:
                db.close()
        except sqlite3.DatabaseError as exc:
            notes.append("SQLite integrity check failed: " + str(exc))
    elif head.startswith(b"\\x89PNG\\r\\n\\x1a\\n"):
        kind = "PNG image"
        notes.append("PNG signature found. Full pixel recovery needs an image decoder.")
    elif head.startswith(b"\\xff\\xd8\\xff"):
        kind = "JPEG image"
        notes.append("JPEG signature found. Entropy-coded image data is not rewritten by this safe mode.")
    elif head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        kind = "WebP image"
    elif head.startswith(b"ID3") or (len(head) > 1 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0):
        kind = "MP3 audio"
    elif head.startswith(b"\\x00\\x00\\x00") and b"ftyp" in head:
        kind = "MP4/ISO media"
    elif suffix == ".csv":
        kind = "CSV text"
    elif suffix in (".json", ".xml", ".txt"):
        kind = suffix[1:].upper() + " text"
    return {
        "name": source.name,
        "path": str(source),
        "size": size,
        "sha256": _sha256(source),
        "type": kind,
        "repair_supported": repairable,
        "notes": notes,
    }


def repair_file(source_path: str, output_dir: str) -> dict:
    """Create a repaired/recovered copy only when a conservative operation exists."""
    source = Path(source_path)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    report = inspect_file(str(source))
    suffix = source.suffix.lower()
    target = output / (source.stem + "_repaired" + (suffix or ".recovered"))
    action = "inspect_only"
    details = []

    if report["type"] == "PDF":
        data = source.read_bytes()
        if b"%%EOF" not in data[-2048:]:
            # A missing terminal marker can be repaired safely as a copy, but
            # this does not reconstruct missing page objects or xref tables.
            with target.open("wb") as stream:
                stream.write(data)
                if not data.endswith(b"\\n"):
                    stream.write(b"\\n")
                stream.write(b"%%EOF\\n")
            action = "terminal_marker_restored"
            details.append("Added a missing terminal EOF marker only; page contents were not reconstructed.")
        else:
            details.append("PDF already has a terminal EOF marker; no rewrite needed.")
    elif report["type"] == "ZIP-based container":
        try:
            with zipfile.ZipFile(source, "r") as archive:
                bad = archive.testzip()
                if bad is None:
                    details.append("Archive passed CRC validation; no repair needed.")
                else:
                    # Recover intact entries into a fresh archive, skipping the
                    # first corrupt member. Never claim the omitted data recovered.
                    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as rebuilt:
                        for info in archive.infolist():
                            try:
                                payload = archive.read(info.filename)
                                rebuilt.writestr(info, payload)
                            except (OSError, RuntimeError, zipfile.BadZipFile):
                                details.append("Skipped unreadable entry: " + info.filename)
                    action = "intact_entries_repacked"
        except (OSError, zipfile.BadZipFile) as exc:
            details.append("Central directory is unreadable; safe entry recovery unavailable: " + str(exc))
    elif report["type"] == "SQLite database":
        try:
            src = sqlite3.connect("file:" + str(source.resolve()) + "?mode=ro", uri=True)
            try:
                check = src.execute("PRAGMA quick_check").fetchone()
                if check and check[0] == "ok":
                    dst = sqlite3.connect(str(target))
                    try:
                        src.backup(dst)
                    finally:
                        dst.close()
                    action = "sqlite_backup_copy"
                    details.append("Database passed quick_check and a verified SQLite backup copy was created.")
                else:
                    details.append("SQLite quick_check reported corruption; automatic recovery was not attempted.")
            finally:
                src.close()
        except sqlite3.DatabaseError as exc:
            details.append("SQLite recovery unavailable: " + str(exc))
    else:
        details.append("This format is currently inspect-only. Original file was not changed.")

    if target.exists():
        report["output_path"] = str(target)
        report["output_size"] = target.stat().st_size
        report["output_sha256"] = _sha256(target)
    report["action"] = action
    report["details"] = details
    report["success"] = target.exists() and target.stat().st_size > 0
    return report


def inspect_json(path: str) -> str:
    return json.dumps(inspect_file(path), ensure_ascii=False)


def repair_json(source_path: str, output_dir: str) -> str:
    return json.dumps(repair_file(source_path, output_dir), ensure_ascii=False)
