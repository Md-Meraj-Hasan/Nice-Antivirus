"""APK metadata analysis helpers.

Android PackageManager should provide installed-app metadata in production.
This module only provides safe filename/container checks for user-selected APKs.
"""
from pathlib import Path
import zipfile


def inspect_apk_container(path: str) -> dict:
    candidate = Path(path)
    if candidate.suffix.lower() != ".apk":
        return {"status": "not_apk", "path": str(candidate)}
    try:
        with zipfile.ZipFile(candidate) as archive:
            names = set(archive.namelist())
            has_manifest = "AndroidManifest.xml" in names
            has_dex = any(name.endswith(".dex") for name in names)
            return {
                "status": "valid_container" if has_manifest and has_dex else "review",
                "has_manifest": has_manifest,
                "has_dex": has_dex,
                "entry_count": len(names),
                "note": "Container structure only; this is not malware verdicting.",
            }
    except (OSError, zipfile.BadZipFile) as exc:
        return {"status": "invalid_or_unreadable", "reason": str(exc)}
