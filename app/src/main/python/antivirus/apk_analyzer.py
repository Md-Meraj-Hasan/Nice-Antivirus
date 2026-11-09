"""Read-only APK ZIP container inspection; does not execute APK code."""
from pathlib import Path
import zipfile


def inspect_apk_container(path: str) -> dict:
    candidate = Path(path)
    if candidate.suffix.lower() != ".apk":
        return {"status": "not_apk"}
    try:
        with zipfile.ZipFile(candidate) as archive:
            names = set(archive.namelist())
            has_manifest = "AndroidManifest.xml" in names
            has_dex = any(name.endswith(".dex") for name in names)
            has_native_libs = any(name.startswith("lib/") and name.endswith(".so") for name in names)
            return {
                "status": "valid_container" if has_manifest and has_dex else "review",
                "has_manifest": has_manifest,
                "has_dex": has_dex,
                "has_native_libs": has_native_libs,
                "entry_count": len(names),
                "note": "Container structure only; not a malware verdict.",
            }
    except (OSError, zipfile.BadZipFile):
        return {"status": "invalid_or_unreadable"}
