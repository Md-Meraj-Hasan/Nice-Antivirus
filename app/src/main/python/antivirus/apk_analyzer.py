"""Read-only APK ZIP inspection with conservative review indicators.

Indicators are triage hints only. They never establish that an APK is malware.
The analyzer does not execute or extract APK contents.
"""
from collections import Counter
from pathlib import Path
import zipfile


_EXECUTABLE_ASSET_SUFFIXES = {".dex", ".jar", ".so", ".sh", ".elf"}
_MAX_ENTRIES_REVIEW = 5000
_HIGH_RATIO_REVIEW = 1000
_MIN_COMPRESSED_SIZE = 10 * 1024 * 1024


def inspect_apk_container(path: str) -> dict:
    candidate = Path(path)
    if candidate.suffix.lower() != ".apk":
        return {"status": "not_apk"}
    try:
        with zipfile.ZipFile(candidate) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            name_set = set(names)
            has_manifest = "AndroidManifest.xml" in name_set
            dex_names = [name for name in names if name.endswith(".dex")]
            has_dex = bool(dex_names)
            has_native_libs = any(
                name.startswith("lib/") and name.endswith(".so") for name in names
            )
            indicators = []

            duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
            if duplicates:
                indicators.append({
                    "code": "duplicate_archive_entries",
                    "detail": "Archive contains duplicate entry names.",
                })

            if len(infos) > _MAX_ENTRIES_REVIEW:
                indicators.append({
                    "code": "unusually_many_entries",
                    "detail": "Archive contains more than 5000 entries.",
                })

            unusual_assets = [
                name for name in names
                if name.startswith("assets/")
                and Path(name).suffix.lower() in _EXECUTABLE_ASSET_SUFFIXES
            ]
            if unusual_assets:
                indicators.append({
                    "code": "executable_like_assets",
                    "detail": "Executable-like files are bundled under assets/.",
                    "count": len(unusual_assets),
                })

            unusual_dex = [name for name in dex_names if "/" in name]
            if unusual_dex:
                indicators.append({
                    "code": "dex_in_nested_path",
                    "detail": "DEX bytecode appears outside the archive root.",
                    "count": len(unusual_dex),
                })

            high_ratio = sum(
                1 for item in infos
                if item.file_size >= _MIN_COMPRESSED_SIZE
                and item.compress_size > 0
                and item.file_size / item.compress_size >= _HIGH_RATIO_REVIEW
            )
            if high_ratio:
                indicators.append({
                    "code": "extreme_compression_ratio",
                    "detail": "Large archive entries have an unusually high compression ratio.",
                    "count": high_ratio,
                })

            if not has_manifest or not has_dex:
                indicators.append({
                    "code": "incomplete_apk_structure",
                    "detail": "Expected Android manifest or DEX entry is missing.",
                })

            return {
                "status": "review" if indicators else "valid_container",
                "has_manifest": has_manifest,
                "has_dex": has_dex,
                "has_native_libs": has_native_libs,
                "entry_count": len(infos),
                "review_indicators": indicators,
                "risk_label": "manual_review" if indicators else "no_structural_flags",
                "note": "Static ZIP metadata only. Indicators are not a malware verdict.",
            }
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return {"status": "invalid_or_unreadable"}
