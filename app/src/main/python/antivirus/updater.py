"""HTTPS signature manifest downloader and validator.

For production, configure a publisher public key and verify a detached
signature (for example Ed25519) before importing the manifest. The initial
scaffold deliberately refuses HTTP and validates all fields.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.request

HASH_RE = re.compile(r"^[a-fA-F0-9]{64}$")
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}


def download_manifest(url: str, timeout: int = 20) -> dict:
    if not url.lower().startswith("https://"):
        raise ValueError("Signature updates require HTTPS.")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "NiceAntivirus/0.1", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError(f"Update server returned HTTP {response.status}")
        data = response.read(5 * 1024 * 1024 + 1)
    if len(data) > 5 * 1024 * 1024:
        raise ValueError("Manifest is larger than 5 MiB.")
    return validate_manifest(json.loads(data.decode("utf-8")))


def validate_manifest(manifest: dict) -> dict:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("Unsupported manifest schema.")
    version = manifest.get("version")
    entries = manifest.get("signatures")
    if not isinstance(version, int) or version < 1:
        raise ValueError("Invalid database version.")
    if not isinstance(entries, list) or len(entries) > 100000:
        raise ValueError("Invalid signature list.")
    validated = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Invalid signature entry.")
        digest = entry.get("sha256", "").lower()
        label = entry.get("label")
        severity = entry.get("severity")
        description = entry.get("description", "")
        if not HASH_RE.fullmatch(digest) or digest in seen:
            raise ValueError("Invalid or duplicate SHA-256 signature.")
        if not isinstance(label, str) or not label.strip() or len(label) > 160:
            raise ValueError("Invalid signature label.")
        if severity not in ALLOWED_SEVERITIES:
            raise ValueError("Invalid severity.")
        if not isinstance(description, str) or len(description) > 1000:
            raise ValueError("Invalid description.")
        seen.add(digest)
        validated.append({
            "sha256": digest,
            "label": label.strip(),
            "severity": severity,
            "description": description,
        })
    return {"schema_version": 1, "version": version, "signatures": validated}
