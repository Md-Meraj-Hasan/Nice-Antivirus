"""Authenticated HTTPS malware-signature updater.

The app intentionally ships with no publisher key or endpoint configured.
A maintainer must publish an RSA-2048+ public modulus and a signed manifest
before live updates can be enabled. The updater fails closed until then.
Signed envelope format:
{"manifest": {...}, "signature": "<base64 RSA PKCS#1 v1.5 SHA-256>"}
The signature covers canonical UTF-8 JSON of the manifest (sorted keys,
compact separators, ensure_ascii=False).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.request

HASH_RE = re.compile(r"^[a-fA-F0-9]{64}$")
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
MAX_MANIFEST_BYTES = 5 * 1024 * 1024
# Configure only after the publisher controls the private signing key.
UPDATE_MANIFEST_URL = ""
PUBLISHER_RSA_MODULUS_HEX = ""
PUBLISHER_RSA_EXPONENT = 65537


def _canonical_manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _verify_rsa_sha256(payload: bytes, signature: bytes, modulus_hex: str,
                       exponent: int = 65537) -> bool:
    """Verify RSASSA-PKCS1-v1_5/SHA-256 using only the Python stdlib."""
    if not modulus_hex or exponent < 3 or exponent % 2 == 0:
        return False
    try:
        modulus = int(modulus_hex, 16)
    except (TypeError, ValueError):
        return False
    size = (modulus.bit_length() + 7) // 8
    if modulus.bit_length() < 2048 or len(signature) != size:
        return False
    sig_int = int.from_bytes(signature, "big")
    if sig_int >= modulus:
        return False
    encoded = pow(sig_int, exponent, modulus).to_bytes(size, "big")
    digest_info = bytes.fromhex(
        "3031300d060960864801650304020105000420"
    ) + hashlib.sha256(payload).digest()
    padding_length = size - len(digest_info) - 3
    if padding_length < 8:
        return False
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    return hmac.compare_digest(encoded, expected)


def verify_signed_envelope(envelope: dict, modulus_hex: str,
                           exponent: int = 65537) -> dict:
    if not modulus_hex:
        raise ValueError("Publisher public key is not configured; updates disabled.")
    if not isinstance(envelope, dict) or set(envelope) != {"manifest", "signature"}:
        raise ValueError("Invalid signed update envelope.")
    manifest = envelope["manifest"]
    if not isinstance(manifest, dict):
        raise ValueError("Invalid update manifest.")
    signature_text = envelope["signature"]
    if not isinstance(signature_text, str) or len(signature_text) > 2048:
        raise ValueError("Invalid update signature.")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, TypeError):
        raise ValueError("Malformed update signature.")
    if not _verify_rsa_sha256(_canonical_manifest_bytes(manifest), signature,
                              modulus_hex, exponent):
        raise ValueError("Update signature verification failed.")
    return validate_manifest(manifest)


def download_signed_manifest(url: str, modulus_hex: str,
                             exponent: int = 65537, timeout: int = 20) -> dict:
    if not url or not url.lower().startswith("https://"):
        raise ValueError("A configured HTTPS update URL is required.")
    if not modulus_hex:
        raise ValueError("Publisher public key is not configured; updates disabled.")
    request = urllib.request.Request(
        url, headers={"User-Agent": "NiceAntivirus/0.3",
                      "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError("Update server returned HTTP " + str(response.status))
        data = response.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("Manifest is larger than 5 MiB.")
    try:
        envelope = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Update response is not valid UTF-8 JSON.") from exc
    return verify_signed_envelope(envelope, modulus_hex, exponent)


def validate_manifest(manifest: dict) -> dict:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("Unsupported manifest schema.")
    version = manifest.get("version")
    entries = manifest.get("signatures")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
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
        if not isinstance(digest, str) or not HASH_RE.fullmatch(digest) or digest in seen:
            raise ValueError("Invalid or duplicate SHA-256 signature.")
        if not isinstance(label, str) or not label.strip() or len(label) > 160:
            raise ValueError("Invalid signature label.")
        if severity not in ALLOWED_SEVERITIES:
            raise ValueError("Invalid severity.")
        if not isinstance(description, str) or len(description) > 1000:
            raise ValueError("Invalid description.")
        seen.add(digest)
        validated.append({"sha256": digest, "label": label.strip(),
                          "severity": severity, "description": description})
    return {"schema_version": 1, "version": version, "signatures": validated}


def install_verified_manifest(connection, manifest: dict) -> int:
    """Atomically replace signatures; reject rollback or same-version rewrites."""
    clean = validate_manifest(manifest)
    current_row = connection.execute(
        "SELECT value FROM metadata WHERE key = 'signature_db_version'"
    ).fetchone()
    current = int(current_row[0]) if current_row else 0
    if clean["version"] <= current:
        raise ValueError("Update is not newer than the installed database.")
    with connection:
        connection.execute("DELETE FROM signatures")
        connection.executemany(
            """INSERT INTO signatures
               (sha256, label, severity, description, source_version)
               VALUES (?, ?, ?, ?, ?)""",
            [(item["sha256"], item["label"], item["severity"],
              item["description"], clean["version"])
             for item in clean["signatures"]],
        )
        connection.execute(
            """INSERT INTO metadata (key, value) VALUES
               ('signature_db_version', ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (str(clean["version"]),),
        )
    return len(clean["signatures"])


def update_database(db_path: str, url: str = UPDATE_MANIFEST_URL,
                    modulus_hex: str = PUBLISHER_RSA_MODULUS_HEX) -> dict:
    from antivirus.database import connect
    manifest = download_signed_manifest(url, modulus_hex)
    connection = connect(db_path)
    try:
        count = install_verified_manifest(connection, manifest)
        return {"status": "updated", "version": manifest["version"],
                "signature_count": count}
    finally:
        connection.close()
