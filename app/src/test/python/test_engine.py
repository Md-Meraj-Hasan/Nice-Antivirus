import hashlib
import os
import tempfile
import unittest
import zipfile

from antivirus.scanner import engine_self_check, inspect_file
from antivirus.updater import validate_manifest, verify_signed_envelope, install_verified_manifest
from antivirus.database import connect


class EngineTests(unittest.TestCase):
    def test_self_check(self):
        self.assertIn("Python engine: OK", engine_self_check())

    def test_hash_match(self):
        with tempfile.NamedTemporaryFile(delete=False) as file:
            file.write(b"sample")
            path = file.name
        try:
            digest = hashlib.sha256(b"sample").hexdigest()
            result = inspect_file(path, {digest: {"label": "Test"}})
            self.assertEqual(result["status"], "detected")
        finally:
            os.unlink(path)

    def test_apk_container_review(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as file:
            path = file.name
        try:
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest-placeholder")
                archive.writestr("classes.dex", b"dex-placeholder")
            result = inspect_file(path, {})
            self.assertEqual(result["apk_review"]["status"], "valid_container")
            self.assertTrue(result["apk_review"]["has_manifest"])
        finally:
            os.unlink(path)

    def test_apk_review_flags_executable_like_assets_without_verdict(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as file:
            path = file.name
        try:
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest-placeholder")
                archive.writestr("classes.dex", b"dex-placeholder")
                archive.writestr("assets/payload.jar", b"sample")
            result = inspect_file(path, {})
            review = result["apk_review"]
            self.assertEqual(result["status"], "no_match")
            self.assertEqual(review["status"], "review")
            self.assertEqual(review["risk_label"], "manual_review")
            self.assertIn(
                "executable_like_assets",
                [item["code"] for item in review["review_indicators"]],
            )
            self.assertIn("not a malware verdict", review["note"].lower())
        finally:
            os.unlink(path)

    def test_normal_apk_has_no_structural_flags(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as file:
            path = file.name
        try:
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest-placeholder")
                archive.writestr("classes.dex", b"dex-placeholder")
                archive.writestr("resources.arsc", b"resources")
            result = inspect_file(path, {})
            self.assertEqual(result["apk_review"]["status"], "valid_container")
            self.assertEqual(result["apk_review"]["review_indicators"], [])
        finally:
            os.unlink(path)

    def test_unsigned_update_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "public key"):
            verify_signed_envelope({"manifest": {}, "signature": ""}, "")

    def test_signature_database_version_is_monotonic(self):
        with tempfile.TemporaryDirectory() as folder:
            connection = connect(os.path.join(folder, "signatures.db"))
            manifest = {
                "schema_version": 1, "version": 2,
                "signatures": [{
                    "sha256": hashlib.sha256(b"malware-sample").hexdigest(),
                    "label": "Test threat", "severity": "high",
                    "description": "Test fixture",
                }],
            }
            self.assertEqual(install_verified_manifest(connection, manifest), 1)
            with self.assertRaisesRegex(ValueError, "not newer"):
                install_verified_manifest(connection, manifest)
            self.assertEqual(connection.execute(
                "SELECT value FROM metadata WHERE key='signature_db_version'"
            ).fetchone()[0], "2")
            connection.close()

    def test_manifest_rejects_non_hash(self):
        with self.assertRaises(ValueError):
            validate_manifest({
                "schema_version": 1,
                "version": 1,
                "signatures": [{"sha256": "bad", "label": "x", "severity": "high"}],
            })


if __name__ == "__main__":
    unittest.main()
