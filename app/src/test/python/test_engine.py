import hashlib
import os
import sqlite3
import tempfile
import unittest
import zipfile

from antivirus.scanner import engine_self_check, inspect_file, scan_local_file, scan_history_report, duplicate_content_report, diagnostics_report
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

    def test_scan_history_records_display_name_and_result(self):
        with tempfile.TemporaryDirectory() as folder:
            sample_path = os.path.join(folder, "temporary-copy.bin")
            db_path = os.path.join(folder, "signatures.db")
            with open(sample_path, "wb") as stream:
                stream.write(b"history sample")
            report = scan_local_file(sample_path, db_path, "Original document.pdf")
            self.assertIn("No local signature match", report)
            history = scan_history_report(db_path)
            self.assertIn("Original document.pdf", history)
            self.assertIn("NO_MATCH", history)
            self.assertNotIn("temporary-copy.bin", history)

    def test_duplicate_content_report_groups_identical_hashes_read_only(self):
        from antivirus.database import record_scan
        with tempfile.TemporaryDirectory() as folder:
            db_path = os.path.join(folder, "signatures.db")
            connection = connect(db_path)
            same_hash = hashlib.sha256(b"identical file content").hexdigest()
            other_hash = hashlib.sha256(b"different content").hexdigest()
            record_scan(connection, "folder/a.txt", same_hash, "no_match")
            record_scan(connection, "folder/copy.txt", same_hash, "no_match")
            record_scan(connection, "folder/other.txt", other_hash, "no_match")
            report = duplicate_content_report(db_path)
            self.assertIn("SAME SHA-256 CONTENT", report)
            self.assertIn("folder/a.txt", report)
            self.assertIn("folder/copy.txt", report)
            self.assertNotIn("folder/other.txt", report)
            self.assertIn("No files were changed or deleted", report)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0],
                3,
            )
            connection.close()

    def test_duplicate_content_report_handles_empty_history(self):
        with tempfile.TemporaryDirectory() as folder:
            report = duplicate_content_report(os.path.join(folder, "empty.db"))
            self.assertIn("NO REPEATED CONTENT HASH FOUND", report)
            self.assertIn("does not search the whole device", report)

    def test_scan_history_persists_archive_manual_review(self):
        with tempfile.TemporaryDirectory() as folder:
            archive_path = os.path.join(folder, "review.zip")
            db_path = os.path.join(folder, "signatures.db")
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../outside.txt", b"sample")
            report = scan_local_file(archive_path, db_path, "review.zip")
            self.assertIn("ARCHIVE REVIEW: review", report)
            history = scan_history_report(db_path)
            self.assertIn("MANUAL REVIEW: Archive (review)", history)
            self.assertIn("path-traversal", history.lower().replace("_", "-"))
            self.assertIn("not a malware verdict", history.lower())

    def test_scan_history_additive_migration_preserves_existing_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            db_path = os.path.join(folder, "old.db")
            connection = sqlite3.connect(db_path)
            connection.execute(
                "CREATE TABLE scan_history (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "path TEXT NOT NULL, sha256 TEXT, status TEXT NOT NULL, "
                "scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )
            connection.execute(
                "INSERT INTO scan_history (path, sha256, status) VALUES (?, ?, ?)",
                ("old-file.txt", None, "no_match"),
            )
            connection.commit()
            connection.close()
            connection = connect(db_path)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(scan_history)")}
            self.assertIn("review_summary", columns)
            row = connection.execute(
                "SELECT path, review_summary FROM scan_history"
            ).fetchone()
            self.assertEqual(row[0], "old-file.txt")
            self.assertEqual(row[1], "")
            connection.close()

    def test_clear_scan_history_preserves_signatures_and_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            db_path = os.path.join(folder, "signatures.db")
            sample_path = os.path.join(folder, "sample.bin")
            with open(sample_path, "wb") as stream:
                stream.write(b"clear history test")
            scan_local_file(sample_path, db_path, "sample.bin")
            connection = connect(db_path)
            connection.execute(
                "INSERT INTO signatures (sha256, label, severity, description, source_version) "
                "VALUES (?, ?, ?, ?, ?)",
                (hashlib.sha256(b"known").hexdigest(), "Known", "low", "fixture", 1),
            )
            connection.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                ("signature_db_version", "7"),
            )
            connection.commit()
            connection.close()

            from antivirus.scanner import clear_scan_history_records
            removed = clear_scan_history_records(db_path)
            self.assertEqual(removed, 1)
            self.assertIn("No scan history yet", scan_history_report(db_path))

            connection = connect(db_path)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM signatures").fetchone()[0], 1)
            self.assertEqual(
                connection.execute("SELECT value FROM metadata WHERE key='signature_db_version'").fetchone()[0],
                "7",
            )
            connection.close()

    def test_scan_history_retains_only_newest_1000_records(self):
        from antivirus.database import record_scan, recent_scans
        with tempfile.TemporaryDirectory() as folder:
            connection = connect(os.path.join(folder, "signatures.db"))
            for index in range(1005):
                record_scan(connection, "file-" + str(index), None, "no_match")
            rows = recent_scans(connection, 200)
            total = connection.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
            self.assertEqual(total, 1000)
            self.assertEqual(rows[0]["path"], "file-1004")
            self.assertEqual(rows[-1]["path"], "file-805")
            connection.close()

    def test_file_header_extension_mismatch_is_manual_review_only(self):
        with tempfile.TemporaryDirectory() as folder:
            disguised = os.path.join(folder, "invoice.pdf")
            with open(disguised, "wb") as stream:
                stream.write(b"MZ" + b"sample executable header")
            result = inspect_file(disguised, {})
            self.assertEqual(result["status"], "no_match")
            self.assertEqual(
                result["file_type_review"]["code"],
                "file_extension_mismatch",
            )
            self.assertIn("not proof of malware", result["file_type_review"]["note"])

    def test_matching_file_header_does_not_raise_mismatch(self):
        with tempfile.TemporaryDirectory() as folder:
            image_path = os.path.join(folder, "photo.png")
            with open(image_path, "wb") as stream:
                stream.write(b"\x89PNG\r\n\x1a\n" + b"sample image data")
            result = inspect_file(image_path, {})
            self.assertNotIn("file_type_review", result)
            self.assertEqual(result["status"], "no_match")

    def test_zip_archive_traversal_is_flagged_without_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "sample.zip")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../outside.txt", b"sample")
                archive.writestr("safe.txt", b"safe")
            result = inspect_file(path, {})
            self.assertEqual(result["status"], "no_match")
            review = result["archive_review"]
            self.assertEqual(review["status"], "review")
            self.assertIn(
                "path_traversal_names",
                [item["code"] for item in review["review_indicators"]],
            )
            self.assertIn("no extraction", review["note"].lower())

    def test_normal_zip_has_no_archive_review_flags(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "normal.zip")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("docs/readme.txt", b"hello")
            result = inspect_file(path, {})
            self.assertEqual(result["archive_review"]["status"], "no_structural_flags")
            self.assertEqual(result["archive_review"]["review_indicators"], [])

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

    def test_tool_diagnostics_runs_isolated_checks(self):
        report = diagnostics_report()
        self.assertIn("NICE ANTIVIRUS — TOOL DIAGNOSTICS", report)
        self.assertIn("[PASS] SHA-256 engine", report)
        self.assertIn("[PASS] File scan + signature database + scan history", report)
        self.assertIn("[PASS] APK structure analyzer", report)
        self.assertIn("[PASS] ZIP archive review", report)
        self.assertIn("[PASS] Storage cleanup analyzer", report)
        self.assertIn("[PASS] Quarantine copy fingerprint", report)
        self.assertIn("[PASS] Duplicate content report", report)
        self.assertIn("[WARNING] Signed virus database updater", report)


if __name__ == "__main__":
    unittest.main()
