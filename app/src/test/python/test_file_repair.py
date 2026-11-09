import json
import os
import sqlite3
import tempfile
import unittest
import zipfile

from antivirus.file_repair import inspect_file, repair_file


class FileRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def test_pdf_missing_eof_creates_copy_and_preserves_original(self):
        source = os.path.join(self.root, "broken.pdf")
        with open(source, "wb") as stream:
            stream.write(b"%PDF-1.4\n1 0 obj <<>> endobj\n")
        result = repair_file(source, os.path.join(self.root, "out"))
        self.assertEqual(result["action"], "terminal_marker_restored")
        self.assertTrue(os.path.exists(result["output_path"]))
        with open(source, "rb") as stream:
            self.assertNotIn(b"%%EOF", stream.read())

    def test_valid_zip_is_not_rewritten(self):
        source = os.path.join(self.root, "valid.zip")
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("hello.txt", "hello")
        result = repair_file(source, os.path.join(self.root, "out"))
        self.assertEqual(result["action"], "inspect_only")
        self.assertFalse(result["success"])

    def test_valid_sqlite_database_backup(self):
        source = os.path.join(self.root, "valid.db")
        db = sqlite3.connect(source)
        db.execute("create table sample(value text)")
        db.execute("insert into sample values ('ok')")
        db.commit()
        db.close()
        result = repair_file(source, os.path.join(self.root, "out"))
        self.assertEqual(result["action"], "sqlite_backup_copy")
        self.assertTrue(os.path.exists(result["output_path"]))

    def test_json_validation_reports_valid_and_invalid_files(self):
        valid = os.path.join(self.root, "valid.json")
        invalid = os.path.join(self.root, "invalid.json")
        with open(valid, "w", encoding="utf-8") as stream:
            stream.write('{"ok": true}')
        with open(invalid, "w", encoding="utf-8") as stream:
            stream.write('{"ok": }')
        self.assertIn("JSON syntax is valid", " ".join(inspect_file(valid)["notes"]))
        self.assertIn("JSON validation failed", " ".join(inspect_file(invalid)["notes"]))

    def test_xml_validation_reports_malformed_document(self):
        source = os.path.join(self.root, "broken.xml")
        with open(source, "w", encoding="utf-8") as stream:
            stream.write("<root><item></root>")
        self.assertIn("XML validation failed", " ".join(inspect_file(source)["notes"]))

    def test_csv_validation_detects_inconsistent_columns(self):
        source = os.path.join(self.root, "uneven.csv")
        with open(source, "w", encoding="utf-8", newline="") as stream:
            stream.write("a,b\n1,2\n3,4,5\n")
        self.assertIn("inconsistent column counts", " ".join(inspect_file(source)["notes"]))

    def test_text_validation_accepts_utf8_bom(self):
        source = os.path.join(self.root, "bom.txt")
        with open(source, "w", encoding="utf-8-sig") as stream:
            stream.write("hello")
        self.assertIn("valid UTF-8", " ".join(inspect_file(source)["notes"]))

    def test_unknown_format_is_inspect_only(self):
        source = os.path.join(self.root, "sample.xyz")
        with open(source, "wb") as stream:
            stream.write(b"not a known format")
        report = inspect_file(source)
        self.assertEqual(report["type"], "unknown")
        result = repair_file(source, os.path.join(self.root, "out"))
        self.assertEqual(result["action"], "inspect_only")


    def test_zip_signature_is_detected_from_content(self):
        source = os.path.join(self.root, "archive.bin")
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("hello.txt", "hello")
        # ZIP files are identified by their real byte signature, not extension.
        self.assertEqual(inspect_file(source)["type"], "ZIP-based container")

    def test_png_signature_is_detected_as_inspect_only(self):
        source = os.path.join(self.root, "image.bin")
        with open(source, "wb") as stream:
            stream.write(bytes.fromhex("89504e470d0a1a0a") + b"payload")
        report = inspect_file(source)
        self.assertEqual(report["type"], "PNG image")
        self.assertFalse(report["repair_supported"])

    def test_pdf_repair_writes_real_line_breaks(self):
        source = os.path.join(self.root, "linebreak.pdf")
        with open(source, "wb") as stream:
            stream.write(b"%PDF-1.4\\nbody")
        result = repair_file(source, os.path.join(self.root, "out"))
        with open(result["output_path"], "rb") as stream:
            repaired = stream.read()
        self.assertTrue(repaired.endswith(b"\\n%%EOF\\n"))
        self.assertNotIn(b"\\\\n%%EOF", repaired)


if __name__ == "__main__":
    unittest.main()
