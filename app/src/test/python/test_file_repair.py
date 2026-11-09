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

    def test_unknown_format_is_inspect_only(self):
        source = os.path.join(self.root, "sample.xyz")
        with open(source, "wb") as stream:
            stream.write(b"not a known format")
        report = inspect_file(source)
        self.assertEqual(report["type"], "unknown")
        result = repair_file(source, os.path.join(self.root, "out"))
        self.assertEqual(result["action"], "inspect_only")


if __name__ == "__main__":
    unittest.main()
