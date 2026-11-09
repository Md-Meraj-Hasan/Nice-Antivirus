import hashlib
import os
import tempfile
import unittest

from antivirus.scanner import engine_self_check, inspect_file
from antivirus.updater import validate_manifest


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

    def test_manifest_rejects_non_hash(self):
        with self.assertRaises(ValueError):
            validate_manifest({
                "schema_version": 1,
                "version": 1,
                "signatures": [{"sha256": "bad", "label": "x", "severity": "high"}],
            })


if __name__ == "__main__":
    unittest.main()
