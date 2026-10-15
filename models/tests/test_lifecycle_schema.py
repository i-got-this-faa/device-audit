import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "packages/contracts/lifecycle-v2.schema.json"
VECTORS_PATH = ROOT / "packages/contracts/fixtures/lifecycle/v2-vectors.json"


class LifecycleSchemaVectorsTest(unittest.TestCase):
    def test_shared_vectors(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["vectors"]
        self.assertTrue(vectors, "no lifecycle vectors")
        for vector in vectors:
            with self.subTest(vector=vector["name"]):
                errors = list(validator.iter_errors(vector["lifecycle"]))
                self.assertEqual(
                    not errors, vector["valid"], "; ".join(e.message for e in errors)
                )


if __name__ == "__main__":
    unittest.main()
