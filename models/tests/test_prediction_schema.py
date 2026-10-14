import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "packages/contracts/prediction-v2.schema.json"
VECTORS_PATH = ROOT / "packages/contracts/fixtures/prediction/v2-vectors.json"


class PredictionSchemaVectorsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema, format_checker=FormatChecker())
        cls.vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["vectors"]
        if not cls.vectors:
            raise AssertionError("no prediction vectors")

    def test_shared_vectors(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                errors = list(self.validator.iter_errors(vector["prediction"]))
                self.assertEqual(not errors, vector["valid"], "; ".join(e.message for e in errors))


if __name__ == "__main__":
    unittest.main()
