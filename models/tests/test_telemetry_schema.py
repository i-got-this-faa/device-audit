import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "packages/contracts/telemetry.schema.json"
VECTORS_PATH = ROOT / "packages/contracts/fixtures/telemetry/vectors.json"
V2_SCHEMA_PATH = ROOT / "packages/contracts/telemetry-v2.schema.json"
V2_VECTORS_PATH = ROOT / "packages/contracts/fixtures/telemetry/v2-vectors.json"


class TelemetrySchemaVectorsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(
            cls.schema, format_checker=FormatChecker()
        )
        cls.vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["vectors"]
        if not cls.vectors:
            raise AssertionError("no telemetry vectors")

    def test_shared_vectors(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                errors = list(self.validator.iter_errors(vector["telemetry"]))
                self.assertEqual(
                    not errors,
                    vector["valid"],
                    "; ".join(error.message for error in errors),
                )

    def test_v2_shared_vectors(self):
        schema = json.loads(V2_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        vectors = json.loads(V2_VECTORS_PATH.read_text(encoding="utf-8"))["vectors"]
        if not vectors:
            raise AssertionError("no v2 telemetry vectors")
        for vector in vectors:
            with self.subTest(vector=vector["name"]):
                errors = list(validator.iter_errors(vector["telemetry"]))
                self.assertEqual(
                    not errors,
                    vector["valid"],
                    "; ".join(error.message for error in errors),
                )


if __name__ == "__main__":
    unittest.main()
