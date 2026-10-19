"""Shared raw-wire reader cases. Python does not authenticate Ed25519 signatures."""
from datetime import timedelta
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker
from test_envelope_contracts import (
    ACK, ENROLLMENT, EVIDENCE, read_envelope, signing_bytes, strict_loads, timestamp,
)

CONTRACTS = Path(__file__).resolve().parents[2] / "packages/contracts"


def load_catalogue(path=CONTRACTS / "conformance-v1.json"):
    catalogue = strict_loads(path.read_text())
    if catalogue["schema_version"] != "device-audit.conformance-catalogue.v1":
        raise ValueError("unsupported conformance catalogue")
    validators = {}
    for suite in catalogue["suites"]:
        for version, filename in suite["schemas"].items():
            if version in validators:
                raise ValueError(f"duplicate reader version {version}")
            schema = strict_loads((CONTRACTS / filename).read_text())
            Draft202012Validator.check_schema(schema)
            validators[version] = Draft202012Validator(schema, format_checker=FormatChecker())
    return catalogue, validators


def reject_nonfinite_constant(value):
    raise ValueError(f"nonfinite JSON constant {value}")


def schema_classification(vector, validators):
    # JSON Schema sees a parsed object and cannot detect repeated object keys.
    try:
        value = json.loads(vector["wire"], parse_constant=reject_nonfinite_constant)
    except ValueError:
        return "invalid_json"
    if not isinstance(value, dict):
        return "invalid_contract"
    version = value.get("schema_version")
    if version is not None and version != vector["reader_version"]:
        return "unsupported_schema"
    return "accepted" if validators[vector["reader_version"]].is_valid(value) else "invalid_contract"


def python_classification(vector, validators):
    try:
        value = strict_loads(vector["wire"])
    except ValueError:
        return "invalid_json"
    if not isinstance(value, dict):
        return "invalid_contract"
    version = value.get("schema_version")
    if version is not None and version != vector["reader_version"]:
        return "unsupported_schema"
    if not validators[vector["reader_version"]].is_valid(value):
        return "invalid_contract"
    if version in (ENROLLMENT, EVIDENCE, ACK):
        try:
            value = read_envelope(validators, vector["wire"])
        except ValueError:
            return "invalid_contract"
        if vector.get("canonical_hex") and signing_bytes(value).hex() != vector["canonical_hex"]:
            raise AssertionError("canonical signing bytes differ")
    if vector.get("now"):
        if version not in (ENROLLMENT, EVIDENCE):
            raise ValueError("freshness requires enrollment or evidence")
        now = timestamp(vector["now"])
        if now >= timestamp(value["expires_at"]):
            return "expired"
        if timestamp(value["issued_at"]) > now + timedelta(minutes=5):
            return "future_timestamp"
        if value["sequence"] <= vector["last_sequence"]:
            return "replay"
    return "accepted"


class ContractConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogue, cls.validators = load_catalogue()
        collection = strict_loads((CONTRACTS / cls.catalogue["wire_vectors"]).read_text())
        if collection["schema_version"] != "device-audit.conformance-wire.v1":
            raise ValueError("unsupported wire vectors")
        cls.vectors = collection["vectors"]

    def test_shared_wire_classifications(self):
        self.assertTrue(self.vectors)
        names = [v["name"] for v in self.vectors]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual({v["reader_version"] for v in self.vectors}, set(self.validators))
        for version in self.validators:
            self.assertIn("valid/" + version, names)
            self.assertIn("unsupported/" + version, names)
        for v in self.vectors:
            with self.subTest(name=v["name"]):
                self.assertEqual(schema_classification(v, self.validators), v["expected_schema"])
                self.assertEqual(python_classification(v, self.validators), v["expected_python"])

    def test_nullable_measurements_survive_python_reader(self):
        v = next(v for v in self.vectors if v["name"] == "valid/device-audit.telemetry.v2")
        value = strict_loads(v["wire"])
        self.assertEqual(python_classification(v, self.validators), "accepted")
        self.assertIsNone(value["metrics"]["gpu_utilization"]["value"])
        self.assertEqual(value["metrics"]["gpu_utilization"]["missing_reason"], "not_applicable")
        self.assertIsNone(value["metrics"]["battery_percent"]["value"])
        evidence = next(v for v in self.vectors if v["name"] == "valid/" + EVIDENCE)
        self.assertEqual(python_classification(evidence, self.validators), "accepted")


if __name__ == "__main__":
    unittest.main()
