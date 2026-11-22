"""CT10 #101 shared model manifest vectors through the Python reference and JSON Schema."""
import base64
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker

from device_audit_models import features, manifest

CONTRACTS = Path(__file__).resolve().parents[2] / "packages/contracts"
# Python takes no Ed25519 dependency; Go verifies these.
SIGNATURE_REJECTIONS = {"invalid_signature", "key_mismatch"}


class ManifestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = json.loads((CONTRACTS / "model-manifest-v1.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        cls.validator = Draft202012Validator(schema, format_checker=FormatChecker())
        collection = json.loads((CONTRACTS / "fixtures/models/v1-vectors.json").read_text(encoding="utf-8"))
        if collection["schema_version"] != "device-audit.model-manifest-fixtures.v1" or not collection["vectors"]:
            raise ValueError("missing or incompatible model manifest fixtures")
        cls.vectors = collection["vectors"]

    def test_shared_vectors(self):
        for v in self.vectors:
            with self.subTest(v["name"]):
                payload, a = v["payload"], v["activation"]
                self.assertEqual(self.validator.is_valid(payload), v["schema_valid"])
                if v["canonical_hex"]:
                    self.assertEqual(manifest.signing_bytes(payload).hex(), v["canonical_hex"])
                if v["rejection"] in SIGNATURE_REJECTIONS:
                    continue
                try:
                    manifest.check_compatibility(
                        payload, runtime_name=a["runtime_name"], runtime_version=a["runtime_version"],
                        architectures=a["architectures"], purpose=a["purpose"],
                        artifact=base64.b64decode(a["artifact_base64"], validate=True))
                except manifest.ManifestRejection as error:
                    self.assertEqual(error.code, v["rejection"], str(error))
                    continue
                self.assertEqual(v["rejection"], "", "accepted a manifest the fixture rejects")

    def test_every_python_rejection_is_exercised(self):
        exercised = {v["rejection"] for v in self.vectors}
        self.assertEqual(exercised - SIGNATURE_REJECTIONS - {""}, {
            "invalid_manifest", "unsupported_manifest_version", "unsupported_feature_version",
            "feature_order_mismatch", "runtime_mismatch", "unsupported_architecture",
            "purpose_unsupported", "digest_mismatch"})
        self.assertTrue(SIGNATURE_REJECTIONS <= exercised)

    def test_manifest_follows_the_frozen_feature_order(self):
        valid = next(v["payload"] for v in self.vectors if v["name"] == "valid_inference")
        self.assertEqual(valid["feature_version"], features.FEATURE_VERSION)
        self.assertEqual(valid["features"], [name for name, _ in features.FEATURES])

    def test_boolean_parameter_count_is_not_a_count(self):
        bad = dict(next(v["payload"] for v in self.vectors if v["name"] == "valid_inference"), parameter_count=True)
        with self.assertRaises(manifest.ManifestRejection) as raised:
            manifest.validate(bad)
        self.assertEqual(raised.exception.code, "invalid_manifest")


if __name__ == "__main__":
    unittest.main()
