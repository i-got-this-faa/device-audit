"""CT03 #32 shared feature vectors through the Python reference and JSON Schema."""
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker

from device_audit_models import features, partitions

CONTRACTS = Path(__file__).resolve().parents[2] / "packages/contracts"


class FeatureContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = json.loads((CONTRACTS / "features-v1.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        cls.validator = Draft202012Validator(schema, format_checker=FormatChecker())
        collection = json.loads((CONTRACTS / "fixtures/features/v1-vectors.json").read_text(encoding="utf-8"))
        if (collection["schema_version"] != "device-audit.feature-fixtures.v1"
                or collection["feature_version"] != features.FEATURE_VERSION
                or collection["tolerance"] != features.TOLERANCE or not collection["vectors"]):
            raise ValueError("missing or incompatible feature fixtures")
        cls.vectors = collection["vectors"]

    def test_shared_vectors(self):
        for v in self.vectors:
            with self.subTest(v["name"]):
                payload = v["payload"]
                self.assertEqual(self.validator.is_valid(payload), v["schema_valid"])
                read = features.compute if payload.get("schema_version") == features.WINDOW_SCHEMA else features.validate_vector
                try:
                    got = read(payload)
                except features.UnsupportedFeatureVersion:
                    self.assertEqual(v["rejection"], "unsupported_feature_version")
                    continue
                except ValueError as error:
                    self.assertEqual(v["rejection"], "invalid_contract", str(error))
                    continue
                self.assertTrue(v["valid"], "accepted an invalid payload")
                if read is features.compute:
                    features.validate_vector(got)
                    features.validate_vector(v["expected"])
                    self.assertTrue(self.validator.is_valid(got))
                    self.assertTrue(features.close(got, v["expected"]), json.dumps(got))

    def test_sample_bound(self):
        samples = [{"observed_at": f"2013-11-{1 + i // 1440:02d}T{i // 60 % 24:02d}:{i % 60:02d}:00Z",
                    "smart_5_raw": 0, "smart_9_raw": 0, "smart_197_raw": 0}
                   for i in range(features.MAX_SAMPLES)]
        window = {"schema_version": features.WINDOW_SCHEMA, "feature_version": features.FEATURE_VERSION,
                  "as_of": "2013-11-07T23:59:59Z", "samples": samples}
        self.assertEqual(features.compute(window)["status"], "complete")
        samples.append({**samples[0], "observed_at": "2013-10-31T00:00:00Z"})
        with self.assertRaises(ValueError):
            features.validate_window(window)

    def test_close_uses_the_recorded_tolerance(self):
        expected = next(v["expected"] for v in self.vectors if v["name"] == "backblaze daily snapshots complete")
        shifted = json.loads(json.dumps(expected))
        value = shifted["features"][2]["value"]
        shifted["features"][2]["value"] = value + features.TOLERANCE * abs(value) * 0.5
        self.assertTrue(features.close(shifted, expected))
        shifted["features"][2]["value"] = value + 1e-9
        self.assertFalse(features.close(shifted, expected))

    def test_selected_counters_follow_ml01_and_exclude_all_null_columns(self):
        # ML01 counted 5,091,501 nulls of 5,091,501 rows for SMART 187 and 198.
        selected = [c for c, _ in features.COUNTERS]
        self.assertEqual(selected, [c for c in partitions.FEATURES if c in selected])
        manifest = json.loads((Path(__file__).resolve().parents[1]
                               / "datasets/backblaze-2013/partitions.json").read_text(encoding="utf-8"))
        observations = manifest["source_observations"]
        for column in partitions.FEATURES:
            all_null = observations["nullable_feature_values"][column] == observations["rows"]
            self.assertEqual(column not in selected, all_null, column)


if __name__ == "__main__":
    unittest.main()
