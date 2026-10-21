import base64
import hashlib
import json
import math
from pathlib import Path
import struct
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]


class FederatedContractTests(unittest.TestCase):
    def test_shared_vectors(self):
        schema = json.loads((ROOT / "packages/contracts/federated-v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        vectors = json.loads((ROOT / "packages/contracts/fixtures/federated/v1-vectors.json").read_text())["vectors"]
        self.assertTrue(vectors)
        for v in vectors:
            with self.subTest(name=v["name"]):
                p = v["payload"]
                self.assertEqual(validator.is_valid(p), v["schema_valid"])
                if p["schema_version"] != "device-audit.federated-update.v1":
                    continue
                raw = base64.b64decode(p["weights_base64"], validate=True)
                weights = [value for (value,) in struct.iter_unpack(">d", raw)]
                if v["name"].startswith("nonfinite_"):
                    self.assertFalse(all(math.isfinite(w) for w in weights))
                if v["valid"]:
                    self.assertTrue(all(math.isfinite(w) for w in weights))
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), p["update_sha256"])
                if not v["canonical_hex"]:
                    continue
                keys = ("schema_version", "deployment_id", "device_id", "signing_key_id", "sequence", "issued_at", "expires_at", "round_id", "base_model_version", "base_model_sha256", "candidate_id", "feature_version", "sample_count", "update_sha256")
                message = b"device-audit/signature/v1\x00"
                for k in keys:
                    data = str(p[k]).encode("utf-8")
                    message += struct.pack(">I", len(data)) + data
                self.assertEqual(message.hex(), v["canonical_hex"])


if __name__ == "__main__":
    unittest.main()
