import base64
import hashlib
import json
from pathlib import Path
import struct
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]


class AuditContractTests(unittest.TestCase):
    def test_shared_vectors_and_commitment(self):
        schema = json.loads((ROOT / "packages/contracts/audit-v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        collection = json.loads((ROOT / "packages/contracts/fixtures/audit/v1-vectors.json").read_text())
        self.assertTrue(collection["vectors"])
        for v in collection["vectors"]:
            with self.subTest(name=v["name"]):
                self.assertEqual(validator.is_valid(v["payload"]), v["schema_valid"])
        m = collection["vectors"][0]["payload"]
        fields = [m[k] for k in ("schema_version", "deployment_id", "manifest_id", "commitment_id", "blinding_nonce", "policy_version", "controller_key_id", "created_at", "expires_at")]
        fields += [len(m["evidence"])]
        self.assertEqual([e["reference_id"] for e in m["evidence"]], sorted(e["reference_id"] for e in m["evidence"]))
        for e in m["evidence"]:
            fields += [e[k] for k in ("reference_id", "schema_version", "sha256", "size_bytes", "expires_at")]
            raw = base64.b64decode(collection["artifacts_base64"][e["reference_id"]], validate=True)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), e["sha256"])
            self.assertEqual(len(raw), e["size_bytes"])
        message = b"device-audit/signature/v1\x00"
        for field in fields:
            raw = str(field).encode("utf-8")
            message += struct.pack(">I", len(raw)) + raw
        self.assertEqual(message.hex(), collection["vectors"][0]["canonical_hex"])
        manifest_digest = hashlib.sha256(message + bytes.fromhex(m["signature"])).digest()
        preimage = b"device-audit/audit-commitment/v1\x00" + bytes.fromhex(m["commitment_id"]) + bytes.fromhex(m["blinding_nonce"]) + manifest_digest
        commitment = collection["vectors"][1]["payload"]
        self.assertEqual(hashlib.sha256(preimage).hexdigest(), commitment["commitment_sha256"])
        self.assertEqual(set(commitment), {"schema_version", "commitment_id", "commitment_sha256"})


if __name__ == "__main__":
    unittest.main()
