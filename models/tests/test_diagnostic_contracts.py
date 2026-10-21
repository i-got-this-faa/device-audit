import json
from pathlib import Path
import struct
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]


class DiagnosticContractTests(unittest.TestCase):
    def test_shared_vectors(self):
        schema = json.loads((ROOT / "packages/contracts/diagnostics-v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        vectors = json.loads((ROOT / "packages/contracts/fixtures/diagnostics/v1-vectors.json").read_text())["vectors"]
        self.assertTrue(vectors)
        for v in vectors:
            with self.subTest(name=v["name"]):
                self.assertEqual(validator.is_valid(v["payload"]), v["schema_valid"])
                if not v["canonical_hex"]:
                    continue
                p = v["payload"]
                fields = [p[k] for k in ("schema_version", "deployment_id", "device_id", "signing_key_id", "sequence", "issued_at", "expires_at")]
                if p["schema_version"] == "device-audit.diagnostic-assignment.v1":
                    fields += [p["assignment_id"], p["probe_id"]]
                    fields += [p["arguments"][k] for k in ("component_id", "lookback_seconds", "max_entries")]
                    fields += [p["budget"][k] for k in ("wall_seconds", "max_output_bytes")]
                else:
                    fields += [p[k] for k in ("assignment_id", "assignment_sha256", "boot_id", "started_at", "finished_at", "state", "reason")]
                    fields += [len(p["evidence"])]
                    for e in p["evidence"]:
                        fields += [e[k] for k in ("reference_id", "sha256", "size_bytes")]
                message = b"device-audit/signature/v1\x00"
                for field in fields:
                    data = ("" if field is None else str(field)).encode("utf-8")
                    message += struct.pack(">I", len(data)) + data
                self.assertEqual(message.hex(), v["canonical_hex"])


if __name__ == "__main__":
    unittest.main()
