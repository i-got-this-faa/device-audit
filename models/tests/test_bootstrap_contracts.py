"""Bootstrap schema and independent framing checks, without signature authentication."""
import hashlib
from pathlib import Path
import struct
import unittest

from test_contract_conformance import load_catalogue
from test_envelope_contracts import signing_bytes, strict_loads

ROOT = Path(__file__).resolve().parents[2] / "packages/contracts"


class BootstrapContractTests(unittest.TestCase):
    def test_shared_vectors(self):
        _, validators = load_catalogue()
        vectors = strict_loads((ROOT / "fixtures/bootstrap/v1-vectors.json").read_text())["vectors"]
        for vector in vectors:
            with self.subTest(name=vector["name"]):
                value = vector["message"]
                self.assertEqual(validators[value["schema_version"]].is_valid(value), vector["schema_valid"])
                if "canonical_hex" not in vector:
                    continue
                inner = value["enrollment"]
                fingerprint = hashlib.sha256(signing_bytes(inner) + bytes.fromhex(inner["signature"])).hexdigest()
                fields = [value["schema_version"], fingerprint, value["network_public_key"], value["network_proof"]]
                framed = b"device-audit/signature/v1\0"
                for field in fields:
                    encoded = field.encode("ascii")
                    framed += struct.pack(">I", len(encoded)) + encoded
                self.assertEqual(framed.hex(), vector["canonical_hex"])

    def test_duplicate_and_trailing_json_rejected(self):
        for wire in ('{"device_id":"a","device_id":"b"}', '{"device_id":"a"}{}'):
            with self.assertRaises(ValueError):
                strict_loads(wire)


if __name__ == "__main__":
    unittest.main()
