"""Test-only envelope reader. No Python signature verifier or ingestion path.

Uses existing test-only jsonschema plus stdlib parsing, hashing and framing.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import struct
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2] / "packages/contracts"
ENROLLMENT = "device-audit.enrollment.v1"
EVIDENCE = "device-audit.evidence.v1"
ACK = "device-audit.acknowledgement.v1"
MAX_SEQUENCE = 9007199254740991
HEADER_FIELDS = ["schema_version", "deployment_id", "device_id", "signing_key_id",
                 "sequence", "issued_at", "expires_at"]
FIELDS = {
    ENROLLMENT: HEADER_FIELDS + ["public_key", "challenge_id"],
    EVIDENCE: HEADER_FIELDS + ["payload_schema_version", "payload_sha256"],
    ACK: ["schema_version", "deployment_id", "device_id", "controller_key_id",
          "request_schema_version", "request_key_id", "request_sequence",
          "request_sha256", "received_at", "status", "rejection_reason", "last_sequence"],
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field {key}")
        result[key] = value
    return result


def strict_loads(data):
    def reject_constant(value):
        raise ValueError(f"nonfinite JSON number {value}")
    value = json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)

    def finite_numbers(item):
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("nonfinite JSON number")
        if isinstance(item, dict):
            for member in item.values():
                finite_numbers(member)
        if isinstance(item, list):
            for member in item:
                finite_numbers(member)
    finite_numbers(value)
    return value


def timestamp(value):
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if parsed.year < 2:
        raise ValueError("zero-year policy")
    return parsed


def signing_bytes(value):
    result = bytearray(b"device-audit/signature/v1\x00")
    for field in FIELDS[value["schema_version"]]:
        text = "" if value[field] is None else str(value[field])
        encoded = text.encode("ascii")
        result += struct.pack(">I", len(encoded)) + encoded
    return bytes(result)


def read_envelope(validators, data):
    value = strict_loads(data)
    version = value["schema_version"]
    errors = list(validators[version].iter_errors(value))
    if errors:
        raise ValueError("; ".join(error.message for error in errors))
    sequences = ["request_sequence", "last_sequence"] if version == ACK else ["sequence"]
    for field in sequences:
        if value[field] is not None and type(value[field]) is not int:
            raise ValueError("sequence must use an integer JSON token")
    if version == ACK:
        timestamp(value["received_at"])
        if value["status"] == "accepted" and value["last_sequence"] != value["request_sequence"]:
            raise ValueError("accepted mark mismatch")
        if value["rejection_reason"] == "replay" and (
                value["last_sequence"] is None or value["last_sequence"] < value["request_sequence"]):
            raise ValueError("replay needs a known high-water mark")
        return value
    issued, expires = timestamp(value["issued_at"]), timestamp(value["expires_at"])
    maximum = timedelta(minutes=10) if version == ENROLLMENT else timedelta(hours=24)
    if not timedelta(0) < expires - issued <= maximum:
        raise ValueError("invalid validity window")
    if version == ENROLLMENT:
        key_id = "ed25519:" + hashlib.sha256(bytes.fromhex(value["public_key"])).hexdigest()
        if key_id != value["signing_key_id"]:
            raise ValueError("enrollment key ID mismatch")
        return value
    payload = base64.b64decode(value["payload_base64"], validate=True)
    if not 0 < len(payload) <= 262144 or base64.b64encode(payload).decode() != value["payload_base64"]:
        raise ValueError("invalid canonical payload base64")
    if hashlib.sha256(payload).hexdigest() != value["payload_sha256"]:
        raise ValueError("payload digest mismatch")
    telemetry = strict_loads(payload.decode("utf-8"))
    errors = list(validators[value["payload_schema_version"]].iter_errors(telemetry))
    if errors:
        raise ValueError("invalid telemetry payload")
    if telemetry["device_id"] != value["device_id"]:
        raise ValueError("payload device mismatch")
    zero = datetime(1, 1, 1, tzinfo=timezone.utc)
    if datetime.fromisoformat(telemetry["collected_at"]) == zero:
        raise ValueError("zero collection time")
    for log in telemetry["log_references"]:
        start = datetime.fromisoformat(log["window_start"])
        end = datetime.fromisoformat(log["window_end"])
        if start == zero or end == zero or end < start:
            raise ValueError("invalid log window")
    return value


class EnvelopeContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validators = {}
        for name, version in [("enrollment", ENROLLMENT), ("evidence", EVIDENCE),
                              ("acknowledgement", ACK), ("telemetry", "device-audit.telemetry.v2")]:
            suffix = "v2" if name == "telemetry" else "v1"
            schema = json.loads((ROOT / f"{name}-{suffix}.schema.json").read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            cls.validators[version] = Draft202012Validator(schema, format_checker=FormatChecker())
        cls.vectors = json.loads((ROOT / "fixtures/envelopes/v1-vectors.json").read_text(encoding="utf-8"))["vectors"]
        if not cls.vectors:
            raise AssertionError("no envelope vectors")

    def test_shared_contract_and_canonical_vectors(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                data = json.dumps(vector["envelope"])
                if not vector["contract_valid"]:
                    with self.assertRaises(ValueError):
                        read_envelope(self.validators, data)
                    continue
                value = read_envelope(self.validators, data)
                canonical = signing_bytes(value)
                self.assertEqual(canonical.hex(), vector["canonical_hex"])
                if value["schema_version"] != ACK:
                    digest = hashlib.sha256(canonical + bytes.fromhex(value["signature"])).hexdigest()
                    self.assertEqual(digest, vector["request_sha256"])
                # Fixture signature results only gate the pure freshness check.
                # This reader decides neither admission nor signature validity.
                if vector["signature_valid"] and value["schema_version"] != ACK:
                    now = timestamp(vector["now"])
                    reason = ""
                    if now >= timestamp(value["expires_at"]):
                        reason = "expired"
                    elif timestamp(value["issued_at"]) > now + timedelta(seconds=300):
                        reason = "future_timestamp"
                    elif value["sequence"] <= vector["last_sequence"]:
                        reason = "replay"
                    self.assertEqual(reason, vector["freshness_rejection"])

    def test_strict_json_and_sequence_tokens(self):
        original = self.vectors[0]["envelope"]
        encoded = json.dumps(original)
        for data in [encoded + " {}", encoded[:-1] + ',"sequence":1}',
                     encoded.replace('"sequence": 1', '"sequence": 1.0'),
                     encoded.replace('"sequence": 1', '"sequence": true')]:
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    read_envelope(self.validators, data)
        evidence = self.vectors[1]["envelope"].copy()
        payload = base64.b64decode(evidence["payload_base64"])
        payload = payload.replace(b'"value":0', b'"value":0,"value":10')
        evidence["payload_base64"] = base64.b64encode(payload).decode()
        evidence["payload_sha256"] = hashlib.sha256(payload).hexdigest()
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            read_envelope(self.validators, json.dumps(evidence))

    def test_acknowledgements_bind_the_request(self):
        for vector in self.vectors:
            value = vector["envelope"]
            if vector["contract_valid"] and value["schema_version"] == ACK and vector["signature_valid"]:
                matches = [request for request in self.vectors if request["request_sha256"] == value["request_sha256"]]
                self.assertTrue(matches)
                for match in matches:
                    request = match["envelope"]
                    for ack_field, request_field in [("deployment_id", "deployment_id"),
                            ("device_id", "device_id"), ("request_schema_version", "schema_version"),
                            ("request_key_id", "signing_key_id"), ("request_sequence", "sequence")]:
                        self.assertEqual(value[ack_field], request[request_field])


if __name__ == "__main__":
    unittest.main()
