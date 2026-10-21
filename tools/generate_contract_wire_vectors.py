"""Derive test-only wire cases from existing golden fixtures, without signing keys."""
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "packages/contracts"


def main():
    catalogue = json.loads((CONTRACTS / "conformance-v1.json").read_text(encoding="utf-8"))
    vectors = []

    def add(name, version, wire, schema="accepted", go="accepted", python="accepted", **context):
        vectors.append(dict(name=name, reader_version=version, wire=wire,
                            expected_schema=schema, expected_go=go,
                            expected_python=python, **context))

    for suite in catalogue["suites"]:
        collection = json.loads((CONTRACTS / "fixtures" / suite["fixture"]).read_text(encoding="utf-8"))
        for version in suite["schemas"]:
            source = next(v for v in collection["vectors"]
                          if v[suite["valid_field"]]
                          and v[suite["payload_field"]]["schema_version"] == version
                          and ("canonical_hex" not in v or v["signature_valid"] or not v["canonical_hex"]))
            payload = source[suite["payload_field"]]
            context = {}
            if source.get("canonical_hex"):
                context["canonical_hex"] = source["canonical_hex"]
                context["verification_key"] = source.get("verification_key", source.get("public_key", collection.get("verification_key")))
                if context["verification_key"] is None:
                    raise ValueError(f"missing verification key for {version}")
            add("valid/" + version, version, json.dumps(payload, separators=(",", ":")), **context)
            incompatible = copy.deepcopy(payload)
            incompatible["schema_version"] = version.rsplit(".", 1)[0] + ".v999"
            add("unsupported/" + version, version, json.dumps(incompatible),
                schema="unsupported_schema", go="unsupported_schema", python="unsupported_schema")

    envelopes = json.loads((CONTRACTS / "fixtures/envelopes/v1-vectors.json").read_text(encoding="utf-8"))["vectors"]
    for name in ["enrollment freshness sequence already consumed",
                 "replayed evidence after lost acknowledgement",
                 "replayed evidence after controller restart", "expired at exact boundary",
                 "expiry precedes replay classification", "future timestamp beyond skew",
                 "future timestamp exact skew allowed"]:
        source = next(v for v in envelopes if v["name"] == name)
        payload = source["envelope"]
        outcome = source["freshness_rejection"] or "accepted"
        add(name, payload["schema_version"], json.dumps(payload), go=outcome, python=outcome,
            canonical_hex=source["canonical_hex"], verification_key=source["verification_key"],
            now=source["now"], last_sequence=source["last_sequence"])

    for name in ["equal validity timestamps", "zero year timestamp", "altered payload stale digest"]:
        source = next(v for v in envelopes if v["name"] == name)
        add(name, source["envelope"]["schema_version"], json.dumps(source["envelope"]),
            go="invalid_contract", python="invalid_contract")
    for name in ["wrong enrollment key", "altered enrollment challenge"]:
        source = next(v for v in envelopes if v["name"] == name)
        add(name, source["envelope"]["schema_version"], json.dumps(source["envelope"]),
            go=source["signature_error"], verification_key=source["verification_key"])

    enrollment = envelopes[0]["envelope"]
    version = enrollment["schema_version"]
    wire = json.dumps(enrollment, separators=(",", ":"))
    add("duplicate_sequence", version, wire[:-1] + ',"sequence":1}',
        go="invalid_json", python="invalid_json")
    add("fractional_sequence_token", version, wire.replace('"sequence":1', '"sequence":1.0'),
        go="invalid_contract", python="invalid_contract")
    for name, malformed in [("trailing_json", wire + " {}"), ("truncated_json", wire[:-1])]:
        add(name, version, malformed, schema="invalid_json", go="invalid_json", python="invalid_json")
    escaped = json.dumps(dict(reversed(list(enrollment.items())))).replace("asset:fixture-01", r"\u0061sset:fixture-01")
    add("nonfinite_json_constant", version, wire.replace('"sequence":1', '"sequence":NaN'),
        schema="invalid_json", go="invalid_json", python="invalid_json")
    add("property_order_and_escapes", version, escaped,
        canonical_hex=envelopes[0]["canonical_hex"], verification_key=envelopes[0]["verification_key"])

    telemetry = json.loads((CONTRACTS / "fixtures/telemetry/v2-vectors.json").read_text(encoding="utf-8"))["vectors"][0]["telemetry"]
    add("v2_sent_to_v1_reader", "device-audit.v1", json.dumps(telemetry),
        schema="unsupported_schema", go="unsupported_schema", python="unsupported_schema")
    telemetry = copy.deepcopy(telemetry)
    del telemetry["metrics"]["gpu_utilization"]["missing_reason"]
    add("null_metric_without_reason", "device-audit.telemetry.v2", json.dumps(telemetry),
        schema="invalid_contract", go="invalid_contract", python="invalid_contract")
    path = CONTRACTS / catalogue["wire_vectors"]
    path.write_text(json.dumps(dict(schema_version="device-audit.conformance-wire.v1", vectors=vectors), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
