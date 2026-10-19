"""Run the versioned Go/schema/Python conformance catalogue and write evidence."""
import argparse
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "models/tests"))
from test_contract_conformance import CONTRACTS, load_catalogue
from test_envelope_contracts import strict_loads


def run(catalogue_path, go, report_path):
    report_path.unlink(missing_ok=True)
    catalogue, validators = load_catalogue(catalogue_path)
    if not catalogue["suites"]:
        raise ValueError("empty conformance catalogue")
    known_fixtures = set(CONTRACTS.glob("fixtures/*/*vectors.json"))
    declared_fixtures = {CONTRACTS / "fixtures" / s["fixture"] for s in catalogue["suites"]}
    wire_path = CONTRACTS / catalogue["wire_vectors"]
    if known_fixtures != declared_fixtures | {wire_path}:
        raise ValueError("fixture inventory differs from catalogue")
    declared_schemas = {CONTRACTS / filename for s in catalogue["suites"] for filename in s["schemas"].values()}
    if declared_schemas != set(CONTRACTS.glob("*.schema.json")):
        raise ValueError("schema inventory differs from catalogue")

    suites = []
    python_names = ["test_contract_conformance.ContractConformanceTests"]
    for suite in catalogue["suites"]:
        path = CONTRACTS / "fixtures" / suite["fixture"]
        source = strict_loads(path.read_text())
        vectors = source["vectors"]
        names = [v["name"] for v in vectors]
        if not names or len(set(names)) != len(names):
            raise ValueError(f"empty or duplicate vector names in {path}")
        for vector in vectors:
            expected = vector[suite["schema_valid_field"]]
            if type(vector[suite["valid_field"]]) is not bool:
                raise ValueError(f"contract expectation is not boolean: {vector['name']}")
            if type(expected) is not bool:
                raise ValueError(f"schema expectation is not boolean: {vector['name']}")
            payload = vector[suite["payload_field"]]
            candidates = [validators[version] for version in suite["schemas"]]
            actual = any(validator.is_valid(payload) for validator in candidates)
            if actual != expected:
                raise ValueError(f"{suite['name']}/{vector['name']}: schema accepted={actual}, expected={expected}")
        if not suite["python_tests"]:
            raise ValueError(f"missing Python reader tests for {suite['name']}")
        python_names.extend(suite["python_tests"])
        suites.append(dict(name=suite["name"], fixture=suite["fixture"],
                           fixture_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                           vectors=len(vectors),
                           contract_valid=sum(v[suite["valid_field"]] for v in vectors),
                           go_test=suite["go_test"],
                           python_tests=suite["python_tests"]))

    completed = subprocess.run([go, "test", "-count=1", "-json", "./packages/contracts"],
                               cwd=ROOT, capture_output=True, text=True, timeout=180)
    if completed.returncode:
        sys.stderr.write(completed.stdout + completed.stderr)
        raise RuntimeError("Go contract checks failed")
    events = [json.loads(line) for line in completed.stdout.splitlines()]
    for suite in suites:
        prefix = suite["go_test"] + "/"
        passed = [e for e in events if e["Action"] == "pass" and e.get("Test", "").startswith(prefix)]
        if len(passed) != suite["vectors"]:
            raise ValueError(f"{suite['name']}: Go ran {len(passed)} vectors, expected {suite['vectors']}")
    wire = strict_loads(wire_path.read_text())
    passed = [e for e in events if e["Action"] == "pass" and e.get("Test", "").startswith("TestContractWireVectors/")]
    if len(passed) != len(wire["vectors"]):
        raise ValueError("Go wire vector count differs from the shared file")

    tests = unittest.defaultTestLoader.loadTestsFromNames(python_names)
    result = unittest.TextTestRunner(verbosity=1).run(tests)
    if not result.wasSuccessful():
        raise RuntimeError("Python reader checks failed")
    schema_hashes = {str(p.relative_to(CONTRACTS)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(declared_schemas)}
    report = dict(schema_version="device-audit.conformance-report.v1", status="passed",
                  go_version=subprocess.check_output([go, "version"], cwd=ROOT, text=True).strip(),
                  python_version=sys.version.split()[0], jsonschema_version=version("jsonschema"),
                  catalogue_sha256=hashlib.sha256(catalogue_path.read_bytes()).hexdigest(),
                  suites=suites,
                  schema_sha256=schema_hashes,
                  wire_vectors=len(wire["vectors"]),
                  wire_sha256=hashlib.sha256(wire_path.read_bytes()).hexdigest(),
                  verified_wire_expectations=[{key: v[key] for key in
                      ("name", "reader_version", "expected_schema", "expected_go", "expected_python")}
                      for v in wire["vectors"]],
                  python_tests=result.testsRun,
                  limitations=["Python does not authenticate signatures",
                               "Schema acceptance is not semantic validation",
                               "No runtime authorization or durable replay storage tested"])
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Conformance passed: {sum(s['vectors'] for s in suites)} golden vectors, "
          f"{len(wire['vectors'])} wire cases, {len(validators)} reader versions.")
    print(f"Report: {report_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalogue", type=Path, default=CONTRACTS / "conformance-v1.json")
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--report", type=Path, default=ROOT / "artifacts/contracts/conformance-v1-report.json")
    args = parser.parse_args()
    try:
        run(args.catalogue, args.go, args.report)
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Conformance failed: {error}\n")


if __name__ == "__main__":
    main()
