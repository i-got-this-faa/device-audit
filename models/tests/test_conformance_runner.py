"""Exercise the real conformance command with deliberately broken declarations."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ConformanceRunnerFailureTests(unittest.TestCase):
    def test_schema_expectations_cannot_substitute_semantic_validity(self):
        catalogue = json.loads((ROOT / "packages/contracts/conformance-v1.json").read_text())
        envelopes = next(s for s in catalogue["suites"] if s["name"] == "envelopes-v1")
        envelopes["schema_valid_field"] = "contract_valid"
        self.assert_failed_run(catalogue, "schema accepted=True, expected=False")

    def test_missing_go_reader_cannot_pass_without_running_vectors(self):
        catalogue = json.loads((ROOT / "packages/contracts/conformance-v1.json").read_text())
        catalogue["suites"][0]["go_test"] = "TestUnregisteredReader"
        self.assert_failed_run(catalogue, "Go ran 0 vectors, expected")

    def assert_failed_run(self, catalogue, expected_error):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalogue.json"
            path.write_text(json.dumps(catalogue))
            report = Path(directory) / "report.json"
            report.write_text('{"status":"passed","stale":true}')
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/contract_conformance.py"),
                 "--catalogue", str(path), "--report", str(report)],
                cwd=ROOT, capture_output=True, text=True, timeout=180,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn(expected_error, result.stderr)
            self.assertFalse(report.exists(), "failed run left a stale passing report")


if __name__ == "__main__":
    unittest.main()
