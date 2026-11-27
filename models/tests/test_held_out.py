"""Synthetic checks for ML06 metrics, guardrails, and the evaluation ledger."""

import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from device_audit_models import evaluation, held_out
from device_audit_models.held_out_metrics import Metrics, ScoredWindow, bootstrap, calibration_slope, operating_point


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = "logistic-baseline.backblaze-2013.v1.json"


class MetricTests(unittest.TestCase):
    def test_validation_budget_never_splits_a_tie(self):
        scores = [5, 5, 4, 4, 0, None]
        cutoff = operating_point(scores, 0.5)
        self.assertEqual(sum(score is not None and score >= cutoff for score in scores), 2)
        self.assertEqual(operating_point([None, None], 0.5), None)
        self.assertGreater(operating_point([0.3, 0.3, 0.1], 0.5), 0.3)

    def test_smart_score_uses_the_latest_complete_pair(self):
        samples = [{"smart_5_raw": 2, "smart_197_raw": 3}, {"smart_5_raw": 100, "smart_197_raw": None}]
        self.assertEqual(held_out.smart_score(samples), 5)
        self.assertIsNone(held_out.smart_score(samples[1:]))

    def test_tied_rankings_and_event_metrics(self):
        rows = [
            ScoredWindow("a", 1, 2, 1.0, 4),
            ScoredWindow("a", 1, 5, 1.0, None),
            ScoredWindow("b", 1, 4, -1.0, 4),
            ScoredWindow("c", 0, 0, 1.0, 0),
            ScoredWindow("c", 0, 0, -1.0, 0),
            ScoredWindow("d", 0, 0, -1.0, None),
        ]
        metrics = Metrics(rows, 0.2, 0.0, 1.1, 4, 7)
        result = metrics.measure(np.ones(4))
        self.assertAlmostEqual(result["average_precision"], (2 / 3 * 2 + 0.5) / 3)
        self.assertAlmostEqual(result["roc_auc"], 2 / 3)
        self.assertAlmostEqual(result["smart_rule_average_precision"], (2 + 0.5) / 3)
        self.assertEqual(result["prevalence_average_precision"], 0.5)
        self.assertEqual(result["event_recall_within_horizon"], 0.5)
        self.assertEqual(result["event_recall_minus_smart_rule"], -0.5)
        self.assertEqual(result["median_first_alert_lead_days"], 5)
        self.assertEqual(result["window_false_positive_rate_degraded"], 1 / 3)
        self.assertEqual(result["window_false_positive_rate_critical"], 0)
        self.assertEqual(result["never_positive_device_alert_fraction"], 0.5)
        # A sampled copy of a device contributes every window and one event.
        result = metrics.measure(np.array([2, 1, 0, 1]))
        self.assertEqual(result["event_recall_within_horizon"], 2 / 3)
        self.assertEqual(result["window_false_positive_rate_degraded"], 0)
        self.assertEqual(result["prevalence_average_precision"], 5 / 6)

    def test_calibration_fit_reports_undefined_slopes(self):
        logits = np.array([-1.0, 1.0])
        total = np.array([4.0, 4.0])
        self.assertAlmostEqual(calibration_slope(logits, np.array([1.0, 3.0]), total), np.log(3))
        self.assertIsNone(calibration_slope(logits, np.array([0.0, 4.0]), total))
        self.assertIsNone(calibration_slope(logits, np.array([0.0, 2.0]), total))

    def test_bootstrap_is_seeded_and_missing_alerts_have_no_lead(self):
        rows = [ScoredWindow("a", 1, 5, 1.0, 1), ScoredWindow("b", 0, 0, 0.0, 0)]
        metrics = Metrics(rows, 0.2, 2.0, 3.0, 1, 7)
        procedure = {"seed": 86, "replicates": 40, "interval": 0.95}
        result = bootstrap(metrics, procedure)
        self.assertEqual(result, bootstrap(metrics, procedure))
        self.assertEqual(result["median_first_alert_lead_days"],
                         {"point": None, "lower": None, "upper": None, "defined_replicates": 0})
        self.assertLess(result["roc_auc"]["defined_replicates"], procedure["replicates"])
        self.assertIs(type(result["roc_auc"]["lower"]), float)
        self.assertIs(type(result["roc_auc"]["upper"]), float)


class RecordedReportTests(unittest.TestCase):
    def test_recorded_gate_matches_the_pinned_policy(self):
        report = json.loads((ROOT / "evaluation/results" / CANDIDATE).read_bytes())
        policy = json.loads((ROOT / "evaluation/ml05-policy.json").read_bytes())
        artifact = (ROOT / "baseline/backblaze-2013/artifact.json").read_bytes()
        self.assertEqual(report["model"]["artifact_sha256"], held_out.baseline.sha256_bytes(artifact))
        self.assertEqual(report["test_evaluations_for_candidate"], 1)
        result = evaluation.evaluate_report(policy, report)
        self.assertEqual(result, report["gate"])
        self.assertEqual(result["status"], "fail")
        self.assertEqual({check["id"] for check in result["checks"] if check["status"] == "fail"},
                         {"baseline_average_precision", "brier_skill", "observed_expected_low",
                          "calibration_slope_low"})


class EvaluationCommandTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        for directory in ("baseline", "datasets"):
            shutil.copytree(ROOT / directory, self.root / directory)
        (self.root / "evaluation").mkdir()
        shutil.copy(ROOT / "evaluation/ml05-policy.json", self.root / "evaluation")
        self.archive = self.root / "data.zip"
        self.archive.write_bytes(b"bad archive")
        self.ledger = self.root / "evaluation/results" / CANDIDATE
        self.source_hash = json.loads((self.root / "datasets/backblaze-2013/policy.json").read_text())["source"]["sha256"]

    def invoke(self):
        with patch("sys.stdout", io.StringIO()) as stream:
            code = held_out.main(["--models-dir", str(self.root), "--archive", str(self.archive)])
        return code, json.loads(stream.getvalue())

    def test_archive_tampering_does_not_consume_test_run(self):
        code, report = self.invoke()
        self.assertEqual(code, evaluation.EXIT["blocked"])
        self.assertIn("SHA-256 mismatch", report["evaluation_error"])
        self.assertFalse(self.ledger.exists())

    def test_unusable_labels_block_and_the_version_cannot_be_evaluated_again(self):
        validation = [ScoredWindow("v", 0, 0, 0.0, 0)]
        test = [ScoredWindow("t", 0, 0, 0.0, 0)]
        with (patch.object(held_out.partitions, "sha256_file", return_value=self.source_hash),
              patch.object(held_out, "score_partitions", return_value=(validation, test)) as score):
            code, report = self.invoke()
            self.assertEqual(code, evaluation.EXIT["blocked"])
            self.assertIn("labels_unavailable", report["gate"]["blocking_reasons"])
            self.assertEqual(report["counts"]["test_positive_windows"], 0)
            first = self.ledger.read_bytes()
            code, duplicate = self.invoke()
            self.assertEqual(code, evaluation.EXIT["blocked"])
            self.assertIn("already reserved or evaluated", duplicate["evaluation_error"])
            self.assertEqual(self.ledger.read_bytes(), first)
            score.assert_called_once()

    def test_invalid_labels_after_reservation_are_saved_as_blocked(self):
        with (patch.object(held_out.partitions, "sha256_file", return_value=self.source_hash),
              patch.object(held_out, "score_partitions", side_effect=ValueError("missing or invalid event label"))):
            code, report = self.invoke()
        self.assertEqual(code, evaluation.EXIT["blocked"])
        self.assertIn("invalid event label", report["evaluation_error"])
        self.assertEqual(json.loads(self.ledger.read_bytes()), report)


if __name__ == "__main__":
    unittest.main()
