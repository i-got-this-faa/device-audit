"""ML05 gate checks. Every report here is synthetic and measures no model."""

import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from device_audit_models.evaluation import (
    BOUNDS, GATE_KINDS, RESOURCE_LIMITS, check_resources, evaluate_report, main,
    policy_sha256, validate_policy, verify_pins,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "evaluation/ml05-policy.json"
DATASET = ROOT / "datasets/backblaze-2013"


def load_policy():
    return json.loads(POLICY.read_text())


def passing_metric(gate):
    """Return an interval that clears one gate by a small margin."""
    step = 0.01 if gate["op"] in (">", ">=") else -0.01
    value = gate["value"] + step
    if gate["bound"] == "lower":
        return {"point": value + abs(step), "lower": value, "upper": value + 2 * abs(step)}
    if gate["bound"] == "upper":
        return {"point": value - abs(step), "lower": value - 2 * abs(step), "upper": value}
    return {"point": value, "lower": value - abs(step), "upper": value + abs(step)}


def passing_report(policy):
    metrics = {}
    for gate in policy["gates"]:
        if gate["metric"] in metrics:
            continue
        # Two-sided point gates need a value inside both limits.
        siblings = [g for g in policy["gates"] if g["metric"] == gate["metric"]]
        if len(siblings) == 2 and all(g["bound"] == "point" for g in siblings):
            middle = sum(g["value"] for g in siblings) / 2
            metrics[gate["metric"]] = {"point": middle, "lower": middle - 0.1, "upper": middle + 0.1}
        else:
            metrics[gate["metric"]] = passing_metric(gate)
    counts = {name: minimum for name, minimum in policy["minimum_evidence"].items()}
    return {
        "schema_version": "device-audit.evaluation-report.v1",
        "policy_sha256": policy_sha256(policy),
        "partition_manifest_sha256": policy["study"]["partition_manifest_sha256"],
        "partition": "test",
        "horizon_hours": 168,
        "test_evaluations_for_candidate": 1,
        "bootstrap": copy.deepcopy(policy["procedure"]["bootstrap"]),
        "model": {"version": "synthetic-candidate", "artifact_sha256": "0" * 64},
        "label_status": "both_classes_present",
        "counts": counts,
        "metrics": metrics,
    }


def resource_report(policy, kind):
    budgets = policy["resource_budgets"]
    target = budgets["target"]
    section = budgets[kind]
    report = {"schema_version": "device-audit.resource-report.v1", "policy_sha256": policy_sha256(policy),
              "budget": kind}
    for field, key, op in RESOURCE_LIMITS[kind]:
        limit = section["negative_subsampling"][key] if key == "min_keep_rate" else section[key]
        report[field] = limit
    if kind.startswith("endpoint_"):
        report["host"] = {"physical": True, **{k: target[k] for k in ("cpu_model", "logical_processors", "os_build_family")}}
    if kind == "endpoint_inference":
        report["predictions"] = section["min_measured_predictions"]
        report["concurrent_sampling_cadence_seconds"] = section["concurrent_sampling_cadence_seconds"]
    if kind == "endpoint_training":
        report["on_ac_power"] = True
    if kind == "central_training":
        report["positives_subsampled"] = False
    return report


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()

    def test_committed_policy_pins_ml01_evidence(self):
        validate_policy(self.policy)
        partition_policy = json.loads((DATASET / "policy.json").read_text())
        manifest = (DATASET / "partitions.json").read_bytes()
        self.assertEqual(verify_pins(self.policy, partition_policy, manifest), [])
        changed = dict(partition_policy, horizon_days=14)
        self.assertTrue(verify_pins(self.policy, changed, manifest))
        self.assertTrue(verify_pins(self.policy, partition_policy, manifest + b" "))

    def test_all_metric_families_have_numeric_thresholds(self):
        kinds = {gate["kind"] for gate in self.policy["gates"]}
        self.assertEqual(kinds, set(GATE_KINDS))
        for gate in self.policy["gates"]:
            self.assertIn(gate["bound"], BOUNDS)
            self.assertIsInstance(gate["value"], (int, float))
        self.assertEqual(self.policy["study"]["horizon_hours"], 168)

    def test_real_test_partition_meets_minimum_but_validation_positives_do_not(self):
        manifest = json.loads((DATASET / "partitions.json").read_text())
        minimum = self.policy["minimum_evidence"]
        test, validation = manifest["partitions"]["test"], manifest["partitions"]["validation"]
        self.assertGreaterEqual(test["positive_event_count"], minimum["test_positive_events"])
        self.assertGreaterEqual(test["labels"]["1"], minimum["test_positive_windows"])
        self.assertGreaterEqual(test["labels"]["0"], minimum["test_negative_windows"])
        self.assertGreaterEqual(test["device_count"], minimum["test_devices"])
        self.assertGreaterEqual(validation["labels"]["0"], minimum["validation_negative_windows"])
        # Four validation events: positives may not tune or calibrate anything.
        self.assertLess(validation["positive_event_count"],
                        self.policy["procedure"]["validation_positive_use_min_events"])
        self.assertEqual(self.policy["procedure"]["operating_point_uses"], "validation_negative_scores_only")

    def test_policy_rejects_weakened_procedures(self):
        mutations = [
            lambda p: p.update(declared_before_fit=False),
            lambda p: p["procedure"].update(evaluation_partition="validation"),
            lambda p: p["procedure"].update(max_test_evaluations_per_candidate=3),
            lambda p: p["procedure"].update(example_sampling="balanced"),
            lambda p: p["procedure"].update(operating_point_uses="test_scores"),
            lambda p: p["procedure"]["bootstrap"].update(unit="window"),
            lambda p: p["procedure"]["bootstrap"].update(replicates=100),
            lambda p: p["minimum_evidence"].update(test_positive_events=0),
            lambda p: p.update(gates=[g for g in p["gates"] if g["kind"] != "calibration"]),
            lambda p: p["gates"][0].update(value=None),
            lambda p: p["gates"][0].update(op="~"),
            lambda p: p["gates"].append(dict(p["gates"][0])),
            lambda p: p["resource_budgets"]["endpoint_inference"].update(timeout_ms=1, latency_p95_max_ms=None),
            lambda p: p["resource_budgets"]["central_training"]["negative_subsampling"].update(min_keep_rate=0),
        ]
        for mutate in mutations:
            policy = load_policy()
            mutate(policy)
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, KeyError)):
                validate_policy(policy)


class EvaluationGateTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()
        self.report = passing_report(self.policy)

    def gate(self, report=None):
        return evaluate_report(self.policy, report or self.report)

    def test_synthetic_passing_report_passes_every_gate(self):
        result = self.gate()
        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(len(result["checks"]), len(self.policy["gates"]))

    def test_each_missed_threshold_fails(self):
        for gate in self.policy["gates"]:
            report = copy.deepcopy(self.report)
            push = -1.0 if gate["op"] in (">", ">=") else 1.0
            missed = gate["value"] + push * 0.5
            report["metrics"][gate["metric"]] = {bound: missed for bound in BOUNDS}
            with self.subTest(gate=gate["id"]):
                result = self.gate(report)
                failed = {c["id"] for c in result["checks"] if c["status"] == "fail"}
                self.assertIn(gate["id"], failed)
                self.assertNotEqual(result["status"], "pass")

    def test_boundary_values_follow_declared_operator(self):
        gate = next(g for g in self.policy["gates"] if g["id"] == "baseline_average_precision")
        report = copy.deepcopy(self.report)
        report["metrics"][gate["metric"]] = {"point": 0.1, "lower": 0.0, "upper": 0.2}
        self.assertEqual(self.gate(report)["status"], "fail")  # strict '>' at zero
        gate = next(g for g in self.policy["gates"] if g["id"] == "window_fpr_degraded")
        report = copy.deepcopy(self.report)
        report["metrics"][gate["metric"]] = {"point": 0.005, "lower": 0.004, "upper": 0.01}
        self.assertEqual(self.gate(report)["status"], "pass")

    def test_insufficient_labels_block_instead_of_relaxing(self):
        cases = {
            "insufficient:test_positive_events": lambda r: r["counts"].update(test_positive_events=4),
            "missing_count:test_devices": lambda r: r["counts"].pop("test_devices"),
            "labels_unavailable": lambda r: r.update(label_status="blocked_missing_class"),
            "insufficient:validation_negative_windows": lambda r: r["counts"].update(validation_negative_windows=10),
        }
        for reason, mutate in cases.items():
            report = copy.deepcopy(self.report)
            mutate(report)
            with self.subTest(reason=reason):
                result = self.gate(report)
                self.assertEqual(result["status"], "blocked")
                self.assertIn(reason, result["blocking_reasons"])
                # Threshold checks are still reported at their declared values.
                self.assertEqual([c["threshold"] for c in result["checks"]],
                                 [g["value"] for g in self.policy["gates"]])

    def test_unavailable_metrics_block(self):
        for change in ({"calibration_slope": None},
                       {"calibration_slope": {"point": 1.0}},
                       {"roc_auc": {"point": 0.8, "lower": None, "upper": 0.9}},
                       {"event_recall_within_horizon": {"point": float("nan"), "lower": 0.2, "upper": 0.5}}):
            report = copy.deepcopy(self.report)
            report["metrics"].update(change)
            with self.subTest(change=change):
                self.assertEqual(self.gate(report)["status"], "blocked")
        report = copy.deepcopy(self.report)
        del report["metrics"]
        self.assertEqual(self.gate(report)["status"], "blocked")

    def test_failed_and_blocked_together_stay_blocked(self):
        report = copy.deepcopy(self.report)
        report["metrics"]["roc_auc"] = {"point": 0.5, "lower": 0.4, "upper": 0.6}
        report["counts"]["test_positive_events"] = 1
        result = self.gate(report)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("fail", {c["status"] for c in result["checks"]})

    def test_procedure_deviations_block(self):
        cases = {
            "policy_mismatch": lambda r: r.update(policy_sha256="f" * 64),
            "partition_manifest_mismatch": lambda r: r.update(partition_manifest_sha256="e" * 64),
            "not_held_out_partition": lambda r: r.update(partition="validation"),
            "horizon_mismatch": lambda r: r.update(horizon_hours=336),
            "held_out_reuse_or_unrecorded": lambda r: r.update(test_evaluations_for_candidate=2),
            "bootstrap_procedure_mismatch": lambda r: r["bootstrap"].update(seed=7),
            "model_provenance_missing": lambda r: r.update(model={"version": "x"}),
            "unsupported_report_schema": lambda r: r.update(schema_version="v0"),
            "inconsistent_interval:roc_auc": lambda r: r["metrics"].update(
                roc_auc={"point": 0.9, "lower": 0.95, "upper": 0.99}),
        }
        for reason, mutate in cases.items():
            report = copy.deepcopy(self.report)
            mutate(report)
            with self.subTest(reason=reason):
                result = self.gate(report)
                self.assertEqual(result["status"], "blocked")
                self.assertIn(reason, result["blocking_reasons"])

    def test_policy_change_invalidates_existing_report(self):
        relaxed = load_policy()
        next(g for g in relaxed["gates"] if g["id"] == "discrimination_roc_auc")["value"] = 0.5
        result = evaluate_report(relaxed, self.report)
        self.assertIn("policy_mismatch", result["blocking_reasons"])


class ResourceGateTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()

    def test_reports_at_budget_pass(self):
        for kind in RESOURCE_LIMITS:
            with self.subTest(kind=kind):
                self.assertEqual(check_resources(self.policy, resource_report(self.policy, kind))["status"], "pass")

    def test_budget_breach_fails(self):
        cases = [("endpoint_inference", "latency_p95_ms", 201), ("endpoint_inference", "peak_working_set_bytes", 2**26 + 1),
                 ("endpoint_inference", "prediction_interval_seconds", 60),
                 ("endpoint_training", "wall_seconds", 601), ("central_training", "peak_rss_bytes", 2**32 + 1),
                 ("central_training", "negative_keep_rate", 0.01)]
        for kind, field, value in cases:
            report = resource_report(self.policy, kind)
            report[field] = value
            with self.subTest(field=field):
                result = check_resources(self.policy, report)
                self.assertEqual(result["status"], "fail")
                self.assertEqual({c["id"] for c in result["checks"] if c["status"] == "fail"}, {field})

    def test_unmeasured_or_wrong_hardware_blocks(self):
        cases = [
            ("endpoint_inference", "not_physical_target", lambda r: r["host"].update(physical=False)),
            ("endpoint_inference", "target_mismatch:cpu_model", lambda r: r["host"].update(cpu_model="AMD EPYC 7763 64-Core Processor")),
            ("endpoint_inference", "target_mismatch:os_build_family", lambda r: r["host"].update(os_build_family=26100)),
            ("endpoint_inference", "insufficient:predictions", lambda r: r.update(predictions=3)),
            ("endpoint_inference", "not_measured_under_concurrent_sampling", lambda r: r.pop("concurrent_sampling_cadence_seconds")),
            ("endpoint_training", "not_on_ac_power", lambda r: r.update(on_ac_power=None)),
            ("central_training", "positives_subsampled_or_unrecorded", lambda r: r.update(positives_subsampled=True)),
            ("central_training", "policy_mismatch", lambda r: r.update(policy_sha256="0" * 64)),
        ]
        for kind, reason, mutate in cases:
            report = resource_report(self.policy, kind)
            mutate(report)
            with self.subTest(reason=reason):
                result = check_resources(self.policy, report)
                self.assertEqual(result["status"], "blocked")
                self.assertIn(reason, result["blocking_reasons"])
        report = resource_report(self.policy, "endpoint_inference")
        report["latency_p95_ms"] = None
        self.assertEqual(check_resources(self.policy, report)["status"], "blocked")
        self.assertEqual(check_resources(self.policy, {"budget": "gpu"})["status"], "blocked")

    def test_budgets_fit_measured_target(self):
        budgets = self.policy["resource_budgets"]
        target = budgets["target"]
        inference = budgets["endpoint_inference"]
        # 64 MiB is under 0.5% of OS-visible memory and under the 98.58 MiB
        # PowerShell probe worker peak recorded on this laptop on 19 October.
        self.assertLess(inference["peak_working_set_max_bytes"] / (target["os_visible_memory_gib"] * 2**30), 0.005)
        self.assertLess(inference["peak_working_set_max_bytes"], 98.58 * 2**20)
        # One prediction per hour at 250 ms CPU is under 0.01% of one core.
        self.assertLess(inference["cpu_ms_per_prediction_max"] / (inference["min_interval_seconds"] * 1000), 0.0001)
        self.assertLess(inference["latency_max_ms"], inference["timeout_ms"])
        self.assertLess(inference["timeout_ms"], inference["concurrent_sampling_cadence_seconds"] * 1000)
        self.assertLessEqual(budgets["endpoint_training"]["max_logical_processors"], target["logical_processors"] // 4)


class CommandTests(unittest.TestCase):
    def run_main(self, *args):
        with patch("sys.stdout", io.StringIO()) as stream:
            code = main(["--policy", str(POLICY), *args])
        return code, stream.getvalue()

    def test_exit_codes(self):
        code, out = self.run_main("--verify-pins", str(DATASET / "policy.json"), str(DATASET / "partitions.json"))
        self.assertEqual(code, 0, out)
        policy = load_policy()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            report = passing_report(policy)
            path.write_text(json.dumps(report))
            self.assertEqual(self.run_main("--report", str(path))[0], 0)
            report["metrics"]["roc_auc"] = {"point": 0.6, "lower": 0.5, "upper": 0.7}
            path.write_text(json.dumps(report))
            self.assertEqual(self.run_main("--report", str(path))[0], 1)
            report["counts"]["test_positive_events"] = 4
            path.write_text(json.dumps(report))
            code, out = self.run_main("--report", str(path))
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out)["status"], "blocked")
            path.write_text(json.dumps(resource_report(policy, "central_training")))
            self.assertEqual(self.run_main("--resources", str(path))[0], 0)


if __name__ == "__main__":
    unittest.main()
