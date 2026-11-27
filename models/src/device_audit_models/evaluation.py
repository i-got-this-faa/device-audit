"""ML05 predeclared evaluation and resource gates.

This module checks reports against a committed policy. It computes no model
metric and trains nothing. Missing labels, data or measurements are a
``blocked`` result: no threshold is relaxed to turn them into a pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

from device_audit_models.partitions import canonical


POLICY_VERSION = "device-audit.evaluation-policy.v1"
REPORT_VERSION = "device-audit.evaluation-report.v1"
RESOURCE_VERSION = "device-audit.resource-report.v1"
GATE_VERSION = "device-audit.evaluation-gate.v1"
BOUNDS = ("point", "lower", "upper")
OPS = {">": lambda a, b: a > b, ">=": lambda a, b: a >= b,
       "<": lambda a, b: a < b, "<=": lambda a, b: a <= b}
GATE_KINDS = ("baseline", "false_positive", "calibration", "horizon")
EXIT = {"pass": 0, "fail": 1, "blocked": 2}

# (report field, budget key, comparison). Every field must be measured.
RESOURCE_LIMITS = {
    "endpoint_inference": (
        ("artifact_bytes", "artifact_max_bytes", "<="),
        ("peak_working_set_bytes", "peak_working_set_max_bytes", "<="),
        ("latency_p95_ms", "latency_p95_max_ms", "<="),
        ("latency_max_ms", "latency_max_ms", "<="),
        ("cpu_ms_per_prediction_max", "cpu_ms_per_prediction_max", "<="),
        ("max_sweep_start_delay_ms", "max_sweep_start_delay_ms", "<="),
        ("prediction_interval_seconds", "min_interval_seconds", ">="),
    ),
    "endpoint_training": (
        ("peak_working_set_bytes", "peak_working_set_max_bytes", "<="),
        ("logical_processors_used", "max_logical_processors", "<="),
        ("wall_seconds", "wall_seconds_max", "<="),
        ("round_interval_seconds", "min_interval_seconds", ">="),
    ),
    "central_training": (
        ("wall_seconds", "wall_seconds_max", "<="),
        ("peak_rss_bytes", "peak_rss_max_bytes", "<="),
        ("logical_processors_used", "max_logical_processors", "<="),
        ("negative_keep_rate", "min_keep_rate", ">="),
    ),
}


def policy_sha256(policy: dict) -> str:
    return hashlib.sha256(canonical(policy)).hexdigest()


def _number(value: object) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def validate_policy(policy: dict) -> dict:
    """Reject a policy that could not gate anything or that weakens itself."""
    if policy.get("schema_version") != POLICY_VERSION or policy.get("declared_before_fit") is not True:
        raise ValueError("unsupported evaluation policy or not declared before fitting")
    study = policy["study"]
    for key in ("partition_policy_sha256", "partition_manifest_sha256"):
        if not isinstance(study.get(key), str) or len(study[key]) != 64:
            raise ValueError(f"study requires {key}")
    if type(study.get("horizon_hours")) is not int or study["horizon_hours"] <= 0:
        raise ValueError("study requires a positive integer horizon")
    procedure = policy["procedure"]
    if procedure.get("evaluation_partition") != "test" or procedure.get("example_sampling") != "none":
        raise ValueError("evaluation must use every test example")
    if procedure.get("max_test_evaluations_per_candidate") != 1:
        raise ValueError("the held-out partition may be evaluated once per candidate")
    if procedure.get("operating_point_uses") != "validation_negative_scores_only":
        raise ValueError("operating points must not use held-out or validation positives")
    boot = procedure.get("bootstrap", {})
    if boot.get("unit") != "device" or type(boot.get("replicates")) is not int or boot["replicates"] < 1000:
        raise ValueError("device-clustered bootstrap with at least 1000 replicates is required")
    for name, value in policy["minimum_evidence"].items():
        if type(value) is not int or value < 1:
            raise ValueError(f"minimum evidence {name} must be a positive integer")
    seen, kinds = set(), set()
    for gate in policy["gates"]:
        if (gate.get("id") in seen or gate.get("kind") not in GATE_KINDS
                or gate.get("bound") not in BOUNDS or gate.get("op") not in OPS
                or not _number(gate.get("value")) or not gate.get("metric")):
            raise ValueError(f"invalid gate {gate.get('id')!r}")
        seen.add(gate["id"])
        kinds.add(gate["kind"])
    if kinds != set(GATE_KINDS):
        raise ValueError("baseline, false-positive, calibration and horizon gates are all required")
    budgets = policy["resource_budgets"]
    for kind, limits in RESOURCE_LIMITS.items():
        section = budgets[kind]
        for _, key, _ in limits:
            source = section["negative_subsampling"] if key == "min_keep_rate" else section
            if not _number(source.get(key)) or source[key] <= 0:
                raise ValueError(f"resource budget {kind}.{key} must be a positive number")
    return policy


def _result(status_checks: list[dict], blocking: list[str], extra: dict) -> dict:
    statuses = {check["status"] for check in status_checks}
    if blocking or "blocked" in statuses:
        status = "blocked"
    elif "fail" in statuses:
        status = "fail"
    else:
        status = "pass"
    return {"schema_version": GATE_VERSION, "status": status,
            "blocking_reasons": sorted(set(blocking)), "checks": status_checks, **extra}


def _compare(check_id: str, observed: object, op: str, threshold: float, **extra) -> dict:
    entry = {"id": check_id, "op": op, "threshold": threshold, "observed": observed, **extra}
    if not _number(observed):
        entry["status"] = "blocked"
    else:
        entry["status"] = "pass" if OPS[op](observed, threshold) else "fail"
    return entry


def evaluate_report(policy: dict, report: dict) -> dict:
    """Return pass, fail or blocked for an ML06 held-out evaluation report."""
    validate_policy(policy)
    digest = policy_sha256(policy)
    blocking = []
    if report.get("schema_version") != REPORT_VERSION:
        blocking.append("unsupported_report_schema")
    if report.get("policy_sha256") != digest:
        blocking.append("policy_mismatch")
    study, procedure = policy["study"], policy["procedure"]
    if report.get("partition_manifest_sha256") != study["partition_manifest_sha256"]:
        blocking.append("partition_manifest_mismatch")
    if report.get("partition") != procedure["evaluation_partition"]:
        blocking.append("not_held_out_partition")
    if report.get("horizon_hours") != study["horizon_hours"]:
        blocking.append("horizon_mismatch")
    evaluations = report.get("test_evaluations_for_candidate")
    if type(evaluations) is not int or not 1 <= evaluations <= procedure["max_test_evaluations_per_candidate"]:
        blocking.append("held_out_reuse_or_unrecorded")
    if report.get("bootstrap") != procedure["bootstrap"]:
        blocking.append("bootstrap_procedure_mismatch")
    model = report.get("model") or {}
    if not model.get("version") or not isinstance(model.get("artifact_sha256"), str) \
            or len(model["artifact_sha256"]) != 64:
        blocking.append("model_provenance_missing")
    if report.get("label_status") != "both_classes_present":
        blocking.append("labels_unavailable")
    if report.get("evaluation_error"):
        blocking.append("evaluation_error")
    counts = report.get("counts") or {}
    for name, minimum in policy["minimum_evidence"].items():
        value = counts.get(name)
        if type(value) is not int:
            blocking.append(f"missing_count:{name}")
        elif value < minimum:
            blocking.append(f"insufficient:{name}")

    metrics = report.get("metrics") or {}
    for metric in {gate["metric"] for gate in policy["gates"]}:
        interval = metrics.get(metric)
        if not isinstance(interval, dict) or not all(_number(interval.get(bound)) for bound in BOUNDS):
            blocking.append(f"missing_interval:{metric}")
        elif not interval["lower"] <= interval["point"] <= interval["upper"]:
            blocking.append(f"inconsistent_interval:{metric}")
    checks = []
    for gate in policy["gates"]:
        interval = metrics.get(gate["metric"])
        observed = interval.get(gate["bound"]) if isinstance(interval, dict) else None
        checks.append(_compare(gate["id"], observed, gate["op"], gate["value"],
                               kind=gate["kind"], metric=gate["metric"], bound=gate["bound"]))
    return _result(checks, blocking, {"evaluation": "held_out", "policy_sha256": digest,
                                      "model": model or None, "counts": counts})


def check_resources(policy: dict, report: dict) -> dict:
    """Compare a resource report with the declared budget for its kind."""
    validate_policy(policy)
    digest = policy_sha256(policy)
    budgets = policy["resource_budgets"]
    kind = report.get("budget")
    blocking = []
    if report.get("schema_version") != RESOURCE_VERSION:
        blocking.append("unsupported_report_schema")
    if report.get("policy_sha256") != digest:
        blocking.append("policy_mismatch")
    if kind not in RESOURCE_LIMITS:
        return _result([], blocking + ["unknown_budget"], {"evaluation": "resources", "policy_sha256": digest})
    section = budgets[kind]
    host = report.get("host") or {}
    if kind.startswith("endpoint_"):
        target = budgets["target"]
        if host.get("physical") is not True:
            blocking.append("not_physical_target")
        for key in ("cpu_model", "logical_processors", "os_build_family"):
            if host.get(key) != target[key]:
                blocking.append(f"target_mismatch:{key}")
    if kind == "endpoint_inference":
        if type(report.get("predictions")) is not int or report["predictions"] < section["min_measured_predictions"]:
            blocking.append("insufficient:predictions")
        if report.get("concurrent_sampling_cadence_seconds") != section["concurrent_sampling_cadence_seconds"]:
            blocking.append("not_measured_under_concurrent_sampling")
    if kind == "endpoint_training" and report.get("on_ac_power") is not True:
        blocking.append("not_on_ac_power")
    if kind == "central_training" and report.get("positives_subsampled") is not False:
        blocking.append("positives_subsampled_or_unrecorded")
    checks = []
    for field, key, op in RESOURCE_LIMITS[kind]:
        limit = section["negative_subsampling"][key] if key == "min_keep_rate" else section[key]
        checks.append(_compare(field, report.get(field), op, limit))
    return _result(checks, blocking, {"evaluation": "resources", "budget": kind, "policy_sha256": digest})


def verify_pins(policy: dict, partition_policy: dict, manifest_bytes: bytes) -> list[str]:
    """Return mismatches between the evaluation policy and the ML01 evidence."""
    validate_policy(policy)
    study = policy["study"]
    errors = []
    if policy_sha256(partition_policy) != study["partition_policy_sha256"]:
        errors.append("partition policy changed after thresholds were declared")
    if hashlib.sha256(manifest_bytes).hexdigest() != study["partition_manifest_sha256"]:
        errors.append("partition manifest changed after thresholds were declared")
    if partition_policy.get("horizon_days", 0) * 24 != study["horizon_hours"] \
            or partition_policy.get("history_days") != study["history_days"]:
        errors.append("study horizon/history differs from the partition policy")
    manifest = json.loads(manifest_bytes)
    if manifest.get("policy_sha256") != study["partition_policy_sha256"]:
        errors.append("manifest does not bind the pinned partition policy")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--report", type=Path, help="held-out evaluation report")
    group.add_argument("--resources", type=Path, help="resource measurement report")
    group.add_argument("--verify-pins", nargs=2, type=Path, metavar=("PARTITION_POLICY", "MANIFEST"))
    args = parser.parse_args(argv)
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    if args.verify_pins:
        errors = verify_pins(policy, json.loads(args.verify_pins[0].read_text(encoding="utf-8")),
                             args.verify_pins[1].read_bytes())
        for error in errors:
            print(f"FAIL: {error}")
        if not errors:
            print(f"PASS: {policy['policy_version']} {policy_sha256(policy)} pins ML01 evidence")
        return 1 if errors else 0
    path = args.report or args.resources
    report = json.loads(path.read_text(encoding="utf-8"))
    result = evaluate_report(policy, report) if args.report else check_resources(policy, report)
    print(json.dumps(result, indent=2, sort_keys=True))
    return EXIT[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
