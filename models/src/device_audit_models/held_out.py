"""Evaluate the frozen ML02 logistic candidate against the ML05 policy."""

import argparse
from collections import Counter
from datetime import date
import hashlib
import json
import math
from pathlib import Path
import re
from tempfile import NamedTemporaryFile
from zipfile import BadZipFile

from . import baseline, evaluation, features, partitions, training_features


def read_json(path):
    return json.loads(path.read_bytes())


def load_candidate(payload, provenance, manifest, policy):
    artifact = baseline.load_artifact(payload)
    version = artifact.get("model_version")
    if not isinstance(version, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", version):
        raise ValueError("invalid model version")
    digest = baseline.sha256_bytes(payload)
    splits = provenance["splits"]
    spec = provenance["spec"]
    if (provenance["schema_version"] != baseline.PROVENANCE_SCHEMA
            or provenance["artifact_sha256"] != digest
            or provenance["dataset"]["sha256"] != manifest["source"]["sha256"]
            or splits["manifest_sha256"] != policy["study"]["partition_manifest_sha256"]
            or splits["policy_sha256"] != manifest["policy_sha256"]
            or splits["examples_sha256"]["train"] != manifest["partitions"]["train"]["examples_sha256"]
            or splits["fit_split"] != "train"
            or spec["fit_split"] != "train"
            or spec["declared_before_held_out_evaluation"] is not True
            or spec["model_version"] != version
            or provenance["spec_sha256"] != artifact["spec_sha256"]):
        raise ValueError("candidate provenance does not bind a train-only fit to the frozen study")
    return artifact, {"version": version, "artifact_sha256": digest}


def smart_score(samples):
    for sample in reversed(samples):
        reallocated, pending = sample["smart_5_raw"], sample["smart_197_raw"]
        if reallocated is not None and pending is not None:
            return reallocated + pending
    return None


def score_partitions(archive, partition_policy, manifest, artifact):
    from .held_out_metrics import ScoredWindow

    validation, test = [], []
    split_rows = {"validation": validation, "test": test}
    digests = {name: hashlib.sha256() for name in split_rows}
    labels = {name: Counter() for name in split_rows}
    events = {name: {} for name in split_rows}
    devices = {name: set() for name in split_rows}
    excluded, stats = {}, {}
    windows = training_features.example_windows(
        partitions.archive_days(archive, partition_policy, stats), partition_policy,
        excluded, include=lambda example: example.split in split_rows)
    for example, window in windows:
        if window is None:
            continue
        name, device = example.split, example.device_key
        baseline.update_example_digest(digests[name], example)
        labels[name][str(example.label)] += 1
        devices[name].add(device)
        lead = 0
        if example.label:
            previous = events[name].setdefault(device, example.label_available_at)
            if previous != example.label_available_at:
                raise ValueError("multiple distinct events for one device")
            lead = (date.fromisoformat(example.label_available_at) - date.fromisoformat(example.anchor)).days
        if name == "validation" and example.label:
            continue
        vector = training_features.model_input(features.compute(window))
        score = baseline.predict_logit(artifact, vector)
        if not math.isfinite(score):
            raise ValueError("candidate produced a non-finite logit")
        split_rows[name].append(ScoredWindow(device, example.label, lead, score, smart_score(window["samples"])))

    for name in split_rows:
        expected = manifest["partitions"][name]
        if (digests[name].hexdigest() != expected["examples_sha256"]
                or dict(labels[name]) != {label: count for label, count in expected["labels"].items() if count}
                or len(events[name]) != expected["positive_event_count"]
                or sorted(devices[name]) != expected["devices"]):
            raise ValueError(f"{name} examples differ from the frozen partition")
    if excluded != manifest["excluded"] or stats != manifest["source_observations"]:
        raise ValueError("source counts differ from the frozen manifest")
    return validation, test


def base_report(policy):
    study, procedure = policy["study"], policy["procedure"]
    return {
        "schema_version": evaluation.REPORT_VERSION,
        "policy_sha256": evaluation.policy_sha256(policy),
        "partition_manifest_sha256": study["partition_manifest_sha256"],
        "partition": procedure["evaluation_partition"],
        "horizon_hours": study["horizon_hours"],
        "bootstrap": procedure["bootstrap"],
        "model": None,
        "test_evaluations_for_candidate": 0,
        "label_status": "unavailable",
        "counts": {},
        "metrics": {},
    }


def evaluate(archive, partition_policy, manifest, artifact, policy, report):
    from .held_out_metrics import Metrics, bootstrap, operating_point

    validation, test = score_partitions(archive, partition_policy, manifest, artifact)
    positives = sum(row.label for row in test)
    report["counts"] = {
        "test_positive_events": len({row.device for row in test if row.label}),
        "test_positive_windows": positives,
        "test_negative_windows": len(test) - positives,
        "test_devices": len({row.device for row in test}),
        "validation_negative_windows": len(validation),
    }
    if positives and positives < len(test):
        report["label_status"] = "both_classes_present"
    if (report["label_status"] != "both_classes_present"
            or any(report["counts"][name] < minimum for name, minimum in policy["minimum_evidence"].items())):
        return

    procedure = policy["procedure"]
    targets = {name: point["target_window_false_positive_rate"]
               for name, point in procedure["operating_points"].items()}
    logits = [row.logit for row in validation]
    smart = [row.smart for row in validation]
    degraded = operating_point(logits, targets["degraded"])
    critical = operating_point(logits, targets["critical"])
    smart_cutoff = operating_point(smart, targets["degraded"])
    train = manifest["partitions"]["train"]
    prevalence = train["labels"]["1"] / train["examples"]
    if not 0 < prevalence < 1:
        raise ValueError("training prevalence requires both label classes")
    report["operating_points"] = {
        "degraded_logit": degraded,
        "critical_logit": critical,
        "smart_degraded_raw_sum": smart_cutoff,
        "validation_false_positive_windows": {
            "degraded": sum(score >= degraded for score in logits),
            "critical": sum(score >= critical for score in logits),
            "smart_degraded": sum(score is not None and smart_cutoff is not None and score >= smart_cutoff
                                  for score in smart),
        },
    }
    report["train_positive_window_prevalence"] = prevalence
    report["partition_examples_sha256"] = {name: entry["examples_sha256"]
                                           for name, entry in manifest["partitions"].items()}
    metrics = Metrics(test, prevalence, degraded, critical, smart_cutoff, partition_policy.horizon_days)
    report["metrics"] = bootstrap(metrics, procedure["bootstrap"])


def render(report, policy):
    return json.dumps({**report, "gate": evaluation.evaluate_report(policy, report)},
                      indent=2, sort_keys=True, allow_nan=False) + "\n"


def reserve(path, report, policy):
    # An exclusive create gives parallel invocations only one reservation.
    # An interrupted evaluation leaves a blocking record for this version.
    pending = {**report, "evaluation_error": "evaluation_interrupted_or_in_progress"}
    with path.open("x", encoding="utf-8", newline="\n") as file:
        file.write(render(pending, policy))


def publish(path, payload):
    with NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as file:
        temp = Path(file.name)
        file.write(payload)
    try:
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--models-dir", type=Path, default=Path("models"))
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--provenance", type=Path)
    args = parser.parse_args(argv)
    root = args.models_dir
    candidate = root / "baseline/backblaze-2013"
    dataset = root / "datasets/backblaze-2013"
    path = None
    try:
        policy = evaluation.validate_policy(read_json(root / "evaluation/ml05-policy.json"))
        report = base_report(policy)
    except (ValueError, OSError, TypeError, KeyError) as exc:
        print(json.dumps({"schema_version": evaluation.GATE_VERSION, "status": "blocked",
                          "blocking_reasons": [f"invalid_evaluation_policy: {exc}"]}))
        return evaluation.EXIT["blocked"]

    try:
        import numpy  # Verify the offline evaluation dependency before reserving.

        report["numpy_version"] = numpy.__version__
        policy_json = read_json(dataset / "policy.json")
        manifest, _, _ = baseline.bind_study(policy_json, (dataset / "partitions.json").read_bytes(), policy)
        partition_policy = partitions.Policy.load(policy_json)
        artifact, report["model"] = load_candidate(
            (args.artifact or candidate / "artifact.json").read_bytes(),
            read_json(args.provenance or candidate / "provenance.json"), manifest, policy)
        if partitions.sha256_file(args.archive) != partition_policy.source["sha256"]:
            raise ValueError("archive SHA-256 mismatch")
        ledger = root / "evaluation/results"
        ledger.mkdir(exist_ok=True)
        destination = ledger / f"{report['model']['version']}.json"
        report["test_evaluations_for_candidate"] = 1
        try:
            reserve(destination, report, policy)
        except FileExistsError:
            report["test_evaluations_for_candidate"] = 0
            raise ValueError("candidate version already reserved or evaluated") from None
        path = destination
        evaluate(args.archive, partition_policy, manifest, artifact, policy, report)
    except (BadZipFile, ValueError, ArithmeticError, ImportError, OSError, TypeError, KeyError) as exc:
        report["evaluation_error"] = str(exc)

    payload = render(report, policy)
    if path is not None:
        try:
            publish(path, payload)
        except OSError as exc:
            report["evaluation_error"] = f"could not publish report: {exc}"
            payload = render(report, policy)
    print(payload, end="")
    return evaluation.EXIT[evaluation.evaluate_report(policy, report)["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
