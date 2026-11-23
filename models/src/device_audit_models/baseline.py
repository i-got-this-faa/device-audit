"""ML02 #33 reproducible logistic baseline for the ML01 HDD study.

This is central training of one declared model. It is not the endpoint
``LocalTrainer`` boundary, not a hosted Jev model, and not an evaluated or
endpoint-qualified predictor. Learned scaling lives in the artifact. The only
preprocessing is ``training_features`` calling the frozen ``hdd-smart-7d.v1``
reference. Validation and test examples are refused. Nothing here is signed
for CT10 activation, and nothing is written to a chain.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from array import array
from dataclasses import asdict
from pathlib import Path
from typing import Iterator

from . import features, partitions, training_features

SCHEMA = "device-audit.logistic-baseline.v1"
PROVENANCE_SCHEMA = "device-audit.training-provenance.v1"
SPEC_SCHEMA = "device-audit.training-spec.v1"
WIDTH = len(features.FEATURES)
DIM = WIDTH + 1
TRAIN = "train"
HELD_OUT = ("validation", "test")
PARAMETER_NAMES = ("intercept", *(name for name, _ in features.FEATURES))
CLAIMS = {
    "endpoint_qualified": False,
    "evaluated_against_ml05": False,
    "hosted_jev": False,
    "on_chain": False,
    "publisher_signed": False,
    "synthetic_training_rows": False,
}
MODELS_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SPEC = MODELS_ROOT / "baseline" / "training-spec.json"
DEFAULT_POLICY = MODELS_ROOT / "datasets" / "backblaze-2013" / "policy.json"
DEFAULT_MANIFEST = MODELS_ROOT / "datasets" / "backblaze-2013" / "partitions.json"
DEFAULT_EVALUATION = MODELS_ROOT / "evaluation" / "ml05-policy.json"
DEFAULT_ARTIFACT = MODELS_ROOT / "baseline" / "backblaze-2013" / "artifact.json"
DEFAULT_PROVENANCE = MODELS_ROOT / "baseline" / "backblaze-2013" / "provenance.json"


class TrainingRefusal(ValueError):
    """Training cannot produce the declared artifact."""


class HeldOutPartition(TrainingRefusal):
    """A validation or test example was offered for fitting."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def encode_float(value: float) -> str:
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        raise TrainingRefusal("a learned parameter is not finite")
    return float(value).hex()


def decode_float(value: object) -> float:
    if not isinstance(value, str):
        raise TrainingRefusal("parameters are stored as hex floats")
    number = float.fromhex(value)
    if not math.isfinite(number):
        raise TrainingRefusal("a stored parameter is not finite")
    return number


def load_spec(path: Path) -> tuple[dict, bytes]:
    """Load the declared training spec. Held-out fitting and a weak keep rate fail."""
    payload = path.read_bytes()
    spec = json.loads(payload)
    names = [name for name, _ in features.FEATURES]
    keep_num, keep_den = spec.get("negative_keep_numerator"), spec.get("negative_keep_denominator")
    integers = ("iterations", "seed", "predictor_clip", "intercept_penalty", "zero_variance_scale")
    if (spec.get("schema_version") != SPEC_SCHEMA or spec.get("feature_version") != features.FEATURE_VERSION
            or spec.get("features") != names or spec.get("class_weight") != "balanced"
            or spec.get("optimizer") != "newton" or spec.get("initialization") != "zeros"
            or spec.get("standardize") != "population_stddev"
            or spec.get("incomplete_vectors") != "excluded" or spec.get("positives") != "never_subsampled"
            or spec.get("l2_applies_to") != "standardized_weights"
            or spec.get("declared_before_held_out_evaluation") is not True
            or not all(type(spec.get(key)) is int for key in integers)
            or spec["iterations"] < 1 or spec["iterations"] > 100 or spec["predictor_clip"] < 1
            or spec["intercept_penalty"] != 0 or spec["zero_variance_scale"] != 1
            or type(spec.get("l2")) not in (int, float) or isinstance(spec.get("l2"), bool) or spec["l2"] < 0
            or not isinstance(spec.get("rerun_atol"), (int, float)) or isinstance(spec.get("rerun_atol"), bool)
            or not isinstance(spec.get("rerun_rtol"), (int, float)) or isinstance(spec.get("rerun_rtol"), bool)
            or spec["rerun_atol"] < 0 or spec["rerun_rtol"] < 0
            or not spec.get("architecture") or not spec.get("model_version") or not spec.get("spec_version")):
        raise TrainingRefusal("training spec is not the declared logistic baseline")
    if spec.get("fit_split") != TRAIN or spec.get("held_out_splits") != list(HELD_OUT):
        raise HeldOutPartition("the training spec must fit train and hold out validation and test")
    if (type(keep_num) is not int or type(keep_den) is not int or isinstance(keep_num, bool)
            or isinstance(keep_den, bool)):
        raise TrainingRefusal("negative keep rate must be two integers")
    full_sample = keep_num == 1 and keep_den == 1
    if not full_sample and (keep_den < 1 or keep_num < 1 or keep_num > keep_den or keep_num * 20 < keep_den):
        raise TrainingRefusal("negative keep rate must be 1/1 or at least 1/20")
    return spec, payload


def keep_negative(example: partitions.Example, numerator: int, denominator: int) -> bool:
    """Hash subsample for negative windows. Positives are never dropped."""
    if example.label == 1 or numerator == denominator:
        return True
    digest = hashlib.sha256(f"{example.device_key}\0{example.anchor}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % denominator < numerator


def update_example_digest(digest, example: partitions.Example) -> None:
    """Same line the ML01 manifest hashes: canonical example JSON plus newline."""
    digest.update(partitions.canonical(asdict(example)) + b"\n")


def _sigmoid(score: float) -> float:
    if score >= 0:
        exponential = math.exp(-score)
        return 1.0 / (1.0 + exponential)
    exponential = math.exp(score)
    return exponential / (1.0 + exponential)


def _moments(values: array, rows: int) -> tuple[list[float], list[float]]:
    totals = [0.0] * WIDTH
    for row in range(rows):
        base = row * WIDTH
        for index in range(WIDTH):
            totals[index] += values[base + index]
    means = [total / rows for total in totals]
    squares = [0.0] * WIDTH
    for row in range(rows):
        base = row * WIDTH
        for index in range(WIDTH):
            delta = values[base + index] - means[index]
            squares[index] += delta * delta
    scales = [math.sqrt(square / rows) if square > 0.0 else 1.0 for square in squares]
    return means, scales


def _standardize(values: array, rows: int, means: list[float], scales: list[float]) -> None:
    for row in range(rows):
        base = row * WIDTH
        for index in range(WIDTH):
            values[base + index] = (values[base + index] - means[index]) / scales[index]


def _newton(values: array, labels: array, negative_weight: float, positive_weight: float,
            iterations: int, l2: float, clip: float) -> list[float]:
    """Newton steps on the balanced L2 logistic loss. The intercept is unpenalized."""
    rows = len(labels)
    beta = [0.0] * DIM
    for _ in range(iterations):
        gradient = [0.0] * DIM
        hessian = [[0.0] * DIM for _ in range(DIM)]
        for row in range(rows):
            base = row * WIDTH
            x1, x2, x3, x4, x5, x6 = (values[base + index] for index in range(WIDTH))
            score = (beta[0] + beta[1] * x1 + beta[2] * x2 + beta[3] * x3
                     + beta[4] * x4 + beta[5] * x5 + beta[6] * x6)
            if score > clip:
                score = float(clip)
            elif score < -clip:
                score = float(-clip)
            probability = _sigmoid(score)
            weight = positive_weight if labels[row] else negative_weight
            residual = weight * (probability - labels[row])
            curve = weight * probability * (1.0 - probability)
            gradient[0] += residual
            gradient[1] += residual * x1
            gradient[2] += residual * x2
            gradient[3] += residual * x3
            gradient[4] += residual * x4
            gradient[5] += residual * x5
            gradient[6] += residual * x6
            hessian[0][0] += curve
            hessian[0][1] += curve * x1
            hessian[0][2] += curve * x2
            hessian[0][3] += curve * x3
            hessian[0][4] += curve * x4
            hessian[0][5] += curve * x5
            hessian[0][6] += curve * x6
            hessian[1][1] += curve * x1 * x1
            hessian[1][2] += curve * x1 * x2
            hessian[1][3] += curve * x1 * x3
            hessian[1][4] += curve * x1 * x4
            hessian[1][5] += curve * x1 * x5
            hessian[1][6] += curve * x1 * x6
            hessian[2][2] += curve * x2 * x2
            hessian[2][3] += curve * x2 * x3
            hessian[2][4] += curve * x2 * x4
            hessian[2][5] += curve * x2 * x5
            hessian[2][6] += curve * x2 * x6
            hessian[3][3] += curve * x3 * x3
            hessian[3][4] += curve * x3 * x4
            hessian[3][5] += curve * x3 * x5
            hessian[3][6] += curve * x3 * x6
            hessian[4][4] += curve * x4 * x4
            hessian[4][5] += curve * x4 * x5
            hessian[4][6] += curve * x4 * x6
            hessian[5][5] += curve * x5 * x5
            hessian[5][6] += curve * x5 * x6
            hessian[6][6] += curve * x6 * x6
        for row in range(DIM):
            for column in range(row):
                hessian[row][column] = hessian[column][row]
            if row:
                hessian[row][row] += l2
        step = _solve(hessian, gradient)
        for index in range(DIM):
            beta[index] -= step[index]
        if not all(math.isfinite(weight) for weight in beta):
            raise TrainingRefusal("Newton iteration produced a non-finite parameter")
        if rows >= 10000:
            print(f"newton iteration gradient_inf={max(abs(value) for value in gradient):.3e}",
                  file=sys.stderr, flush=True)
    return beta


def _solve(matrix: list[list[float]], rhs: list[float]) -> list[float]:
    """Solve a dense system. Partial pivoting keeps the first maximum."""
    size = len(rhs)
    augmented = [row[:] + [rhs[index]] for index, row in enumerate(matrix)]
    for column in range(size):
        pivot = max(range(column, size), key=lambda row: abs(augmented[row][column]))
        if augmented[pivot][column] == 0.0:
            raise TrainingRefusal("normal equations are singular")
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        scale = augmented[column][column]
        for index in range(column, size + 1):
            augmented[column][index] /= scale
        for row in range(size):
            if row == column:
                continue
            factor = augmented[row][column]
            if factor == 0.0:
                continue
            for index in range(column, size + 1):
                augmented[row][index] -= factor * augmented[column][index]
    return [augmented[index][size] for index in range(size)]


class Collected:
    def __init__(self) -> None:
        self.values: array = array("d")
        self.labels: array = array("B")
        self.positive = 0
        self.negative = 0
        self.incomplete = 0
        self.subsampled = 0
        self.counts = {name: 0 for name in (TRAIN, *HELD_OUT)}
        self.digests = {name: hashlib.sha256() for name in self.counts}


def collect(pairs: Iterator[tuple[partitions.Example, dict | None]], policy: partitions.Policy,
            spec: dict) -> Collected:
    """Hash every split and keep only complete train rows. Any held-out vector is refused."""
    collected = Collected()
    numerator, denominator = spec["negative_keep_numerator"], spec["negative_keep_denominator"]
    for example, vector in pairs:
        if example.split not in collected.counts:
            raise TrainingRefusal(f"unknown split {example.split}")
        update_example_digest(collected.digests[example.split], example)
        collected.counts[example.split] += 1
        scanned = sum(collected.counts.values())
        if scanned % 500_000 == 0:
            print(f"scanned {scanned} examples", file=sys.stderr, flush=True)
        if example.split != TRAIN:
            if vector is not None:
                raise HeldOutPartition(f"refusing to train on split {example.split}")
            continue
        cohort = policy.cohort(example.device_key).name
        if cohort != TRAIN:
            raise HeldOutPartition(f"refusing to train on split {example.split} in cohort {cohort}")
        partitions.audit_example(example, policy)
        if vector is None:
            raise TrainingRefusal("train example was not preprocessed")
        try:
            values = training_features.model_input(vector)
        except training_features.IncompleteFeatures:
            collected.incomplete += 1
            continue
        if example.label == 0 and not keep_negative(example, numerator, denominator):
            collected.subsampled += 1
            continue
        if example.label == 1 and not keep_negative(example, numerator, denominator):
            raise TrainingRefusal("a positive example was subsampled")
        collected.values.extend(values)
        collected.labels.append(example.label)
        if example.label:
            collected.positive += 1
        else:
            collected.negative += 1
    return collected


def _artifact(spec: dict, spec_sha256: str, means: list[float], scales: list[float], beta: list[float],
              negative_weight: float, positive_weight: float, collected: Collected) -> bytes:
    document = {
        "architecture": spec["architecture"],
        "class_weight": {"0": encode_float(negative_weight), "1": encode_float(positive_weight)},
        "feature_version": features.FEATURE_VERSION,
        "features": [name for name, _ in features.FEATURES],
        "incomplete_excluded": collected.incomplete,
        "initialization": spec["initialization"],
        "intercept": encode_float(beta[0]),
        "iterations": spec["iterations"],
        "l2": encode_float(float(spec["l2"])),
        "mean": [encode_float(value) for value in means],
        "model_version": spec["model_version"],
        "negative_rows": collected.negative,
        "negative_subsampled_out": collected.subsampled,
        "positive_rows": collected.positive,
        "predictor_clip": encode_float(float(spec["predictor_clip"])),
        "scale": [encode_float(value) for value in scales],
        "schema_version": SCHEMA,
        "seed": spec["seed"],
        "spec_sha256": spec_sha256,
        "spec_version": spec["spec_version"],
        "standardize": spec["standardize"],
        "weights": [encode_float(value) for value in beta[1:]],
    }
    payload = canonical(document)
    if json.loads(payload).keys() != document.keys():
        raise TrainingRefusal("artifact field set changed while encoding")
    return payload


def fit_collected(collected: Collected, spec: dict, spec_sha256: str) -> bytes:
    rows = collected.positive + collected.negative
    if collected.positive < 1 or collected.negative < 1:
        raise TrainingRefusal("both classes are required; refusing to train")
    negative_weight = rows / (2.0 * collected.negative)
    positive_weight = rows / (2.0 * collected.positive)
    means, scales = _moments(collected.values, rows)
    _standardize(collected.values, rows, means, scales)
    beta = _newton(collected.values, collected.labels, negative_weight, positive_weight,
                   spec["iterations"], float(spec["l2"]), float(spec["predictor_clip"]))
    return _artifact(spec, spec_sha256, means, scales, beta, negative_weight, positive_weight, collected)


def fit_examples(pairs: Iterator[tuple[partitions.Example, dict | None]], policy: partitions.Policy,
                 spec: dict, spec_sha256: str) -> bytes:
    """Fit one artifact. There is no split argument: non-train rows raise."""
    return fit_collected(collect(pairs, policy, spec), spec, spec_sha256)


def predict_probability(artifact: dict, values: list[float]) -> float:
    """Probability from a loaded artifact. This does not assign a health label."""
    if len(values) != WIDTH or any(type(value) not in (int, float) or isinstance(value, bool)
                                   or not math.isfinite(value) for value in values):
        raise TrainingRefusal("prediction requires the six finite frozen features")
    weights = [decode_float(value) for value in artifact["weights"]]
    means = [decode_float(value) for value in artifact["mean"]]
    scales = [decode_float(value) for value in artifact["scale"]]
    score = decode_float(artifact["intercept"])
    for weight, value, mean, scale in zip(weights, values, means, scales):
        score += weight * ((value - mean) / scale)
    clip = decode_float(artifact["predictor_clip"])
    if score > clip:
        score = clip
    elif score < -clip:
        score = -clip
    return _sigmoid(score)


def load_artifact(payload: bytes) -> dict:
    document = json.loads(payload)
    if payload != canonical(document):
        raise TrainingRefusal("artifact bytes are not canonical")
    if (document.get("schema_version") != SCHEMA or document.get("feature_version") != features.FEATURE_VERSION
            or document.get("features") != [name for name, _ in features.FEATURES]
            or len(document.get("weights", [])) != WIDTH or len(document.get("mean", [])) != WIDTH
            or len(document.get("scale", [])) != WIDTH or type(document.get("seed")) is not int
            or type(document.get("positive_rows")) is not int or type(document.get("negative_rows")) is not int):
        raise TrainingRefusal("artifact does not match the logistic baseline schema")
    return document


def within_tolerance(declared: dict, actual: dict, atol: float, rtol: float) -> None:
    """Raise unless learned floats match the declared artifact inside the recorded tolerance."""
    exact = ("architecture", "feature_version", "features", "incomplete_excluded", "initialization",
             "iterations", "model_version", "negative_rows", "negative_subsampled_out", "positive_rows",
             "schema_version", "seed", "spec_sha256", "spec_version", "standardize")
    for key in exact:
        if declared[key] != actual[key]:
            raise TrainingRefusal(f"rerun changed {key}")
    for key in ("l2", "predictor_clip", "intercept"):
        if not _close(decode_float(declared[key]), decode_float(actual[key]), atol, rtol):
            raise TrainingRefusal(f"rerun {key} is outside the recorded tolerance")
    for key in ("mean", "scale", "weights"):
        for index, (left, right) in enumerate(zip(declared[key], actual[key], strict=True)):
            if not _close(decode_float(left), decode_float(right), atol, rtol):
                raise TrainingRefusal(f"rerun {key}[{index}] is outside the recorded tolerance")
    for label in ("0", "1"):
        if not _close(decode_float(declared["class_weight"][label]), decode_float(actual["class_weight"][label]),
                      atol, rtol):
            raise TrainingRefusal(f"rerun class weight {label} is outside the recorded tolerance")


def _close(declared: float, actual: float, atol: float, rtol: float) -> bool:
    return abs(actual - declared) <= atol + rtol * abs(declared)


def provenance_document(spec: dict, spec_sha256: str, dataset: dict, splits: dict, artifact: bytes,
                        collected: Collected, resources: dict) -> dict:
    return {
        "artifact_sha256": sha256_bytes(artifact),
        "claims": dict(CLAIMS),
        "dataset": dataset,
        "feature_version": features.FEATURE_VERSION,
        "fit": {
            "incomplete_excluded": collected.incomplete,
            "negative_rows": collected.negative,
            "negative_subsampled_out": collected.subsampled,
            "parameter_count": DIM,
            "parameter_names": list(PARAMETER_NAMES),
            "positive_rows": collected.positive,
        },
        "resources": resources,
        "rerun_tolerance": {
            "atol": spec["rerun_atol"],
            "fields": ["mean", "scale", "weights", "intercept", "l2", "predictor_clip", "class_weight"],
            "rtol": spec["rerun_rtol"],
            "rule": "abs(actual-declared) <= atol + rtol * abs(declared)",
        },
        "schema_version": PROVENANCE_SCHEMA,
        "seeds": {
            "declaration": spec["seed"],
            "example_order": "anchor-then-device-key",
            "optimizer_draws": 0,
            "split_rule": "ml01-device-hash",
        },
        "spec": spec,
        "spec_sha256": spec_sha256,
        "splits": splits,
    }


def _bind_study(policy_json: dict, manifest_bytes: bytes, evaluation: dict) -> tuple[dict, str, str]:
    study = evaluation["study"]
    # ML05 pins the canonical policy object, not the policy file's whitespace.
    policy_sha = hashlib.sha256(partitions.canonical(policy_json)).hexdigest()
    manifest_sha = sha256_bytes(manifest_bytes)
    if policy_sha != study["partition_policy_sha256"] or manifest_sha != study["partition_manifest_sha256"]:
        raise TrainingRefusal("dataset pins do not match the ML05 evaluation policy")
    manifest = json.loads(manifest_bytes)
    if manifest.get("policy_sha256") != policy_sha or manifest.get("source", {}).get("sha256") != policy_json["source"]["sha256"]:
        raise TrainingRefusal("partition manifest does not match the policy file")
    if study.get("history_days") != policy_json["history_days"] or study.get("horizon_hours") != policy_json["horizon_days"] * 24:
        raise TrainingRefusal("evaluation horizon does not match the partition policy")
    return manifest, policy_sha, manifest_sha


def _resources(started: float) -> dict:
    rss = None
    if sys.platform == "linux":
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    return {
        "logical_processors_used": 1,
        "peak_rss_bytes": rss,
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "wall_ms": int((time.perf_counter() - started) * 1000),
    }


def train_stream(pairs: Iterator[tuple[partitions.Example, dict | None]], policy: partitions.Policy, spec: dict,
                 spec_sha256: str, dataset: dict, split_source: dict, resources: dict) -> tuple[bytes, dict]:
    collected = collect(pairs, policy, spec)
    expected = split_source["examples_sha256"]
    actual = {name: collected.digests[name].hexdigest() for name in collected.digests}
    if actual != expected or collected.counts != split_source["counts"]:
        raise TrainingRefusal("split digests or counts differ from the pinned manifest")
    artifact = fit_collected(collected, spec, spec_sha256)
    splits = {
        "examples_sha256": actual,
        "fit_split": TRAIN,
        "held_out": list(HELD_OUT),
        "manifest_sha256": split_source["manifest_sha256"],
        "policy_sha256": split_source["policy_sha256"],
    }
    document = provenance_document(spec, spec_sha256, dataset, splits, artifact, collected, resources)
    if sha256_bytes(artifact) != document["artifact_sha256"]:
        raise TrainingRefusal("artifact digest does not describe the artifact bytes")
    return artifact, document


def _train_include(example: partitions.Example) -> bool:
    return example.split == TRAIN


def train_archive(archive: Path, policy_json: dict, manifest_bytes: bytes, evaluation: dict, spec: dict,
                  spec_bytes: bytes) -> tuple[bytes, dict]:
    started = time.perf_counter()
    manifest, policy_sha, manifest_sha = _bind_study(policy_json, manifest_bytes, evaluation)
    policy = partitions.Policy.load(policy_json)
    if partitions.sha256_file(archive) != policy.source["sha256"]:
        raise TrainingRefusal("archive SHA-256 does not match the pinned dataset")
    excluded: dict[str, int] = {}
    stats: dict = {}
    pairs = training_features.training_vectors(
        partitions.archive_days(archive, policy, stats), policy, excluded, include=_train_include)
    split_source = {
        "counts": {name: manifest["partitions"][name]["examples"] for name in (TRAIN, *HELD_OUT)},
        "examples_sha256": {name: manifest["partitions"][name]["examples_sha256"] for name in (TRAIN, *HELD_OUT)},
        "manifest_sha256": manifest_sha,
        "policy_sha256": policy_sha,
    }
    dataset = {"bytes": None, "name": policy.source["name"], "sha256": policy.source["sha256"], "url": policy.source["url"]}
    # ``pairs`` is lazy. Resources have to be sampled after train_stream consumes
    # it; an argument would be evaluated before the scan and the Newton steps.
    artifact, document = train_stream(pairs, policy, spec, sha256_bytes(spec_bytes), dataset, split_source, {})
    if excluded != manifest["excluded"] or stats.get("rows") != manifest["source_observations"]["rows"]:
        raise TrainingRefusal("archive exclusion counts differ from the pinned manifest")
    document["dataset"]["bytes"] = stats["archive_bytes"]
    document["resources"] = _resources(started)
    return artifact, document


def compare_rerun(declared_artifact: bytes, declared_provenance: dict, actual_artifact: bytes,
                  actual_provenance: dict) -> str:
    """Return ``exact`` or ``within_tolerance``. Resources may differ; learned rows may not."""
    declared = load_artifact(declared_artifact)
    actual = load_artifact(actual_artifact)
    if declared_provenance["artifact_sha256"] != sha256_bytes(declared_artifact):
        raise TrainingRefusal("declared provenance does not match the declared artifact bytes")
    ignored = {"resources"}
    declared_identity = {key: value for key, value in declared_provenance.items() if key not in ignored}
    actual_identity = {key: value for key, value in actual_provenance.items() if key not in ignored}
    if actual_artifact == declared_artifact and actual_identity == declared_identity:
        return "exact"
    # A tolerant rerun keeps the declared digest in the saved provenance. Compare
    # everything else, then the learned floats against the recorded tolerance.
    declared_identity.pop("artifact_sha256")
    actual_identity.pop("artifact_sha256")
    if actual_identity != declared_identity:
        raise TrainingRefusal("rerun provenance differs beyond resources and the artifact digest")
    tolerance = declared_provenance["rerun_tolerance"]
    within_tolerance(declared, actual, float(tolerance["atol"]), float(tolerance["rtol"]))
    return "within_tolerance"


def verify_archive(archive: Path, policy_json: dict, manifest_bytes: bytes, evaluation: dict, spec: dict,
                   spec_bytes: bytes, declared_artifact: bytes, declared_provenance: dict) -> str:
    artifact, document = train_archive(archive, policy_json, manifest_bytes, evaluation, spec, spec_bytes)
    return compare_rerun(declared_artifact, declared_provenance, artifact, document)


def _read_json(path: Path) -> tuple[dict, bytes]:
    payload = path.read_bytes()
    return json.loads(payload), payload


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("train", "verify"))
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--evaluation-policy", type=Path, default=DEFAULT_EVALUATION)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--provenance", type=Path, default=DEFAULT_PROVENANCE)
    args = parser.parse_args(argv)
    spec, spec_bytes = load_spec(args.spec)
    policy_json = json.loads(args.policy.read_text(encoding="utf-8"))
    manifest_bytes = args.manifest.read_bytes()
    evaluation = json.loads(args.evaluation_policy.read_text(encoding="utf-8"))
    if args.command == "train":
        artifact, document = train_archive(args.archive, policy_json, manifest_bytes, evaluation, spec, spec_bytes)
        args.artifact.parent.mkdir(parents=True, exist_ok=True)
        args.artifact.write_bytes(artifact)
        args.provenance.write_bytes(canonical(document))
        print(f"PASS train artifact_sha256={document['artifact_sha256']} "
              f"positive_rows={document['fit']['positive_rows']} negative_rows={document['fit']['negative_rows']} "
              f"wall_ms={document['resources']['wall_ms']}")
        return
    declared_provenance, provenance_bytes = _read_json(args.provenance)
    if provenance_bytes != canonical(declared_provenance):
        raise SystemExit("FAIL: provenance is not canonical")
    result = verify_archive(args.archive, policy_json, manifest_bytes, evaluation, spec, spec_bytes,
                            args.artifact.read_bytes(), declared_provenance)
    print(f"PASS {result} artifact_sha256={declared_provenance['artifact_sha256']}")


if __name__ == "__main__":
    try:
        main()
    except (TrainingRefusal, OSError, ValueError, KeyError) as error:
        raise SystemExit(f"FAIL: {error}") from error
