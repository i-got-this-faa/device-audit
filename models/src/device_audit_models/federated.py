"""Weighted aggregation and reproducible candidate builders (FED03 #43)."""

from dataclasses import dataclass
import hashlib
import json
from math import fsum, isfinite
import struct
from typing import Sequence

WEIGHTING_POLICY = "sample-count-weighted.v1"
GENERIC_CANDIDATE_SCHEMA = "device-audit.federated-candidate.v1"
LOGISTIC_BASELINE_SCHEMA = "device-audit.logistic-baseline.v1"
_AGGREGATION_INPUT_DOMAIN = b"device-audit/federated-aggregation/v1\x00"


@dataclass(frozen=True)
class Update:
    base_version: str
    sample_count: int
    weights: tuple[float, ...]


@dataclass(frozen=True)
class ParticipantInput:
    device_id: str
    signing_key_id: str
    sequence: int
    sample_count: int
    update_sha256: str
    request_sha256: str


def weighted_average(updates: Sequence[Update]) -> tuple[float, ...]:
    """Average compatible model vectors by local sample count.

    Authentication, poisoning defenses, secure aggregation, privacy accounting,
    and holdout evaluation belong to the controller and FED10.
    """
    if not updates:
        raise ValueError("at least one update is required")
    version, width = updates[0].base_version, len(updates[0].weights)
    if not version or not width:
        raise ValueError("model version and nonempty weights are required")
    for update in updates:
        if update.base_version != version or len(update.weights) != width:
            raise ValueError("updates must share base version and dimensions")
        if type(update.sample_count) is not int or update.sample_count <= 0:
            raise ValueError("sample_count must be a positive integer")
        if not all(isfinite(weight) for weight in update.weights):
            raise ValueError("weights must be finite")
    total = sum(update.sample_count for update in updates)
    result = tuple(
        fsum(update.weights[i] * (update.sample_count / total) for update in updates)
        for i in range(width)
    )
    if not all(isfinite(weight) for weight in result):
        raise ValueError("aggregated weights must be finite")
    return result


def aggregation_input_sha256(
    *,
    deployment_id: str,
    round_id: str,
    candidate_id: str,
    base_model_version: str,
    base_model_sha256: str,
    feature_version: str,
    parameter_count: int,
    participants: Sequence[ParticipantInput],
    policy: str = WEIGHTING_POLICY,
) -> tuple[str, int]:
    """Compute canonical SHA-256 input provenance matching Go federated.AggregationInputSHA256."""
    if policy != WEIGHTING_POLICY:
        raise ValueError("unsupported weighting policy")
    ordered = sorted(participants, key=lambda p: p.device_id)
    seen: set[str] = set()
    total_samples = 0
    for p in ordered:
        if p.device_id in seen or not p.device_id or not p.signing_key_id or p.sequence < 2 or p.sample_count <= 0:
            raise ValueError("invalid participant input")
        seen.add(p.device_id)
        total_samples += p.sample_count
    fields = [
        deployment_id,
        round_id,
        candidate_id,
        base_model_version,
        base_model_sha256,
        feature_version,
        str(parameter_count),
        policy,
        str(len(ordered)),
        str(total_samples),
    ]
    for p in ordered:
        fields.extend([
            p.device_id,
            p.signing_key_id,
            str(p.sequence),
            str(p.sample_count),
            p.update_sha256,
            p.request_sha256,
        ])
    buf = bytearray(_AGGREGATION_INPUT_DOMAIN)
    for field in fields:
        data = field.encode("utf-8")
        buf.extend(struct.pack(">I", len(data)))
        buf.extend(data)
    return hashlib.sha256(bytes(buf)).hexdigest(), total_samples


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON constant {value!r} is not allowed")


def build_logistic_candidate_artifact(
    base_artifact: bytes,
    candidate_model_version: str,
    weights: Sequence[float],
) -> bytes:
    """Produce deterministic logistic-baseline.v1 JSON bytes matching Go."""
    doc = json.loads(base_artifact, parse_constant=_reject_json_constant)
    if not isinstance(doc, dict) or doc.get("schema_version") != LOGISTIC_BASELINE_SCHEMA:
        raise ValueError("base artifact is not logistic-baseline.v1")
    features = doc.get("features")
    if not isinstance(features, list) or len(weights) != len(features) + 1:
        raise ValueError("weights dimension does not match logistic features")
    if not all(isfinite(w) for w in weights):
        raise ValueError("aggregated weights must be finite")
    doc["model_version"] = candidate_model_version
    doc["intercept"] = float(weights[0]).hex()
    doc["weights"] = [float(w).hex() for w in weights[1:]]
    return json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
