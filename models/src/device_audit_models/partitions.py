"""Reproducible, bounded-memory indexes for the ML01 Backblaze study.

This constructs labels and evidence indexes, not a trained predictor. Raw
observations stay in the locally downloaded archive; manifests contain hashes.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
from datetime import date, timedelta
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
from typing import Iterable, Iterator
import zipfile


VERSION = "device-audit.partitions.v1"
DAY = timedelta(days=1)
FEATURES = ("smart_5_raw", "smart_9_raw", "smart_187_raw", "smart_197_raw", "smart_198_raw")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


@dataclass(frozen=True)
class Split:
    name: str
    start: date
    end: date
    bucket_start: int
    bucket_end: int


@dataclass(frozen=True)
class Policy:
    source: dict
    salt: str
    history_days: int
    horizon_days: int
    splits: tuple[Split, ...]

    @classmethod
    def load(cls, value: dict) -> Policy:
        if value["schema_version"] != VERSION or tuple(value["feature_columns"]) != FEATURES:
            raise ValueError("unsupported policy schema or feature ordering")
        for key in ("history_days", "horizon_days"):
            if type(value[key]) is not int or not 1 <= value[key] <= 366:
                raise ValueError(f"invalid {key}")
        splits = tuple(Split(s["name"], date.fromisoformat(s["start"]),
                             date.fromisoformat(s["end"]), s["bucket_start"],
                             s["bucket_end"]) for s in value["splits"])
        if tuple(s.name for s in splits) != ("train", "validation", "test"):
            raise ValueError("train, validation and test must be declared in order")
        previous_end = None
        previous_bucket = 0
        for split in splits:
            if (type(split.bucket_start) is not int or type(split.bucket_end) is not int
                    or split.bucket_start != previous_bucket
                    or not split.bucket_start < split.bucket_end <= 10000
                    or split.end < split.start
                    or (previous_end is not None and split.start <= previous_end)
                    or (split.end - split.start).days + 1 < value["history_days"] + value["horizon_days"]):
                raise ValueError("overlapping/invalid device cohorts or temporal windows")
            previous_end, previous_bucket = split.end, split.bucket_end
        if previous_bucket != 10000 or not value["device_hash_salt"]:
            raise ValueError("cohorts must cover all 10000 buckets with a fixed salt")
        if not re.fullmatch(r"[0-9a-f]{64}", value["source"]["sha256"]):
            raise ValueError("source archive requires a SHA-256 pin")
        return cls(value["source"], value["device_hash_salt"], value["history_days"],
                   value["horizon_days"], splits)

    def device_key(self, serial: str) -> str:
        if not serial or serial != serial.strip():
            raise ValueError("empty or ambiguous serial number")
        # Model is deliberately excluded: a serial cannot enter another cohort
        # if a model spelling changes. These public hashes are not anonymization.
        return hashlib.sha256((self.salt + "\0" + serial).encode()).hexdigest()

    def cohort(self, device_key: str) -> Split:
        if not re.fullmatch(r"[0-9a-f]{64}", device_key):
            raise ValueError("invalid device key")
        bucket = int(device_key[:16], 16) % 10000
        return next(s for s in self.splits if s.bucket_start <= bucket < s.bucket_end)


@dataclass(frozen=True, slots=True)
class Observation:
    failure: int
    features_sha256: str

    @classmethod
    def from_values(cls, failure: int, values: tuple[int | None, ...]) -> Observation:
        if type(failure) is not int or failure not in (0, 1):
            raise ValueError("failure must be the source's binary event flag")
        if len(values) != len(FEATURES) or any(v is not None and (type(v) is not int or v < 0) for v in values):
            raise ValueError("SMART fields must be nullable nonnegative integers")
        # Failure, serial, future observations and model identity are never features.
        return cls(failure, hashlib.sha256(canonical(values)).hexdigest())


@dataclass(frozen=True)
class Example:
    split: str
    device_key: str
    anchor: str
    feature_start: str
    feature_end: str
    label_end: str
    label_available_at: str
    label: int
    features_sha256: str


def audit_example(example: Example, policy: Policy) -> None:
    """Check boundaries independently of the streaming window constructor."""
    split = policy.cohort(example.device_key)
    anchor = date.fromisoformat(example.anchor)
    start, end = date.fromisoformat(example.feature_start), date.fromisoformat(example.feature_end)
    label_end = date.fromisoformat(example.label_end)
    available = date.fromisoformat(example.label_available_at)
    if (split.name != example.split or end != anchor
            or start != anchor - DAY * (policy.history_days - 1)
            or label_end != anchor + DAY * policy.horizon_days
            or not split.start <= start <= end < available <= label_end <= split.end
            or type(example.label) is not int or example.label not in (0, 1)
            or (example.label == 0 and available != label_end)
            or not re.fullmatch(r"[0-9a-f]{64}", example.features_sha256)):
        raise ValueError("device, feature or future-label leakage in example")


def examples(days: Iterable[tuple[date, dict[str, Observation]]], policy: Policy,
             excluded: dict[str, int]) -> Iterator[Example]:
    """Keep only history+horizon daily frames; no whole-corpus RAM load."""
    frames: dict[date, dict[str, Observation]] = {}
    first_failure: dict[str, date] = {}
    previous_day = None

    def reject(reason: str) -> None:
        excluded[reason] = excluded.get(reason, 0) + 1

    for current, observations in days:
        if previous_day is not None and current <= previous_day:
            raise ValueError("daily frames must be strictly chronological")
        previous_day = current
        for device, row in observations.items():
            policy.cohort(device)  # also validate every supplied device key
            if row.failure:
                first_failure.setdefault(device, current)
        frames[current] = observations
        anchor = current - DAY * policy.horizon_days
        feature_start = anchor - DAY * (policy.history_days - 1)
        frames = {d: rows for d, rows in frames.items() if d >= feature_start}
        for device, row in sorted(frames.get(anchor, {}).items()):
            split = policy.cohort(device)
            if not (split.start <= feature_start and current <= split.end):
                reject("outside_cohort_time_window")
                continue
            if device in first_failure and first_failure[device] <= anchor:
                reject("failure_on_or_before_anchor")
                continue
            history = [(feature_start + DAY * n, frames.get(feature_start + DAY * n, {}).get(device))
                       for n in range(policy.history_days)]
            if any(item is None for _, item in history):
                reject("incomplete_history")
                continue
            future = [(anchor + DAY * n, frames.get(anchor + DAY * n, {}).get(device))
                      for n in range(1, policy.horizon_days + 1)]
            failures = [d for d, item in future if item is not None and item.failure == 1]
            if not failures and any(item is None for _, item in future):
                reject("right_censored")
                continue
            feature_hash = hashlib.sha256(canonical(
                [(d.isoformat(), item.features_sha256) for d, item in history]
            )).hexdigest()
            result = Example(split.name, device, anchor.isoformat(), feature_start.isoformat(),
                             anchor.isoformat(), current.isoformat(),
                             (min(failures) if failures else current).isoformat(),
                             int(bool(failures)), feature_hash)
            audit_example(result, policy)
            yield result


def archive_days(path: Path, policy: Policy, stats: dict) -> Iterator[tuple[date, dict[str, Observation]]]:
    if sha256_file(path) != policy.source["sha256"]:
        raise ValueError("archive SHA-256 mismatch")
    stats.update(archive_bytes=path.stat().st_size, rows=0, failure_rows=0,
                 nullable_feature_values={f: 0 for f in FEATURES})
    identities: dict[str, str] = {}
    with zipfile.ZipFile(path) as archive:
        members = {}
        for info in archive.infolist():
            name = PurePosixPath(info.filename)
            if "__MACOSX" in name.parts or not re.fullmatch(r"\d{4}-\d{2}-\d{2}\.csv", name.name):
                continue
            day = date.fromisoformat(name.stem)
            if day in members:
                raise ValueError("duplicate daily CSV member")
            members[day] = info
        if len(members) != policy.source["daily_csv_count"]:
            raise ValueError("unexpected daily CSV count")
        if (not members or min(members).isoformat() != policy.source["start"]
                or max(members).isoformat() != policy.source["end"]):
            raise ValueError("unexpected archive date range")
        stats["daily_csv_count"] = len(members)
        stats["first_day"], stats["last_day"] = min(members).isoformat(), max(members).isoformat()
        for day, info in sorted(members.items()):
            observations = {}
            with archive.open(info) as raw, io.TextIOWrapper(raw, encoding="utf-8", newline="") as stream:
                reader = csv.reader(stream)
                header = next(reader)
                if len(header) != len(set(header)):
                    raise ValueError("duplicate CSV columns")
                required = ("date", "serial_number", "model", "failure", *FEATURES)
                if not set(required) <= set(header):
                    raise ValueError("missing required CSV columns")
                indexes = {name: header.index(name) for name in required}
                for record in reader:
                    if len(record) != len(header) or record[indexes["date"]] != day.isoformat():
                        raise ValueError("malformed or misdated CSV row")
                    serial = record[indexes["serial_number"]]
                    if serial not in identities:
                        identities[serial] = policy.device_key(serial)
                    device = identities[serial]
                    if device in observations:
                        raise ValueError("duplicate device/day observation")
                    flag = record[indexes["failure"]]
                    if flag not in ("0", "1"):
                        raise ValueError("missing or invalid event label")
                    values = []
                    for field in FEATURES:
                        value = record[indexes[field]]
                        if value and not re.fullmatch(r"[0-9]+", value):
                            raise ValueError("invalid SMART raw value")
                        values.append(int(value) if value else None)
                        stats["nullable_feature_values"][field] += int(not value)
                    observations[device] = Observation.from_values(int(flag), tuple(values))
                    stats["rows"] += 1
                    stats["failure_rows"] += int(flag)
            yield day, observations
    stats["source_devices"] = len(identities)


def build_manifest(path: Path, policy_json: dict) -> dict:
    policy = Policy.load(policy_json)
    stats, excluded = {}, {}
    summaries = {s.name: {"examples": 0, "labels": {"0": 0, "1": 0}, "devices": set(),
                           "positive_events": set(), "digest": hashlib.sha256(),
                           "first_anchor": None, "last_anchor": None}
                 for s in policy.splits}
    for example in examples(archive_days(path, policy, stats), policy, excluded):
        entry = summaries[example.split]
        entry["examples"] += 1
        entry["labels"][str(example.label)] += 1
        entry["devices"].add(example.device_key)
        if example.label:
            entry["positive_events"].add((example.device_key, example.label_available_at))
        entry["digest"].update(canonical(asdict(example)) + b"\n")
        entry["first_anchor"] = entry["first_anchor"] or example.anchor
        entry["last_anchor"] = example.anchor
    for split in policy.splits:
        entry = summaries[split.name]
        entry["devices"] = sorted(entry["devices"])
        entry["device_count"] = len(entry["devices"])
        entry["positive_event_count"] = len(entry.pop("positive_events"))
        entry["examples_sha256"] = entry.pop("digest").hexdigest()
        entry["label_status"] = "both_classes_present" if all(entry["labels"].values()) else "blocked_missing_class"
    device_sets = [set(summaries[s.name]["devices"]) for s in policy.splits]
    if any(device_sets[a] & device_sets[b] for a in range(3) for b in range(a + 1, 3)):
        raise ValueError("cross-partition device leakage")
    return {"schema_version": VERSION, "policy_sha256": hashlib.sha256(canonical(policy_json)).hexdigest(),
            "source": policy.source, "source_observations": stats, "excluded": excluded,
            "partitions": summaries,
            "claim_status": "blocked_untrained_model_and_unmapped_endpoint_telemetry"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--verify", type=Path)
    args = parser.parse_args()
    manifest = build_manifest(args.archive, json.loads(args.policy.read_text(encoding="utf-8")))
    payload = (json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    if args.verify:
        if args.verify.read_bytes() != payload:
            raise SystemExit("FAIL: partition manifest differs from pinned source/policy")
        print("PASS: partition manifest reproduced byte-for-byte")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
    print(json.dumps({name: {key: value for key, value in entry.items() if key != "devices"}
                      for name, entry in manifest["partitions"].items()}, indent=2, sort_keys=True))
    print("Endpoint failure-prediction claims remain blocked; this is a dataset/index check.")


if __name__ == "__main__":
    main()
