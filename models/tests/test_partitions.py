"""Adversarial leakage/censoring checks use explicitly synthetic observations."""

from dataclasses import asdict, replace
from datetime import date, timedelta
import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from device_audit_models.partitions import (
    FEATURES, Observation, Policy, archive_days, audit_example, build_manifest, canonical, examples, main,
)


ROOT = Path(__file__).resolve().parents[1]
PINNED = ROOT / "datasets/backblaze-2013"
DAY = timedelta(days=1)


class PartitionTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((PINNED / "policy.json").read_text())
        # Three adjacent artificial months: input values are never real evidence.
        for split, month in zip(self.config["splits"], (1, 2, 3)):
            split.update(start=f"2024-{month:02}-01", end=f"2024-{month:02}-28")
        self.policy = Policy.load(self.config)
        self.devices = {}
        for number in range(1000):
            key = self.policy.device_key(f"synthetic-{number}")
            self.devices.setdefault(self.policy.cohort(key).name, key)
            if len(self.devices) == 3:
                break

    def frames(self, failure=None, missing=(), future_value=None):
        for offset in range(88):
            day = date(2024, 1, 1) + DAY * offset
            observations = {}
            for device in self.devices.values():
                if (device, day) in missing:
                    continue
                value = future_value if future_value is not None and day > date(2024, 1, 10) else offset
                observations[device] = Observation.from_values(int(day == failure), (value, None, 0, 0, 0))
            yield day, observations

    def generate(self, **kwargs):
        return list(examples(self.frames(**kwargs), self.policy, {}))

    def test_device_and_full_evidence_intervals_are_disjoint(self):
        rows = self.generate()
        sets = {name: set() for name in self.devices}
        self.assertEqual(set(row.split for row in rows), set(sets))
        for row in rows:
            audit_example(row, self.policy)
            sets[row.split].add(row.device_key)
            split = self.policy.cohort(row.device_key)
            self.assertGreaterEqual(date.fromisoformat(row.feature_start), split.start)
            self.assertLessEqual(date.fromisoformat(row.label_end), split.end)
        self.assertFalse(sets["train"] & (sets["validation"] | sets["test"]))
        self.assertFalse(sets["validation"] & sets["test"])

    def test_future_smart_values_cannot_change_anchor_features(self):
        before = next(r for r in self.generate() if r.anchor == "2024-01-10")
        after = next(r for r in self.generate(future_value=999999) if r.anchor == "2024-01-10")
        self.assertEqual(before.features_sha256, after.features_sha256)

    def test_future_event_changes_label_but_never_features(self):
        negative = next(r for r in self.generate() if r.anchor == "2024-01-10")
        positive = next(r for r in self.generate(failure=date(2024, 1, 17)) if r.anchor == "2024-01-10")
        self.assertEqual((negative.label, positive.label), (0, 1))
        self.assertEqual(negative.features_sha256, positive.features_sha256)
        beyond = next(r for r in self.generate(failure=date(2024, 1, 18)) if r.anchor == "2024-01-10")
        self.assertEqual(beyond, negative)

    def test_missing_future_is_censored_not_a_healthy_negative(self):
        missing = ((self.devices["train"], date(2024, 1, 11)),)
        rows = self.generate(missing=missing)
        self.assertFalse(any(r.anchor == "2024-01-10" for r in rows))
        # A subsequently observed event is still a known positive despite a gap.
        rows = self.generate(missing=missing, failure=date(2024, 1, 12))
        self.assertEqual(next(r for r in rows if r.anchor == "2024-01-10").label, 1)

    def test_missing_history_and_failure_day_or_later_are_excluded(self):
        rows = self.generate(missing=((self.devices["train"], date(2024, 1, 9)),))
        self.assertFalse(any(r.anchor == "2024-01-10" for r in rows))
        rows = self.generate(failure=date(2024, 1, 15))
        self.assertFalse(any(r.split == "train" and r.anchor >= "2024-01-15" for r in rows))

    def test_tampered_device_features_and_future_labels_fail_audit(self):
        row = self.generate()[0]
        for invalid in (replace(row, split="test"),
                        replace(row, device_key=self.devices["test"]),
                        replace(row, feature_end="2024-01-20"),
                        replace(row, label_end="2024-02-01"),
                        replace(row, label_available_at=row.anchor),
                        replace(row, label=True)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                audit_example(invalid, self.policy)

    def test_hash_and_row_order_are_deterministic(self):
        expected = [asdict(r) for r in self.generate()]
        reversed_devices = [(day, dict(reversed(list(rows.items())))) for day, rows in self.frames()]
        actual = [asdict(r) for r in examples(reversed_devices, self.policy, {})]
        self.assertEqual(actual, expected)
        self.assertEqual(self.policy.device_key("synthetic-0"), self.policy.device_key("synthetic-0"))
        with self.assertRaises(ValueError):
            list(examples(reversed(list(self.frames())), self.policy, {}))

    def test_overlapping_time_or_device_policies_rejected(self):
        for field, value in (("start", "2024-01-15"), ("bucket_start", 6000)):
            config = copy.deepcopy(self.config)
            config["splits"][1][field] = value
            with self.assertRaises(ValueError):
                Policy.load(config)
        config = copy.deepcopy(self.config)
        config["horizon_days"] = True
        with self.assertRaises(ValueError):
            Policy.load(config)

    def test_missing_metrics_are_not_zero_or_invalid_numbers(self):
        missing = Observation.from_values(0, (None, 1, None, None, None))
        zero = Observation.from_values(0, (0, 1, None, None, None))
        self.assertNotEqual(missing.features_sha256, zero.features_sha256)
        for value in (-1, 1.5, float("nan"), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Observation.from_values(0, (value, 1, None, None, None))

    def make_archive(self, directory, *, duplicate=False, missing_column=False, reverse=False):
        path = Path(directory) / "synthetic.zip"
        config = copy.deepcopy(self.config)
        dates = [date(2024, 1, 1) + DAY * offset for offset in range(28)]
        header = ["date", "serial_number", "model", "failure", *FEATURES]
        if missing_column:
            header.remove("failure")
        with zipfile.ZipFile(path, "w") as archive:
            for day in reversed(dates) if reverse else dates:
                buffer = io.StringIO(newline="")
                writer = csv.writer(buffer)
                writer.writerow(header)
                record = {"date": day.isoformat(), "serial_number": "synthetic-0", "model": "test",
                          "failure": "0", **{feature: "0" for feature in FEATURES}}
                writer.writerow([record[name] for name in header])
                if duplicate:
                    writer.writerow([record[name] for name in header])
                archive.writestr(day.isoformat() + ".csv", buffer.getvalue())
        config["source"].update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                start=dates[0].isoformat(), end=dates[-1].isoformat(), daily_csv_count=28)
        return path, config

    def test_archive_pin_duplicate_rows_and_absent_labels_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path, config = self.make_archive(directory)
            path.write_bytes(path.read_bytes() + b"tampering")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                list(archive_days(path, Policy.load(config), {}))
            for kwargs in ({"duplicate": True}, {"missing_column": True}):
                path, config = self.make_archive(directory, **kwargs)
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    list(archive_days(path, Policy.load(config), {}))

    def test_archive_order_independent_and_missing_classes_block(self):
        with tempfile.TemporaryDirectory() as directory:
            path, config = self.make_archive(directory)
            first = build_manifest(path, config)
            path, config = self.make_archive(directory, reverse=True)
            second = build_manifest(path, config)
            # Different container hashes, identical examples and membership.
            self.assertEqual(first["partitions"], second["partitions"])
            self.assertTrue(all(p["label_status"] == "blocked_missing_class"
                                for p in second["partitions"].values()))

    def test_cli_verifies_exact_bytes_and_rejects_tampered_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, config = self.make_archive(directory)
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps(config))
            output = Path(directory) / "manifest.json"
            arguments = ["partitions", "--archive", str(archive), "--policy", str(policy)]
            with patch("sys.argv", arguments + ["--output", str(output)]), patch("sys.stdout", io.StringIO()):
                main()
            with patch("sys.argv", arguments + ["--verify", str(output)]), patch("sys.stdout", io.StringIO()) as stream:
                main()
                self.assertIn("reproduced byte-for-byte", stream.getvalue())
            output.write_bytes(output.read_bytes() + b" ")
            with patch("sys.argv", arguments + ["--verify", str(output)]), self.assertRaises(SystemExit):
                main()

    def test_committed_real_manifest_has_disjoint_devices_and_both_labels(self):
        path = PINNED / "partitions.json"
        if not path.exists():
            self.fail("generate and commit the real-source partition manifest")
        manifest = json.loads(path.read_text())
        pinned_policy = json.loads((PINNED / "policy.json").read_text())
        self.assertEqual(manifest["source"], pinned_policy["source"])
        self.assertEqual(manifest["policy_sha256"], hashlib.sha256(canonical(pinned_policy)).hexdigest())
        sets = []
        for name in ("train", "validation", "test"):
            part = manifest["partitions"][name]
            self.assertGreater(part["labels"]["0"], 0)
            self.assertGreater(part["labels"]["1"], 0)
            self.assertGreater(part["positive_event_count"], 0)
            self.assertEqual(part["examples"], sum(part["labels"].values()))
            self.assertEqual(part["device_count"], len(part["devices"]))
            devices = set(part["devices"])
            self.assertEqual(len(devices), part["device_count"])
            self.assertTrue(all(self.policy.cohort(key).name == name for key in devices))
            self.assertFalse(any(devices & other for other in sets))
            sets.append(devices)


if __name__ == "__main__":
    unittest.main()
