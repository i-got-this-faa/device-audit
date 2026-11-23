"""ML02 training: reproducible logistic baseline and held-out refusal.

Synthetic frames exercise the trainer. They are not the packaged artifact.
The committed Backblaze artifact is checked separately and is not refit here.
"""
from array import array
from dataclasses import asdict, replace
from datetime import date, timedelta
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from device_audit_models import baseline, features, partitions, training_features

ROOT = Path(__file__).resolve().parents[2]
DAY = timedelta(days=1)
RESOURCES = {"logical_processors_used": 1, "peak_rss_bytes": 1, "platform": "test", "python": "3.12", "wall_ms": 1}


class SyntheticStudy:
    def __init__(self):
        config = json.loads((ROOT / "models/datasets/backblaze-2013/policy.json").read_text(encoding="utf-8"))
        for split, month in zip(config["splits"], (1, 2, 3)):
            split.update(start=f"2024-{month:02}-01", end=f"2024-{month:02}-28")
        self.policy = partitions.Policy.load(config)
        self.devices = {}
        for number in range(1000):
            key = self.policy.device_key(f"synthetic-{number}")
            self.devices.setdefault(self.policy.cohort(key).name, key)
            if len(self.devices) == 3:
                break
        self.spec, self.spec_bytes = baseline.load_spec(baseline.DEFAULT_SPEC)
        self.spec_sha = baseline.sha256_bytes(self.spec_bytes)

    def frames(self, mutate=None, failure=date(2024, 1, 17), values_for=None):
        for offset in range(88):
            day = date(2024, 1, 1) + DAY * offset
            observations = {}
            for name, device in self.devices.items():
                values = (3, 100, None, 1, None) if values_for is None else values_for(offset)
                if mutate is not None:
                    values = mutate(name, day, values)
                observations[device] = partitions.Observation.from_values(
                    int(name == "train" and day == failure), values)
            yield day, observations

    def pairs(self, **kwargs):
        return list(training_features.training_vectors(self.frames(**kwargs), self.policy, {}))

    def fit(self, pairs=None, spec=None, **kwargs):
        chosen = self.spec if spec is None else spec
        # The study stream preprocesses train rows only. Passing pairs= keeps the
        # caller's selection so a held-out vector can be refused explicitly.
        if pairs is None:
            pairs = [(example, vector) for example, vector in self.pairs(**kwargs) if example.split == "train"]
        return baseline.fit_examples(iter(pairs), self.policy, chosen, self.spec_sha)


class NewtonTests(unittest.TestCase):
    def test_one_step_matches_the_hand_solution(self):
        # Two standardized rows, one active feature. The other five stay zero.
        values = array("d", [1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0])
        labels = array("B", [1, 0])
        beta = baseline._newton(values, labels, 1.0, 1.0, iterations=1, l2=1.0, clip=40.0)
        self.assertEqual(beta[0], 0.0)
        self.assertAlmostEqual(beta[1], 2.0 / 3.0)
        self.assertEqual(beta[2:], [0.0, 0.0, 0.0, 0.0, 0.0])


class FitTests(unittest.TestCase):
    def setUp(self):
        self.study = SyntheticStudy()

    def test_a_clean_rerun_reproduces_the_artifact_bytes(self):
        first = self.study.fit()
        second = self.study.fit()
        self.assertEqual(first, second)
        artifact = baseline.load_artifact(first)
        self.assertEqual(artifact["feature_version"], features.FEATURE_VERSION)
        self.assertEqual(artifact["features"], [name for name, _ in features.FEATURES])
        self.assertEqual(artifact["seed"], 33)
        self.assertGreater(artifact["positive_rows"], 0)
        self.assertGreater(artifact["negative_rows"], 0)
        probability = baseline.predict_probability(artifact, [0.1, 0.2, 0.3, 0.4, 0.5, 0.6])
        self.assertGreater(probability, 0.0)
        self.assertLess(probability, 1.0)
        self.assertNotIn("health", artifact)
        self.assertNotIn("signature", artifact)

    def test_the_seed_is_part_of_the_artifact_and_the_optimizer_draws_nothing(self):
        seeded = json.loads(json.dumps(self.study.spec))
        seeded["seed"] = 34
        first = baseline.load_artifact(self.study.fit())
        second = baseline.load_artifact(self.study.fit(spec=seeded))
        self.assertEqual(first["weights"], second["weights"])
        self.assertEqual(first["intercept"], second["intercept"])
        self.assertNotEqual(first["seed"], second["seed"])
        with patch("random.Random", side_effect=AssertionError("optimizer drew a random number")):
            self.study.fit()

    def test_constant_features_stay_at_the_zero_start(self):
        artifact = baseline.load_artifact(self.study.fit(values_for=lambda _offset: (3, 100, None, 1, None)))
        learned = [baseline.decode_float(value) for value in artifact["weights"]]
        learned.append(baseline.decode_float(artifact["intercept"]))
        self.assertTrue(all(abs(value) < 1e-12 for value in learned))
        self.assertAlmostEqual(baseline.predict_probability(artifact, [0.0] * 6), 0.5, places=12)

    def test_values_after_the_anchor_do_not_change_the_artifact(self):
        base = self.study.fit()
        changed = self.study.fit(mutate=lambda _name, day, values: (
            (99999, 99999, None, 99999, None) if day > date(2024, 1, 16) else values))
        self.assertEqual(base, changed)

    def test_held_out_device_values_do_not_change_the_artifact(self):
        base = self.study.fit()

        def mutate(name, _day, values):
            if name == "train":
                return values
            return tuple(None if value is None else 99999 for value in values)

        self.assertEqual(base, self.study.fit(mutate=mutate))

    def test_a_held_out_vector_is_refused_before_newton(self):
        held = [(example, vector) for example, vector in self.study.pairs() if example.split != "train"]
        self.assertTrue(any(example.split == "validation" for example, _ in held))
        self.assertTrue(any(example.split == "test" for example, _ in held))
        with patch("device_audit_models.baseline._newton") as newton:
            with self.assertRaises(baseline.HeldOutPartition) as raised:
                self.study.fit(pairs=held)
            newton.assert_not_called()
        self.assertNotRegex(str(raised.exception), r"[0-9a-f]{64}")
        self.assertNotIn("signature", str(raised.exception))

    def test_a_train_label_on_a_held_out_device_is_refused(self):
        example, vector = next((item, features_vector) for item, features_vector in self.study.pairs()
                               if item.split == "validation")
        spoofed = [(replace(example, split="train"), vector)]
        with patch("device_audit_models.baseline._newton") as newton:
            with self.assertRaises(baseline.HeldOutPartition) as raised:
                self.study.fit(pairs=spoofed)
            newton.assert_not_called()
        self.assertIn("cohort validation", str(raised.exception))
        self.assertNotRegex(str(raised.exception), r"[0-9a-f]{64}")

    def test_skipping_held_out_vectors_does_not_fit_them(self):
        skipped = [(example, None) for example, _ in self.study.pairs() if example.split != "train"]
        with patch("device_audit_models.baseline._newton") as newton:
            with self.assertRaises(baseline.TrainingRefusal):
                self.study.fit(pairs=skipped)
            newton.assert_not_called()

    def test_fit_examples_has_no_held_out_split_argument(self):
        self.assertEqual(list(inspect.signature(baseline.fit_examples).parameters),
                         ["pairs", "policy", "spec", "spec_sha256"])

    def test_incomplete_train_vectors_are_excluded(self):
        def mutate(name, day, values):
            if name == "train" and day == date(2024, 1, 4):
                return (values[0], None, None, values[3], None)
            return values

        pairs = [(example, vector) for example, vector in self.study.pairs(mutate=mutate, failure=date(2024, 1, 24))
                 if example.split == "train"]
        collected = baseline.collect(iter(pairs), self.study.policy, self.study.spec)
        self.assertGreater(collected.incomplete, 0)
        self.assertGreater(collected.positive, 0)
        self.assertGreater(collected.negative, 0)
        self.assertEqual(collected.positive + collected.negative + collected.incomplete,
                         collected.counts["train"])
        with self.assertRaises(baseline.TrainingRefusal):
            self.study.fit(pairs=self.study.pairs(values_for=lambda _offset: (1, None, None, 1, None)))

    def test_split_digests_use_the_ml01_example_line(self):
        rows = [example for example, _ in self.study.pairs()]
        digest = hashlib.sha256()
        for example in rows:
            baseline.update_example_digest(digest, example)
        expected = hashlib.sha256()
        for example in rows:
            line = json.dumps(asdict(example), sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
            expected.update(line)
        self.assertEqual(digest.hexdigest(), expected.hexdigest())
        self.assertNotEqual(digest.hexdigest(), hashlib.sha256(b"").hexdigest())


class SpecAndToleranceTests(unittest.TestCase):
    def setUp(self):
        self.study = SyntheticStudy()

    def test_the_spec_cannot_aim_training_at_a_held_out_split_or_drop_below_the_keep_floor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "spec.json"
            aimed = json.loads(json.dumps(self.study.spec))
            aimed["fit_split"] = "test"
            path.write_text(json.dumps(aimed), encoding="utf-8")
            with self.assertRaises(baseline.HeldOutPartition):
                baseline.load_spec(path)
            weak = json.loads(json.dumps(self.study.spec))
            weak["fit_split"] = "train"
            weak["negative_keep_numerator"] = 1
            weak["negative_keep_denominator"] = 21
            path.write_text(json.dumps(weak), encoding="utf-8")
            with self.assertRaises(baseline.TrainingRefusal):
                baseline.load_spec(path)

    def test_positives_are_never_subsampled(self):
        example = next(item for item, _ in self.study.pairs() if item.split == "train" and item.label == 1)
        self.assertTrue(baseline.keep_negative(example, 1, 20))
        negative = next(item for item, _ in self.study.pairs() if item.split == "train" and item.label == 0)
        decisions = {baseline.keep_negative(replace(negative, anchor=str(index)), 1, 20) for index in range(400)}
        self.assertEqual(decisions, {True, False})
        self.assertTrue(baseline.keep_negative(negative, 1, 1))

    def test_recorded_tolerance_accepts_a_small_parameter_change_and_rejects_a_large_one(self):
        pairs = [(example, vector) for example, vector in self.study.pairs() if example.split == "train"]
        collected = baseline.collect(iter(pairs), self.study.policy, self.study.spec)
        artifact = baseline.fit_collected(collected, self.study.spec, self.study.spec_sha)
        document = self._provenance(collected, artifact)
        self.assertEqual(baseline.compare_rerun(artifact, document, artifact, json.loads(json.dumps(document))), "exact")
        moved = json.loads(json.dumps(document))
        moved["resources"] = dict(moved["resources"], wall_ms=999)
        self.assertEqual(baseline.compare_rerun(artifact, document, artifact, moved), "exact")

        nudged = baseline.load_artifact(artifact)
        weight = baseline.decode_float(nudged["weights"][0]) + self.study.spec["rerun_atol"] / 10
        nudged["weights"][0] = baseline.encode_float(weight)
        nudged_bytes = baseline.canonical(nudged)
        nudged_document = self._provenance(collected, nudged_bytes)
        self.assertEqual(baseline.compare_rerun(artifact, document, nudged_bytes, nudged_document), "within_tolerance")

        broken = baseline.load_artifact(artifact)
        broken["intercept"] = baseline.encode_float(baseline.decode_float(broken["intercept"]) + 1.0)
        broken_bytes = baseline.canonical(broken)
        with self.assertRaises(baseline.TrainingRefusal):
            baseline.compare_rerun(artifact, document, broken_bytes, self._provenance(collected, broken_bytes))

    def test_provenance_records_the_required_declaration_and_no_activation_claim(self):
        pairs = [(example, vector) for example, vector in self.study.pairs() if example.split == "train"]
        collected = baseline.collect(iter(pairs), self.study.policy, self.study.spec)
        artifact = baseline.fit_collected(collected, self.study.spec, self.study.spec_sha)
        document = self._provenance(collected, artifact)
        self.assertEqual(document["schema_version"], baseline.PROVENANCE_SCHEMA)
        self.assertEqual(document["feature_version"], features.FEATURE_VERSION)
        self.assertEqual(document["seeds"]["declaration"], 33)
        self.assertEqual(document["seeds"]["optimizer_draws"], 0)
        self.assertEqual(document["splits"]["fit_split"], "train")
        self.assertEqual(document["splits"]["held_out"], ["validation", "test"])
        self.assertEqual(document["artifact_sha256"], baseline.sha256_bytes(artifact))
        self.assertEqual(document["fit"]["parameter_count"], 7)
        self.assertEqual(document["fit"]["parameter_names"][0], "intercept")
        self.assertEqual(len(document["fit"]["parameter_names"]), 7)
        self.assertFalse(any(document["claims"].values()))
        self.assertNotIn(self.study.devices["train"], json.dumps(document))

    def _provenance(self, collected, artifact):
        splits = {
            "examples_sha256": {name: collected.digests[name].hexdigest() for name in collected.digests},
            "fit_split": "train",
            "held_out": ["validation", "test"],
            "manifest_sha256": "c" * 64,
            "policy_sha256": "d" * 64,
        }
        dataset = {"bytes": 3, "name": "synthetic-not-a-substitute", "sha256": "a" * 64, "url": "https://example.invalid"}
        return baseline.provenance_document(self.study.spec, self.study.spec_sha, dataset, splits, artifact,
                                            collected, dict(RESOURCES))


class PackagedArtifactTests(unittest.TestCase):
    """The committed artifact was fit on the pinned archive. This does not refit it."""

    def test_packaged_provenance_is_the_pinned_backblaze_study(self):
        artifact_bytes = baseline.DEFAULT_ARTIFACT.read_bytes()
        provenance_bytes = baseline.DEFAULT_PROVENANCE.read_bytes()
        artifact = baseline.load_artifact(artifact_bytes)
        provenance = json.loads(provenance_bytes)
        self.assertEqual(provenance_bytes, baseline.canonical(provenance))
        self.assertEqual(provenance["artifact_sha256"], baseline.sha256_bytes(artifact_bytes))
        spec, spec_bytes = baseline.load_spec(baseline.DEFAULT_SPEC)
        self.assertEqual(provenance["spec_sha256"], baseline.sha256_bytes(spec_bytes))
        self.assertEqual(provenance["spec"], spec)
        self.assertEqual(artifact["spec_sha256"], provenance["spec_sha256"])
        self.assertEqual(artifact["seed"], spec["seed"])
        self.assertEqual(artifact["feature_version"], features.FEATURE_VERSION)
        policy = json.loads(baseline.DEFAULT_POLICY.read_text(encoding="utf-8"))
        manifest_bytes = baseline.DEFAULT_MANIFEST.read_bytes()
        manifest = json.loads(manifest_bytes)
        evaluation = json.loads(baseline.DEFAULT_EVALUATION.read_text(encoding="utf-8"))
        study = evaluation["study"]
        self.assertEqual(provenance["splits"]["policy_sha256"], study["partition_policy_sha256"])
        self.assertEqual(provenance["splits"]["policy_sha256"],
                         hashlib.sha256(partitions.canonical(policy)).hexdigest())
        self.assertEqual(provenance["splits"]["manifest_sha256"], study["partition_manifest_sha256"])
        self.assertEqual(provenance["splits"]["manifest_sha256"], hashlib.sha256(manifest_bytes).hexdigest())
        self.assertEqual(provenance["dataset"]["sha256"], policy["source"]["sha256"])
        self.assertEqual(provenance["dataset"]["bytes"], manifest["source_observations"]["archive_bytes"])
        self.assertIn("Backblaze", provenance["dataset"]["name"])
        self.assertEqual(provenance["splits"]["examples_sha256"],
                         {name: manifest["partitions"][name]["examples_sha256"] for name in ("train", "validation", "test")})
        self.assertEqual(provenance["splits"]["fit_split"], "train")
        self.assertEqual(provenance["splits"]["held_out"], ["validation", "test"])
        labels = manifest["partitions"]["train"]["labels"]
        self.assertEqual(provenance["fit"]["positive_rows"], labels["1"])
        self.assertEqual(provenance["fit"]["negative_rows"], labels["0"])
        self.assertEqual(provenance["fit"]["incomplete_excluded"], 0)
        self.assertEqual(provenance["fit"]["negative_subsampled_out"], 0)
        self.assertEqual(provenance["seeds"]["optimizer_draws"], 0)
        self.assertEqual(provenance["seeds"]["declaration"], 33)
        self.assertFalse(any(provenance["claims"].values()))
        self.assertNotIn("signature", artifact)
        resources = provenance["resources"]
        self.assertEqual(resources["logical_processors_used"], 1)
        self.assertGreaterEqual(resources["wall_ms"], 60_000)
        self.assertLessEqual(resources["wall_ms"], 1_800_000)
        self.assertGreaterEqual(resources["peak_rss_bytes"], 64 * 1024 ** 2)
        self.assertLessEqual(resources["peak_rss_bytes"], 4 * 1024 ** 3)
        self.assertNotRegex(provenance_bytes.decode(), r"serial_number")


if __name__ == "__main__":
    unittest.main()
