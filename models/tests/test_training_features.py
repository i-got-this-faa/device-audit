"""ML07 #102 training preprocessing: shared pipeline cases and the ML01 example stream.

Observations are artificial; none is Backblaze evidence.
"""
from datetime import date, timedelta
import json
import math
from pathlib import Path
import unittest

from device_audit_models import features, partitions, training_features

ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / "packages/contracts/fixtures/features/pipeline-cases.json").read_text(encoding="utf-8"))
DAY = timedelta(days=1)


def observations(rows):
    return {date.fromisoformat(r["date"]): partitions.Observation.from_values(
        0, tuple(r[column] for column in CASES["columns"])) for r in rows}


class PipelineCaseTests(unittest.TestCase):
    def test_cases_declare_the_frozen_version_and_tolerance(self):
        self.assertEqual(CASES["feature_version"], features.FEATURE_VERSION)
        self.assertEqual(CASES["tolerance"], features.TOLERANCE)
        self.assertEqual(CASES["columns"], list(partitions.FEATURES))
        self.assertTrue(CASES["cases"])

    def test_training_path_matches_the_shared_cases(self):
        for case in CASES["cases"]:
            with self.subTest(case["name"]):
                anchor = date.fromisoformat(case["anchor"])
                # Training builds each example from the seven days ending at the anchor.
                history = sorted((d, o) for d, o in observations(case["rows"]).items()
                                 if anchor - DAY * 6 <= d <= anchor)
                vector = features.compute(training_features.window(anchor, history))
                features.validate_vector(vector)
                self.assertTrue(features.close(vector, case["expected"]), json.dumps(vector))

    def test_future_rows_cannot_reach_training_even_when_passed_in(self):
        case = next(c for c in CASES["cases"] if c["name"] == "future rows are never evidence")
        anchor = date.fromisoformat(case["anchor"])
        everything = sorted(observations(case["rows"]).items())
        vector = features.compute(training_features.window(anchor, everything))
        self.assertTrue(features.close(vector, case["expected"]))


class ExampleStreamTests(unittest.TestCase):
    """training_vectors over the ML01 example generator."""

    def setUp(self):
        config = json.loads((ROOT / "models/datasets/backblaze-2013/policy.json").read_text(encoding="utf-8"))
        for split, month in zip(config["splits"], (1, 2, 3)):
            split.update(start=f"2024-{month:02}-01", end=f"2024-{month:02}-28")
        self.policy = partitions.Policy.load(config)
        self.device = next(key for key in (self.policy.device_key(f"synthetic-{n}") for n in range(1000))
                           if self.policy.cohort(key).name == "train")

    def frames(self, make):
        for offset in range(40):
            day = date(2024, 1, 1) + DAY * offset
            yield day, {self.device: partitions.Observation.from_values(0, make(offset))}

    def vectors(self, make):
        excluded = {}
        return list(training_features.training_vectors(self.frames(make), self.policy, excluded)), excluded

    def test_a_complete_example_yields_a_model_input(self):
        results, _ = self.vectors(lambda n: (n, 1000 + 24 * n, None, n // 2, None))
        self.assertTrue(results)
        for example, vector in results:
            anchor = date.fromisoformat(example.anchor)
            self.assertEqual(vector["window_end"], anchor.isoformat())
            self.assertEqual(vector["window_start"], (anchor - DAY * 6).isoformat())
            values = training_features.model_input(vector)
            self.assertEqual(len(values), len(features.FEATURES))
        # Anchor 2024-01-10 covers offsets 9 down to 3, so counter 5 grows by 6.
        _, vector = next(r for r in results if r[0].anchor == "2024-01-10")
        self.assertAlmostEqual(vector["features"][1]["value"], math.log1p(6), places=12)

    def test_values_after_the_anchor_never_change_the_vector(self):
        # The label horizon is seven days past the anchor; its SMART values are unused.
        base, _ = self.vectors(lambda n: (n, 1000 + n, None, 0, None))
        changed, _ = self.vectors(lambda n: (n if n <= 12 else 9999, 1000 + n if n <= 12 else 99999, None, 0, None))
        before = next(v for e, v in base if e.anchor == "2024-01-10")
        after = next(v for e, v in changed if e.anchor == "2024-01-10")
        self.assertEqual(before, after)

    def test_a_null_counter_is_kept_by_ml01_but_never_reaches_a_model(self):
        results, _ = self.vectors(lambda n: (n, None, None, 0, None))
        self.assertTrue(results)
        for _, vector in results:
            self.assertEqual(vector["status"], "incomplete")
            self.assertEqual(vector["features"][2]["missing_reason"], "no_observation")
            with self.assertRaises(training_features.IncompleteFeatures):
                training_features.model_input(vector)

    def test_a_sparse_window_is_excluded_by_ml01_before_preprocessing(self):
        def frames():
            for day, observations in self.frames(lambda n: (n, n, None, 0, None)):
                if day != date(2024, 1, 8):
                    yield day, observations
        excluded = {}
        anchors = {e.anchor for e, _ in training_features.training_vectors(frames(), self.policy, excluded)}
        # Any anchor whose seven-day history includes 2024-01-08 is not an example.
        self.assertTrue(all(not date(2024, 1, 8) <= date.fromisoformat(a) <= date(2024, 1, 14) for a in anchors))
        self.assertGreater(excluded["incomplete_history"], 0)

    def test_policy_history_must_equal_the_feature_window(self):
        config = json.loads((ROOT / "models/datasets/backblaze-2013/policy.json").read_text(encoding="utf-8"))
        config["history_days"] = 5
        with self.assertRaises(ValueError):
            list(training_features.training_vectors([], partitions.Policy.load(config), {}))


class ModelInputTests(unittest.TestCase):
    def test_only_a_complete_vector_is_model_input(self):
        complete = next(c["expected"] for c in CASES["cases"] if c["name"] == "complete week")
        values = training_features.model_input(complete)
        self.assertEqual(values, [f["value"] for f in complete["features"]])
        for case in CASES["cases"]:
            if case["expected"]["status"] == "incomplete":
                with self.subTest(case["name"]), self.assertRaises(training_features.IncompleteFeatures):
                    training_features.model_input(case["expected"])

    def test_a_malformed_vector_is_rejected_not_read(self):
        reordered = json.loads(json.dumps(next(c["expected"] for c in CASES["cases"] if c["name"] == "complete week")))
        reordered["features"][0], reordered["features"][1] = reordered["features"][1], reordered["features"][0]
        with self.assertRaises(ValueError):
            training_features.model_input(reordered)


if __name__ == "__main__":
    unittest.main()
