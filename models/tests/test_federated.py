import hashlib
import json
import pathlib
import unittest

from device_audit_models.federated import (
    ParticipantInput,
    Update,
    aggregation_input_sha256,
    build_logistic_candidate_artifact,
    weighted_average,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]


class WeightedAverageTests(unittest.TestCase):
    def test_weights_by_local_sample_count(self):
        self.assertEqual(
            weighted_average([Update("v1", 1, (2.0, 4.0)), Update("v1", 3, (6.0, 8.0))]),
            (5.0, 7.0),
        )

    def test_rejects_incompatible_or_invalid_updates(self):
        cases = [
            [],
            [Update("", 1, (1.0,))],
            [Update("v1", 0, (1.0,))],
            [Update("v1", True, (1.0,))],
            [Update("v1", 1, (float("nan"),))],
            [Update("v1", 1, (1.0,)), Update("v2", 1, (1.0,))],
            [Update("v1", 1, (1.0,)), Update("v1", 1, (1.0, 2.0))],
        ]
        for updates in cases:
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                weighted_average(updates)

    def test_reproducible_candidate_and_input_digest(self):
        base_artifact = (ROOT / "models" / "baseline" / "backblaze-2013" / "artifact.json").read_bytes()
        base_sha = hashlib.sha256(base_artifact).hexdigest()
        inputs = [
            ParticipantInput("device:b", "ed25519:" + "b" * 64, 2, 30, "2" * 64, "4" * 64),
            ParticipantInput("device:a", "ed25519:" + "a" * 64, 2, 10, "1" * 64, "3" * 64),
        ]
        d1, total1 = aggregation_input_sha256(
            deployment_id="deployment:fed03",
            round_id="round:fed03:1",
            candidate_id="candidate:fed03:1",
            base_model_version="logistic-baseline.backblaze-2013.v1",
            base_model_sha256=base_sha,
            feature_version="hdd-smart-7d.v1",
            parameter_count=7,
            participants=inputs,
        )
        d2, total2 = aggregation_input_sha256(
            deployment_id="deployment:fed03",
            round_id="round:fed03:1",
            candidate_id="candidate:fed03:1",
            base_model_version="logistic-baseline.backblaze-2013.v1",
            base_model_sha256=base_sha,
            feature_version="hdd-smart-7d.v1",
            parameter_count=7,
            participants=list(reversed(inputs)),
        )
        self.assertEqual((d1, total1), (d2, total2))
        self.assertEqual(d1, "bca4312ae1bf578677a758b61ffcdc80543f724e346ad72eaef45564599299c5")
        self.assertEqual(total1, 40)

        weights = weighted_average([
            Update("logistic-baseline.backblaze-2013.v1", 30, (6.0, 8.0, 10.0, 12.0, 14.0, 16.0, 18.0)),
            Update("logistic-baseline.backblaze-2013.v1", 10, (2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0)),
        ])
        cand = build_logistic_candidate_artifact(base_artifact, "candidate:fed03:1", weights)
        self.assertEqual(
            hashlib.sha256(cand).hexdigest(),
            "e300389821efb716a3202090b09a4149429894158583301a83a5a89a511d5e77",
        )
        parsed = json.loads(cand)
        self.assertEqual(parsed["model_version"], "candidate:fed03:1")
        self.assertEqual(parsed["intercept"], float(5.0).hex())
        self.assertEqual(len(parsed["weights"]), 6)
