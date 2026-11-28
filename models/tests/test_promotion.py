import json
from pathlib import Path
import unittest

from device_audit_models import promotion

EVALUATION = Path(__file__).resolve().parents[1] / "evaluation"
POLICY = json.loads((EVALUATION / "promotion-policy.json").read_text(encoding="utf-8"))
VECTORS = json.loads((EVALUATION / "promotion-vectors.json").read_text(encoding="utf-8"))


class PromotionPolicyTests(unittest.TestCase):
    def test_vectors_match_the_policy(self):
        self.assertEqual(VECTORS["policy_version"], POLICY["policy_version"])
        for case in VECTORS["cases"]:
            with self.subTest(case["name"]):
                result = promotion.decide(POLICY, case["candidate"], case["active"])
                self.assertEqual(result, {"outcome": case["outcome"], "reasons": case["reasons"]})

    def test_policy_gates_are_valid_and_unique(self):
        promotion.validate_policy(POLICY)
        ids = [gate["id"] for gate in POLICY["regression_gates"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_a_policy_declared_after_candidates_is_refused(self):
        with self.assertRaises(ValueError):
            promotion.validate_policy({**POLICY, "declared_before_candidates": False})

    def test_a_negative_tolerance_is_refused(self):
        gate = {**POLICY["regression_gates"][0], "max_degradation": -0.1}
        with self.assertRaises(ValueError):
            promotion.validate_policy({**POLICY, "regression_gates": [gate]})


if __name__ == "__main__":
    unittest.main()
