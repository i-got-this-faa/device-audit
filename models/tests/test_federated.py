import unittest

from device_audit_models.federated import Update, weighted_average


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
