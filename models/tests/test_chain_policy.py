"""Schema checks for the CHAIN01 descriptor. Schema success is not chain evidence."""

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "contracts/release-policy.schema.json"
POLICY_PATH = ROOT / "contracts/release-policy.json"
VECTORS_PATH = ROOT / "contracts/fixtures/policy/v1-vectors.json"


class ChainPolicySchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)
        cls.policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        cls.vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["vectors"]
        if not cls.vectors:
            raise AssertionError("no chain policy vectors")

    def test_committed_descriptor_shape(self):
        errors = list(self.validator.iter_errors(self.policy))
        self.assertEqual([], errors, "; ".join(error.message for error in errors))
        self.assertEqual(self.policy["environment"], "mainnet")
        self.assertEqual(self.policy["chain_id"], 8453)
        self.assertFalse(self.policy["enabled"])
        self.assertIsNone(self.policy["contract_address"])
        self.assertIsNone(self.policy["writer_address"])
        self.assertIsNone(self.policy["administrator_multisig"])
        self.assertIsNone(self.policy["signer_service_reference"])
        self.assertEqual(self.policy["administrator_threshold"], 2)
        self.assertEqual(self.policy["administrator_owner_count"], 3)

    def test_vectors(self):
        tx_ceiling = int(self.policy["max_total_fee_wei"])
        daily_ceiling = int(self.policy["rolling_24h_fee_budget_wei"])
        classes = set()
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                descriptor = vector["descriptor"]
                schema_ok = self.validator.is_valid(descriptor)
                self.assertEqual(schema_ok, vector["schema_valid"])
                if vector["valid"]:
                    self.assertTrue(schema_ok)
                    self.assertLessEqual(int(descriptor["max_total_fee_wei"]), tx_ceiling)
                    self.assertLessEqual(int(descriptor["rolling_24h_fee_budget_wei"]), daily_ceiling)
                    self.assertLessEqual(
                        int(descriptor["max_total_fee_wei"]),
                        int(descriptor["rolling_24h_fee_budget_wei"]),
                    )
                    if descriptor["enabled"]:
                        self.assertNotEqual(descriptor["writer_address"], descriptor["administrator_multisig"])
                        self.assertNotIn("://", descriptor["signer_service_reference"])
                    classes.add(vector["evidence_class"])
                    self.assertEqual(
                        vector["evidence_class"],
                        {
                            "mainnet": "selected-release-network",
                            "testnet": "integration-testnet",
                            "local": "local-test",
                        }[descriptor["environment"]],
                    )
        self.assertEqual(
            classes,
            {"selected-release-network", "integration-testnet", "local-test"},
        )


if __name__ == "__main__":
    unittest.main()
