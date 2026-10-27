"""Inventory shape checks; schema cannot prove provenance or authorization."""
from pathlib import Path
import unittest

from test_contract_conformance import load_catalogue
from test_envelope_contracts import strict_loads

ROOT = Path(__file__).resolve().parents[2] / "packages/contracts"


class InventoryContractTests(unittest.TestCase):
    def test_shared_vectors(self):
        _, validators = load_catalogue()
        vectors = strict_loads((ROOT / "fixtures/inventory/v1-vectors.json").read_text())["vectors"]
        for vector in vectors:
            with self.subTest(name=vector["name"]):
                payload = vector["payload"]
                accepted = any(validators[version].is_valid(payload) for version in (
                    "device-audit.inventory-update.v1", "device-audit.inventory-record.v1"))
                self.assertEqual(accepted, vector["schema_valid"])
