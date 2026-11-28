"""FED10 #115 promotion decision over two ML05 evaluation summaries.

The controller applies this policy when it promotes a candidate. This module
mirrors it so a candidate can be checked offline before it is submitted. Both
read ``models/evaluation/promotion-policy.json`` and agree on
``promotion-vectors.json``.
"""

from __future__ import annotations

POLICY_VERSION = "device-audit.promotion-policy.v1"


def validate_policy(policy: dict) -> dict:
    """Reject a policy that was not frozen before candidates or can gate nothing."""
    if policy.get("schema_version") != POLICY_VERSION or policy.get("declared_before_candidates") is not True:
        raise ValueError("unsupported promotion policy or not declared before candidates")
    seen = set()
    for gate in policy.get("regression_gates", []):
        degradation = gate.get("max_degradation")
        if (gate.get("id") in seen or not gate.get("metric") or type(gate.get("higher_is_better")) is not bool
                or type(degradation) not in (int, float) or degradation < 0):
            raise ValueError(f"invalid regression gate {gate.get('id')!r}")
        seen.add(gate["id"])
    if not seen:
        raise ValueError("at least one regression gate is required")
    return policy


def decide(policy: dict, candidate: dict, active: dict | None) -> dict:
    """Return ``{"outcome", "reasons"}`` for a candidate against the active model.

    Each side is ``{"verdict", "reasons", "test_partition_sha256", "metrics"}``
    where ``metrics`` maps a name to its point estimate. ``active`` is None when
    no model is active, and then only the ML05 verdict applies.
    """
    validate_policy(policy)
    if candidate["verdict"] != "pass":
        return {"outcome": "rejected", "reasons": [f"evaluation_{candidate['verdict']}", *candidate["reasons"]]}
    if active is None:
        return {"outcome": "promoted", "reasons": []}
    if active["verdict"] != "pass" or active["test_partition_sha256"] != candidate["test_partition_sha256"]:
        return {"outcome": "rejected", "reasons": ["baseline_not_comparable"]}
    reasons = []
    for gate in policy["regression_gates"]:
        new, old = candidate["metrics"][gate["metric"]], active["metrics"][gate["metric"]]
        loss = old - new if gate["higher_is_better"] else new - old
        if loss > gate["max_degradation"]:
            reasons.append(f"regression:{gate['id']}")
    return {"outcome": "rejected" if reasons else "promoted", "reasons": reasons}
