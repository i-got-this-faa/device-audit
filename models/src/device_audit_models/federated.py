"""A small weighted aggregation primitive, not a federated learning service."""

from dataclasses import dataclass
from math import fsum, isfinite
from typing import Sequence


@dataclass(frozen=True)
class Update:
    base_version: str
    sample_count: int
    weights: tuple[float, ...]


def weighted_average(updates: Sequence[Update]) -> tuple[float, ...]:
    """Average compatible model vectors by local sample count.

    Authentication, poisoning defenses, secure aggregation, privacy accounting,
    and holdout evaluation belong to the future coordinator.
    """
    if not updates:
        raise ValueError("at least one update is required")
    version, width = updates[0].base_version, len(updates[0].weights)
    if not version or not width:
        raise ValueError("model version and nonempty weights are required")
    for update in updates:
        if update.base_version != version or len(update.weights) != width:
            raise ValueError("updates must share base version and dimensions")
        if type(update.sample_count) is not int or update.sample_count <= 0:
            raise ValueError("sample_count must be a positive integer")
        if not all(isfinite(weight) for weight in update.weights):
            raise ValueError("weights must be finite")
    total = sum(update.sample_count for update in updates)
    result = tuple(
        fsum(update.weights[i] * (update.sample_count / total) for update in updates)
        for i in range(width)
    )
    if not all(isfinite(weight) for weight in result):
        raise ValueError("aggregated weights must be finite")
    return result
