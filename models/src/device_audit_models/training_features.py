"""ML07 #102 training-side feature preprocessing for the frozen ``hdd-smart-7d.v1``.

ML01's ``partitions.examples`` picks which device and anchor day are examples.
This module turns the same frames into CT03 feature vectors by calling
``features.compute``; it does not restate any preprocessing rule. The endpoint
path is ``packages/health`` in Go, and both read the shared cases in
``packages/contracts/fixtures/features/pipeline-cases.json``.
"""
from __future__ import annotations

from datetime import date, timedelta
from typing import Callable, Iterable, Iterator

from . import features, partitions

DAY = timedelta(days=1)
# Position of each selected CT03 counter in the ML01 column order.
_COLUMN = {counter: partitions.FEATURES.index(counter) for counter, _ in features.COUNTERS}


class IncompleteFeatures(ValueError):
    """A vector with a missing counter was offered to a model."""


def window(anchor: date, history: Iterable[tuple[date, partitions.Observation]]) -> dict:
    """The CT03 input for one anchor day.

    Each Backblaze daily row is one sample at 00:00:00Z and the anchor ends at
    23:59:59Z, so the window is the seven days ending on the anchor. A null
    source value stays null. Rows after the anchor are not part of ``history``
    and a date outside the window is ignored by ``features.compute``.
    """
    samples = [{"observed_at": f"{day.isoformat()}T00:00:00Z",
                **{counter: observation.values[column] for counter, column in _COLUMN.items()}}
               for day, observation in history]
    return {"schema_version": features.WINDOW_SCHEMA, "feature_version": features.FEATURE_VERSION,
            "as_of": f"{anchor.isoformat()}T23:59:59Z", "samples": samples}


def training_vectors(days: Iterable[tuple[date, dict[str, partitions.Observation]]],
                     policy: partitions.Policy, excluded: dict[str, int],
                     include: Callable[[partitions.Example], bool] | None = None,
                     ) -> Iterator[tuple[partitions.Example, dict | None]]:
    """Yield each ML01 example with its CT03 vector.

    A vector can be ``incomplete`` even though ML01 kept the example, because ML01
    only requires seven daily rows, not non-null counters. Pass it through
    ``model_input`` so an incomplete vector never reaches a model.

    ``include`` does not change which examples exist. When it returns false the
    example is still yielded and ``features.compute`` is not called; the vector
    is ``None``. ``None`` is a skipped window, not an incomplete vector.
    """
    if policy.history_days != features.WINDOW_DAYS:
        raise ValueError(f"policy history of {policy.history_days} days differs from the {features.WINDOW_DAYS}-day feature window")
    retained: dict[date, dict[str, partitions.Observation]] = {}
    span = policy.history_days + policy.horizon_days - 1

    def frames() -> Iterator[tuple[date, dict[str, partitions.Observation]]]:
        for day, observations in days:
            retained[day] = observations
            for old in [d for d in retained if d < day - DAY * span]:
                del retained[old]
            yield day, observations

    for example in partitions.examples(frames(), policy, excluded):
        if include is not None and not include(example):
            yield example, None
            continue
        start = date.fromisoformat(example.feature_start)
        history = [(start + DAY * n, retained[start + DAY * n][example.device_key]) for n in range(policy.history_days)]
        yield example, features.compute(window(date.fromisoformat(example.anchor), history))


def model_input(vector: dict) -> list[float]:
    """The ordered values a model may read. Only a complete vector qualifies."""
    features.validate_vector(vector)
    if vector["status"] != "complete":
        reasons = sorted({f["missing_reason"] for f in vector["features"] if f["value"] is None})
        raise IncompleteFeatures(f"vector is incomplete: {', '.join(reasons)}")
    return [f["value"] for f in vector["features"]]
