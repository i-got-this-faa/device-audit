"""CT03 #32 frozen feature preprocessing, the Python reference.

Training, endpoint and controller code must produce the same vector from the
same window. ``packages/contracts/features-v1.md`` defines the rules; the Go
reference is ``packages/contracts/features_v1.go``. Shared vectors in
``packages/contracts/fixtures/features/v1-vectors.json`` hold both to
``TOLERANCE``.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import math
import re

WINDOW_SCHEMA = "device-audit.feature-window.v1"
VECTOR_SCHEMA = "device-audit.feature-vector.v1"
FEATURE_VERSION = "hdd-smart-7d.v1"
WINDOW_DAYS = 7
MAX_SAMPLES = 10080
MAX_COUNTER = 2**53 - 1
# |python - other| <= TOLERANCE + TOLERANCE * |other| for each feature value.
TOLERANCE = 1e-12
MISSING_REASONS = ("no_observation", "incomplete_history")

# Frozen order. Each counter yields ``.last`` then ``.delta``.
COUNTERS = (("smart_5_raw", "count"), ("smart_9_raw", "hours"), ("smart_197_raw", "count"))
FEATURES = tuple(
    feature
    for counter, unit in COUNTERS
    for feature in ((f"{counter}.last", f"log1p_{unit}"), (f"{counter}.delta", f"signed_log1p_{unit}"))
)

_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class UnsupportedFeatureVersion(ValueError):
    """A well-formed request for a feature version this reader does not implement."""


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp must be a UTC whole-second date")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if parsed.year < 2:
        raise ValueError("timestamp year must be 0002..9999")
    return parsed


def _exact_keys(value: object, required: set[str], optional: frozenset[str] = frozenset()) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() <= required | optional:
        raise ValueError(f"object must have fields {sorted(required)}")
    return value


def _check_version(value: dict, schema: str) -> None:
    if value["schema_version"] != schema:
        raise ValueError(f"unsupported schema {value['schema_version']!r}")
    if value["feature_version"] != FEATURE_VERSION:
        raise UnsupportedFeatureVersion(value["feature_version"])


def _window_bounds(as_of: datetime) -> tuple[datetime, date]:
    end = as_of.date()
    start = end - timedelta(days=WINDOW_DAYS - 1)
    return datetime(start.year, start.month, start.day, tzinfo=timezone.utc), end


def validate_window(window: object) -> None:
    window = _exact_keys(window, {"schema_version", "feature_version", "as_of", "samples"})
    _check_version(window, WINDOW_SCHEMA)
    _timestamp(window["as_of"])
    samples = window["samples"]
    if not isinstance(samples, list) or len(samples) > MAX_SAMPLES:
        raise ValueError(f"samples are required and limited to {MAX_SAMPLES}")
    seen = set()
    for sample in samples:
        sample = _exact_keys(sample, {"observed_at", *(c for c, _ in COUNTERS)})
        _timestamp(sample["observed_at"])
        if sample["observed_at"] in seen:
            raise ValueError(f"duplicate sample at {sample['observed_at']}")
        seen.add(sample["observed_at"])
        for counter, _ in COUNTERS:
            value = sample[counter]
            # bool is an int subclass; JSON floats such as 1.0 are not counters.
            if value is not None and (type(value) is not int or not 0 <= value <= MAX_COUNTER):
                raise ValueError(f"{counter} must be null or an integer 0..{MAX_COUNTER}")


def _signed_log1p(x: int) -> float:
    return -math.log1p(-x) if x < 0 else math.log1p(x)


def compute(window: object) -> dict:
    """Return the feature vector for a window. Missing counters are never filled."""
    validate_window(window)
    as_of = _timestamp(window["as_of"])
    start, end = _window_bounds(as_of)
    # daily[counter][day] = (observed_at, value) of that day's latest non-null reading.
    daily: dict[str, dict[int, tuple[datetime, int]]] = {c: {} for c, _ in COUNTERS}
    for sample in window["samples"]:
        at = _timestamp(sample["observed_at"])
        if not start <= at <= as_of:
            continue
        day = (at - start).days
        for counter, _ in COUNTERS:
            value = sample[counter]
            if value is not None and (day not in daily[counter] or at > daily[counter][day][0]):
                daily[counter][day] = (at, value)

    features = []
    for counter, unit in COUNTERS:
        days = daily[counter]
        last = {"name": f"{counter}.last", "value": None, "unit": f"log1p_{unit}"}
        delta = {"name": f"{counter}.delta", "value": None, "unit": f"signed_log1p_{unit}"}
        if len(days) == WINDOW_DAYS:
            first, final = days[0][1], days[WINDOW_DAYS - 1][1]
            last["value"], delta["value"] = math.log1p(final), _signed_log1p(final - first)
        else:
            reason = "no_observation" if not days else "incomplete_history"
            last["missing_reason"] = delta["missing_reason"] = reason
        features += [last, delta]
    return {
        "schema_version": VECTOR_SCHEMA,
        "feature_version": FEATURE_VERSION,
        "as_of": window["as_of"],
        "window_start": start.date().isoformat(),
        "window_end": end.isoformat(),
        "status": "complete" if all(f["value"] is not None for f in features) else "incomplete",
        "features": features,
    }


def validate_vector(vector: object) -> None:
    """Reject a vector whose version, window, order, units or missing state differ."""
    vector = _exact_keys(vector, {"schema_version", "feature_version", "as_of", "window_start",
                                  "window_end", "status", "features"})
    _check_version(vector, VECTOR_SCHEMA)
    start, end = _window_bounds(_timestamp(vector["as_of"]))
    if vector["window_start"] != start.date().isoformat() or vector["window_end"] != end.isoformat():
        raise ValueError("window does not end on the as_of UTC day")
    features = vector["features"]
    if not isinstance(features, list) or len(features) != len(FEATURES):
        raise ValueError(f"expected {len(FEATURES)} features")
    for index, (feature, (name, unit)) in enumerate(zip(features, FEATURES)):
        feature = _exact_keys(feature, {"name", "value", "unit"}, frozenset({"missing_reason"}))
        if (feature["name"], feature["unit"]) != (name, unit):
            raise ValueError(f"feature {index} is not {name}/{unit}")
        value = feature["value"]
        if value is None:
            if feature.get("missing_reason") not in MISSING_REASONS:
                raise ValueError(f"{name}: null value needs a missing reason")
        elif ("missing_reason" in feature or type(value) not in (int, float)
              or not math.isfinite(value)):
            raise ValueError(f"{name}: known value must be finite without a missing reason")
        elif index % 2 == 0 and value < 0:
            raise ValueError(f"{name} cannot be negative")
        if index % 2 == 1:
            previous = features[index - 1]
            if ((value is None) != (previous["value"] is None)
                    or feature.get("missing_reason") != previous.get("missing_reason")):
                raise ValueError(f"{previous['name']} and {name} disagree on missing state")
    complete = all(f["value"] is not None for f in features)
    if vector["status"] not in ("complete", "incomplete") or (vector["status"] == "complete") != complete:
        raise ValueError("status does not match the feature values")


def close(actual: dict, expected: dict) -> bool:
    """Compare two vectors exactly except feature values, which use TOLERANCE."""
    strip = lambda v: {**v, "features": [{**f, "value": None} for f in v["features"]]}
    if strip(actual) != strip(expected):
        return False
    for a, e in zip(actual["features"], expected["features"]):
        if (a["value"] is None) != (e["value"] is None):
            return False
        if a["value"] is not None and abs(a["value"] - e["value"]) > TOLERANCE + TOLERANCE * abs(e["value"]):
            return False
    return True
