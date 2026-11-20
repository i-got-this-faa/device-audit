"""Write CT03 #32 shared feature vectors: python3 packages/contracts/fixtures/features/generate.py

Expected vectors come from the hand-written (first, final) day values below,
not from either reference implementation, so the vectors also check day
selection, window bounds and missing reasons. log1p is evaluated with 50-digit
decimal arithmetic, not math.log1p, so neither language's libm is the oracle.
"""
import copy
import json
from decimal import Decimal, localcontext
from pathlib import Path

WINDOW = "device-audit.feature-window.v1"
VECTOR = "device-audit.feature-vector.v1"
VERSION = "hdd-smart-7d.v1"
COUNTERS = (("smart_5_raw", "count"), ("smart_9_raw", "hours"), ("smart_197_raw", "count"))
DAYS = [f"2013-11-0{d}" for d in range(1, 8)]
AS_OF = "2013-11-07T23:59:59Z"


def sample(at, s5, s9, s197):
    return {"observed_at": at, "smart_5_raw": s5, "smart_9_raw": s9, "smart_197_raw": s197}


def daily(s5, s9, s197, hour="00:00:00"):
    """One Backblaze-style snapshot per window day."""
    return [sample(f"{d}T{hour}Z", *v) for d, v in zip(DAYS, zip(s5, s9, s197))]


def window(samples, as_of=AS_OF, version=VERSION):
    return {"schema_version": WINDOW, "feature_version": version, "as_of": as_of, "samples": samples}


def log1p(x):
    with localcontext() as ctx:
        ctx.prec = 50
        return float((Decimal(x) + 1).ln())


def signed_log1p(x):
    return -log1p(-x) if x < 0 else log1p(x)


def vector(state, as_of=AS_OF, start="2013-11-01", end="2013-11-07"):
    """state maps each counter to (first, final) day values or a missing reason."""
    features = []
    for counter, unit in COUNTERS:
        last = {"name": f"{counter}.last", "value": None, "unit": f"log1p_{unit}"}
        delta = {"name": f"{counter}.delta", "value": None, "unit": f"signed_log1p_{unit}"}
        if isinstance(state[counter], str):
            last["missing_reason"] = delta["missing_reason"] = state[counter]
        else:
            first, final = state[counter]
            last["value"], delta["value"] = log1p(final), signed_log1p(final - first)
        features += [last, delta]
    complete = all(f["value"] is not None for f in features)
    return {"schema_version": VECTOR, "feature_version": VERSION, "as_of": as_of,
            "window_start": start, "window_end": end,
            "status": "complete" if complete else "incomplete", "features": features}


HOURS = [11000 + 24 * i for i in range(7)]
ZEROS = [0] * 7
vectors = []


def valid(name, payload, expected=None):
    vectors.append({"name": name, "payload": payload, "schema_valid": True, "valid": True,
                    "rejection": None, "expected": expected})


def invalid(name, payload, schema_valid, rejection="invalid_contract"):
    vectors.append({"name": name, "payload": payload, "schema_valid": schema_valid, "valid": False,
                    "rejection": rejection, "expected": None})


complete = vector({"smart_5_raw": (0, 16), "smart_9_raw": (11000, 11144), "smart_197_raw": (0, 0)})
valid("backblaze daily snapshots complete",
      window(daily([0, 0, 0, 0, 8, 8, 16], HOURS, ZEROS)), complete)

# Several readings a day, shuffled. The latest non-null reading of each day wins
# per counter; a later null does not erase it.
intraday = daily([0, 0, 0, 0, 8, 8, 3], HOURS, ZEROS, hour="01:00:00")
intraday += [sample("2013-11-07T22:00:00Z", 16, None, None),
             sample("2013-11-07T23:00:00Z", None, 11144, None),
             sample("2013-11-01T00:30:00Z", 5, 10990, 4)]
valid("latest reading of each UTC day wins in any input order", window(list(reversed(intraday))), complete)

future = daily([0, 0, 0, 0, 8, 8, 16], HOURS, ZEROS)
future += [sample("2013-11-07T12:00:01Z", 900, 99999, 900), sample("2013-11-08T00:00:00Z", 901, 99999, 901)]
valid("samples after as_of are never evidence", window(future, as_of="2013-11-07T12:00:00Z"),
      vector({"smart_5_raw": (0, 16), "smart_9_raw": (11000, 11144), "smart_197_raw": (0, 0)},
             as_of="2013-11-07T12:00:00Z"))

earlier = [sample("2013-10-31T23:59:59Z", 999, 1, 999)] + daily([0, 0, 0, 0, 8, 8, 16], HOURS, ZEROS)
valid("samples before the window are excluded", window(earlier), complete)

gap = daily([0, 0, 0, 0, 8, 8, 16], HOURS, [0, 0, None, 0, 0, 0, 0])
valid("one unobserved day gives incomplete history", window(gap),
      vector({"smart_5_raw": (0, 16), "smart_9_raw": (11000, 11144), "smart_197_raw": "incomplete_history"}))

valid("no SMART samples, the current endpoint", window([]),
      vector({c: "no_observation" for c, _ in COUNTERS}))
valid("null readings are not zero", window(daily([None] * 7, [None] * 7, [None] * 7)),
      vector({c: "no_observation" for c, _ in COUNTERS}))

valid("pending sectors that clear give a negative delta",
      window(daily(ZEROS, HOURS, [8, 8, 4, 4, 0, 0, 0])),
      vector({"smart_5_raw": (0, 0), "smart_9_raw": (11000, 11144), "smart_197_raw": (8, 0)}))
valid("a power-on hours reset is kept as a signed change",
      window(daily(ZEROS, [5000, 5024, 5048, 0, 24, 48, 72], ZEROS)),
      vector({"smart_5_raw": (0, 0), "smart_9_raw": (5000, 72), "smart_197_raw": (0, 0)}))
top = 2**53 - 1
valid("largest exact counter", window(daily([top] * 7, HOURS, ZEROS)),
      vector({"smart_5_raw": (top, top), "smart_9_raw": (11000, 11144), "smart_197_raw": (0, 0)}))

# Every decade and power of two a counter can reach, as final value and as delta.
for n, top_value in enumerate([1, 2, 255, 65535, 10**6, 2**31, 10**10, 2**40, 10**13, 2**52, 2**53 - 1]):
    valid(f"log1p over the counter range, final {top_value}",
          window(daily([0, 0, 0, 0, 0, 0, top_value], HOURS, [top_value, 0, 0, 0, 0, 0, 0])),
          vector({"smart_5_raw": (0, top_value), "smart_9_raw": (11000, 11144), "smart_197_raw": (top_value, 0)}))

base = window(daily([0, 0, 0, 0, 8, 8, 16], HOURS, ZEROS))


def mutated(change):
    value = copy.deepcopy(base)
    change(value)
    return value


invalid("counter above the exact JSON integer range",
        mutated(lambda w: w["samples"][0].update(smart_5_raw=2**53)), False)
invalid("negative counter", mutated(lambda w: w["samples"][0].update(smart_5_raw=-1)), False)
invalid("fractional counter", mutated(lambda w: w["samples"][0].update(smart_9_raw=1.5)), False)
# JSON Schema counts 1.0 as an integer; both strict readers do not.
invalid("integral float counter token", mutated(lambda w: w["samples"][0].update(smart_9_raw=1.0)), True)
invalid("duplicate sample timestamp", mutated(lambda w: w["samples"].append(copy.deepcopy(w["samples"][0]))), True)
invalid("unsupported feature version", mutated(lambda w: w.update(feature_version="hdd-smart-7d.v2")),
        False, "unsupported_feature_version")
invalid("excluded SMART 187 counter", mutated(lambda w: w["samples"][0].update(smart_187_raw=0)), False)
invalid("counter key omitted instead of null", mutated(lambda w: w["samples"][0].pop("smart_197_raw")), False)
invalid("as_of with a numeric offset", mutated(lambda w: w.update(as_of="2013-11-07T23:59:59+00:00")), False)

valid("complete vector", complete)
valid("incomplete vector", vector({"smart_5_raw": (0, 16), "smart_9_raw": (11000, 11144),
                                   "smart_197_raw": "incomplete_history"}))


def vmutated(change):
    value = copy.deepcopy(complete)
    change(value)
    return value


invalid("reordered features", vmutated(lambda v: v.update(features=v["features"][2:4] + v["features"][:2] + v["features"][4:])), False)
invalid("vector from an unsupported feature version", vmutated(lambda v: v.update(feature_version="hdd-smart-7d.v2")),
        False, "unsupported_feature_version")
invalid("complete status with a missing value", vmutated(lambda v: [v["features"][4].update(value=None, missing_reason="no_observation"),
                                                                     v["features"][5].update(value=None, missing_reason="no_observation")]), True)
invalid("last and delta disagree", vmutated(lambda v: v.update(status="incomplete") or v["features"][0].update(value=None, missing_reason="no_observation")), True)
invalid("window not ending on the as_of day", vmutated(lambda v: v.update(window_start="2013-10-31", window_end="2013-11-06")), True)
invalid("known value with an empty missing reason", vmutated(lambda v: v["features"][0].update(missing_reason="")), False)
invalid("known value with a missing reason", vmutated(lambda v: v["features"][0].update(missing_reason="no_observation")), False)
invalid("negative last value", vmutated(lambda v: v["features"][0].update(value=-0.5)), True)
invalid("missing feature", vmutated(lambda v: v["features"].pop()), False)

path = Path(__file__).with_name("v1-vectors.json")
path.write_text(json.dumps({"schema_version": "device-audit.feature-fixtures.v1",
                            "feature_version": VERSION, "tolerance": 1e-12,
                            "vectors": vectors}, indent=1) + "\n", encoding="utf-8")
print(f"wrote {len(vectors)} vectors to {path}")
