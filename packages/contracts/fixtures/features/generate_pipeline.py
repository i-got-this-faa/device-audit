"""Write ML07 #102 pipeline cases: python3 packages/contracts/fixtures/features/generate_pipeline.py

Each case is a device's daily Backblaze-style rows and the vector the frozen
feature version must give for one anchor day. The training path (Python) and the
endpoint path (Go, `packages/health`) both read the rows, so a disagreement
between them or with the hand-written expected vector fails. Expected vectors
come from the (first, final) day values below, not from either implementation,
and log1p is evaluated in 50-digit decimal arithmetic.
"""
import json
from decimal import Decimal, localcontext
from pathlib import Path

VECTOR = "device-audit.feature-vector.v1"
VERSION = "hdd-smart-7d.v1"
COUNTERS = (("smart_5_raw", "count"), ("smart_9_raw", "hours"), ("smart_197_raw", "count"))
COLUMNS = ("smart_5_raw", "smart_9_raw", "smart_187_raw", "smart_197_raw", "smart_198_raw")
ANCHOR = "2013-11-07"
WINDOW_DAYS = [f"2013-11-0{d}" for d in range(1, 8)]


def log1p(x):
    with localcontext() as ctx:
        ctx.prec = 50
        return float((Decimal(x) + 1).ln())


def signed_log1p(x):
    return -log1p(-x) if x < 0 else log1p(x)


def row(day, s5, s9, s197, s187=None, s198=None):
    return {"date": day, "smart_5_raw": s5, "smart_9_raw": s9, "smart_187_raw": s187,
            "smart_197_raw": s197, "smart_198_raw": s198}


def week(s5, s9, s197, days=WINDOW_DAYS):
    return [row(d, *v) for d, v in zip(days, zip(s5, s9, s197))]


def vector(state):
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
    return {"schema_version": VECTOR, "feature_version": VERSION, "as_of": f"{ANCHOR}T23:59:59Z",
            "window_start": "2013-11-01", "window_end": ANCHOR,
            "status": "complete" if complete else "incomplete", "features": features}


HOURS = [11000 + 24 * i for i in range(7)]
ZEROS = [0] * 7
GROWTH = [0, 0, 0, 0, 8, 8, 16]
BASE = {"smart_5_raw": (0, 16), "smart_9_raw": (11000, 11144), "smart_197_raw": (0, 0)}
cases = []


def case(name, rows, state, note):
    cases.append({"name": name, "anchor": ANCHOR, "note": note, "rows": rows, "expected": vector(state)})


case("complete week", week(GROWTH, HOURS, ZEROS), BASE, "Seven rows with every selected counter known.")
case("excluded columns are ignored",
     [row(d, *v, s187=900, s198=7) for d, v in zip(WINDOW_DAYS, zip(GROWTH, HOURS, ZEROS))], BASE,
     "SMART 187 and 198 hold values; the feature version does not read them.")
case("future rows are never evidence",
     week(GROWTH, HOURS, ZEROS) + [row("2013-11-08", 9999, 99999, 9999), row("2013-11-09", 9999, 99999, 9999)], BASE,
     "Rows after the anchor day, as a late-arriving upload would add them, change nothing.")
case("rows before the window are ignored",
     [row("2013-10-30", 500, 1, 500), row("2013-10-31", 500, 2, 500)] + week(GROWTH, HOURS, ZEROS), BASE,
     "History older than seven days is not read.")
dropped = [d for d in WINDOW_DAYS if d != "2013-11-04"]
case("missing day row is sparse",
     [row(d, *v) for d, v in zip(dropped, zip(GROWTH[:3] + GROWTH[4:], HOURS[:3] + HOURS[4:], ZEROS[:6]))],
     {c: "incomplete_history" for c, _ in COUNTERS},
     "One daily row is absent, so no counter has all seven days and nothing is filled.")
case("missing sensor column",
     [row(d, a, None, c) for d, a, c in zip(WINDOW_DAYS, GROWTH, ZEROS)],
     {"smart_5_raw": BASE["smart_5_raw"], "smart_9_raw": "no_observation", "smart_197_raw": BASE["smart_197_raw"]},
     "SMART 9 is null on every day: it is not zero, and the vector is incomplete.")
case("null on the first day",
     week(GROWTH, HOURS, [None] + [0] * 6),
     {"smart_5_raw": BASE["smart_5_raw"], "smart_9_raw": BASE["smart_9_raw"], "smart_197_raw": "incomplete_history"},
     "One null day makes that counter incomplete_history; the other counters stay known.")
case("power-on hours reset", week(GROWTH, [11000, 11024, 11048, 11072, 5, 29, 53], ZEROS),
     {"smart_5_raw": BASE["smart_5_raw"], "smart_9_raw": (11000, 53), "smart_197_raw": BASE["smart_197_raw"]},
     "A counter reset is real evidence: the delta stays negative and no reset rule applies.")
case("pending sectors remapped", week(GROWTH, HOURS, [5, 5, 5, 3, 3, 0, 0]),
     {"smart_5_raw": BASE["smart_5_raw"], "smart_9_raw": BASE["smart_9_raw"], "smart_197_raw": (5, 0)},
     "SMART 197 can fall; the decrease is kept.")
case("no rows", [], {c: "no_observation" for c, _ in COUNTERS},
     "A device with no history gives an incomplete vector, never a zero vector.")

out = {"schema_version": "device-audit.feature-pipeline-cases.v1", "feature_version": VERSION,
       "columns": list(COLUMNS), "tolerance": 1e-12, "cases": cases}
path = Path(__file__).with_name("pipeline-cases.json")
path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
