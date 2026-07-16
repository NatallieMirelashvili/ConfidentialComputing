"""Application-specific processing over a set of samples.

This is the "what does the user actually get" step: `CollectionService` calls
`aggregate()` on the samples returned by `DataStore.window()`. The aggregation
kind is chosen by the user in the UI. `weighted_avg` is the headline example from
the project proposal: a recency-weighted average over the window.
"""

from __future__ import annotations

from typing import Any

from .device_link.base import Sample


def aggregate(samples: list[Sample], kind: str) -> dict[str, Any]:
    """Reduce `samples` to a small JSON-able result for the given aggregation.

    Args:
        samples: the samples already filtered to the requested time window.
        kind: one of "raw" | "mean" | "min" | "max" | "weighted_avg".

    Returns:
        For "raw": {kind, n, series:[{ts,value}...]}.
        Otherwise: {kind, n, value} (value rounded), or value=None if no samples.
    """
    values = [s.value for s in samples]
    n = len(values)

    # "raw" returns the whole series (the UI draws/records it) rather than a
    # single number, so it is handled before the empty-check below.
    if kind == "raw":
        return {
            "kind": "raw",
            "n": n,
            "series": [{"ts": s.ts, "value": s.value} for s in samples],
        }

    # No data in the window -> report it explicitly instead of dividing by zero.
    if n == 0:
        return {"kind": kind, "n": 0, "value": None, "note": "no samples in window"}

    if kind == "mean":
        value = sum(values) / n
    elif kind == "min":
        value = min(values)
    elif kind == "max":
        value = max(values)
    elif kind == "weighted_avg":
        value = _weighted_avg(samples)
    else:
        # Unknown kind is a programming error here (the route validates the input
        # against constants.AGGREGATIONS before we ever get called).
        raise ValueError(f"unknown aggregation: {kind}")

    return {"kind": kind, "n": n, "value": round(value, 4)}


def _weighted_avg(samples: list[Sample]) -> float:
    """Recency-weighted average: more recent samples weigh more.

    Each sample's weight grows with its timestamp, so newer readings pull the
    result more than old ones. Concretely: weight = (ts - ts_min) + step, where
    `step` is the average spacing between samples. That makes every weight
    strictly positive (even the oldest sample counts) while still ranking by
    recency. Returns the plain value if there is only one sample.
    """
    if len(samples) == 1:
        return samples[0].value

    ts_min = min(s.ts for s in samples)
    ts_max = max(s.ts for s in samples)
    span = (ts_max - ts_min) or 1.0            # guard against all-equal timestamps
    step = span / max(1, len(samples) - 1)     # typical gap between samples

    num = 0.0  # sum of weight * value
    den = 0.0  # sum of weights
    for s in samples:
        w = (s.ts - ts_min) + step  # strictly positive, grows with recency
        num += w * s.value
        den += w
    return num / den
