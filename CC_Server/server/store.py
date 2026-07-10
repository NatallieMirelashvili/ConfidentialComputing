"""In-memory sample store with a time-window filter.

Where it sits in the pipeline: `CollectionService` writes each collected batch
here with `add()`, then reads back the recent samples with `window()` before
aggregating. Deliberately simple (a dict of ring buffers, no database). Swap for
SQLite later if you need persistence across restarts — the interface is tiny.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from .device_link.base import Sample

# Hard cap on samples kept per device, so a long-running demo can't grow without
# bound. `deque(maxlen=...)` drops the oldest sample once the cap is reached.
_MAX_PER_DEVICE = 100_000


class DataStore:
    """Holds collected `Sample`s per device id, newest appended last.

    Created once at startup (owned by `CollectionService`) and shared across all
    requests, so a `threading.Lock` guards the shared dict/deques.
    """

    def __init__(self) -> None:
        # device_id -> bounded deque of samples. defaultdict makes the first
        # write for a new device create its deque automatically.
        self._by_device: dict[str, deque[Sample]] = defaultdict(
            lambda: deque(maxlen=_MAX_PER_DEVICE)
        )
        self._lock = threading.Lock()

    def add(self, device_id: str, samples: list[Sample]) -> None:
        """Append a batch of samples for `device_id` (thread-safe)."""
        with self._lock:
            self._by_device[device_id].extend(samples)

    def window(self, device_id: str, seconds: int) -> list[Sample]:
        """Return this device's samples from the last `seconds` (by timestamp).

        The cutoff is "now minus seconds"; any sample whose `ts` is at or after
        the cutoff is included. This is what turns "last hour"/"last 24h" into an
        actual subset of the stored data.
        """
        cutoff = time.time() - seconds
        with self._lock:
            return [s for s in self._by_device[device_id] if s.ts >= cutoff]

    def all(self, device_id: str) -> list[Sample]:
        """Return a copy of every stored sample for `device_id` (unused by the
        app; handy for debugging/tests)."""
        with self._lock:
            return list(self._by_device[device_id])
