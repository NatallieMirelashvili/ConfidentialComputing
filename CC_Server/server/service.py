"""Application service layer.

Business logic for "collect and aggregate", kept out of the HTTP layer so the
routes in `app_server.py` stay thin. Wires together the three collaborators:
`DeviceLink` (the seam) -> `DataStore` -> `processing`.
"""

from __future__ import annotations

from . import constants as C
from . import processing
from .device_link import DeviceLink, get_device_link
from .store import DataStore


class CollectionService:
    """Orchestrates one "collect" end to end.

    Created once in `create_app()` and reused for every request, so its
    `device_link` and `store` are effectively singletons (the store accumulates
    across requests). Both collaborators can be injected for testing; by default
    they come from the factory / a fresh store.
    """

    def __init__(self, device_link: DeviceLink | None = None, store: DataStore | None = None) -> None:
        self.device_link = device_link or get_device_link()   # the data-source seam
        self.store = store or DataStore()                     # accumulates samples

    def devices(self) -> dict:
        """Return the device link's status dict (used by GET /api/devices)."""
        return self.device_link.status()

    async def collect(self, device_id: str, window: str, aggregation: str) -> dict:
        """Run the full collect pipeline and return a JSON-able result.

        Steps: validate inputs -> pull a Batch from the device link (the seam) ->
        store its samples -> filter to the requested time window -> aggregate ->
        attach the verification verdict from the Batch.

        Raises:
            ValueError: if `window` or `aggregation` is not recognised (the route
            turns this into an HTTP 400).
        """
        # 1. Validate against the allowed sets (defence in depth; the route also
        #    checks, but the service must not trust its caller).
        if window not in C.WINDOWS:
            raise ValueError(f"bad window {window!r}")
        if aggregation not in C.AGGREGATIONS:
            raise ValueError(f"bad aggregation {aggregation!r}")

        # 2. Ask the device link for data. This is the ONLY way sensor data
        #    enters the server; the Batch also carries the trust verdict.
        batch = await self.device_link.collect(device_id, window)

        # 3. Store what we got, then read back just the requested window.
        self.store.add(device_id, batch.samples)
        window_samples = self.store.window(device_id, C.WINDOWS[window])

        # 4. Reduce to the aggregation the user asked for.
        result = processing.aggregate(window_samples, aggregation)

        # 5. Package the answer + the verdict the UI shows as trust chips.
        return {
            "device_id": device_id,
            "window": window,
            "aggregation": aggregation,
            "result": result,
            "n_samples": len(window_samples),
            "attested": batch.attested,
            "integrity": batch.integrity,
            "measurement_ok": batch.measurement_ok,
            "note": batch.note,
        }
