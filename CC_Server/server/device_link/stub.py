"""StubDeviceLink — synthetic, always-attested data.

The data source for the User<->Server app: lets everything run and demo without
any real device. It is the DEFAULT (and only) link here.

Demo aid: if a caller asks for a device_id containing "tampered", the stub
returns a failed verdict, so you can exercise the UI's "rejected" path.
"""

from __future__ import annotations

import math
import random
import time

from .. import constants as C
from .base import Batch, DeviceLink, Sample


class StubDeviceLink(DeviceLink):
    """A `DeviceLink` that fabricates plausible sensor data on demand."""

    def __init__(self) -> None:
        # A couple of "known" devices for the UI dropdown.
        self._devices = [C.DEFAULT_DEVICE_ID, "iot-edge-02"]

    async def collect(self, device_id: str, window: str) -> Batch:
        """Return a batch of synthetic samples for the window (always attested),
        except for the "tampered" demo device which returns a failed verdict."""
        seconds = C.WINDOWS.get(window, C.WINDOWS[C.DEFAULT_WINDOW])
        samples = _synthetic_samples(device_id, seconds)

        if "tampered" in device_id.lower():
            # Simulate a device that failed attestation (for UI demo only).
            return Batch(
                device_id=device_id,
                window=window,
                samples=[],
                attested=False,
                integrity="fail",
                measurement_ok=False,
                note="STUB: simulated attestation failure (device_id contains 'tampered')",
            )

        return Batch(
            device_id=device_id,
            window=window,
            samples=samples,
            attested=True,
            integrity="ok",
            measurement_ok=True,
            note="STUB: synthetic data (no real device / attestation)",
        )

    def status(self) -> dict:
        """Report the fake devices as connected/attested (for the UI dropdown)."""
        return {
            "link": "stub",
            "devices": [
                {"device_id": d, "connected": True, "attested": True}
                for d in self._devices
            ],
        }


def _synthetic_samples(device_id: str, seconds: int) -> list[Sample]:
    """Evenly spaced samples over the last `seconds`, ending now.

    ~1/minute for 1h, ~1/30min for 24h, so batch sizes stay small and demoable.
    """
    now = time.time()
    step = 60 if seconds <= 3600 else 1800
    n = max(2, seconds // step)

    base = 22.0 + (hash(device_id) % 5)   # per-device baseline (e.g. °C)
    drift = random.uniform(-1.0, 1.0)     # new each collect -> the aggregate moves

    samples: list[Sample] = []
    for i in range(n):
        ts = now - (n - 1 - i) * step
        # smooth daily-ish oscillation + per-call drift + small noise
        value = base + drift + 3.0 * math.sin(i / 6.0) + random.uniform(-0.4, 0.4)
        samples.append(
            Sample(ts=ts, value=round(value, 3), sensor_id=f"{device_id}:temp", unit="C")
        )
    return samples
