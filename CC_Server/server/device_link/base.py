"""The DeviceLink interface and the data types crossing the seam.

The user-facing code consumes a `DeviceLink` to obtain sensor data; the data
source (a real edge device, over `network` or `attested_network`) implements it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field


@dataclass
class Sample:
    """One sensor reading."""

    ts: float           # UNIX epoch seconds when the sample was taken
    value: float        # the measurement itself
    sensor_id: str = "sensor-0"
    unit: str = "unit"

    def to_dict(self) -> dict:
        """Plain dict (for JSON / storing)."""
        return asdict(self)


@dataclass
class Batch:
    """One collection result handed back to the user side.

    `attested`/`integrity`/`measurement_ok` are the *verification verdict* shown
    in the UI as trust chips, set by the real DeviceLink from remote attestation.
    """

    device_id: str
    window: str
    samples: list[Sample] = field(default_factory=list)
    attested: bool = True            # did the device prove it's genuine?
    integrity: str = "ok"            # "ok" | "fail" — was the data unmodified?
    measurement_ok: bool = True      # did the device run known-good code?
    note: str = ""                   # human-readable explanation (esp. on failure)

    def to_dict(self) -> dict:
        """Plain dict with samples expanded (for JSON responses)."""
        d = asdict(self)
        d["samples"] = [s.to_dict() for s in self.samples]
        return d


class DeviceLink(ABC):
    """Abstraction over "get authenticated sensor data from a device".

    Implementations MUST NOT leak transport details to the caller; they return a
    `Batch` whose verdict fields say whether the data can be trusted.
    """

    @abstractmethod
    async def collect(self, device_id: str, window: str) -> Batch:
        """Collect the samples for `window` ("1h"/"24h") from `device_id`.

        On a failed/untrusted result, return a Batch with attested=False /
        integrity="fail" (do NOT raise for that path — the UI shows the verdict).
        """

    @abstractmethod
    def status(self) -> dict:
        """Return a small dict for the UI (known/connected/attested devices)."""
