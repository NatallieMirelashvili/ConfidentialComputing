# `device_link/` — the data-source seam

The user-facing server only gets sensor data through this seam, so the data
source stays decoupled from the app (routes/service never change if it changes).

## Interface (`base.py`)
```python
class DeviceLink(ABC):
    async def collect(self, device_id: str, window: str) -> Batch: ...
    def status(self) -> dict: ...

@dataclass
class Sample: ts: float; value: float; sensor_id: str; unit: str

@dataclass
class Batch:
    device_id: str; window: str; samples: list[Sample]
    attested: bool; integrity: str            # "ok" | "fail"
    measurement_ok: bool; note: str
```
`collect()` returns a `Batch` whose verdict fields (`attested` / `integrity` /
`measurement_ok`) are what the UI shows as trust chips.

## Implementation
- **`stub.py` — `StubDeviceLink`**: synthesises attested sensor data so the
  User↔Server app runs and demos with no hardware. `get_device_link()` returns it.

The real Server↔Device link (remote attestation, encrypted sensor channel) is a
separate part of the project and is intentionally **not** in this codebase.
