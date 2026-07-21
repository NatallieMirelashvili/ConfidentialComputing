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
No synthetic fallback — `MS_DEVICE_LINK` must select one of these, or
`get_device_link()` raises at startup:

- **`network.py` — `NetworkDeviceLink`**: a TCP listener fed by a real edge
  device; plaintext, trusts a self-reported `attested` flag. Lightweight
  demo/back-compat mode.
- **`attested_network.py` — `AttestedNetworkDeviceLink`**: a TCP listener fed
  by a real edge device, gated by remote attestation + key exchange
  (`../attestation.py`), with sensor data carried as AES-256-GCM envelopes.
