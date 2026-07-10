"""Device registry — admin-enrolled device identities for attestation.

A device must be enrolled here (via `POST /api/devices/register`, gated
behind the existing authenticated User<->Server channel — never the open
device-facing TCP port) before it can complete remote attestation. This is
the piece the codebase's own docs flagged as an explicit gap: previously
`NetworkDeviceLink` accepted any `device_id` a connecting socket claimed to
be, with no identity check at all.

Storage is a single JSON file (course-project scope; a real deployment would
use a proper datastore) written atomically (write-to-temp + os.replace) so a
crash mid-write can't corrupt it.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from threading import Lock

from .config import CONFIG


@dataclass
class DeviceRecord:
    """One enrolled device's attestation identity.

    `ak_pub_pem` is the device's TPM Attestation Key, PEM-encoded (see
    `tpm2_readpublic -f pem` in scripts/provision-device.sh) — used to
    verify the signature on every quote this device ever sends.
    `expected_pcr` is the raw `tpm2_pcrread` text captured at enrollment
    time — the known-good baseline a fresh quote's PCR values must match.
    """

    device_id: str
    ak_pub_pem: str
    expected_pcr: str
    pcr_bank: str
    created_at: float

    def to_dict(self) -> dict:
        return asdict(self)


class DeviceRegistry:
    """Persistent {device_id -> DeviceRecord} store."""

    def __init__(self, path: str | None = None) -> None:
        self._path = path or CONFIG.device_registry_path
        self._lock = Lock()
        self._records: dict[str, DeviceRecord] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        with open(self._path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self._records = {
            device_id: DeviceRecord(**rec) for device_id, rec in data.items()
        }

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        tmp = f"{self._path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({k: v.to_dict() for k, v in self._records.items()}, f, indent=2)
        os.replace(tmp, self._path)

    def register(
        self, device_id: str, ak_pub_pem: str, expected_pcr: str, pcr_bank: str
    ) -> DeviceRecord:
        """Enroll (or re-enroll) a device. Overwrites any existing record for
        the same device_id — re-running provisioning replaces the old identity."""
        with self._lock:
            record = DeviceRecord(
                device_id=device_id,
                ak_pub_pem=ak_pub_pem,
                expected_pcr=expected_pcr,
                pcr_bank=pcr_bank,
                created_at=time.time(),
            )
            self._records[device_id] = record
            self._save()
            return record

    def lookup(self, device_id: str) -> DeviceRecord | None:
        with self._lock:
            return self._records.get(device_id)

    def list(self) -> list[DeviceRecord]:
        with self._lock:
            return list(self._records.values())


_REGISTRY: DeviceRegistry | None = None


def get_device_registry() -> DeviceRegistry:
    """Process-wide registry singleton (mirrors get_device_link()'s shape)."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = DeviceRegistry()
    return _REGISTRY
