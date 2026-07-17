"""Device registry — enrolled device identities for attestation.

A device must be enrolled here (via `POST /api/devices/register`, gated
behind the existing authenticated User<->Server channel — never the open
device-facing TCP port) before it can complete remote attestation. This is
the piece the codebase's own docs flagged as an explicit gap: previously
`NetworkDeviceLink` accepted any `device_id` a connecting socket claimed to
be, with no identity check at all.

Enrollment is self-service and idempotent (a device can register itself):
an unseen device_id is added; a resubmission with the same key is a no-op;
a resubmission with a different key is rejected rather than silently
overwriting the trusted identity (see docs/HANDOFF_MISSIONS.md §2.2.b).

Storage is a single JSON file (course-project scope; a real deployment would
use a proper datastore), written atomically (write-to-temp + os.replace) and
chmod'd owner-only (0600) so it's readable/writable only by the OS user the
server runs as - the entire protection model for this registry.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from threading import Lock

from .config import CONFIG


class DeviceKeyMismatch(Exception):
    """Raised by register() when device_id is already enrolled with a
    different ak_pub_pem — refuses to silently replace a trusted identity.
    See docs/HANDOFF_MISSIONS.md §2.2.b."""

    def __init__(self, device_id: str) -> None:
        super().__init__(
            f"device {device_id!r} is already registered with a different key"
        )
        self.device_id = device_id


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
        # os.replace() swaps in a fresh inode, so the mode has to be
        # re-applied every save, not just once at file creation. This file is
        # the device<->key trust mapping ("the admin has a saved file of a
        # key") - owner-only access is the entire protection model: whoever
        # can read/write it (i.e. is or sudos to the server's OS user) is the
        # admin, no separate auth layer needed.
        os.chmod(self._path, 0o600)

    def register(
        self, device_id: str, ak_pub_pem: str, expected_pcr: str, pcr_bank: str
    ) -> tuple[DeviceRecord, bool]:
        """Enroll a device, idempotently.

        Returns (record, newly_registered). An unseen device_id is enrolled.
        A device_id that's already enrolled with the *same* ak_pub_pem is a
        no-op (nothing to overwrite). A device_id already enrolled with a
        *different* ak_pub_pem raises DeviceKeyMismatch instead of silently
        replacing the trusted identity — see docs/HANDOFF_MISSIONS.md §2.2.b.
        """
        with self._lock:
            existing = self._records.get(device_id)
            if existing is not None:
                if existing.ak_pub_pem == ak_pub_pem:
                    return existing, False
                raise DeviceKeyMismatch(device_id)

            record = DeviceRecord(
                device_id=device_id,
                ak_pub_pem=ak_pub_pem,
                expected_pcr=expected_pcr,
                pcr_bank=pcr_bank,
                created_at=time.time(),
            )
            self._records[device_id] = record
            self._save()
            return record, True

    def lookup(self, device_id: str) -> DeviceRecord | None:
        with self._lock:
            return self._records.get(device_id)

    def list(self) -> list[DeviceRecord]:
        with self._lock:
            return list(self._records.values())

    def remove(self, device_id: str) -> bool:
        """Delete one enrolled device. Returns False if it wasn't enrolled.

        The deliberate admin escape hatch for the trade-off documented on
        register(): normal registration can never overwrite an existing
        entry, so re-provisioning a device under a new key (e.g. after
        wiping its persisted AK for a fresh-device test) means removing its
        old entry here first. See scripts/reset-device-registry.sh.
        """
        with self._lock:
            if device_id not in self._records:
                return False
            del self._records[device_id]
            self._save()
            return True

    def clear(self) -> None:
        """Delete every enrolled device."""
        with self._lock:
            self._records = {}
            self._save()


_REGISTRY: DeviceRegistry | None = None


def get_device_registry() -> DeviceRegistry:
    """Process-wide registry singleton (mirrors get_device_link()'s shape)."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = DeviceRegistry()
    return _REGISTRY
