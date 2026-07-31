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
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, fields
from threading import Lock

from . import constants as C
from .config import CONFIG

_logger = logging.getLogger(__name__)


class DeviceKeyMismatch(Exception):
    """Raised by register() when device_id is already enrolled with a
    different pinned key (ak_pub_pem or ta_pub_b64) — refuses to silently
    replace a trusted identity. See docs/HANDOFF_MISSIONS.md §2.2.b and
    docs/HANDOFF_taIdentityBinding.md §8.5."""

    def __init__(self, device_id: str, field: str = "ak_pub_pem") -> None:
        super().__init__(
            f"device {device_id!r} is already registered with a different key "
            f"({field}); registration never overwrites a pinned identity — "
            f"remove it with scripts/reset-device-registry.sh, then restart "
            f"the server"
        )
        self.device_id = device_id
        self.field = field


_DEVICE_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,62}\Z")


def validate_device_id(device_id: str) -> str:
    """Raise ValueError unless device_id is safe to hash into the TA-identity
    pre-image on BOTH sides (see attestation.build_ta_identity_preimage).

    Deliberately narrow. ASCII-only removes the Unicode-normalisation class of
    bug — NFC and NFD are different byte strings for the same visual id, and
    provision-device.sh assembles its JSON with printf/sed/awk, which will not
    round-trip that reliably. Banning NUL stops the C side's strlen() from
    hashing a prefix of what Python hashes. The length cap matches the TA's
    fixed sealed buffer.

    NOT called on the hello path: a new error string there would break
    edge_device.c's strstr("not registered") trigger for self-registration.
    """
    if not _DEVICE_ID_RE.match(device_id):
        raise ValueError(
            "device_id must be 1-63 characters of [A-Za-z0-9._:-] "
            "and start with a letter or digit"
        )
    if len(device_id.encode("utf-8")) > C.DEVICE_ID_MAX_LEN:
        raise ValueError("device_id too long")
    return device_id


@dataclass
class DeviceRecord:
    """One enrolled device's attestation identity.

    `ak_pub_pem` is the device's TPM Attestation Key, PEM-encoded (see
    `tpm2_readpublic -f pem` in scripts/provision-device.sh) — used to
    verify the signature on every quote this device ever sends.
    `expected_pcr` is the raw `tpm2_pcrread` text captured at enrollment
    time — the known-good baseline a fresh quote's PCR values must match.
    `ta_pub_b64` is the TA's own sealed identity key (see below).
    """

    device_id: str
    ak_pub_pem: str
    expected_pcr: str
    pcr_bank: str
    created_at: float
    # The TA's sealed ECDSA P-256 identity public key: the RAW 65-byte
    # uncompressed SEC1 point (0x04 || X || Y), base64 — NOT a PEM. The TA can
    # only export the raw point, and every other key on this wire uses that
    # encoding; ak_pub_pem is PEM only because `tpm2_readpublic -f pem` emits
    # one. Canonically re-encoded at registration so the immutability check in
    # register() stays a plain string compare that cosmetic base64 variants of
    # the same key cannot trip.
    #
    # Defaults to "" ONLY so a registry file written before TA-identity binding
    # still loads (see from_dict). "" is not "skip the check": AttestationVerifier
    # .verify_and_derive rejects such a record outright.
    ta_pub_b64: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceRecord":
        """Tolerant deserialisation, replacing a strict DeviceRecord(**rec).

        Drops unknown keys and lets defaulted fields default, so neither an
        older registry file (missing ta_pub_b64) nor a newer one written by a
        later server version can raise TypeError inside DeviceRegistry._load()
        — which runs at server startup, where a bare TypeError tells the
        operator nothing.
        """
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(data) - known)
        if unknown:
            _logger.warning(
                "device_registry: ignoring unknown field(s) %s for device %r",
                unknown,
                data.get("device_id"),
            )
        return cls(**{k: v for k, v in data.items() if k in known})


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
            device_id: DeviceRecord.from_dict(rec) for device_id, rec in data.items()
        }
        for device_id, rec in self._records.items():
            if not rec.ta_pub_b64:
                _logger.warning(
                    "device %r was enrolled before TA-identity binding and has no "
                    "ta_pub_b64, so it can no longer attest. Run "
                    "'scripts/reset-device-registry.sh %s', restart this server, "
                    "and let the device re-provision.",
                    device_id,
                    device_id,
                )

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
        self,
        device_id: str,
        ak_pub_pem: str,
        expected_pcr: str,
        pcr_bank: str,
        ta_pub_b64: str,
    ) -> tuple[DeviceRecord, bool]:
        """Enroll a device, idempotently.

        Returns (record, newly_registered). An unseen device_id is enrolled.
        A device_id already enrolled with the *same* pinned keys is a no-op
        (nothing to overwrite). A device_id already enrolled with a *different*
        ak_pub_pem or ta_pub_b64 raises DeviceKeyMismatch instead of silently
        replacing the trusted identity — see docs/HANDOFF_MISSIONS.md §2.2.b
        and docs/HANDOFF_taIdentityBinding.md §8.5.
        """
        with self._lock:
            existing = self._records.get(device_id)
            if existing is not None:
                # EVERY pinned field is compared BEFORE the idempotent early
                # return. Comparing ak_pub_pem alone and returning on a match
                # would let a resubmission with the same AK but a different
                # ta_pub silently keep the old TA key while reporting success —
                # a swapped TA identity that never raises.
                if existing.ak_pub_pem != ak_pub_pem:
                    raise DeviceKeyMismatch(device_id, field="ak_pub_pem")
                # A record enrolled before TA-identity binding (ta_pub_b64 == "")
                # also lands here and is rejected, deliberately: backfilling a
                # TA key onto an already-enrolled device would reopen the
                # trust-on-first-use window that this binding exists to close —
                # registration is self-service, so root on a compromised device
                # could pin its own TA key by resubmitting the honest AK. The
                # admin path is reset-device-registry.sh + a server restart.
                if existing.ta_pub_b64 != ta_pub_b64:
                    raise DeviceKeyMismatch(device_id, field="ta_pub_b64")
                return existing, False

            record = DeviceRecord(
                device_id=device_id,
                ak_pub_pem=ak_pub_pem,
                expected_pcr=expected_pcr,
                pcr_bank=pcr_bank,
                created_at=time.time(),
                ta_pub_b64=ta_pub_b64,
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
