"""DeviceRegistry.register() idempotency tests.

Covers docs/HANDOFF_MISSIONS.md §2.2.b: registration must not silently
overwrite an already-enrolled device's trusted key. Since TA-identity binding
(docs/HANDOFF_taIdentityBinding.md) that applies to *both* pinned keys — the
TPM Attestation Key and the TA's own sealed identity key.

Run:  python -m pytest server/tests -q     (from the project root)
"""

from __future__ import annotations

import json

import pytest

from server.device_registry import (
    DeviceKeyMismatch,
    DeviceRegistry,
    validate_device_id,
)


def _registry(tmp_path):
    return DeviceRegistry(path=str(tmp_path / "device_registry.json"))


def test_register_unseen_device_is_new(tmp_path):
    registry = _registry(tmp_path)

    record, newly = registry.register(
        "iot-edge-01", "pem-a", "pcr-a", "sha256:0", "ta-a"
    )

    assert newly is True
    assert record.ak_pub_pem == "pem-a"
    assert record.ta_pub_b64 == "ta-a"
    assert registry.lookup("iot-edge-01") is record


def test_register_matching_key_is_a_noop(tmp_path):
    registry = _registry(tmp_path)
    first, _ = registry.register("iot-edge-01", "pem-a", "pcr-a", "sha256:0", "ta-a")

    second, newly = registry.register(
        "iot-edge-01", "pem-a", "pcr-a", "sha256:0", "ta-a"
    )

    assert newly is False
    assert second is first
    assert second.created_at == first.created_at


def test_register_mismatched_key_is_rejected(tmp_path):
    registry = _registry(tmp_path)
    registry.register("iot-edge-01", "pem-a", "pcr-a", "sha256:0", "ta-a")

    with pytest.raises(DeviceKeyMismatch) as exc:
        registry.register("iot-edge-01", "pem-b", "pcr-a", "sha256:0", "ta-a")

    assert exc.value.field == "ak_pub_pem"
    # The original identity must survive the rejected attempt untouched.
    assert registry.lookup("iot-edge-01").ak_pub_pem == "pem-a"


def test_register_mismatched_ta_pub_is_rejected(tmp_path):
    """docs/HANDOFF_taIdentityBinding.md §8.5.

    Note the AK is IDENTICAL here — only the TA key differs. That is the case
    an ak_pub-only check would wave through as "already registered", silently
    keeping the old TA key while reporting success.
    """
    registry = _registry(tmp_path)
    registry.register("iot-edge-01", "pem-a", "pcr-a", "sha256:0", "ta-a")

    with pytest.raises(DeviceKeyMismatch) as exc:
        registry.register("iot-edge-01", "pem-a", "pcr-a", "sha256:0", "ta-b")

    assert exc.value.field == "ta_pub_b64"
    assert registry.lookup("iot-edge-01").ta_pub_b64 == "ta-a"


def test_registry_file_is_owner_only(tmp_path):
    registry = _registry(tmp_path)
    registry.register("iot-edge-01", "pem-a", "pcr-a", "sha256:0", "ta-a")

    mode = (tmp_path / "device_registry.json").stat().st_mode & 0o777
    assert mode == 0o600


def test_ta_pub_survives_a_reload(tmp_path):
    """The pinned TA key must round-trip through the JSON file, not just live
    in memory — every attestation reads it back from the loaded record."""
    path = tmp_path / "device_registry.json"
    DeviceRegistry(path=str(path)).register(
        "iot-edge-01", "pem-a", "pcr-a", "sha256:0", "ta-a"
    )

    assert DeviceRegistry(path=str(path)).lookup("iot-edge-01").ta_pub_b64 == "ta-a"


def _write_registry(path, record: dict) -> None:
    path.write_text(json.dumps({record["device_id"]: record}), encoding="utf-8")


def test_legacy_record_without_ta_pub_still_loads(tmp_path):
    """A registry written before TA-identity binding must not stop the server
    from starting. DeviceRecord(**rec) was strict, so a new required field
    would raise TypeError inside _load() — at startup, with no useful context.

    Loading is all this guarantees: such a record cannot attest (see
    test_verify_rejects_record_with_empty_ta_pub in test_attestation.py).
    """
    path = tmp_path / "device_registry.json"
    _write_registry(path, {
        "device_id": "iot-edge-01",
        "ak_pub_pem": "pem-a",
        "expected_pcr": "pcr-a",
        "pcr_bank": "sha256:0",
        "created_at": 1.0,
    })

    record = DeviceRegistry(path=str(path)).lookup("iot-edge-01")

    assert record is not None
    assert record.ta_pub_b64 == ""


def test_registry_ignores_unknown_fields(tmp_path):
    """Forward compatibility: a file written by a newer server must still load
    after a rollback, rather than crashing this one at startup."""
    path = tmp_path / "device_registry.json"
    _write_registry(path, {
        "device_id": "iot-edge-01",
        "ak_pub_pem": "pem-a",
        "expected_pcr": "pcr-a",
        "pcr_bank": "sha256:0",
        "created_at": 1.0,
        "ta_pub_b64": "ta-a",
        "some_future_field": {"nested": 1},
    })

    record = DeviceRegistry(path=str(path)).lookup("iot-edge-01")

    assert record is not None
    assert record.ta_pub_b64 == "ta-a"


def test_legacy_record_cannot_be_backfilled_with_a_ta_pub(tmp_path):
    """A pre-binding record must NOT gain a TA key by re-registering.

    Registration is self-service with no client auth, so a backfill path would
    let root on a compromised device resubmit the honest ak_pub alongside a TA
    key of its own and pin that — reopening the trust-on-first-use window this
    binding closes. The admin path is reset-device-registry.sh + a restart.
    """
    path = tmp_path / "device_registry.json"
    _write_registry(path, {
        "device_id": "iot-edge-01",
        "ak_pub_pem": "pem-a",
        "expected_pcr": "pcr-a",
        "pcr_bank": "sha256:0",
        "created_at": 1.0,
    })
    registry = DeviceRegistry(path=str(path))

    with pytest.raises(DeviceKeyMismatch) as exc:
        registry.register("iot-edge-01", "pem-a", "pcr-a", "sha256:0", "ta-a")

    assert exc.value.field == "ta_pub_b64"
    assert registry.lookup("iot-edge-01").ta_pub_b64 == ""


@pytest.mark.parametrize(
    "device_id",
    ["", "a" * 64, "has space", "has\x00nul", "日本", "-leading-dash", "has/slash"],
)
def test_validate_device_id_rejects_unsafe_ids(device_id):
    """device_id is hashed into the TA-identity pre-image by both a C TA and
    Python, so it is restricted to ASCII with no NUL and a bounded length —
    see validate_device_id's docstring for why each of those matters."""
    with pytest.raises(ValueError):
        validate_device_id(device_id)


@pytest.mark.parametrize("device_id", ["iot-edge-01", "a", "A.b_c:d-1", "a" * 63])
def test_validate_device_id_accepts_real_ids(device_id):
    assert validate_device_id(device_id) == device_id
