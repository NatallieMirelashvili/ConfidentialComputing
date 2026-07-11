"""DeviceRegistry.register() idempotency tests.

Covers docs/HANDOFF_MISSIONS.md §2.2.b: registration must not silently
overwrite an already-enrolled device's trusted key.

Run:  python -m pytest server/tests -q     (from the project root)
"""

from __future__ import annotations

import pytest

from server.device_registry import DeviceKeyMismatch, DeviceRegistry


def _registry(tmp_path):
    return DeviceRegistry(path=str(tmp_path / "device_registry.json"))


def test_register_unseen_device_is_new(tmp_path):
    registry = _registry(tmp_path)

    record, newly = registry.register("iot-edge-01", "pem-a", "pcr-a", "sha256:0")

    assert newly is True
    assert record.ak_pub_pem == "pem-a"
    assert registry.lookup("iot-edge-01") is record


def test_register_matching_key_is_a_noop(tmp_path):
    registry = _registry(tmp_path)
    first, _ = registry.register("iot-edge-01", "pem-a", "pcr-a", "sha256:0")

    second, newly = registry.register("iot-edge-01", "pem-a", "pcr-a", "sha256:0")

    assert newly is False
    assert second is first
    assert second.created_at == first.created_at


def test_register_mismatched_key_is_rejected(tmp_path):
    registry = _registry(tmp_path)
    registry.register("iot-edge-01", "pem-a", "pcr-a", "sha256:0")

    with pytest.raises(DeviceKeyMismatch):
        registry.register("iot-edge-01", "pem-b", "pcr-a", "sha256:0")

    # The original identity must survive the rejected attempt untouched.
    assert registry.lookup("iot-edge-01").ak_pub_pem == "pem-a"


def test_registry_file_is_owner_only(tmp_path):
    registry = _registry(tmp_path)
    registry.register("iot-edge-01", "pem-a", "pcr-a", "sha256:0")

    mode = (tmp_path / "device_registry.json").stat().st_mode & 0o777
    assert mode == 0o600
