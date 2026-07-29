"""POST /api/devices/register tests.

This endpoint had no tests before TA-identity binding
(docs/HANDOFF_taIdentityBinding.md) gave it real work to do: it now validates
the TA's identity public key as an actual P-256 point before it can enter the
registry, canonicalises its encoding so the immutability check cannot be
tripped by cosmetic base64 differences, and constrains device_id to characters
that a C TA and Python will hash identically.

Run:  python -m pytest server/tests -q     (from the project root)
"""

from __future__ import annotations

import base64
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from server import crypto
from server import device_registry as dr
from server.app_server import create_app
from server.device_link.base import Batch, DeviceLink


class _StubLink(DeviceLink):
    """Minimal DeviceLink so create_app doesn't build the real one, which
    would bind the device-facing TCP port."""

    async def collect(self, device_id: str, window: str) -> Batch:
        return Batch(device_id=device_id, window=window)

    async def status(self) -> dict:
        return {}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient whose registry singleton points at tmp_path.

    app_server imports get_device_registry (the function), so patching the
    module-level _REGISTRY it reads is enough to redirect it.
    """
    monkeypatch.setattr(
        dr, "_REGISTRY", dr.DeviceRegistry(path=str(tmp_path / "device_registry.json"))
    )
    app, _channel = create_app("tls", device_link=_StubLink())
    with TestClient(app) as c:
        yield c


def _ta_pub_b64() -> str:
    return crypto.b64e(crypto.public_point_raw(ec.generate_private_key(ec.SECP256R1())))


def _body(**overrides) -> dict:
    body = {
        "device_id": "iot-edge-01",
        "ak_pub_pem_b64": base64.b64encode(b"-----BEGIN PUBLIC KEY-----\n").decode(),
        "expected_pcr": "sha256:\n  0 : 0xabc\n",
        "pcr_bank": "sha256:0",
        "ta_pub_b64": _ta_pub_b64(),
    }
    body.update(overrides)
    return body


def test_register_accepts_a_valid_ta_pub(client):
    body = _body()

    resp = client.post("/api/devices/register", json=body)

    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["already_registered"] is False
    record = dr.get_device_registry().lookup("iot-edge-01")
    assert crypto.b64d(record.ta_pub_b64) == crypto.b64d(body["ta_pub_b64"])


def test_register_rejects_a_missing_ta_pub(client):
    """Required, not optional-with-later-pin: a record with no TA key can never
    attest, and a backfill path would reopen the TOFU window this closes."""
    body = _body()
    del body["ta_pub_b64"]

    resp = client.post("/api/devices/register", json=body)

    assert resp.status_code == 400
    assert "ta_pub_b64" in resp.json()["error"]


@pytest.mark.parametrize(
    "raw",
    [
        b"\x04" + bytes(63),          # 64 bytes - one short
        b"\x04" + bytes(65),          # 66 bytes - one long
        b"",                           # empty
        b"\x02" + bytes(32),          # compressed point (33 bytes)
    ],
    ids=["short", "long", "empty", "compressed"],
)
def test_register_rejects_malformed_ta_pub(client, raw):
    resp = client.post(
        "/api/devices/register", json=_body(ta_pub_b64=base64.b64encode(raw).decode())
    )

    assert resp.status_code == 400
    assert dr.get_device_registry().lookup("iot-edge-01") is None


def test_register_rejects_an_off_curve_ta_pub(client):
    """Right length and right prefix, but not a point on P-256. Rejecting it
    here means junk can never reach the verifier."""
    off_curve = b"\x04" + os.urandom(64)

    resp = client.post(
        "/api/devices/register",
        json=_body(ta_pub_b64=base64.b64encode(off_curve).decode()),
    )

    assert resp.status_code == 400
    assert dr.get_device_registry().lookup("iot-edge-01") is None


def test_register_with_a_changed_ta_pub_is_a_conflict(client):
    """docs/HANDOFF_taIdentityBinding.md §8.5, at the HTTP layer. The AK is
    unchanged - only the TA key differs."""
    body = _body()
    assert client.post("/api/devices/register", json=body).status_code == 200

    resp = client.post(
        "/api/devices/register", json=_body(ta_pub_b64=_ta_pub_b64())
    )

    assert resp.status_code == 409
    assert resp.json()["ok"] is False
    assert dr.get_device_registry().lookup("iot-edge-01").ta_pub_b64 == body["ta_pub_b64"]


def test_register_canonicalises_base64_variants(client):
    """The same key re-submitted with cosmetically different base64 must be an
    idempotent no-op, not a 409. Without canonical re-encoding the immutability
    string compare would fire and look exactly like an attack."""
    body = _body()
    assert client.post("/api/devices/register", json=body).status_code == 200

    noisy = body["ta_pub_b64"]
    noisy = noisy[:20] + "\n" + noisy[20:]

    resp = client.post("/api/devices/register", json=_body(ta_pub_b64=noisy))

    assert resp.status_code == 200
    assert resp.json()["already_registered"] is True


@pytest.mark.parametrize(
    "device_id",
    ["", "a" * 64, "has space", "日本", "has/slash"],
)
def test_register_rejects_an_unsafe_device_id(client, device_id):
    """device_id is hashed into the TA-identity pre-image by both sides, so it
    must be ASCII, NUL-free and bounded - see validate_device_id."""
    resp = client.post("/api/devices/register", json=_body(device_id=device_id))

    assert resp.status_code == 400
