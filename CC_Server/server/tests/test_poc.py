"""PoC tests: crypto building blocks, processing, and a full E2E pass over the
User<->Server API in TLS mode (via ASGI).

The E2E tests need a real, attested edge device (QEMU or hardware) pushing
data for `constants.DEFAULT_DEVICE_ID` over `attested_network` — there is no
synthetic stub anymore. Start one before running these tests (see
docs/runtime.html); otherwise they're skipped.

Run:  python -m pytest server/tests -q     (from the project root)
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from server import constants as C
from server import crypto, processing
from server.app_server import create_app
from server.config import CONFIG
from server.device_link.attested_network import AttestedNetworkDeviceLink
from server.device_link.base import Sample

_DEVICE_WAIT_SECONDS = 15.0


@pytest.fixture(scope="module")
def device_link():
    """A live AttestedNetworkDeviceLink, shared across every E2E test in this
    module (one TCP listener bound to CONFIG.device_port — a fresh one per
    test would fail to rebind the port).

    Skips the whole module if no real device attests for DEFAULT_DEVICE_ID
    within _DEVICE_WAIT_SECONDS.
    """
    link = AttestedNetworkDeviceLink()
    deadline = time.monotonic() + _DEVICE_WAIT_SECONDS
    while time.monotonic() < deadline:
        devices = link.status()["devices"]
        if any(d["device_id"] == C.DEFAULT_DEVICE_ID and d["attested"] for d in devices):
            return link
        time.sleep(0.5)
    pytest.skip(
        "no attested edge device connected on "
        f"{CONFIG.device_host}:{CONFIG.device_port} for device_id={C.DEFAULT_DEVICE_ID} "
        "- start a real/QEMU edge device before running the E2E tests"
    )


# --------------------------------------------------------------------------
# crypto primitives (shared with the Device<->Server attested channel)
# --------------------------------------------------------------------------
def test_aead_roundtrip_and_tamper():
    """AES-GCM decrypts what it encrypted, and rejects a flipped bit (InvalidTag)."""
    key = crypto.random_bytes(32)
    nonce = crypto.random_bytes(12)
    ct = crypto.aead_encrypt(key, nonce, b"hello", b"aad")
    assert crypto.aead_decrypt(key, nonce, ct, b"aad") == b"hello"

    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    with pytest.raises(crypto.InvalidTag):
        crypto.aead_decrypt(key, nonce, bytes(tampered), b"aad")


def test_p256_ecdh_agreement():
    """Two ECDH parties derive the same shared secret (the handshake basis)."""
    a_priv, a_pub = crypto.p256_generate()
    b_priv, b_pub = crypto.p256_generate()
    assert crypto.p256_shared(a_priv, b_pub) == crypto.p256_shared(b_priv, a_pub)


# --------------------------------------------------------------------------
# processing
# --------------------------------------------------------------------------
def test_weighted_avg_favours_recent():
    """The weighted average leans toward the newer sample."""
    samples = [Sample(ts=0.0, value=10.0), Sample(ts=100.0, value=20.0)]
    r = processing.aggregate(samples, "weighted_avg")
    # recency-weighted average of 10 (old) and 20 (recent) leans toward 20
    assert 15.0 < r["value"] < 20.0


def test_mean_and_empty():
    """Mean is correct, and an empty window yields value=None (no crash)."""
    assert processing.aggregate([Sample(0.0, 4.0), Sample(1.0, 6.0)], "mean")["value"] == 5.0
    assert processing.aggregate([], "mean")["value"] is None


# --------------------------------------------------------------------------
# E2E — TLS mode (ASGI level; endpoints are plain JSON)
# --------------------------------------------------------------------------
def test_e2e_tls_mode(device_link):
    """TLS mode: /security reports tls, and a collect returns an attested result."""
    app, _ = create_app(C.USER_SECURITY_TLS, device_link=device_link)
    client = TestClient(app)

    assert client.get("/api/security").json()["mode"] == "tls"
    assert client.get("/api/health").json()["ok"] is True

    r = client.post(
        "/api/collect",
        json={"device_id": C.DEFAULT_DEVICE_ID, "window": "1h", "aggregation": "weighted_avg"},
    ).json()
    assert r["attested"] is True
    assert r["integrity"] == "ok"
    assert r["result"]["kind"] == "weighted_avg"
    assert r["n_samples"] > 0


def test_ws_collect_live_feed(device_link):
    """/ws/collect pushes a fresh collect result automatically, on a timer,
    over one socket - same shape /api/collect returns, no client request needed
    per frame."""
    app, _ = create_app(C.USER_SECURITY_TLS, device_link=device_link)
    client = TestClient(app)

    with client.websocket_connect(
        f"/ws/collect?device_id={C.DEFAULT_DEVICE_ID}&window=1h&aggregation=mean"
    ) as ws:
        first = ws.receive_json()
        assert first["attested"] is True
        assert first["integrity"] == "ok"
        assert first["measurement_ok"] is True
        assert first["result"]["kind"] == "mean"

        second = ws.receive_json()  # proves the server loop ticks again on its own
        assert second["device_id"] == C.DEFAULT_DEVICE_ID
