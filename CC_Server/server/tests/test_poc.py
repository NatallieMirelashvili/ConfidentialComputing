"""PoC tests: crypto building blocks, processing, and full E2E in BOTH transport
security modes (TLS via ASGI, and application-layer AES-GCM including a tamper
rejection).

Run:  python -m pytest server/tests -q     (from the project root)
"""

from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from server import constants as C
from server import crypto, processing
from server.app_server import create_app
from server.device_link.base import Sample
from server.device_link.stub import StubDeviceLink


# --------------------------------------------------------------------------
# crypto primitives (user-side essentials)
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


def test_stub_link_attested():
    """The stub returns a good verdict + non-empty samples for a normal device."""
    batch = asyncio.run(StubDeviceLink().collect(C.DEFAULT_DEVICE_ID, "1h"))
    assert batch.attested and batch.integrity == "ok"
    assert len(batch.samples) > 0


def test_stub_link_simulated_failure():
    """A 'tampered' device id yields the failed (rejected) verdict."""
    batch = asyncio.run(StubDeviceLink().collect("tampered-dev", "1h"))
    assert not batch.attested and batch.integrity == "fail"


# --------------------------------------------------------------------------
# E2E — TLS mode (ASGI level; endpoints are plain JSON)
# --------------------------------------------------------------------------
def test_e2e_tls_mode():
    """TLS mode: /security reports tls, and a collect returns an attested result."""
    app, _ = create_app(C.USER_SECURITY_TLS)
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


# --------------------------------------------------------------------------
# E2E — AES-GCM app-layer mode (emulate the browser in Python)
# --------------------------------------------------------------------------
def _aesgcm_client():
    """Build an AES-GCM app, do the ECDH handshake, return (client, sid, key).

    This mirrors what web/app.js does in the browser, but in Python.
    """
    app, _ = create_app(C.USER_SECURITY_AESGCM)
    client = TestClient(app)

    # 1) handshake (cleartext)
    priv, client_pub = crypto.p256_generate()
    hs = client.post("/api/handshake", json={"client_pub": crypto.b64e(client_pub)}).json()
    sid = hs["session_id"]
    server_pub = crypto.b64d(hs["server_pub"])
    shared = crypto.p256_shared(priv, server_pub)
    key = crypto.hkdf(shared, salt=client_pub + server_pub, info=C.INFO_USER_AEAD)
    return client, sid, key


def _seal(key, obj):
    """Encrypt a dict into an {iv, ct} envelope (what the browser sends)."""
    iv = crypto.random_bytes(12)
    ct = crypto.aead_encrypt(key, iv, json.dumps(obj).encode(), b"")
    return {"iv": crypto.b64e(iv), "ct": crypto.b64e(ct)}


def _open(key, env):
    """Decrypt an {iv, ct} envelope back into a dict (what the browser does)."""
    return json.loads(crypto.aead_decrypt(key, crypto.b64d(env["iv"]), crypto.b64d(env["ct"]), b""))


def test_e2e_aesgcm_mode():
    """AES-GCM mode: an enveloped collect round-trips and returns an attested result."""
    client, sid, key = _aesgcm_client()

    # security endpoint is cleartext
    assert client.get("/api/security").json()["mode"] == "aesgcm"

    # secured collect via encrypted envelope
    env = _seal(key, {"device_id": C.DEFAULT_DEVICE_ID, "window": "1h", "aggregation": "mean"})
    resp = client.post("/api/collect", json=env, headers={"X-Session-Id": sid})
    assert resp.status_code == 200
    out = _open(key, resp.json())
    assert out["attested"] is True
    assert out["result"]["kind"] == "mean"


def test_e2e_aesgcm_requires_session():
    """A secured request without a session header is rejected (401)."""
    client, _sid, key = _aesgcm_client()
    env = _seal(key, {"window": "1h"})
    # no X-Session-Id header -> rejected
    assert client.post("/api/collect", json=env).status_code == 401


def test_e2e_aesgcm_tamper_rejected():
    """A tampered envelope fails AEAD auth and is rejected (400)."""
    client, sid, key = _aesgcm_client()
    env = _seal(key, {"device_id": C.DEFAULT_DEVICE_ID, "window": "1h", "aggregation": "mean"})

    ct = bytearray(crypto.b64d(env["ct"]))
    ct[0] ^= 0x01  # flip a ciphertext byte
    env["ct"] = crypto.b64e(bytes(ct))

    resp = client.post("/api/collect", json=env, headers={"X-Session-Id": sid})
    assert resp.status_code == 400  # AEAD auth failure -> request rejected
