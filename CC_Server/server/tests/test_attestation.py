"""Device<->Server remote attestation tests.

These build a syntactically-correct TPM2B_ATTEST + TPMT_SIGNATURE byte
sequence in pure Python (real ECDSA signing via `cryptography`, no actual
TPM/simulator involved) matching exactly what `attestation.py` expects to
parse from `tpm2_quote -m`/`-s` output. This exercises the server-side
parsing + verification logic end to end with real cryptographic operations,
independent of whether the tpm2-tools CLI invocation in attestation.c turns
out to need adjustment once tested against real hardware.

Run:  python -m pytest server/tests -q     (from the project root)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import struct
import threading

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from server import constants as C
from server import crypto
from server.attestation import (
    SERVER_IDENTITY_LABEL,
    TA_IDENTITY_LABEL,
    TPM_ALG_ECDSA,
    TPM_ALG_SHA256,
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_QUOTE,
    AttestationError,
    AttestationVerifier,
    build_ta_identity_preimage,
    compute_ta_identity_msg,
    compute_transcript_hash,
    recompute_pcr_digest,
)
from server.device_registry import DeviceRegistry


def sign_ta_identity(ta_priv, device_id, nonce, server_pub, device_pub) -> bytes:
    """What the genuine TA produces: a raw 64-byte r||s ECDSA-P256 signature
    over SHA-256(pre-image). crypto.sign_server_identity_raw is exactly that
    operation (it takes the pre-image and hashes internally), so reuse it
    rather than re-deriving the encoding here."""
    return crypto.sign_server_identity_raw(
        ta_priv,
        build_ta_identity_preimage(device_id, nonce, server_pub, device_pub),
    )


def _assert_server_sig_ok(identity_pub_raw, server_sig_raw, nonce,
                          server_ecdh_pub, device_ecdh_pub):
    """Verify a raw 64-byte r||s server-identity signature exactly as the TA
    will: reconstruct the pre-image, DER-wrap (r, s), and verify against the
    advertised identity public point. Also asserts the raw form is a clean
    32+32 split (what TEE_AsymmetricVerifyDigest consumes)."""
    assert len(server_sig_raw) == 64
    pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), identity_pub_raw
    )
    pre_image = SERVER_IDENTITY_LABEL + nonce + server_ecdh_pub + device_ecdh_pub
    r = int.from_bytes(server_sig_raw[:32], "big")
    s = int.from_bytes(server_sig_raw[32:], "big")
    pub.verify(encode_dss_signature(r, s), pre_image, ec.ECDSA(hashes.SHA256()))


def _tpm2b(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def build_fake_quote_body(extra_data: bytes, pcr_digest: bytes) -> bytes:
    """The marshaled TPMS_ATTEST (without the outer TPM2B_ATTEST size prefix)."""
    body = struct.pack(">I", TPM_GENERATED_VALUE)
    body += struct.pack(">H", TPM_ST_ATTEST_QUOTE)
    body += _tpm2b(b"fake-qualified-signer-name")  # TPM2B_NAME (unchecked)
    body += _tpm2b(extra_data)                      # TPM2B_DATA extraData
    body += b"\x00" * 17                             # TPMS_CLOCK_INFO
    body += struct.pack(">Q", 1)                     # firmwareVersion
    # TPML_PCR_SELECTION: one bank (sha256), selecting PCR index 0.
    body += struct.pack(">I", 1)
    body += struct.pack(">H", TPM_ALG_SHA256)
    body += struct.pack(">B", 3)
    body += bytes([0x01, 0x00, 0x00])
    body += _tpm2b(pcr_digest)                       # TPM2B_DIGEST pcrDigest
    return body


def build_fake_quote(extra_data: bytes, pcr_digest: bytes) -> bytes:
    """A full TPM2B_ATTEST: 2-byte size prefix + the TPMS_ATTEST body."""
    return _tpm2b(build_fake_quote_body(extra_data, pcr_digest))


def sign_quote_body(ak_priv: ec.EllipticCurvePrivateKey, body: bytes) -> bytes:
    """A TPMT_SIGNATURE (ECDSA/P-256/SHA-256) over the quote body."""
    from cryptography.hazmat.primitives import hashes

    der_sig = ak_priv.sign(body, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    sig = struct.pack(">H", TPM_ALG_ECDSA)
    sig += struct.pack(">H", TPM_ALG_SHA256)
    sig += _tpm2b(r.to_bytes(32, "big"))
    sig += _tpm2b(s.to_bytes(32, "big"))
    return sig


def _ak_pub_pem(ak_priv: ec.EllipticCurvePrivateKey) -> str:
    return ak_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


class _Fixture:
    """One enrolled fake device + a fresh challenge, ready to answer."""

    def __init__(self, tmp_path, device_id: str = "iot-edge-test") -> None:
        self.device_id = device_id
        self.ak_priv = ec.generate_private_key(ec.SECP256R1())
        # Stands in for the ECDSA key the real TA generates inside the TEE and
        # seals in secure storage; only its public point is ever enrolled.
        self.ta_priv = ec.generate_private_key(ec.SECP256R1())
        self.ta_pub_raw = crypto.public_point_raw(self.ta_priv)
        self.pcr0 = hashlib.sha256(b"known-good-firmware").digest()
        self.pcr_text = f"sha256:\n  0 : 0x{self.pcr0.hex()}\n"

        self.registry = DeviceRegistry(path=str(tmp_path / "device_registry.json"))
        self.registry.register(
            device_id,
            _ak_pub_pem(self.ak_priv),
            self.pcr_text,
            "sha256:0",
            crypto.b64e(self.ta_pub_raw),
        )
        self.verifier = AttestationVerifier(registry=self.registry)

    def challenge(self) -> tuple[bytes, bytes]:
        c = self.verifier.issue_challenge(self.device_id)
        return crypto.b64d(c["nonce"]), crypto.b64d(c["server_ecdh_pub"])

    def build_response(self, nonce: bytes, server_pub: bytes, pcr_text: str | None = None):
        """Builds a genuine, correctly-signed attest_response for this
        challenge - callers mutate individual fields to test rejection paths.

        Returns (device_priv, device_pub, quote, sig, ta_sig)."""
        device_priv, device_pub = crypto.p256_generate()
        transcript_hash = compute_transcript_hash(nonce, server_pub, device_pub)
        pcr_digest = recompute_pcr_digest(pcr_text if pcr_text is not None else self.pcr_text)
        quote = build_fake_quote(transcript_hash, pcr_digest)
        sig = sign_quote_body(self.ak_priv, quote[2:])
        ta_sig = sign_ta_identity(
            self.ta_priv, self.device_id, nonce, server_pub, device_pub
        )
        return device_priv, device_pub, quote, sig, ta_sig


def test_attestation_full_roundtrip(tmp_path):
    """A genuine, correctly-signed response is accepted and both sides derive
    the identical AES-256 session key, which then round-trips a data payload
    exactly like the device<->server "data" message would."""
    fx = _Fixture(tmp_path)
    nonce, server_pub = fx.challenge()
    device_priv, device_pub, quote, sig, ta_sig = fx.build_response(nonce, server_pub)

    fx.verifier.verify_and_derive(
        device_id=fx.device_id,
        device_ecdh_pub_b64=crypto.b64e(device_pub),
        quote_b64=crypto.b64e(quote),
        signature_b64=crypto.b64e(sig),
        pcr_values_text=fx.pcr_text,
        ta_sig_b64=crypto.b64e(ta_sig),
    )

    key = fx.verifier.session_key(fx.device_id)
    assert key is not None

    # The device derives the same key independently from its own ECDH private
    # key + the server's public key + the same nonce/info.
    shared = crypto.p256_shared(device_priv, server_pub)
    expected_key = crypto.hkdf(shared, salt=nonce, info=C.INFO_DEVICE_AEAD)
    assert key == expected_key

    # And the resulting key actually protects a "data" payload end to end,
    # with the per-message seq authenticated as the AAD (matches the TA + the
    # attested_network link).
    payload = json.dumps({"samples": [{"value": 23.5, "unit": "C"}]}).encode()
    data_nonce = crypto.random_bytes(12)
    aad = (1).to_bytes(8, "big")
    ct = crypto.aead_encrypt(key, data_nonce, payload, aad=aad)
    assert crypto.aead_decrypt(key, data_nonce, ct, aad=aad) == payload


def test_attestation_rejects_unregistered_device(tmp_path):
    registry = DeviceRegistry(path=str(tmp_path / "device_registry.json"))
    verifier = AttestationVerifier(registry=registry)
    with pytest.raises(AttestationError):
        verifier.issue_challenge("never-enrolled")


def test_attestation_rejects_bad_signature(tmp_path):
    """A quote signed by the wrong key must be rejected."""
    fx = _Fixture(tmp_path)
    nonce, server_pub = fx.challenge()
    device_priv, device_pub, quote, _real_sig, ta_sig = fx.build_response(nonce, server_pub)

    wrong_key = ec.generate_private_key(ec.SECP256R1())
    bad_sig = sign_quote_body(wrong_key, quote[2:])

    with pytest.raises(AttestationError):
        fx.verifier.verify_and_derive(
            device_id=fx.device_id,
            device_ecdh_pub_b64=crypto.b64e(device_pub),
            quote_b64=crypto.b64e(quote),
            signature_b64=crypto.b64e(bad_sig),
            pcr_values_text=fx.pcr_text,
            ta_sig_b64=crypto.b64e(ta_sig),
        )
    assert fx.verifier.session_key(fx.device_id) is None


def test_attestation_rejects_pcr_mismatch(tmp_path):
    """A quote over the wrong (tampered) PCR baseline must be rejected."""
    fx = _Fixture(tmp_path)
    nonce, server_pub = fx.challenge()

    tampered_pcr = f"sha256:\n  0 : 0x{hashlib.sha256(b'tampered-firmware').hexdigest()}\n"
    device_priv, device_pub, quote, sig, ta_sig = fx.build_response(
        nonce, server_pub, pcr_text=tampered_pcr
    )

    with pytest.raises(AttestationError):
        fx.verifier.verify_and_derive(
            device_id=fx.device_id,
            device_ecdh_pub_b64=crypto.b64e(device_pub),
            quote_b64=crypto.b64e(quote),
            signature_b64=crypto.b64e(sig),
            pcr_values_text=tampered_pcr,
            ta_sig_b64=crypto.b64e(ta_sig),
        )
    assert fx.verifier.session_key(fx.device_id) is None


def test_server_identity_signature_verifies_and_is_raw_64(tmp_path):
    """verify_and_derive returns a raw 64-byte r||s server-identity signature
    that (a) verifies against the challenge's server_identity_pub over the
    labelled transcript, and (b) does NOT verify over a different transcript
    (a tampered device pubkey) - the exact TOFU check the TA performs."""
    fx = _Fixture(tmp_path)
    challenge = fx.verifier.issue_challenge(fx.device_id)
    identity_pub_raw = crypto.b64d(challenge["server_identity_pub"])
    nonce = crypto.b64d(challenge["nonce"])
    server_pub = crypto.b64d(challenge["server_ecdh_pub"])

    device_priv, device_pub, quote, sig, ta_sig = fx.build_response(nonce, server_pub)
    server_sig = fx.verifier.verify_and_derive(
        device_id=fx.device_id,
        device_ecdh_pub_b64=crypto.b64e(device_pub),
        quote_b64=crypto.b64e(quote),
        signature_b64=crypto.b64e(sig),
        pcr_values_text=fx.pcr_text,
        ta_sig_b64=crypto.b64e(ta_sig),
    )

    # (a) valid over the real transcript.
    _assert_server_sig_ok(identity_pub_raw, server_sig, nonce, server_pub, device_pub)

    # (b) a fake server (different identity key) can't produce a sig that
    #     verifies against the pinned key - this is the vuln's regression check.
    _, other_pub_raw = crypto.p256_generate()
    with pytest.raises(InvalidSignature):
        _assert_server_sig_ok(other_pub_raw, server_sig, nonce, server_pub, device_pub)

    # (c) tampered transcript (wrong device pubkey) must fail too.
    _, wrong_device_pub = crypto.p256_generate()
    with pytest.raises(InvalidSignature):
        _assert_server_sig_ok(identity_pub_raw, server_sig, nonce, server_pub, wrong_device_pub)


def test_attested_network_link_full_protocol(tmp_path):
    """Drives AttestedNetworkDeviceLink's per-connection state machine
    directly (hello -> attest_challenge -> attest_response -> attest_result
    -> data) via a fake readline/writeline pair, without opening a real
    socket - the TCP framing itself is stdlib socketserver, not worth
    re-testing. `readline` is stateful: it reacts to what the server has
    already written, exactly like a real device would react to each reply,
    all within one continuous simulated connection (state_id persists)."""
    from collections import defaultdict, deque
    from server.device_link import attested_network as an

    link = an.AttestedNetworkDeviceLink.__new__(an.AttestedNetworkDeviceLink)
    link._buf = defaultdict(lambda: deque(maxlen=100))
    link._verdict = {}
    link._lock = threading.Lock()

    fx = _Fixture(tmp_path, device_id="iot-edge-live")
    link._verifier = fx.verifier

    outgoing: list[dict] = []
    step = {"n": 0}
    session_key: dict[str, bytes] = {}

    def readline():
        step["n"] += 1
        if step["n"] == 1:
            return json.dumps({"type": "hello", "device_id": fx.device_id})
        if step["n"] == 2:
            challenge = outgoing[-1]
            nonce = crypto.b64d(challenge["nonce"])
            server_pub = crypto.b64d(challenge["server_ecdh_pub"])
            device_priv, device_pub, quote, sig, ta_sig = fx.build_response(nonce, server_pub)
            session_key["key"] = crypto.hkdf(
                crypto.p256_shared(device_priv, server_pub),
                salt=nonce, info=C.INFO_DEVICE_AEAD,
            )
            session_key["nonce"] = nonce
            session_key["server_pub"] = server_pub
            session_key["device_pub"] = device_pub
            return json.dumps({
                "type": "attest_response",
                "device_id": fx.device_id,
                "device_ecdh_pub": crypto.b64e(device_pub),
                "quote": crypto.b64e(quote),
                "signature": crypto.b64e(sig),
                "pcr_values": fx.pcr_text,
                "ta_sig": crypto.b64e(ta_sig),
            })
        if step["n"] == 3:
            key = session_key["key"]
            data_nonce = crypto.random_bytes(12)
            payload = json.dumps({"samples": [{"value": 42.0, "unit": "C"}]}).encode()
            seq = 1
            ct = crypto.aead_encrypt(key, data_nonce, payload,
                                     aad=seq.to_bytes(8, "big"))
            return json.dumps({
                "type": "data",
                "device_id": fx.device_id,
                "seq": seq,
                "nonce": crypto.b64e(data_nonce),
                "ciphertext": crypto.b64e(ct),
            })
        # Called again right after the data message was processed -> the
        # connection is still open at this point, so the verdict must
        # already reflect a live, attested, integrity-ok session before we
        # simulate the disconnect below.
        assert link._verdict[fx.device_id]["attested"] is True
        assert link._verdict[fx.device_id]["integrity"] == "ok"
        return None  # simulated disconnect

    def writeline(obj):
        outgoing.append(obj)

    link._handle_connection(readline, writeline)

    assert outgoing[0]["type"] == "attest_challenge"
    # The challenge advertises the server's identity public key (65-byte point).
    assert len(crypto.b64d(outgoing[0]["server_identity_pub"])) == 65
    # attest_result carries a server_sig that proves possession of that key over
    # this session's transcript - the device pins + verifies it (TOFU).
    assert outgoing[1]["type"] == "attest_result"
    assert outgoing[1]["ok"] is True
    assert outgoing[1]["session_ttl"] == C.DEVICE_SESSION_TTL_SECONDS
    _assert_server_sig_ok(
        identity_pub_raw=crypto.b64d(outgoing[0]["server_identity_pub"]),
        server_sig_raw=crypto.b64d(outgoing[1]["server_sig"]),
        nonce=session_key["nonce"],
        server_ecdh_pub=session_key["server_pub"],
        device_ecdh_pub=session_key["device_pub"],
    )
    assert outgoing[2] == {"ok": True}

    # Once the connection has ended, the cached verdict must reflect that -
    # not keep reporting a stale "attested/ok" for a device that's now gone
    # (the sample it sent while still connected is still delivered, though).
    batch = asyncio.run(link.collect(fx.device_id, "1h"))
    assert batch.attested is False
    assert batch.note == "device disconnected"
    assert len(batch.samples) == 1
    assert batch.samples[0].value == 42.0


def test_check_and_advance_seq_enforces_monotonicity(tmp_path):
    """Unit-level: the anti-replay counter accepts only strictly-increasing,
    in-range seqs and never a repeat/regress/booleans."""
    fx = _Fixture(tmp_path)
    nonce, server_pub = fx.challenge()
    device_priv, device_pub, quote, sig, ta_sig = fx.build_response(nonce, server_pub)
    fx.verifier.verify_and_derive(
        device_id=fx.device_id,
        device_ecdh_pub_b64=crypto.b64e(device_pub),
        quote_b64=crypto.b64e(quote),
        signature_b64=crypto.b64e(sig),
        pcr_values_text=fx.pcr_text,
        ta_sig_b64=crypto.b64e(ta_sig),
    )
    v = fx.verifier
    assert v.check_and_advance_seq(fx.device_id, 1) is True
    assert v.check_and_advance_seq(fx.device_id, 2) is True
    assert v.check_and_advance_seq(fx.device_id, 2) is False   # replay
    assert v.check_and_advance_seq(fx.device_id, 1) is False   # regress
    assert v.check_and_advance_seq(fx.device_id, 5) is True    # gaps allowed
    assert v.check_and_advance_seq(fx.device_id, 0) is False   # out of range
    assert v.check_and_advance_seq(fx.device_id, True) is False  # bool != int
    assert v.check_and_advance_seq("unknown-device", 1) is False


def test_attested_network_rejects_replayed_data(tmp_path):
    """An attacker capturing a valid, AEAD-authenticated `data` message and
    re-sending it byte-for-byte within the same session must be rejected: its
    seq was already accepted, so it is not buffered a second time."""
    from collections import defaultdict, deque
    from server.device_link import attested_network as an

    link = an.AttestedNetworkDeviceLink.__new__(an.AttestedNetworkDeviceLink)
    link._buf = defaultdict(lambda: deque(maxlen=100))
    link._verdict = {}
    link._lock = threading.Lock()

    fx = _Fixture(tmp_path, device_id="iot-edge-replay")
    link._verifier = fx.verifier

    outgoing: list[dict] = []
    step = {"n": 0}
    captured: dict[str, str] = {}

    def readline():
        step["n"] += 1
        if step["n"] == 1:
            return json.dumps({"type": "hello", "device_id": fx.device_id})
        if step["n"] == 2:
            challenge = outgoing[-1]
            nonce = crypto.b64d(challenge["nonce"])
            server_pub = crypto.b64d(challenge["server_ecdh_pub"])
            device_priv, device_pub, quote, sig, ta_sig = fx.build_response(nonce, server_pub)
            key = crypto.hkdf(
                crypto.p256_shared(device_priv, server_pub),
                salt=nonce, info=C.INFO_DEVICE_AEAD,
            )
            data_nonce = crypto.random_bytes(12)
            payload = json.dumps({"samples": [{"value": 7.0, "unit": "C"}]}).encode()
            seq = 1
            ct = crypto.aead_encrypt(key, data_nonce, payload,
                                     aad=seq.to_bytes(8, "big"))
            captured["data"] = json.dumps({
                "type": "data", "device_id": fx.device_id, "seq": seq,
                "nonce": crypto.b64e(data_nonce), "ciphertext": crypto.b64e(ct),
            })
            return json.dumps({
                "type": "attest_response",
                "device_id": fx.device_id,
                "device_ecdh_pub": crypto.b64e(device_pub),
                "quote": crypto.b64e(quote),
                "signature": crypto.b64e(sig),
                "pcr_values": fx.pcr_text,
                "ta_sig": crypto.b64e(ta_sig),
            })
        if step["n"] == 3:
            return captured["data"]            # first, legitimate delivery
        if step["n"] == 4:
            return captured["data"]            # exact replay
        return None

    def writeline(obj):
        outgoing.append(obj)

    link._handle_connection(readline, writeline)

    batch = asyncio.run(link.collect(fx.device_id, "1h"))
    # Only the first delivery was buffered; the replay was dropped and left the
    # latest verdict marking integrity failure.
    assert len(batch.samples) == 1
    assert batch.integrity == "fail"


def test_attestation_rejects_replayed_response(tmp_path):
    """The same (previously valid) response can't be replayed for a second,
    independent challenge - each challenge's nonce is single-use."""
    fx = _Fixture(tmp_path)
    nonce, server_pub = fx.challenge()
    device_priv, device_pub, quote, sig, ta_sig = fx.build_response(nonce, server_pub)

    fx.verifier.verify_and_derive(
        device_id=fx.device_id,
        device_ecdh_pub_b64=crypto.b64e(device_pub),
        quote_b64=crypto.b64e(quote),
        signature_b64=crypto.b64e(sig),
        pcr_values_text=fx.pcr_text,
        ta_sig_b64=crypto.b64e(ta_sig),
    )

    # No new hello/challenge was issued - replaying the exact same response
    # must fail because the challenge was already consumed.
    with pytest.raises(AttestationError):
        fx.verifier.verify_and_derive(
            device_id=fx.device_id,
            device_ecdh_pub_b64=crypto.b64e(device_pub),
            quote_b64=crypto.b64e(quote),
            signature_b64=crypto.b64e(sig),
            pcr_values_text=fx.pcr_text,
            ta_sig_b64=crypto.b64e(ta_sig),
        )


# ---------------------------------------------------------------------------
# TA identity binding (docs/HANDOFF_taIdentityBinding.md, Gap 2).
#
# Checks a-d prove the DEVICE (its AK) and the FIRMWARE (PCR0). They do not
# prove the genuine TA did the crypto: the AK belongs to the fTPM, has no auth
# value, and the quote is assembled by the untrusted Host. So root in Normal
# World can bypass the TA entirely - generate its own ECDH keypair, have the
# real fTPM quote it under real PCR0 - and every one of a-d passes. The tests
# below are what make that scenario fail.
# ---------------------------------------------------------------------------


def _attest(fx, device_pub, quote, sig, ta_sig, pcr_text=None):
    return fx.verifier.verify_and_derive(
        device_id=fx.device_id,
        device_ecdh_pub_b64=crypto.b64e(device_pub),
        quote_b64=crypto.b64e(quote),
        signature_b64=crypto.b64e(sig),
        pcr_values_text=fx.pcr_text if pcr_text is None else pcr_text,
        ta_sig_b64=crypto.b64e(ta_sig) if isinstance(ta_sig, bytes) else ta_sig,
    )


def test_ta_identity_bypass_with_wrong_key_is_rejected(tmp_path):
    """THE Gap-2 regression: a compromised Host that skips the TA.

    Everything the old three checks look at is genuine here - real AK
    signature, real PCR0 baseline, a quote correctly bound to this session's
    transcript. The only thing the attacker cannot produce is a signature under
    the TA identity key sealed inside the TEE.
    """
    fx = _Fixture(tmp_path)
    nonce, server_pub = fx.challenge()
    device_priv, device_pub, quote, sig, _genuine = fx.build_response(nonce, server_pub)

    attacker_key = ec.generate_private_key(ec.SECP256R1())
    forged = sign_ta_identity(attacker_key, fx.device_id, nonce, server_pub, device_pub)

    with pytest.raises(AttestationError) as exc:
        _attest(fx, device_pub, quote, sig, forged)

    # Assert on the exact message: it proves the rejection came from the new
    # leg, not incidentally from one of the pre-existing checks.
    assert str(exc.value) == "TA identity verification failed"
    # And no session key may survive a failed verification.
    assert fx.verifier.session_key(fx.device_id) is None


def test_ta_identity_bypass_with_missing_ta_sig_is_rejected(tmp_path):
    """The same bypass, attempted by simply omitting the signature - and the
    control that proves the ta_sig is the ONLY difference between the two."""
    fx = _Fixture(tmp_path)
    nonce, server_pub = fx.challenge()
    device_priv, device_pub, quote, sig, genuine = fx.build_response(nonce, server_pub)

    with pytest.raises(AttestationError) as exc:
        _attest(fx, device_pub, quote, sig, "")
    assert str(exc.value) == "bad ta_sig length"
    assert fx.verifier.session_key(fx.device_id) is None

    # Control: identical evidence, genuine ta_sig -> accepted. (A fresh
    # challenge, since the failed attempt above consumed the pending one.)
    nonce, server_pub = fx.challenge()
    device_priv, device_pub, quote, sig, genuine = fx.build_response(nonce, server_pub)
    _attest(fx, device_pub, quote, sig, genuine)
    assert fx.verifier.session_key(fx.device_id) is not None


def test_ta_sig_over_a_different_device_pub_is_rejected(tmp_path):
    """The sharpest statement of the property: root replays a genuine TA
    signature while substituting an ECDH key whose private half it holds.

    The signature is real and made by the real TA key - just over a different
    device_ecdh_pub than the one submitted. Binding device_ecdh_pub into the
    pre-image is what makes the session key unusable to anyone but the TA.
    """
    fx = _Fixture(tmp_path)
    nonce, server_pub = fx.challenge()
    _priv, device_pub, quote, sig, _genuine = fx.build_response(nonce, server_pub)

    _attacker_priv, attacker_pub = crypto.p256_generate()
    ta_sig_for_other_key = sign_ta_identity(
        fx.ta_priv, fx.device_id, nonce, server_pub, attacker_pub
    )

    with pytest.raises(AttestationError) as exc:
        _attest(fx, device_pub, quote, sig, ta_sig_for_other_key)

    assert str(exc.value) == "TA identity verification failed"
    assert fx.verifier.session_key(fx.device_id) is None


def test_ta_sig_over_a_different_device_id_is_rejected(tmp_path):
    """Locks the per-device binding in executable form: drop device_id from
    the pre-image and this test fails. The TA seals its device_id alongside the
    key, so it cannot be talked into signing under another device's identity."""
    fx = _Fixture(tmp_path)
    nonce, server_pub = fx.challenge()
    _priv, device_pub, quote, sig, _genuine = fx.build_response(nonce, server_pub)

    ta_sig_other_id = sign_ta_identity(
        fx.ta_priv, "iot-edge-somewhere-else", nonce, server_pub, device_pub
    )

    with pytest.raises(AttestationError) as exc:
        _attest(fx, device_pub, quote, sig, ta_sig_other_id)

    assert str(exc.value) == "TA identity verification failed"
    assert fx.verifier.session_key(fx.device_id) is None


def test_ta_sig_from_an_earlier_session_is_rejected(tmp_path):
    """Freshness: a ta_sig captured from session 1 must not authorise session
    2, even with session 2's own valid quote. The nonce in the pre-image is
    what provides this, independently of the quote's transcript check."""
    fx = _Fixture(tmp_path)

    nonce1, server_pub1 = fx.challenge()
    _p1, device_pub1, quote1, sig1, ta_sig1 = fx.build_response(nonce1, server_pub1)
    _attest(fx, device_pub1, quote1, sig1, ta_sig1)

    # A completely fresh, otherwise-valid session - but replaying session 1's
    # TA signature, which is bound to session 1's nonce and ephemeral key.
    nonce2, server_pub2 = fx.challenge()
    _p2, device_pub2, quote2, sig2, _ta_sig2 = fx.build_response(nonce2, server_pub2)

    with pytest.raises(AttestationError) as exc:
        _attest(fx, device_pub2, quote2, sig2, ta_sig1)

    assert str(exc.value) == "TA identity verification failed"


def test_verify_rejects_record_with_empty_ta_pub(tmp_path):
    """A device enrolled before TA-identity binding loads (so the server
    starts) but can never attest. Fail-closed, with an actionable message."""
    fx = _Fixture(tmp_path)
    # Simulate a pre-binding record surviving the upgrade.
    fx.registry.lookup(fx.device_id).ta_pub_b64 = ""

    nonce, server_pub = fx.challenge()
    _priv, device_pub, quote, sig, ta_sig = fx.build_response(nonce, server_pub)

    with pytest.raises(AttestationError) as exc:
        _attest(fx, device_pub, quote, sig, ta_sig)

    assert str(exc.value).startswith("device has no enrolled TA identity key")
    assert fx.verifier.session_key(fx.device_id) is None


@pytest.mark.parametrize(
    "bad_ta_sig",
    [
        crypto.b64e(b"\x01" * 63),      # one byte short
        crypto.b64e(b"\x01" * 65),      # one byte long
        "",                              # absent
        "not!valid!base64!",             # undecodable
        None,                            # null field in a malformed message
    ],
)
def test_malformed_ta_sig_raises_attestation_error(tmp_path, bad_ta_sig):
    """Every malformed ta_sig must surface as AttestationError, never as a
    bare binascii.Error/AttributeError: attested_network.py catches only
    AttestationError and KeyError, so anything else would kill the TCP
    connection instead of returning attest_result{ok:false}."""
    fx = _Fixture(tmp_path)
    nonce, server_pub = fx.challenge()
    _priv, device_pub, quote, sig, _ta_sig = fx.build_response(nonce, server_pub)

    with pytest.raises(AttestationError):
        _attest(fx, device_pub, quote, sig, bad_ta_sig)

    assert fx.verifier.session_key(fx.device_id) is None


def test_ta_identity_preimage_is_byte_exact(tmp_path):
    """The C/Python parity lock, and the highest-value test here for anyone
    touching the TA: the TA computes this digest in C over the same inputs, and
    a single byte of disagreement makes every honest device fail to attest with
    no clue as to why.

    The known-answer digest below lets the TA developer compute the same value
    in C and compare directly, instead of bisecting a byte-parity bug.
    """
    # The label must be usable as a C string literal hashed WITHOUT its NUL
    # (the TA does sizeof(label) - 1).
    assert TA_IDENTITY_LABEL == b"CC-IOT-1 ta-identity"
    assert len(TA_IDENTITY_LABEL) == 20
    assert b"\x00" not in TA_IDENTITY_LABEL

    nonce = bytes(range(32))
    server_pub = b"\x04" + bytes(64)
    device_pub = b"\x04" + bytes([0xAA]) * 64
    device_id = "iot-edge-01"

    pre_image = build_ta_identity_preimage(device_id, nonce, server_pub, device_pub)

    # Field order and the no-length-prefix decision, spelled out.
    assert pre_image == (
        TA_IDENTITY_LABEL + nonce + server_pub + device_pub + b"iot-edge-01"
    )
    assert len(pre_image) == 20 + 32 + 65 + 65 + len(device_id)

    # Known-answer test. Derived from the wire spec alone:
    #   sha256(b"CC-IOT-1 ta-identity" + bytes(range(32))
    #          + b"\x04" + bytes(64) + b"\x04" + bytes([0xAA]) * 64
    #          + b"iot-edge-01")
    # In the TA, hash the identical inputs and compare against this hex string.
    assert len(pre_image) == 193
    assert compute_ta_identity_msg(device_id, nonce, server_pub, device_pub).hex() == (
        "b34347ceed037083e6678f4ca1ee3306388e8da501cae328cf60c59fac294c96"
    )

    # device_id is last precisely so the encoding stays unambiguous for any
    # field lengths. These constants are what make the OTHER fields fixed, so
    # changing either must be a deliberate, test-breaking act.
    assert C.ATTEST_NONCE_LEN == 32
    assert C.DEVICE_ECDH_PUBKEY_LEN == 65


def test_ta_identity_is_domain_separated_from_the_other_signatures(tmp_path):
    """Cross-protocol signature confusion guard. The TA-identity digest must
    never coincide with the quote's qualifying data or with the
    server-identity pre-image over the same session."""
    nonce = bytes(range(32))
    server_pub = b"\x04" + bytes(64)
    device_pub = b"\x04" + bytes([0xAA]) * 64

    for device_id in ["", "a", "iot-edge-01", "x" * 63]:
        pre_image = build_ta_identity_preimage(device_id, nonce, server_pub, device_pub)
        # vs. the server-identity pre-image (different label, same transcript).
        assert pre_image != (
            SERVER_IDENTITY_LABEL + nonce + server_pub + device_pub + device_id.encode()
        )
        # vs. the fTPM quote's qualifying data.
        assert compute_ta_identity_msg(
            device_id, nonce, server_pub, device_pub
        ) != compute_transcript_hash(nonce, server_pub, device_pub)


def test_ta_sig_must_be_verified_over_the_preimage_not_the_digest(tmp_path):
    """Regression for the double-hash trap.

    The TA signs SHA-256(pre_image) via TEE_AsymmetricSignDigest. `cryptography`
    hashes whatever message it is handed, so verifying against the DIGEST hashes
    it a second time and rejects every genuine signature - a total outage that
    presents as "the TA's ECDSA sign is broken". If anyone "simplifies"
    verify_and_derive to pass compute_ta_identity_msg(), this fails immediately.
    """
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    fx = _Fixture(tmp_path)
    nonce, server_pub = fx.challenge()
    _priv, device_pub, _quote, _sig, ta_sig = fx.build_response(nonce, server_pub)

    ta_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), fx.ta_pub_raw
    )
    der = encode_dss_signature(
        int.from_bytes(ta_sig[:32], "big"), int.from_bytes(ta_sig[32:], "big")
    )
    pre_image = build_ta_identity_preimage(fx.device_id, nonce, server_pub, device_pub)
    digest = compute_ta_identity_msg(fx.device_id, nonce, server_pub, device_pub)

    # Correct: verify over the pre-image.
    ta_pub.verify(der, pre_image, ec.ECDSA(hashes.SHA256()))
    # Equivalent: verify the digest, declared as already hashed.
    ta_pub.verify(
        der, digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))
    )
    # Wrong: the digest hashed a second time.
    with pytest.raises(InvalidSignature):
        ta_pub.verify(der, digest, ec.ECDSA(hashes.SHA256()))


def test_ta_identity_errors_never_say_not_registered(tmp_path):
    """edge_device.c triggers self-registration on strstr(err, "not registered").
    A TA-identity failure that happened to contain that phrase would send the
    device into a register/attest loop instead of surfacing the real problem."""
    fx = _Fixture(tmp_path)
    messages = []

    for bad in ["", "not!base64!", crypto.b64e(b"\x01" * 63)]:
        nonce, server_pub = fx.challenge()
        _p, device_pub, quote, sig, _t = fx.build_response(nonce, server_pub)
        with pytest.raises(AttestationError) as exc:
            _attest(fx, device_pub, quote, sig, bad)
        messages.append(str(exc.value))

    nonce, server_pub = fx.challenge()
    _p, device_pub, quote, sig, _t = fx.build_response(nonce, server_pub)
    forged = sign_ta_identity(
        ec.generate_private_key(ec.SECP256R1()), fx.device_id,
        nonce, server_pub, device_pub,
    )
    with pytest.raises(AttestationError) as exc:
        _attest(fx, device_pub, quote, sig, forged)
    messages.append(str(exc.value))

    for msg in messages:
        assert "not registered" not in msg


def test_attested_network_rejects_attest_response_without_ta_sig(tmp_path):
    """The Gap-2 bypass driven through the real connection state machine: a
    Host that skipped the TA simply has no ta_sig to send. The server must
    answer attest_result{ok:false}, derive no session key, and report the
    device as unattested - not drop the connection with an unhandled error."""
    from collections import defaultdict, deque
    from server.device_link import attested_network as an

    link = an.AttestedNetworkDeviceLink.__new__(an.AttestedNetworkDeviceLink)
    link._buf = defaultdict(lambda: deque(maxlen=100))
    link._verdict = {}
    link._lock = threading.Lock()

    fx = _Fixture(tmp_path, device_id="iot-edge-bypass")
    link._verifier = fx.verifier

    outgoing: list[dict] = []
    step = {"n": 0}

    def readline():
        step["n"] += 1
        if step["n"] == 1:
            return json.dumps({"type": "hello", "device_id": fx.device_id})
        if step["n"] == 2:
            challenge = outgoing[-1]
            nonce = crypto.b64d(challenge["nonce"])
            server_pub = crypto.b64d(challenge["server_ecdh_pub"])
            _priv, device_pub, quote, sig, _ta_sig = fx.build_response(nonce, server_pub)
            # Everything genuine EXCEPT the omitted ta_sig.
            return json.dumps({
                "type": "attest_response",
                "device_id": fx.device_id,
                "device_ecdh_pub": crypto.b64e(device_pub),
                "quote": crypto.b64e(quote),
                "signature": crypto.b64e(sig),
                "pcr_values": fx.pcr_text,
            })
        return None  # disconnect

    link._handle_connection(readline, lambda obj: outgoing.append(obj))

    assert outgoing[0]["type"] == "attest_challenge"
    assert outgoing[1]["type"] == "attest_result"
    assert outgoing[1]["ok"] is False
    assert "server_sig" not in outgoing[1]
    assert fx.verifier.session_key(fx.device_id) is None
    assert fx.verifier.is_attested(fx.device_id) is False
