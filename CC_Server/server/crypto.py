"""Shared crypto primitives: P-256 ECDH, HKDF-SHA256, AES-256-GCM, base64/random
helpers, built on the `cryptography` library.

Used by the Device <-> Server remote-attestation + encrypted sensor channel
(`attestation.py`, `device_link/attested_network.py`). The User <-> Server side
is plain TLS 1.3 (uvicorn + SSLContext) and does not use this file.

How the pieces build AES-GCM, in order:
    1. p256_generate + p256_shared -> a shared secret agreed via ECDH
    2. hkdf(shared, ...)           -> turns that secret into the 32-byte AES-256 key
    3. random_bytes(12)            -> a fresh unique nonce for each message
    4. aead_encrypt / aead_decrypt -> the actual AES-256-GCM (confidentiality + tag)
    b64e / b64d wrap the binary fields (keys, nonce, ciphertext) for JSON transport.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import constants as C


# --- encoding / randomness helpers ----------------------------------------
def b64e(data: bytes) -> str:
    """Bytes -> base64 ASCII string (so binary can travel inside JSON)."""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Base64 ASCII string -> bytes (inverse of b64e)."""
    return base64.b64decode(text.encode("ascii"))


def random_bytes(n: int) -> bytes:
    """`n` cryptographically secure random bytes (used for the GCM nonce)."""
    return os.urandom(n)


# --- P-256 ECDH (key exchange with the edge device) ------------------------
# Public keys are the 65-byte uncompressed SEC1 point (0x04 || X || Y) — see
# DEVICE_ECDH_PUBKEY_LEN and edge_device/ta's own ECDH keypair generation.
# The ECDH shared secret is the 32-byte X coordinate.
def p256_generate() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Generate an ephemeral P-256 keypair.

    Returns (private_key, public_bytes) where public_bytes is the 65-byte
    uncompressed SEC1 point the device expects.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return priv, pub_raw


def p256_shared(priv: ec.EllipticCurvePrivateKey, peer_pub_raw: bytes) -> bytes:
    """ECDH: combine our private key with the peer's public key.

    Both sides compute the SAME 32-byte secret (the X coordinate) without it
    ever crossing the wire. Not used directly as a key -> feed it to hkdf().
    """
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub_raw)
    return priv.exchange(ec.ECDH(), peer)


# --- HKDF-SHA256 (key derivation) -----------------------------------------
def hkdf(shared: bytes, salt: bytes, info: bytes, length: int = C.AEAD_KEY_LEN) -> bytes:
    """Derive a uniform key from the ECDH secret.

    The raw ECDH output is a curve point, not good key material; HKDF stretches
    it into `length` uniform bytes (default 32 -> the AES-256 key). `salt` and
    `info` add domain separation so the same secret can't yield the same key in
    a different context.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(shared)


# --- AES-256-GCM (the AEAD itself) ----------------------------------------
def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM encrypt.

    Returns ciphertext with the 16-byte authentication tag appended. `nonce`
    MUST be unique per key (we pass a fresh random 12 bytes each call). `aad` is
    authenticated but not encrypted (we pass b"").
    """
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt.

    Verifies the tag first: returns the plaintext only if it is authentic, else
    raises `InvalidTag`. That is how a tampered {iv, ct} envelope is rejected.
    """
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


__all__ = [
    "b64e", "b64d", "random_bytes",
    "p256_generate", "p256_shared",
    "hkdf", "aead_encrypt", "aead_decrypt",
    "InvalidTag",
]
