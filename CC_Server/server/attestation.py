"""Device <-> Server remote attestation + key exchange (the Verifier side).

The Device is the Prover, this module is the Verifier (see the project's
threat model doc). Protocol, matched against the Host CA
(project/optee_examples/confidential_iot/edge_device/host/edge_device.c +
attestation.c):

  1. hello            device -> server  {device_id}
  2. attest_challenge server -> device  {nonce, server_ecdh_pub}
  3. attest_response  device -> server  {device_id, device_ecdh_pub, quote,
                                         signature, pcr_values}
  4. attest_result    server -> device  {ok, session_ttl?} | {ok: false, error}
  5. data             device -> server  {device_id, seq, nonce, ciphertext}

Each `data` message (step 5) is AES-256-GCM with a per-session monotonic `seq`
authenticated as the AAD. `check_and_advance_seq` enforces inner-session
anti-replay: the server accepts a seq only once and only if it advances, so a
captured data message can't be replayed within the session (and it can't be
renumbered to dodge that check without breaking the GCM tag).

Verification performed on the attest_response (see `verify_and_derive`):
  a. Recompute the PCR digest from the reported pcr_values and check it
     matches the pcrDigest embedded *inside* the signed quote (the device
     can't lie about PCRs out of band from what was actually signed).
  b. Verify `signature` over the quote using the registered device's AK.
  c. Recompute the transcript hash (nonce || server_ecdh_pub ||
     device_ecdh_pub) and check it matches the quote's qualifying data
     (freshness/anti-replay - a replayed old quote won't match this
     session's nonce or ephemeral keys).
  d. Compare the verified PCR digest against the registry's expected_pcr
     baseline (integrity - was this the registered, untampered device).

On success, derives the AES-256-GCM session key via ECDH + HKDF exactly like
the User<->Server AES-GCM channel (crypto.py), just with a distinct info
label (constants.INFO_DEVICE_AEAD) so the two channels can never collide.

NOTE: the TPM2B_ATTEST / TPMT_SIGNATURE field layouts below follow the TPM 2.0
Part 2 structures spec, and the exact bytes tpm2_quote's -m/-s output files
contain should be cross-checked against a real captured quote during first
integration test (this couldn't be executed from the planning environment).
"""

from __future__ import annotations

import hashlib
import re
import struct
import threading
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import constants as C
from . import crypto
from .config import CONFIG
from .device_registry import DeviceRegistry, get_device_registry

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018
TPM_ALG_SHA256 = 0x000B
TPM_ALG_ECDSA = 0x0018

# Domain-separation label for the server-identity signature (device pins the
# server, TOFU - docs/HANDOFF_serverAuthentication.md §4). Distinct from the
# device's own TPM-quote transcript so the two signatures can never be confused
# (cross-protocol signature confusion). MUST equal the TA's
# TA_CONFIDENTIAL_IOT_SERVER_IDENTITY_LABEL byte for byte (no NUL terminator).
SERVER_IDENTITY_LABEL = b"CC-IOT-1 server-identity"


class AttestationError(ValueError):
    """Any failure of the attestation protocol (bad signature, stale nonce,
    PCR mismatch, unregistered device, ...). Callers treat this uniformly as
    'reject the session' - the message is for logs/diagnostics only."""


@dataclass
class PendingChallenge:
    nonce: bytes
    server_priv: ec.EllipticCurvePrivateKey
    server_pub: bytes
    issued_at: float


@dataclass
class DeviceSession:
    key: bytes
    expires: float
    # Highest data-message sequence number accepted so far, for inner-session
    # anti-replay. Starts at 0; the device's first message is seq 1. Reset with
    # the key on every fresh attestation (mirrors the TA's send_seq reset).
    last_seq: int = 0


class AttestationVerifier:
    """Owns in-flight challenges and completed session keys, keyed by
    device_id. One instance is shared by the whole process (see
    device_link/attested_network.py)."""

    def __init__(self, registry: DeviceRegistry | None = None) -> None:
        self._registry = registry or get_device_registry()
        self._pending: dict[str, PendingChallenge] = {}
        self._sessions: dict[str, DeviceSession] = {}
        # Guards _sessions reads/updates that race across connection threads
        # (notably the anti-replay seq bump in check_and_advance_seq).
        self._lock = threading.Lock()
        # Server-identity signing key (device pins its public half, TOFU).
        # Loaded once (generate-if-missing) and held for the process lifetime,
        # like the TLS context - NEVER regenerated, see ensure_server_identity_key.
        self._identity_priv = crypto.ensure_server_identity_key(
            CONFIG.server_identity_key_path
        )
        self._identity_pub_raw = crypto.public_point_raw(self._identity_priv)

    # -- step 1/2: hello -> attest_challenge --------------------------------
    def issue_challenge(self, device_id: str) -> dict:
        """Raises AttestationError if device_id isn't enrolled. Otherwise
        returns the {nonce, server_ecdh_pub, server_identity_pub} dict to send
        as attest_challenge.

        server_identity_pub is sent early (like a TLS certificate in
        ServerHello); proof-of-possession comes later in attest_result's
        server_sig (like CertificateVerify) - see verify_and_derive."""
        if self._registry.lookup(device_id) is None:
            raise AttestationError(f"device {device_id!r} is not registered")

        nonce = crypto.random_bytes(C.ATTEST_NONCE_LEN)
        priv, pub = crypto.p256_generate()
        self._pending[device_id] = PendingChallenge(
            nonce=nonce, server_priv=priv, server_pub=pub, issued_at=time.time()
        )
        return {
            "nonce": crypto.b64e(nonce),
            "server_ecdh_pub": crypto.b64e(pub),
            "server_identity_pub": crypto.b64e(self._identity_pub_raw),
        }

    # -- step 3/4: attest_response -> attest_result -------------------------
    def verify_and_derive(
        self,
        device_id: str,
        device_ecdh_pub_b64: str,
        quote_b64: str,
        signature_b64: str,
        pcr_values_text: str,
    ) -> bytes:
        """Raises AttestationError on any failed check; otherwise stores the
        derived session key for `device_id` (see `session_key`) and returns the
        raw 64-byte server-identity signature (r||s) to ship in attest_result,
        which lets the device prove it's talking to the server it pinned."""
        record = self._registry.lookup(device_id)
        if record is None:
            raise AttestationError(f"device {device_id!r} is not registered")

        pending = self._pending.pop(device_id, None)
        if pending is None:
            raise AttestationError(f"no pending challenge for {device_id!r}")
        if time.time() - pending.issued_at > C.ATTEST_CHALLENGE_TTL_SECONDS:
            raise AttestationError("attestation challenge expired")

        device_ecdh_pub = crypto.b64d(device_ecdh_pub_b64)
        if len(device_ecdh_pub) != C.DEVICE_ECDH_PUBKEY_LEN:
            raise AttestationError("bad device_ecdh_pub length")

        quote_raw = crypto.b64d(quote_b64)
        sig_raw = crypto.b64d(signature_b64)

        attest = parse_tpms_attest(quote_raw)
        r, s = parse_tpmt_signature_ecdsa(sig_raw)

        # (a) recompute PCR digest from the reported values, check it's what
        # was actually signed (not a value the device attached separately).
        recomputed_pcr_digest = recompute_pcr_digest(pcr_values_text)
        if recomputed_pcr_digest != attest["pcr_digest"]:
            raise AttestationError("reported PCR values don't match the signed quote")

        # (b) verify the signature over the quote using the registered AK.
        ak_pub = serialization.load_pem_public_key(record.ak_pub_pem.encode())
        if not isinstance(ak_pub, ec.EllipticCurvePublicKey):
            raise AttestationError("registered AK is not an EC public key")
        der_sig = encode_dss_signature(r, s)
        try:
            ak_pub.verify(der_sig, attest["raw_body"], ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise AttestationError("quote signature verification failed") from exc

        # (c) freshness/anti-replay: the quote must be over *this* session's
        # transcript, not a replayed one from a previous session.
        transcript_hash = compute_transcript_hash(
            pending.nonce, pending.server_pub, device_ecdh_pub
        )
        if attest["extra_data"] != transcript_hash:
            raise AttestationError("quote does not match this session's transcript")

        # (d) integrity: PCRs must match the registered known-good baseline.
        expected_digest = recompute_pcr_digest(record.expected_pcr)
        if recomputed_pcr_digest != expected_digest:
            raise AttestationError("PCR values do not match the registered baseline")

        # All checks passed: derive the session key exactly like the
        # browser<->server AES-GCM channel, just with a distinct info label.
        shared = crypto.p256_shared(pending.server_priv, device_ecdh_pub)
        key = crypto.hkdf(shared, salt=pending.nonce, info=C.INFO_DEVICE_AEAD)
        with self._lock:
            # Fresh key => last_seq resets to 0 (dataclass default), so the
            # device's post-attestation seq 1 is the first message accepted.
            self._sessions[device_id] = DeviceSession(
                key=key, expires=time.time() + C.DEVICE_SESSION_TTL_SECONDS
            )

        # Prove server identity: sign this session's transcript with the pinned
        # identity key. Labelled + distinct from the device's own quote so the
        # two signatures can't be confused. The device recomputes the identical
        # pre-image in the TA and verifies against its pinned public key before
        # trusting the session key.
        pre_image = (
            SERVER_IDENTITY_LABEL + pending.nonce + pending.server_pub + device_ecdh_pub
        )
        return crypto.sign_server_identity_raw(self._identity_priv, pre_image)

    # -- session key lookup (used by attested_network.py to decrypt "data") -
    def session_key(self, device_id: str) -> bytes | None:
        with self._lock:
            sess = self._sessions.get(device_id)
            if sess is None:
                return None
            if sess.expires < time.time():
                self._sessions.pop(device_id, None)
                return None
            return sess.key

    def check_and_advance_seq(self, device_id: str, seq: int) -> bool:
        """Inner-session anti-replay. Accept `seq` only if it is strictly
        greater than the highest seq already accepted for this device's current
        session, then record it as the new high-water mark.

        MUST be called only *after* the message's GCM tag has been verified:
        the seq is authenticated as the AEAD's AAD, so a forged/renumbered seq
        fails decryption before ever reaching here. This method then rejects a
        *genuine* captured message that is being replayed (its seq is <= one
        already seen) or arrives out of order. Returns False for a
        replayed/out-of-order/expired/out-of-range seq.
        """
        # JSON booleans are ints in Python (True == 1); reject them explicitly.
        if isinstance(seq, bool) or not isinstance(seq, int):
            return False
        if seq <= 0 or seq > 0xFFFFFFFF:
            return False
        with self._lock:
            sess = self._sessions.get(device_id)
            if sess is None or sess.expires < time.time():
                return False
            if seq <= sess.last_seq:
                return False
            sess.last_seq = seq
            return True

    def is_attested(self, device_id: str) -> bool:
        return self.session_key(device_id) is not None


def compute_transcript_hash(nonce: bytes, server_pub: bytes, device_pub: bytes) -> bytes:
    """SHA-256(nonce || server_ecdh_pub || device_ecdh_pub) - must match the
    Host CA's edge_attest_to_server() computation exactly, byte for byte."""
    return hashlib.sha256(nonce + server_pub + device_pub).digest()


# ---------------------------------------------------------------------------
# TPM2B_ATTEST / TPMS_ATTEST parsing (TPM 2.0 Part 2, "Structures")
# ---------------------------------------------------------------------------
def parse_tpms_attest(raw: bytes) -> dict:
    """Parses a TPM2B_ATTEST (as written by `tpm2_quote -m`): a 2-byte size
    prefix followed by the marshaled TPMS_ATTEST body. Returns the fields we
    need plus `raw_body` (the exact bytes the signature was computed over -
    the size-prefix is NOT included in what's signed)."""
    if len(raw) < 2:
        raise AttestationError("quote too short")

    (body_len,) = struct.unpack_from(">H", raw, 0)
    body = raw[2 : 2 + body_len]
    if len(body) != body_len:
        raise AttestationError("truncated quote")

    off = 0
    (magic,) = struct.unpack_from(">I", body, off)
    off += 4
    if magic != TPM_GENERATED_VALUE:
        raise AttestationError("not a TPM-generated structure (bad magic)")

    (attest_type,) = struct.unpack_from(">H", body, off)
    off += 2
    if attest_type != TPM_ST_ATTEST_QUOTE:
        raise AttestationError("not a QUOTE attestation structure")

    (name_len,) = struct.unpack_from(">H", body, off)
    off += 2 + name_len  # qualifiedSigner (TPM2B_NAME) - not needed here

    (extra_len,) = struct.unpack_from(">H", body, off)
    off += 2
    extra_data = body[off : off + extra_len]
    off += extra_len

    off += 17  # TPMS_CLOCK_INFO: clock(8) + resetCount(4) + restartCount(4) + safe(1)
    off += 8  # firmwareVersion (UINT64)

    # TPML_PCR_SELECTION
    (pcr_sel_count,) = struct.unpack_from(">I", body, off)
    off += 4
    for _ in range(pcr_sel_count):
        off += 2  # hash alg
        (size_of_select,) = struct.unpack_from(">B", body, off)
        off += 1 + size_of_select

    # TPM2B_DIGEST pcrDigest
    (pcr_digest_len,) = struct.unpack_from(">H", body, off)
    off += 2
    pcr_digest = body[off : off + pcr_digest_len]
    off += pcr_digest_len

    return {
        "raw_body": body,
        "extra_data": extra_data,
        "pcr_digest": pcr_digest,
    }


def parse_tpmt_signature_ecdsa(raw: bytes) -> tuple[int, int]:
    """Parses a TPMT_SIGNATURE (as written by `tpm2_quote -s`) for the ECDSA
    case: sigAlg(2) + hashAlg(2) + TPM2B_ECC_PARAMETER r + TPM2B_ECC_PARAMETER s.
    Returns (r, s) as integers for cryptography's encode_dss_signature()."""
    if len(raw) < 4:
        raise AttestationError("signature too short")

    (sig_alg,) = struct.unpack_from(">H", raw, 0)
    if sig_alg != TPM_ALG_ECDSA:
        raise AttestationError("expected an ECDSA signature")

    off = 2
    off += 2  # hash alg (expected sha256; not cross-checked beyond the verify() call)

    (r_len,) = struct.unpack_from(">H", raw, off)
    off += 2
    r = int.from_bytes(raw[off : off + r_len], "big")
    off += r_len

    (s_len,) = struct.unpack_from(">H", raw, off)
    off += 2
    s = int.from_bytes(raw[off : off + s_len], "big")

    return r, s


# ---------------------------------------------------------------------------
# PCR text parsing + digest recompute
# ---------------------------------------------------------------------------
_PCR_LINE_RE = re.compile(r"^\s*(\d+)\s*:\s*0x([0-9A-Fa-f]+)\s*$")


def parse_pcr_text(text: str) -> dict[int, bytes]:
    """Parses `tpm2_pcrread`'s plain-text output into {index: raw_bytes}.
    Tolerant of the exact banner/bank-name lines; only the "N : 0xHEX" value
    lines are matched. Raises AttestationError if none are found."""
    values: dict[int, bytes] = {}
    for line in text.splitlines():
        m = _PCR_LINE_RE.match(line)
        if m:
            index = int(m.group(1))
            values[index] = bytes.fromhex(m.group(2))
    if not values:
        raise AttestationError("could not parse any PCR values")
    return values


def recompute_pcr_digest(pcr_text: str) -> bytes:
    """Recomputes the quote's pcrDigest from raw PCR values: SHA-256 of the
    selected PCRs' raw bytes concatenated in ascending index order (this
    project only ever selects a single PCR/bank - sha256:0 - so this
    simplifies to SHA-256(pcr0), but is written to generalise if that
    changes)."""
    values = parse_pcr_text(pcr_text)
    concatenated = b"".join(values[i] for i in sorted(values))
    return hashlib.sha256(concatenated).digest()
