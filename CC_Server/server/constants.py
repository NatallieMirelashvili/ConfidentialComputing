"""Pure constants for the User <-> Server side.

No environment access here — everything runtime-configurable lives in
`config.Config`. These are fixed protocol/application values.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# User <-> Server transport-security modes (see transport/)
# ---------------------------------------------------------------------------
USER_SECURITY_TLS = "tls"        # TLS 1.3 via a ready library (uvicorn + SSLContext)
USER_SECURITY_MODES = (USER_SECURITY_TLS,)

# Device-link kinds (the sensor-data source; see device_link/). No synthetic
# fallback — MS_DEVICE_LINK must name one of these or the server refuses to start.
DEVICE_LINK_NETWORK = "network"  # TCP listener, trusts a self-reported `attested` flag
DEVICE_LINK_ATTESTED_NETWORK = "attested_network"  # TCP listener + real remote attestation

# ---------------------------------------------------------------------------
# Shared AEAD parameter (see crypto.py). Used as the default key length for
# HKDF -> AES-256 key derivation on the Device <-> Server channel.
# ---------------------------------------------------------------------------
AEAD_KEY_LEN = 32                        # 32 bytes -> AES-256 (vs 16 = AES-128)

# ---------------------------------------------------------------------------
# Device <-> Server remote attestation + key exchange (see attestation.py and
# device_link/attested_network.py). Must match the Host CA's HKDF info label
# (TA_CONFIDENTIAL_IOT_HKDF_INFO in edge_device/ta/include/confidential_iot_ta.h).
# ---------------------------------------------------------------------------
INFO_DEVICE_AEAD = b"CC-IOT-1 device-aead"
DEVICE_SESSION_TTL_SECONDS = 3600         # how long a completed attestation stays valid
ATTEST_NONCE_LEN = 32                     # bytes of randomness sent as the attestation nonce
ATTEST_CHALLENGE_TTL_SECONDS = 30         # how long a device has to answer a challenge
DEVICE_ECDH_PUBKEY_LEN = 65                # uncompressed P-256 SEC1 point (0x04 || X || Y)

# ---------------------------------------------------------------------------
# TA identity binding (see attestation.py, docs/HANDOFF_taIdentityBinding.md).
# The TA's sealed ECDSA P-256 identity key: the public half uses the same
# 65-byte uncompressed SEC1 encoding as the ECDH keys, and the signature is
# raw r||s. Mirrors TA_CONFIDENTIAL_IOT_TA_SIG_SIZE in confidential_iot_ta.h.
# ---------------------------------------------------------------------------
TA_IDENTITY_PUBKEY_LEN = 65
TA_IDENTITY_SIG_LEN = 64
# Max device_id length in bytes. device_id is hashed into the TA-identity
# pre-image on both sides, and the TA holds it in a fixed-size sealed buffer -
# MUST equal TA_CONFIDENTIAL_IOT_DEVICE_ID_MAX in confidential_iot_ta.h.
DEVICE_ID_MAX_LEN = 63

# ---------------------------------------------------------------------------
# Application values
# ---------------------------------------------------------------------------
WINDOWS = {"1h": 3600, "24h": 86400}     # user-selectable window -> length in seconds
DEFAULT_WINDOW = "1h"

# Aggregations the user can pick; validated against this tuple before processing.
AGGREGATIONS = ("raw", "mean", "min", "max", "weighted_avg")
DEFAULT_AGGREGATION = "weighted_avg"

DEFAULT_DEVICE_ID = "iot-edge-01"        # used when a request omits device_id

WS_COLLECT_POLL_SECONDS = 1.0            # /ws/collect: seconds between live pushes
