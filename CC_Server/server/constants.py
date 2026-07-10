"""Pure constants for the User <-> Server side.

No environment access here — everything runtime-configurable lives in
`config.Config`. These are fixed protocol/application values.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# User <-> Server transport-security modes (see transport/)
# ---------------------------------------------------------------------------
USER_SECURITY_TLS = "tls"        # TLS 1.3 via a ready library (uvicorn + SSLContext)
USER_SECURITY_AESGCM = "aesgcm"  # application-layer AES-256-GCM (ECDH-negotiated key)
USER_SECURITY_MODES = (USER_SECURITY_TLS, USER_SECURITY_AESGCM)

# Device-link kinds (the sensor-data source; see device_link/)
DEVICE_LINK_STUB = "stub"        # synthetic data, self-contained (default)
DEVICE_LINK_NETWORK = "network"  # TCP listener, trusts a self-reported `attested` flag
DEVICE_LINK_ATTESTED_NETWORK = "attested_network"  # TCP listener + real remote attestation

# Endpoints that must stay in cleartext even in aesgcm mode, because the browser
# needs them to bootstrap encryption (learn the mode, do the ECDH handshake) or
# they carry no secret. The AES-GCM middleware skips these paths.
CLEAR_PATHS = ("/", "/api/security", "/api/handshake", "/api/health")
CLEAR_PATH_PREFIXES = ("/web", "/favicon")   # static UI assets + browser favicon

# ---------------------------------------------------------------------------
# AES-GCM (browser <-> server) crypto parameters
# Must match web/app.js on the browser side.
# ---------------------------------------------------------------------------
INFO_USER_AEAD = b"CC-IOT-1 user-aead"   # HKDF "info" label binding the session key
AEAD_KEY_LEN = 32                        # 32 bytes -> AES-256 (vs 16 = AES-128)
AEAD_NONCE_LEN = 12                      # GCM standard 96-bit nonce/iv length
USER_SESSION_TTL_SECONDS = 3600          # how long a handshake-derived key stays valid

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
# Application values
# ---------------------------------------------------------------------------
WINDOWS = {"1h": 3600, "24h": 86400}     # user-selectable window -> length in seconds
DEFAULT_WINDOW = "1h"

# Aggregations the user can pick; validated against this tuple before processing.
AGGREGATIONS = ("raw", "mean", "min", "max", "weighted_avg")
DEFAULT_AGGREGATION = "weighted_avg"

DEFAULT_DEVICE_ID = "iot-edge-01"        # used when a request omits device_id
