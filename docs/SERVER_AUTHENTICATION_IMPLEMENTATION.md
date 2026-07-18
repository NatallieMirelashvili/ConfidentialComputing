# Server-authenticated attestation (device pins the server, TOFU) — implementation notes

**Spec this follows:** `docs/HANDOFF_serverAuthentication.md` (written before this
implementation; read it for the full rationale and the alternatives rejected).
**Design summary:** `docs/ATTESTATION_DESIGN.md` §2.10;
**flow diagram:** `docs/CONNECTION_INITIATION.md`.
**Status:** implemented; server side unit-tested (`test_attestation.py`), device
side syntax-checked against the TA dev-kit + host toolchain. The live QEMU
end-to-end run is the remaining verification step (see §5).

---

## 1. The gap, in one paragraph

Device↔server attestation was **one-directional**: the device proved itself to
the server with a TPM quote, but nothing proved the server's identity to the
device. Port 9000/9100 has no TLS, and the quote's qualifying data is all
public, so a compromised Host that redirects `SERVER_HOST`/`SERVER_PORT` could
point the device at an impostor that just speaks the JSON protocol and always
answers `"ok": true`. The device would derive a real session key with the
attacker and stream genuine AES-256-GCM readings it can decrypt. This work makes
trust **mutual**: the server now proves possession of a device-pinned identity
key, verified inside the TA before any session key is derived.

## 2. Architecture of the fix

```
Server (CC_Server)                         Device (QEMU guest)
──────────────────                         ───────────────────
server_identity_key.pem  ── attest_challenge ──►  Host CA parses
  (ECDSA P-256, persisted,   server_identity_pub    server_identity_pub (65B)
   generated once)           (65-byte point)               │
        │                                                   │
   sign transcript ── attest_result ──► Host CA parses      │
   with identity key    server_sig (raw 64B r‖s)   server_sig (64B)          │
        │                                                   ▼
   SHA-256("CC-IOT-1 server-identity"           ta_handshake_complete():
     ‖ nonce ‖ server_ecdh_pub ‖ device_ecdh_pub)   authenticate_server()
                                                    ├─ recompute same digest
                                                    ├─ open "ciot.server.pubkey"
                                                    │   ├ first use → verify vs
                                                    │   │  presented key, then PIN
                                                    │   └ later    → compare vs
                                                    │      pinned, then verify
                                                    └─ only on success: derive
                                                       the ECDH+HKDF session key
```

Two independent trust gates now protect the session key: the **server** verifies
the device's quote, and the **device (TA)** verifies the server's identity
signature. Both verdicts live in the TEE / Verifier, never in untrusted code.

## 3. Files changed

### 3.1 Server (`CC_Server/server/`)

- **`config.py`** — new `server_identity_key_path` property (`certs_dir` +
  `server_identity_key.pem`), so the key persists in the same `server-certs`
  volume as the TLS key.
- **`crypto.py`** — `ensure_server_identity_key()` (load-or-generate a P-256
  PKCS8 PEM; **never** regenerate an existing key — that would lock out every
  device that pinned the old one), `public_point_raw()`, and
  `sign_server_identity_raw()` (ECDSA-P256-SHA256 → DER → raw 64-byte `r‖s` via
  `decode_dss_signature` + 32-byte left-pad, so the TA never parses ASN.1).
- **`attestation.py`** — `AttestationVerifier` loads the identity key once at
  construction; `issue_challenge()` advertises `server_identity_pub`;
  `verify_and_derive()` now signs the labelled pre-image
  `b"CC-IOT-1 server-identity" + nonce + server_ecdh_pub + device_ecdh_pub`
  after deriving the session and **returns** the raw signature.
- **`device_link/attested_network.py`** — `attest_challenge` carries
  `server_identity_pub` (via `issue_challenge`); `attest_result` (ok case)
  carries `server_sig` (from `verify_and_derive`'s return). Wire-protocol
  docstring updated.
- **`tests/test_attestation.py`** — the full-protocol test asserts the challenge
  advertises a 65-byte identity key and that `attest_result`'s `server_sig`
  verifies over the labelled transcript; a new focused test proves the raw-64
  signature verifies under the advertised key and fails under a wrong
  key/transcript (the vuln's regression check).

### 3.2 Device — Host CA (`edge_device/host/`)

- **`edge_device.c`** — caches `g_server_identity_pub` (65B) and `g_server_sig`
  (64B); `edge_attest_to_server()` parses `server_identity_pub` out of
  `attest_challenge` and `server_sig` out of `attest_result` (same base64 +
  size-check idiom as the ECDH keys); `edge_handshake()` passes both into
  `CMD_HANDSHAKE_COMPLETE` as params[2]/[3].
- **`edge_device.h`** — updated the `edge_attest_to_server`/`edge_handshake`
  doc comments.

### 3.3 Device — TA (`edge_device/ta/`)

- **`include/confidential_iot_ta.h`** — `HANDSHAKE_COMPLETE` param shape extended
  to params[2] = server identity pubkey (65B), params[3] = server signature
  (64B); new `TA_CONFIDENTIAL_IOT_SERVER_SIG_SIZE` (64),
  `..._SERVER_IDENTITY_LABEL` (`"CC-IOT-1 server-identity"`),
  `..._SERVER_PUBKEY_OBJID` (`"ciot.server.pubkey"`); new failure codes
  documented (`TEE_ERROR_SIGNATURE_INVALID`, `TEE_ERROR_ACCESS_CONFLICT`).
- **`trusted_app.c`** — new static `authenticate_server()`: recompute the
  labelled digest via `TEE_ALG_SHA256`, open the `ciot.server.pubkey`
  persistent object (`TEE_STORAGE_PRIVATE`), compare-or-bootstrap (TOFU), and do
  the **first TA-side ECDSA verify** in the codebase
  (`TEE_ALG_ECDSA_P256` / `TEE_TYPE_ECDSA_PUBLIC_KEY` populated with X/Y +
  curve / `TEE_AsymmetricVerifyDigest`). `ta_handshake_complete()` reconstructs
  `device_ecdh_pub` from its still-live ephemeral keypair, calls
  `authenticate_server()` **before** the ECDH+HKDF body, and `goto out`s on any
  failure so `session_key_valid` stays false and the single-use keypair is
  consumed.

### 3.4 Fresh device on rebuild (`scripts/`)

The pinned key lives in secure storage on the persistent per-instance disk
(`.device-state/*.img`), so it survives reboots — but a rebuild can rotate the
server identity key, which would permanently lock a pinned device out.

- **`build.sh`** — writes a fresh, per-build-unique `.build-stamp` after each
  successful build.
- **`run-project.sh`** — host-side (before the Docker re-exec, where CC_Server's
  Python env lives): diffs `.build-stamp` against a per-instance stored stamp
  and, on a genuine rebuild, **wipes the device disk** (`rm -f` → the existing
  block recreates a blank ext4 → empty secure storage → new AK + fresh TOFU) and
  drops the stale registry entry via `reset-device-registry.sh` (a fresh disk
  means a new AK, and the server 409-rejects a known `device_id` re-registering
  with a different key — `docs/SELF_REGISTRATION_IMPLEMENTATION.md` §6). Only
  fires when a *previous* stamp was recorded and differs, so a plain relaunch or
  guest `reboot` keeps the pin.
- **`.gitignore`** — `.build-stamp`.

**Security note.** The *automatic* rebuild-reset is a QEMU/dev convenience,
deliberately coupled to a **full** disk wipe (it also destroys the AK) so it is
not a quiet bypass a compromised Host could use to force a re-TOFU — matching the
spec's principle. On real hardware, re-pinning would be an operator-controlled
re-provision. Same "not hardware-rooted under QEMU" caveat class as the PCR0
stand-in (`docs/ATTESTATION_DESIGN.md` §2.9).

## 4. Cross-side invariants (must stay byte-identical)

- **Pre-image:** `"CC-IOT-1 server-identity"` (no NUL) ‖ nonce ‖ server_ecdh_pub
  (65B) ‖ device_ecdh_pub (65B). Server hashes it with `ec.ECDSA(SHA256())`; the
  TA hashes the identical bytes with `TEE_ALG_SHA256` and calls
  `TEE_AsymmetricVerifyDigest`. Label constant is duplicated in
  `attestation.py` (`SERVER_IDENTITY_LABEL`) and the TA header
  (`TA_CONFIDENTIAL_IOT_SERVER_IDENTITY_LABEL`) — keep them equal.
- **Signature encoding:** raw 64-byte `r‖s`, each integer big-endian
  left-padded to 32 bytes.

## 5. Verification

- **Done — server unit tests:** `python3 -m pytest CC_Server/server/tests -q`
  (all green; the new server-identity tests exercise the exact raw-64 verify the
  TA performs).
- **Done — device compiles:** `trusted_app.c` and `edge_device.c` pass
  `-fsyntax-only` against the TA dev-kit and host toolchain in `.optee-workspace`.
- **Pending — live QEMU E2E** (per `docs/HANDOFF_serverAuthentication.md` §7 and
  `docs/PERSISTENT_AK_IMPLEMENTATION.md` §7 for the runbook):
  1. first use → handshake succeeds, `ciot.server.pubkey` pinned, `data` flows;
  2. guest `reboot` → pin survives, re-attest succeeds with no new TOFU;
  3. point at a *different* server (different identity key) → `attest_result
     ok:true` but signature fails against the pinned key → `HANDSHAKE_COMPLETE`
     fails, no `data` sent (the vuln's regression test);
  4. malformed first-use signature → rejected (TOFU skips comparison, not
     verification);
  5. rebuild → `run-project.sh` logs "rebuild detected", disk wiped, new AK, clean
     re-TOFU + re-register; a plain relaunch leaves the AK unchanged.
