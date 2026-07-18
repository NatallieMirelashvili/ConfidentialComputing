# Handoff: Server-Authenticated Attestation (Device Pins the Server's Identity)

Status: **IMPLEMENTED.** This document is the original spec; the shipped design
follows it (TOFU pinning of a dedicated ECDSA-P256 server-identity key, verified
inside the TA before session-key derivation). What was actually built, file by
file, plus the verification results and the "fresh device on rebuild" behavior
added on top, is in **`docs/SERVER_AUTHENTICATION_IMPLEMENTATION.md`**; the
design is also summarized in `docs/ATTESTATION_DESIGN.md` §2.10 and reflected in
`docs/CONNECTION_INITIATION.md`'s diagram. Kept below as the rationale of record.

Resolutions to the open decisions in §8: the "first genuine attestation" trigger
is the first successful `HANDSHAKE_COMPLETE` (the TA pins there, independent of
the self-registration HTTP path — §2's caveat honored); the rebuild-reset was
chosen to be a **full disk wipe** (fresh AK + fresh TOFU), deliberately coupled
to destroying the AK so it is not a quiet bypass; the DER→raw `(r,s)` re-encode
round-trips against OP-TEE's `TEE_ALG_ECDSA_P256` verify (raw 64-byte `r‖s`),
now exercised by `test_attestation.py`.

## 1. The problem this fixes

The existing device↔server attestation (`docs/ATTESTATION_DESIGN.md`) is
**unilateral**: the device (Prover) proves its identity to the server
(Verifier) via a TPM quote, but nothing proves the server's identity to the
device. Concretely:

- The TPM quote's qualifying data is `SHA256(nonce ‖ server_ecdh_pub ‖
  device_ecdh_pub)` — all public values. It proves *"this device, with its
  real AK, produced this transcript"*. It says nothing about who supplied
  `server_ecdh_pub`.
- `ta_handshake_complete` derives the session key via `HKDF(ECDH(device_priv,
  server_ecdh_pub), ...)`. ECDH always produces a *real* shared secret with
  whoever supplied the peer public key — there's no way to get "the right"
  shared secret with the wrong party.
- Port 9000/9100 has no TLS and no server certificate check, by design
  (`docs/ARCHITECTURE.md`: "No TLS here at all — deliberately").

**Consequence:** a compromised Host (or anyone able to redirect
`SERVER_HOST`/`SERVER_PORT`, e.g. by editing `/etc/confidential_iot/device.conf`
or `CIOT_SERVER_HOST`/`CIOT_SERVER_PORT`) can point the device at a server it
controls. The fake server needs no cryptographic capability at all — it just
has to speak the JSON protocol and always answer `"ok": true"`. The device
completes a fully "successful" handshake, derives a real session key with the
attacker, and starts sending genuine AES-256-GCM-encrypted sensor readings
that the attacker can decrypt. This is a real data-theft path, not a
theoretical one, and it is independent of the sensor-path work in
`docs/SENSOR_PATH_IMPLEMENTATION.md` (this fixes a pre-existing gap in the
device↔server core, not anything in the sensor path).

## 2. Agreed design (from the design discussion — do not re-litigate these)

- **Trust-on-first-use (TOFU), then immutable.** We explicitly assume the
  server is a good actor **the first time** the device genuinely attests to
  it after being provisioned/deployed. On that first successful handshake,
  the device pins the server's public key into secure storage. On every
  handshake after that, the device requires the server to prove possession
  of the *same* pinned key and refuses to proceed otherwise — permanently,
  until the TA's storage is wiped (which also destroys the AK/sensor secret,
  so that's not a quiet bypass).
- **This must NOT reuse the existing automatic self-registration flow as the
  trust bootstrap.** `edge_register_with_server()` / `POST
  /api/devices/register` is explicitly for **testing convenience only** (the
  user's own words) — it is not a trusted, one-time, operator-controlled
  event. Whatever code path ends up being "first use" for pinning purposes
  must not be silently identical to a flow whose whole point is that it
  fires automatically, unattended, every time an unregistered `device_id`
  shows up. Flag this precisely to the user before wiring anything up —
  the exact "first genuine attestation" trigger point needs to be agreed,
  not assumed.
- **Verification MUST happen inside the TA**, never in `edge_device.c`. Same
  rule as every other trust gate in this project (§2.6 of
  `docs/ATTESTATION_DESIGN.md`, and the sensor-auth design in
  `docs/SENSOR_PATH_IMPLEMENTATION.md`): if the Host decides whether to trust
  the check, a compromised Host just skips the check. The TA must refuse to
  derive/trust the session key on its own, based on its own verification.
- **Pin the raw public key, not an X.509 certificate.** Parsing ASN.1/X.509
  inside a TA's minimal libc is unnecessary attack surface for no benefit —
  a self-signed certificate's own signature only proves it wasn't corrupted
  in transit, it proves nothing about server identity. What actually proves
  identity is the server signing something fresh, per-session, with the
  private key matching an *already-trusted* public key. So: extract the raw
  public key server-side, send only that raw value to the device, and never
  send/parse a certificate structure on the device side at all.

## 3. Decided: dedicated ECDSA P-256 key, NOT the existing RSA TLS cert

**Confirmed fact (checked, not assumed):** `CC_Server/server/transport/tls.py`'s
`ensure_self_signed_cert()` generates a **2048-bit RSA** key
(`rsa.generate_private_key(public_exponent=65537, key_size=2048)`), self-signed,
stored at `CONFIG.tls_cert_path` / `CONFIG.tls_key_path`
(`CC_Server/server/certs/server_cert.pem` / `server_key.pem` by default,
overridable via `MS_CERTS_DIR`). **This key stays exactly as-is and keeps
serving TLS on port 8000 (`TlsUserChannel`) — it is not touched by this work
at all.**

For the new server-identity signature, **use a dedicated ECDSA P-256 keypair**,
generated once and persisted separately, matching every other key in this
project (device AK, the ECDH session-key exchange, the sensor's HMAC scheme).
Reasons this beats reusing the RSA cert:

- **Consistency.** Every other asymmetric operation anywhere in this project
  — the device↔server ECDH exchange, the AK's ECDSA quote signature — is
  P-256. RSA-2048 would be the only RSA operation anywhere, on either side.
- **TA cost.** A P-256 signature is 64 raw bytes (`r‖s`); an RSA-2048
  signature is 256 bytes, and RSA public-key verification in a TEE exercises
  much heavier bignum code than ECDSA. ECC support is already confirmed
  enabled in this OP-TEE build (`docs/ATTESTATION_DESIGN.md` §2.1); RSA
  support in the crypto backend has **not** been verified for this project
  and would need its own check before relying on it.
- **No coupling to TLS.** The TLS cert is allowed to rotate/change
  independently (e.g. if TLS mode configuration changes) without that having
  any bearing on device-pinned server identity, and vice versa — a device's
  pinned identity is a Secure-World deployment fact, not the same lifecycle
  as an HTTPS certificate that a browser happens to also see.

Both algorithms are equally supported by the GP TEE Internal Core API in
principle (`TEE_ALG_ECDSA_P256` and `TEE_ALG_RSASSA_PKCS1_V1_5_SHA256` are
both defined in this build's headers, both go through
`TEE_AsymmetricVerifyDigest()`) — this is a design-consistency and
TEE-code-weight decision, not a hard technical constraint. If a future need
ever arises to bind this to the *actual* TLS identity, revisit; for now, keep
them separate.

### Generating and storing the new key (server-side)

Mirror `ensure_self_signed_cert()`'s idempotent, generate-if-missing pattern
in `transport/tls.py`, but simpler — a bare EC private key, no certificate
object at all (see §2: no X.509 anywhere in this new path).

1. **Add a new config path**, next to `tls_cert_path`/`tls_key_path` in
   `CC_Server/server/config.py`:
   ```python
   @property
   def server_identity_key_path(self) -> str:
       """Full path to the device-facing server-identity ECDSA P-256 key."""
       return os.path.join(self.certs_dir, "server_identity_key.pem")
   ```
   (Reuses the existing `certs_dir`/`MS_CERTS_DIR` — same volume that already
   persists `server_cert.pem`/`server_key.pem` across container restarts per
   `docker-compose.yml`'s `server-certs` volume, so this new key persists the
   same way for free.)

2. **New helper to generate-or-load it**, e.g. in `crypto.py` (which already
   has `p256_generate()` for the ephemeral per-session ECDH keys — this is
   the same primitive, just persisted instead of ephemeral):
   ```python
   def ensure_server_identity_key(key_path: str) -> ec.EllipticCurvePrivateKey:
       """Load the persisted server-identity P-256 key, generating it once
       if it doesn't exist yet. Never regenerate an existing key - doing so
       would silently break every device that has already pinned the old
       public key (see docs/HANDOFF_serverAuthentication.md)."""
       if os.path.exists(key_path):
           with open(key_path, "rb") as f:
               return serialization.load_pem_private_key(f.read(), password=None)

       os.makedirs(os.path.dirname(key_path), exist_ok=True)
       key = ec.generate_private_key(ec.SECP256R1())
       with open(key_path, "wb") as f:
           f.write(
               key.private_bytes(
                   encoding=serialization.Encoding.PEM,
                   format=serialization.PrivateFormat.PKCS8,
                   encryption_algorithm=serialization.NoEncryption(),
               )
           )
       return key
   ```
   Call this once at server startup (wherever `AttestationVerifier` is
   constructed — `CC_Server/server/attestation.py`) and keep the loaded key
   object in memory for the process lifetime, same as how the TLS context is
   built once in `TlsUserChannel.__init__`.

3. **The public key to send to devices** is the raw 65-byte uncompressed
   SEC1 point — the *exact* encoding already used for `server_ecdh_pub`/
   `device_ecdh_pub` elsewhere in this protocol, so the device-side parsing
   code has nothing new to learn:
   ```python
   pub_point = key.public_key().public_bytes(
       encoding=serialization.Encoding.X962,
       format=serialization.PublicFormat.UncompressedPoint,
   )  # 65 bytes: 0x04 || X || Y
   ```

**Important operational note to flag in the eventual PR:** because this is a
TOFU-pinned key, generating a *new* one after devices have already pinned the
old one **permanently locks those devices out** (by design — that's the
point of pinning) until they're re-provisioned. Treat `server_identity_key.pem`
with the same care as the TLS key: back it up, don't delete the certs volume
casually, and don't regenerate it as part of routine maintenance.

## 4. What gets signed (domain separation)

Reuse the existing transcript concept
(`compute_transcript_hash()`, `CC_Server/server/attestation.py:230`) rather
than inventing a new one, but do **not** sign the exact same bytes the
device's own TPM quote already covers without a distinct label — reusing an
identical message format across two different protocols is a known footgun
(cross-protocol signature confusion). Mirror this project's own existing
domain-separation convention (`TA_CONFIDENTIAL_IOT_HKDF_INFO =
"CC-IOT-1 device-aead"` in `confidential_iot_ta.h`):

```
server_identity_msg = SHA256("CC-IOT-1 server-identity" || nonce || server_ecdh_pub || device_ecdh_pub)
server_sig          = ECDSA-SHA256-Sign(server_identity_priv, server_identity_msg)   # raw r‖s, 64 bytes
```

Computed server-side once both `device_ecdh_pub` and the rest of the
transcript inputs are known — i.e., **after** `attest_response` arrives, when
building `attest_result` (see §6). Use `ec.ECDSA(hashes.SHA256())` from the
`cryptography` library already used throughout `crypto.py`/`attestation.py`;
note that library returns DER-encoded `(r, s)` by default — **decode and
re-encode to raw 32-byte-`r` ‖ 32-byte-`s`** (64 bytes total) before putting
it on the wire, so the TA never has to parse DER (same "avoid parsing
complexity in the TEE" principle as skipping X.509 entirely). `cryptography`'s
`decode_dss_signature()` gives you the integers; left-pad each to 32 bytes.

## 5. New persistent object on the device (TA secure storage)

Mirror `ta_provision_sensor_secret`'s pattern exactly
(`edge_device/ta/trusted_app.c`):

- Object ID: a new fixed string, e.g. `"ciot.server.pubkey"`,
  `TEE_STORAGE_PRIVATE`, holding the 65-byte raw SEC1 point.
- **First use:** `TEE_OpenPersistentObject` returns "not found" → this is the
  TOFU bootstrap. Verify the presented signature is internally consistent
  (genuinely produced by the presented public key, over the correct
  transcript) — reject malformed/garbage signatures even on first use, don't
  skip crypto entirely, just skip the *comparison* step because there's
  nothing yet to compare against. If the signature checks out, pin the
  presented public key via `TEE_CreatePersistentObject` (no
  `TEE_DATA_FLAG_OVERWRITE`).
- **Every use after:** `TEE_OpenPersistentObject` succeeds → **compare** the
  freshly-received public key against the pinned one first. Any mismatch is
  an immediate, unconditional rejection (don't even bother verifying the
  signature against the wrong key). Only on a match, verify the signature
  using the value read from secure storage.
- Either way, on any failure: do **not** derive/store the session key.
  `sess->session_key_valid` stays `false`, `ta_handshake_complete` returns an
  error (e.g. `TEE_ERROR_SECURITY_NOT_ESTABLISHED` or `TEE_ERROR_ACCESS_DENIED`
  — pick one and document it in `confidential_iot_ta.h`, matching how other
  commands document their return-code contract there).

## 6. Protocol/message changes

Current (`CC_Server/server/device_link/attested_network.py`):
```
server -> device   {"type":"attest_challenge","nonce":"<b64>","server_ecdh_pub":"<b64>"}
device -> server   {"type":"attest_response","device_id":"...","device_ecdh_pub":"<b64>","quote":"<b64>","signature":"<b64>","pcr_values":"<text>"}
server -> device   {"type":"attest_result","ok":true,"session_ttl":3600} | {"ok":false,"error":"..."}
```

New fields (send the public key early, prove possession late — the same
two-phase shape TLS itself uses: certificate in `ServerHello`, proof of
possession in `CertificateVerify`):

- `attest_challenge` gains `"server_identity_pub":"<b64>"` — the 65-byte raw
  SEC1 point from §3, base64-encoded like every other key on the wire in
  this protocol.
- `attest_result` (the `ok:true` case) gains `"server_sig":"<b64>"` — the raw
  64-byte `r‖s` signature from §4.

Server-side (`CC_Server/server/attestation.py`, `crypto.py`):
- Load `server_identity_priv` once at startup via `ensure_server_identity_key()`
  (§3). Do **not** regenerate per-process/per-connection.
- Add the signing helper from §4 to `crypto.py`.
- Wire the two new fields into wherever `attest_challenge`/`attest_result`
  are constructed (`attested_network.py` lines ~95, ~118).

Device-side (`edge_device/host/edge_device.c`):
- `edge_attest_to_server()` parses `server_identity_pub` out of
  `attest_challenge` (alongside the existing `nonce`/`server_ecdh_pub`
  parsing — same base64-decode pattern, same 65-byte size check) and
  `server_sig` out of `attest_result` (64-byte size check).
- Both get threaded into `edge_handshake()`'s `TEEC_InvokeCommand` call.

TA-side (`edge_device/ta/trusted_app.c`, `.h`,
`edge_device/ta/include/confidential_iot_ta.h`):
- `ta_handshake_complete`'s current param shape is confirmed (read directly
  from source) to be `(MEMREF_INPUT server_ecdh_pub, MEMREF_INPUT nonce,
  NONE, NONE)` — **params[2] and params[3] are currently unused**, so the two
  new inputs (`server_identity_pub`, `server_sig`) fit into the existing
  4-parameter budget without restructuring anything else. Update the
  command's documented param shape in `confidential_iot_ta.h` accordingly.
- Insert the persistent-object pin/compare/verify logic from §5 **before**
  the existing ECDH+HKDF session-key derivation body — on failure, `goto out`
  (or equivalent) without ever touching `sess->session_key`.
- Verification itself: `TEE_AllocateOperation(&op, TEE_ALG_ECDSA_P256,
  TEE_MODE_VERIFY, 256)`, populate a `TEE_TYPE_ECDSA_PUBLIC_KEY` transient
  object from the 65-byte point's X/Y coordinates (same
  `TEE_InitRefAttribute(TEE_ATTR_ECC_PUBLIC_VALUE_X/Y, ...)` pattern
  `ta_handshake_complete` already uses to populate the peer's ECDH public
  key — copy that shape), then `TEE_AsymmetricVerifyDigest(op,
  server_identity_msg, 32, sig, 64)`. `server_identity_msg` itself is a
  second, distinctly-labeled SHA-256 digest computed in the TA the same way
  the existing transcript hash already is in
  `ta_generate_attestation_evidence` (`TEE_ALG_SHA256`, `TEE_DigestUpdate`
  over each component in order, including the `"CC-IOT-1 server-identity"`
  label bytes first).

## 7. Testing plan

1. **Positive, first use:** fresh device (no `ciot.server.pubkey` pinned yet)
   attests against the real server → handshake succeeds, key gets pinned.
2. **Positive, persistence:** reboot the device (same persistent disk, same
   pattern already used to test AK persistence in
   `docs/HANDOFF_persistentAK.md`) → the pinned key survives, second real
   server attestation still succeeds without a new TOFU bootstrap.
3. **Negative:** after a key is pinned, point the device at a *different*
   server process (different signing key, same wire protocol) → `attest_result`
   arrives with `ok:true` but a signature that doesn't verify against the
   pinned key → `ta_handshake_complete` must fail, `session_key_valid` stays
   false, no `data` messages are ever sent. This is the actual regression
   test for the vulnerability this document fixes — confirm it explicitly,
   the same way the sensor path's negative test
   (`docs/SENSOR_PATH_IMPLEMENTATION.md` §"Verification performed") proved
   the HMAC gate was real and not a stub.
4. **Negative, malformed first-use signature:** a "server" that supplies a
   `server_identity_pub` but a garbage/non-matching `server_sig` on the
   *first* attestation must also be rejected — confirm TOFU doesn't
   accidentally mean "skip verification," only "skip comparison."

## 8. Before writing code — checklist

- [ ] Decide and document the new TA error code(s) for "server identity
      verification failed" in `confidential_iot_ta.h`.
- [ ] Confirm with the user what event counts as "first genuine attestation"
      for pinning purposes in the real (non-testing) deployment flow — do
      not silently wire this to the existing self-registration path.
- [ ] Confirm `cryptography`'s DER→raw `(r,s)` re-encoding (§4) round-trips
      correctly against what the TA's `TEE_AsymmetricVerifyDigest` expects —
      OP-TEE's ECDSA verify may want raw `r‖s` or may accept/require a
      different concatenation order; check `core/pta/` or existing TA ECDSA
      usage examples (there is none in this project yet — the AK's ECDSA
      signature is verified *server-side* in Python via
      `parse_tpmt_signature_ecdsa()`, not TA-side, so this will be the first
      TA-side ECDSA verify in the codebase; treat it as unverified until
      tested against a real signature).

## 9. Files to touch

| File | Change |
|---|---|
| `CC_Server/server/config.py` | new `server_identity_key_path` property |
| `CC_Server/server/crypto.py` | `ensure_server_identity_key()`, signing helper (§3, §4) |
| `CC_Server/server/attestation.py` | load the key once, build/track `server_identity_msg`, call the signer |
| `CC_Server/server/device_link/attested_network.py` | add `server_identity_pub` to `attest_challenge`, `server_sig` to `attest_result` |
| `edge_device/host/edge_device.c` | parse the two new fields, thread into `edge_handshake()` |
| `edge_device/ta/trusted_app.c` | pin/compare/verify logic in `ta_handshake_complete`, before session-key derivation |
| `edge_device/ta/trusted_app.h` | no struct changes expected (verdict is a local decision inside `ta_handshake_complete`, not new session state) — confirm during implementation |
| `edge_device/ta/include/confidential_iot_ta.h` | update `HANDSHAKE_COMPLETE`'s documented param shape; new error code doc |
| `docs/ATTESTATION_DESIGN.md` | new subsection once implemented, cross-referencing this document (matching how `docs/SENSOR_PATH_IMPLEMENTATION.md` was cross-referenced into §2.6 and `ARCHITECTURE.md`) |
