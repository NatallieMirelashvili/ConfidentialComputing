# Handoff: Binding Attestation to the Genuine TA (private TA signing key + TA-identity key)

Status: **NOT IMPLEMENTED — this is the spec for the next instance.** It closes
two gaps found by a code scan on 2026-07-25 (device side, server side, and the
OP-TEE TA-signing/load path were all read directly — see §1 for the grounding).
Do **not** edit `docs/DESIGN.md` for this yet; that was explicitly deferred by
the user. This document is the mirror image of `docs/HANDOFF_serverAuthentication.md`
— that one made the **server** prove its identity to the **device**; this one
makes the **TA** prove *its* identity to the **server**. Reuse that document's
patterns wherever possible; they are already shipped and tested.

Base paths (same convention as `HANDOFF_serverAuthentication.md`):
- Device TA/host paths are relative to `project/optee_examples/confidential_iot/`.
- Server paths are relative to repo root (`CC_Server/server/...`).
- OP-TEE core paths are under `.optee-workspace/optee_os/` (git-ignored, regenerated).

---

## 0. TL;DR — what this fixes and the shape of the fix

**The attestation today proves the *device* (AK) and the *firmware* (PCR0), but
NOT that the genuine `confidential_iot` TA is the thing that ran the crypto.**
Two independent gaps make "the TA that encrypted the data is original"
unprovable to the server:

- **Gap 1 — the TA is signed with OP-TEE's public *default* dev key.** A root
  attacker can re-sign a tampered TA (the private half of that key ships with
  OP-TEE) and it will load and verify.
- **Gap 2 — the attestation is not bound to the TA.** The AK is a bare fTPM
  handle usable by any Normal-World process, and the quote is built by the
  untrusted Host. A root attacker can *bypass the TA entirely* — run its own
  ECDH+AES in Normal World, get the fTPM to quote its own ECDH key (PCR0 real,
  AK real), complete the handshake itself, and feed the server fabricated data.
  The server sees `attested=true, integrity=ok`.

**The fix has two parts, both required — Part A is a prerequisite for Part B:**

- **Part A (Gap 1): sign the TA with a project-private key** (`TA_SIGN_KEY`). Now
  a tampered TA cannot load, because root cannot forge its signature.
- **Part B (Gap 2): give the genuine TA its own sealed identity keypair**,
  enroll its public half at registration, have the TA **sign its ephemeral ECDH
  public key each session**, and have the server **verify that signature**
  against the enrolled TA key before deriving the session key. Now the session
  key can only belong to the genuine TA.

Why A gates B: OP-TEE secure storage is scoped to the **TA UUID**. Without a
private signing key, root could load a *malicious TA with the same UUID* and
read the sealed identity key. Part A is what makes the sealed key in Part B
trustworthy. Ship them together.

End state — three independent legs, all must pass server-side:
**AK → correct device · PCR0 → genuine firmware · TA signature → genuine TA.**

---

## 1. The two gaps, grounded (read directly on 2026-07-25 — not assumed)

### Gap 1 — default TA signing key
- The TA Makefile (`edge_device/ta/Makefile`, and the identical top-level
  `ta/Makefile`) sets only `CFG_TEE_TA_LOG_LEVEL`, `BINARY =
  7d9f6d20-5f11-4d0c-9a17-61c9c91c0001`, and includes `ta_dev_kit.mk`. **No
  `TA_SIGN_KEY` / `TA_PUBLIC_KEY` override anywhere** in `scripts/`, `project/`,
  `docker/`, `manifests/`, or the generated build makefiles.
- So the dev-kit default applies: `.optee-workspace/optee_os/mk/config.mk:248`
  → `TA_SIGN_KEY ?= keys/default_ta.pem`, `TA_PUBLIC_KEY ?= $(TA_SIGN_KEY)`.
  `keys/default_ta.pem` → symlink to `keys/default.pem` = a **4096-bit RSA key
  whose private half is git-committed in upstream OP-TEE**. Anyone with the
  OP-TEE tree has it.
- Load-time verify (works, but only as strong as the key's secrecy):
  `shdr_verify_signature()` at `.optee-workspace/optee_os/core/crypto/signed_hdr.c:70`,
  called from `.optee-workspace/optee_os/core/kernel/ree_fs_ta.c:278`. It uses
  the RSA public key **compiled into the core** (`ta_pub_key_modulus/exponent`,
  generated from `TA_PUBLIC_KEY` in `core/sub.mk:10-14`). The core is measured
  into PCR0, so the *verifier* is trustworthy — the problem is purely that the
  *signing* key is public.

### Gap 2 — attestation not bound to the TA
- The quote is produced by the **untrusted Host**, not the TA:
  `attestation/attestation.c:89-92` shells out `system("tpm2_quote -c
  0x8101000A -l sha256:0 -q <transcript_hash> ...")`. The `confidential_iot` TA
  never talks to the fTPM.
- The **AK has no auth value and no policy**: `scripts/provision-device.sh:31`
  (`AK_HANDLE=0x8101000A`) and `:73-76` (`tpm2_createak` with no `-p`,
  `tpm2_evictcontrol -C o`). Any Normal-World process that opens `/dev/tpmrm0`
  can drive it.
- The quote's only device-supplied bytes are the qualifying data =
  `SHA-256(nonce ‖ server_ecdh_pub ‖ device_ecdh_pub)`, computed in the TA at
  `edge_device/ta/trusted_app.c:277-298`, but **passed to `tpm2_quote` by the
  Host as an opaque blob** — nothing forces `device_ecdh_pub` to have come from
  the TA.
- Server-side (`CC_Server/server/attestation.py:143-223`,
  `AttestationVerifier.verify_and_derive`) checks: device registered, challenge
  fresh, PCR digest matches the signed quote (`:175-179`), **AK ECDSA signature**
  (`:181-189`), transcript/nonce (`:191-197`), and **PCR0 baseline** (`:199-202`)
  — then derives the session key (`:206-207`). **There is no check of any TA
  identity anywhere.** `DeviceRecord` (`CC_Server/server/device_registry.py:44-63`)
  holds only `device_id`, `ak_pub_pem`, `expected_pcr`, `pcr_bank`, `created_at`.

**Net:** with root in Normal World, a genuine `.ta` can be tampered (Gap 1) or
simply bypassed (Gap 2) with no effect on PCR0 (the TA is not measured) and no
effect on the AK (it belongs to the fTPM, not the TA). Both close only with the
two-part fix below.

---

## 2. Agreed design (from the discussion — do not re-litigate)

- **Keep the AK + PCR0 checks exactly as they are.** This work *adds* a third
  leg (TA identity); it does not replace measured boot or the AK quote. See §7
  for why we keep the AK and why we are *not* re-architecting to bind the AK
  itself to the TA.
- **TA identity key = ECDSA P-256.** Same reasoning as the server-identity key
  decision (`HANDOFF_serverAuthentication.md` §3): every other asymmetric op in
  this project is P-256, a P-256 signature is 64 raw bytes (`r‖s`), and ECC is
  confirmed enabled in this OP-TEE build. Do not introduce a second RSA path.
- **The TA identity private key is generated *inside* the TA and sealed in
  OP-TEE secure storage — it never leaves the TEE.** Only the public half is
  ever exported/enrolled. (This is the property root cannot defeat: it cannot
  read secure storage.)
- **The TA *signs*; the server *verifies*.** Mirror of server-auth, reversed.
  The verification decision lives server-side in `verify_and_derive`, never in
  the Host.
- **TOFU, then immutable — pin the TA key at registration alongside the AK.**
  The registration flow is already TOFU for `ak_pub` + `expected_pcr`; add
  `ta_pub` to the same immutable-on-first-use record. A later mismatch is a hard
  reject, exactly like the existing `DeviceKeyMismatch` on `ak_pub`
  (`device_registry.py:113`).
- **Part A gates Part B** (see §0). Ship both or neither — a private signing key
  alone leaves Gap 2 open; the TA identity key alone is readable by a malicious
  same-UUID TA without the private signing key.
- **Domain separation.** The TA identity signature must use a *distinct label*
  and must **not** sign the exact bytes the fTPM quote already covers
  (cross-protocol signature confusion — same footgun called out in
  `HANDOFF_serverAuthentication.md` §4). Use label `"CC-IOT-1 ta-identity"`,
  matching the project's convention (`"CC-IOT-1 device-aead"`,
  `"CC-IOT-1 server-identity"`).

---

## 3. Part A — private TA signing key (Gap 1)

**Goal:** replace `keys/default_ta.pem` with a project-private key so a tampered
TA cannot be re-signed by an attacker.

1. **Generate the key** (RSA; OP-TEE requires ≥2048-bit — the weak-key guard is
   `signed_hdr.c:90`). A 3072- or 4096-bit RSA key mirrors the upstream default
   size. Example: `openssl genrsa -out ciot_ta.pem 4096`.

2. **Wire `TA_SIGN_KEY` into the build so BOTH consumers see the same key:**
   - the **OP-TEE core** build (which bakes `TA_PUBLIC_KEY = $(TA_SIGN_KEY)`
     into `ta_pub_key.c` → the in-core verifier), and
   - the **TA link step** (`ta_dev_kit`'s `link.mk:5-6,122-123` signs the `.ta`
     with `TA_SIGN_KEY`).
   The cleanest place is where the project already threads OP-TEE flags —
   `scripts/build.sh` / `scripts/sync-project.sh` (they already pass many CFG_*
   flags). Set `TA_SIGN_KEY=<abs path>` as a make/env variable that reaches the
   `optee_os` build **and** the `optee_examples` TA build. **Verify it reaches
   both** (grep the build logs for the key path in both the core `ta_pub_key`
   gen step and the TA `sign_encrypt.py` invocation) — a mismatch (core baked
   with key X, TA signed with key Y) silently fails to load every TA.

3. **DECISION FOR THE USER — where the private signing key lives.** Options:
   - (a) commit it under a repo `keys/` dir (simple; acceptable for this
     project *because the repo is not on the device* — the whole point is only
     that it is not the universally-known upstream key), or
   - (b) keep it out-of-tree and inject the path at build time (stronger; the
     private key never enters version control).
   Either way it must **never** ship inside the firmware image or the rootfs.
   Recommend (a) for this course project unless the user wants (b). Flag it;
   don't assume.

4. **This is a firmware/TA change, so it lands in PCR0 indirectly** — the
   in-core public key changes, so the OP-TEE core image changes, so PCR0
   changes. That means every already-registered device's `expected_pcr` becomes
   stale and must be re-provisioned after this change (a full
   rebuild/re-register cycle — same reset dance as
   `docs/RESET_DEVICE_REGISTRY.md`). Note this in the PR.

**Verification for Part A alone:** tamper one byte of the built `.ta` on the
rootfs → OP-TEE core must refuse to load it (`shdr_verify_signature` fails).
Rebuild cleanly → loads. Confirm the loaded TA is signed with the new key
(inspect the `.ta` header / build log), not `default_ta.pem`.

---

## 4. Part B — TA identity key + session binding (Gap 2)

### 4a. New sealed object in the TA
Mirror `ta_provision_sensor_secret` / the `"ciot.server.pubkey"` pin exactly
(`edge_device/ta/trusted_app.c`):
- Object ID: new fixed string `"ciot.ta.identity"`, `TEE_STORAGE_PRIVATE`,
  holding the TA's **ECDSA P-256 private key** (store the key material in
  whatever form is convenient to reload into a `TEE_TYPE_ECDSA_KEYPAIR`
  transient object — e.g. the private scalar `d` plus public `X`/`Y`, or use
  `TEE_PopulateTransientObject` round-tripping; keep it simple and internal).

### 4b. Key generation + export (one-time, at provisioning)
- Add a TA command, e.g. `CMD 6 GENERATE_TA_IDENTITY` (next free id after the
  existing `PROVISION_SENSOR_SECRET`; the command enum is in
  `edge_device/ta/include/confidential_iot_ta.h`, dispatched at
  `trusted_app.c:842-858`).
- On first call: if `"ciot.ta.identity"` does not exist, `TEE_GenerateKey`
  (ECDSA P-256) → seal the private key (`TEE_CreatePersistentObject`, no
  overwrite flag) → return the 65-byte uncompressed SEC1 public point
  (`0x04 ‖ X ‖ Y`, the same encoding used for every other key on the wire).
  Idempotent: if it already exists, just return the stored public point.
- Host side (`edge_device/host/edge_device.c`): a small path that invokes this
  command during provisioning and hands the pubkey to registration (§5).
- Provisioning (`scripts/provision-device.sh`): call it alongside AK creation
  (`:73-76`) so `ta_pub` is available when the device self-registers (`:53-58`).

### 4c. What gets signed (domain-separated, per-session, fresh)
```
ta_identity_msg = SHA-256("CC-IOT-1 ta-identity" ‖ nonce ‖ server_ecdh_pub ‖ device_ecdh_pub)
ta_sig          = ECDSA-SHA256-Sign(ta_identity_priv, ta_identity_msg)   # raw r‖s, 64 bytes
```
- Binding `device_ecdh_pub` is the crux: it forces the session's ECDH key to be
  the genuine TA's (root cannot sign a substitute key). Binding `nonce` gives
  freshness (no replay). Using a distinct label keeps it disjoint from the
  fTPM quote's qualifying data over the same transcript.

### 4d. Where the TA signs
- The TA already receives `nonce` + `server_ecdh_pub` and computes the
  transcript hash in `CMD 3 GENERATE_ATTESTATION_EVIDENCE`
  (`trusted_app.c:249-298`), where it also generates the ephemeral ECDH keypair.
  **Add the identity signature here**: after generating `device_ecdh_pub`,
  compute `ta_identity_msg` (second, distinctly-labeled digest, same
  `TEE_ALG_SHA256` / `TEE_DigestUpdate` pattern already there), load the sealed
  identity key, `TEE_AllocateOperation(&op, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
  256)`, `TEE_AsymmetricSignDigest(...)` → return `ta_sig` (64 bytes) as an
  extra output param alongside the existing ECDH pub + transcript outputs.
- Update `CMD 3`'s documented param shape in `confidential_iot_ta.h`.

### 4e. Server verification (new check in `verify_and_derive`)
- `CC_Server/server/device_registry.py`: add `ta_pub_pem` to `DeviceRecord`
  (`:44-63`), populate it from registration (§5), and treat it as immutable —
  extend the `DeviceKeyMismatch` logic (`:113`) so a later different `ta_pub`
  also rejects (HTTP 409, like `ak_pub`).
- `CC_Server/server/attestation.py`, inside `verify_and_derive` **before** the
  ECDH+HKDF derivation (`:206-207`): recompute `ta_identity_msg`
  (`SHA-256("CC-IOT-1 ta-identity" ‖ nonce ‖ server_pub ‖ device_ecdh_pub)`
  — mirror `compute_transcript_hash` at `:266-269` with the new label), load
  `record.ta_pub_pem`, and verify `ta_sig`. The AK-quote verify at `:181-189`
  is the exact template: parse the raw `r‖s` → `encode_dss_signature(r, s)` →
  `ta_pub.verify(der_sig, ta_identity_msg, ec.ECDSA(hashes.SHA256()))`. On
  failure raise `AttestationError("TA identity verification failed")` and do
  **not** derive/store the session key.

---

## 5. Protocol / message changes

Registration (`POST /api/devices/register`, `CC_Server/server/app_server.py:74-117`):
- Request body gains `"ta_pub_pem_b64"` (or the raw 65-byte SEC1 point,
  base64) alongside the existing `device_id`, `ak_pub_pem_b64`, `expected_pcr`,
  `pcr_bank`. Pin it into the `DeviceRecord`.

Attestation (`CC_Server/server/device_link/attested_network.py`):
```
device -> server  attest_response  += "ta_sig":"<b64>"     # raw 64-byte r‖s from CMD 3
```
- No change needed to `attest_challenge` (the TA already has `nonce` +
  `server_ecdh_pub` from it). `ta_sig` rides along in `attest_response` next to
  `quote` / `signature` / `pcr_values` (built in `edge_device.c:466-476`).

---

## 6. New TA-side primitives required (what's genuinely new here)

The server-auth work already added TA-side ECDSA **verify**
(`TEE_ALG_ECDSA_P256`, `TEE_MODE_VERIFY`), so ECC verify is proven in the
codebase. **New for this work:**
- **ECDSA P-256 key generation in the TA** (`TEE_GenerateKey` on a
  `TEE_TYPE_ECDSA_KEYPAIR` transient object).
- **Persisting/reloading a keypair** in secure storage (copy the sensor-secret /
  server-pubkey storage pattern; the object just holds keypair material now).
- **TA-side ECDSA sign** (`TEE_MODE_SIGN`, `TEE_AsymmetricSignDigest`) — first
  signing (not verifying) operation in a TA in this project.

Treat all three as **unverified until exercised against a real signature**:
confirm this OP-TEE build supports ECDSA keygen + sign (verify alone being
present does not guarantee sign/keygen are enabled), and confirm the TEE emits
raw `r‖s` (64 bytes) in the order `cryptography.decode_dss_signature` expects —
the same round-trip caveat as `HANDOFF_serverAuthentication.md` §8, just in the
opposite direction (TA signs, Python verifies).

---

## 7. Why keep the AK+PCR0, and why not just bind the AK to the TA

- **Keep AK+PCR0:** PCR0 (via the AK quote) proves the *firmware/TEE the TA runs
  on* is genuine and un-tampered — a property the TA identity signature does not
  give you on its own (a sealed key proves a genuine TEE unsealed it, but not
  *which firmware version/config* booted; PCR0 catches firmware tampering that
  doesn't break secure storage). The AK is also the device's registration
  identity. So the three legs are complementary; do not drop any.
- **Why not re-architect so only the TA can use the fTPM AK** (e.g. a TPM auth
  policy, or routing all fTPM access through the TA): that is a much larger
  change — today the Host drives `tpm2-tools` and the TA never touches the fTPM.
  The sealed-TA-identity-key approach closes Gap 2 with a localized change that
  fits the existing ECDH handshake, and is the recommended path. Note the
  alternative exists if the user ever wants the AK itself bound.

---

## 8. Testing plan

1. **Part A — tamper rejection:** flip a byte in the built `.ta` → core refuses
   to load (`shdr_verify_signature` fail in the boot/TA log). Clean rebuild →
   loads. Confirm the `.ta` is signed with the new key, not `default_ta.pem`.
2. **Part B positive, first use:** fresh device generates its identity key,
   registers with `ta_pub`, attests → server verifies `ta_sig`, handshake
   succeeds, session key derived, AES-256-GCM sensor data flows to the dashboard
   (full E2E, same as the current green path).
3. **Part B persistence:** reboot (same persistent `/var/lib/tee` disk as the
   AK-persistence test, `docs/HANDOFF_persistentAK.md`) → `"ciot.ta.identity"`
   survives, re-attestation still succeeds without regenerating the key.
4. **Part B negative — the bypass regression (this is THE test for Gap 2):**
   simulate a compromised Host that skips the TA — generate an ECDH keypair in
   plain Normal World, quote it with the real AK (real PCR0), send a valid quote
   but **no valid `ta_sig`** (or a `ta_sig` from the wrong key). Server must
   reject at the new TA-identity check; no session key, no `data` accepted.
5. **Part B negative — key immutability:** re-register the same `device_id` with
   a different `ta_pub` → HTTP 409 (`DeviceKeyMismatch`), like the `ak_pub` case.

---

## 9. Before writing code — checklist

- [ ] **DECISION:** where the Part A private signing key lives (repo `keys/` vs
      out-of-tree) — §3.3. Confirm with the user.
- [ ] Confirm `TA_SIGN_KEY` reaches **both** the core (`ta_pub_key` gen) and the
      TA (`sign_encrypt.py`) builds — §3.2.
- [ ] Confirm this OP-TEE build supports ECDSA **keygen + sign** in a TA (verify
      is already used; sign/keygen are new) — §6.
- [ ] Confirm the TA→server raw `r‖s` encoding round-trips against
      `cryptography`'s `encode_dss_signature` server-side — §4e, §6.
- [ ] Add the new TA error code(s) ("TA identity op failed" /
      "GENERATE_TA_IDENTITY failed") to `confidential_iot_ta.h`, matching the
      return-code documentation convention there.
- [ ] Plan the re-provision cycle: Part A changes PCR0, so all existing
      `expected_pcr` baselines are stale — §3.4, `docs/RESET_DEVICE_REGISTRY.md`.
- [ ] Only after it's implemented and E2E-verified: update `docs/DESIGN.md`
      (§8 measured boot / §14 chain of trust / §18 limitations) and
      `docs/ATTESTATION_DESIGN.md` to add the TA-identity leg and to reframe the
      "TA integrity rests on signed loading with the default key" caveat.

---

## 10. Files to touch

| File | Change |
|---|---|
| `scripts/build.sh` / `scripts/sync-project.sh` | thread `TA_SIGN_KEY=<key>` into the OP-TEE core **and** TA builds (Part A) |
| `keys/` (new, or out-of-tree) | the project-private TA signing key (Part A, §3.3) |
| `edge_device/ta/include/confidential_iot_ta.h` | new `CMD 6 GENERATE_TA_IDENTITY`; updated `CMD 3` param shape; new error codes; `"CC-IOT-1 ta-identity"` label |
| `edge_device/ta/trusted_app.c` | key gen + seal `"ciot.ta.identity"` (CMD 6); ECDSA sign of `ta_identity_msg` in CMD 3 |
| `edge_device/host/edge_device.c` | invoke CMD 6 at provisioning; carry `ta_pub` to registration; add `ta_sig` to `attest_response` |
| `scripts/provision-device.sh` | generate/export the TA identity pubkey; include it in the register call |
| `CC_Server/server/app_server.py` | accept `ta_pub_pem_b64` in `POST /api/devices/register` |
| `CC_Server/server/device_registry.py` | add `ta_pub_pem` to `DeviceRecord`; immutable/`DeviceKeyMismatch` on change |
| `CC_Server/server/device_link/attested_network.py` | parse `ta_sig` out of `attest_response`, pass to verifier |
| `CC_Server/server/attestation.py` | recompute `ta_identity_msg`; verify `ta_sig` against `record.ta_pub_pem` before session-key derivation |
| `docs/DESIGN.md`, `docs/ATTESTATION_DESIGN.md` | **deferred** — only after implemented + verified (§9) |
