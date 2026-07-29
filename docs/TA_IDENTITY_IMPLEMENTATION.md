# Binding attestation to the genuine TA (private signing key + sealed TA identity) — implementation notes

**Spec this follows:** `docs/HANDOFF_taIdentityBinding.md` (written before this
implementation; read it for the full rationale and the alternatives rejected —
but see §6, three of its details were wrong and are corrected here).
**Design summary:** `docs/ATTESTATION_DESIGN.md` §2.11; `docs/DESIGN.md` §9/§14.
**Status:** implemented and verified end to end — live QEMU run plus 63 server
tests (§5).

---

## 1. The gap, in one paragraph

Attestation proved the **device** (its fTPM Attestation Key) and the
**firmware** (PCR0), but not that the genuine `confidential_iot` TA did the
crypto. The AK belongs to the fTPM, not the TA, and is persisted at
`0x8101000A` with no auth value and no policy — any Normal-World process that
can open `/dev/tpmrm0` can drive it. The quote itself is assembled by the
untrusted Host (`system("tpm2_quote …")`); the TA never talks to the fTPM. So
root could **bypass the TA entirely**: generate its own ECDH keypair in Normal
World, have the real fTPM quote it under the real PCR0, complete the handshake,
and stream fabricated readings — with the server reporting
`attested=true, integrity=ok`. Separately, the TA was signed with OP-TEE's
shipped default key, whose private half is committed upstream, so a tampered TA
could simply be re-signed and would load.

## 2. Architecture of the fix

Two parts, and **the first gates the second**.

**Part A — private TA signing key.** `scripts/build.sh` exports
`TA_SIGN_KEY=$ROOT_DIR/keys/ciot_ta.pem` (RSA-4096, committed). A single export
is enough because all three consumers read it with `?=`, which defers to an
environment value:

| Consumer | Effect |
|---|---|
| OP-TEE core build | bakes `TA_PUBLIC_KEY` into `ta_pub_key.c` — the in-core load-time verifier |
| `ta_dev_kit` export | copies the key into `export-ta_arm64/keys/` |
| every TA link step | signs the `.ta` via `sign_encrypt.py` |

**Part B — sealed TA identity key.** `CMD 6 GENERATE_TA_IDENTITY` generates an
ECDSA P-256 keypair inside the TA and seals it in `ciot.ta.identity` together
with the `device_id` it is bound to. Only the 65-byte public point leaves;
`provision-device.sh` puts it in the enrollment record and the server pins it
immutably. Each session, `CMD 3` signs a labelled, device-bound digest and the
server verifies it before deriving anything.

**Why A gates B:** OP-TEE secure storage is scoped to the **TA UUID**. Without
a private signing key, root could load a malicious TA carrying the same UUID and
read the sealed identity key. Neither part is sufficient alone.

## 3. Files changed

### 3.1 Build (`scripts/`, `keys/`)

- **`keys/ciot_ta.pem`** (new, committed) + `keys/README.md`. Never reaches the
  device: `ta.mk` copies it only into the dev-kit export dir, and the Buildroot
  package installs only `*.ta` into the target.
- **`scripts/build.sh`** — exports `TA_SIGN_KEY`, fails fast if the key is
  missing, and runs the verifier below *before* writing `.build-stamp`, so a
  mismatched build is never recorded as good.
- **`scripts/verify-ta-signing.sh`** (new) — two mechanical checks, no log
  grepping: regenerate `ta_pub_key.c` from our key with the same
  `pem_to_pub_c.py` the core uses and `diff` it against what the core compiled
  in; then `sign_encrypt.py verify` the installed `.ta` against the same key.

> **Rejected: setting `TA_SIGN_KEY` in the TA's own Makefile.** `ta.mk` copies
> `default.pem` into the dev kit *only* when `TA_SIGN_KEY` is literally
> `keys/default_ta.pem`. Once the core uses our key, a clean dev kit contains
> only `ciot_ta.pem` — so the ~51 optee_test TAs and the fTPM would resolve
> `link.mk`'s default to a nonexistent file and the **image build would fail**.
> A per-TA override cannot reach them; the env var can.

### 3.2 Device — TA (`edge_device/ta/`)

- **`confidential_iot_ta.h`** — `CMD 6`; `TA_CONFIDENTIAL_IOT_TA_IDENTITY_LABEL`,
  `..._TA_SIG_SIZE`, `..._EVIDENCE_BLOCK_SIZE`, `..._TA_IDENTITY_OBJID`,
  `..._TA_IDENTITY_BLOB_SIZE`, `..._DEVICE_ID_MAX`, `..._NONCE_MAX`; rewritten
  `CMD 3` output docs. No custom error codes — the file documents stock GP
  `TEE_ERROR_*` per command, and this follows that convention.
- **`user_ta_header_defines.h`** — `TA_STACK_SIZE` 2 KB → 4 KB. The signing path
  nests a 160-byte blob, three copied buffers, a digest and an attribute array
  on top of CMD 3's existing frame. A TA stack overflow presents as an opaque
  data abort, not an error return, so this is the first thing to raise if an
  unexplained panic ever appears here.
- **`trusted_app.c`** — `ta_generate_ta_identity()` (CMD 6: the first
  `TEE_GenerateKey` on an ECDSA keypair in this codebase, sealed first-write-wins),
  `read_ta_identity_blob()` / `ta_identity_blob_to_sec1()`, and
  `sign_ta_identity()` — **the first signing operation in this project**,
  mirroring the existing `authenticate_server()` verify path with
  `TEE_MODE_SIGN` / `TEE_AsymmetricSignDigest`. `read_ec_coordinate()` is reused
  unchanged for the private scalar; it already left-zero-pads a minimal-length
  attribute encoding to 32 bytes, which `TEE_ATTR_ECC_PRIVATE_VALUE` needs
  exactly as much as X and Y do.

Sealed blob layout (`ciot.ta.identity`, fixed 160 bytes, no version byte — the
device disk is wiped on every rebuild, so there is no format to migrate):

```
[0..32)    private scalar d      [32..64)  public X     [64..96)  public Y
[96]       device_id length      [97..160) device_id, zero-padded, no NUL
```

### 3.3 Device — Host CA (`edge_device/host/`)

- **`edge_device.c` / `.h`** — `ta_handshake_init()` now receives the 96-byte
  evidence block; `edge_attest_to_server()` splits it (first 32 bytes to
  `create_attestation_report()` unchanged, last 64 to `attest_response.ta_sig`);
  new `edge_provision_ta_identity()` drives CMD 6, passing `g_device_id` — the
  same global every `attest_response` carries, so the sealed identity is
  byte-identical to the one the server looks the key up by. **Added to both
  halves of the `CONFIDENTIAL_IOT_NATIVE` split**, or the native build breaks.
- **`main.c`** — `--provision-ta-identity` mode. stdout carries the base64 key
  **and nothing else** (human text goes to stderr) because the shell captures it
  with `$(...)`.

### 3.4 Device — provisioning (`scripts/provision-device.sh`)

`print_enrollment_record()` calls `--provision-ta-identity` and adds
`ta_pub_b64` to the record. Ordering already worked: `device.conf` is written
first, the record printed last, and the edge binary reads `device.conf` for its
`device_id`.

### 3.5 Server (`CC_Server/server/`)

- **`constants.py`** — `TA_IDENTITY_PUBKEY_LEN`, `TA_IDENTITY_SIG_LEN`,
  `DEVICE_ID_MAX_LEN`.
- **`attestation.py`** — `TA_IDENTITY_LABEL`, `build_ta_identity_preimage()`,
  `compute_ta_identity_msg()`, and **check (e)** in `verify_and_derive`, placed
  after the PCR baseline and *before* key derivation so a failure leaves no
  session behind. Base64 decoding is now wrapped in `AttestationError`, which
  also fixes a pre-existing bug: `crypto.b64d` raises `binascii.Error`, which
  `attested_network.py` does not catch, so a malformed `quote` used to drop the
  TCP connection instead of returning a result.
- **`device_registry.py`** — pinned `ta_pub_b64`; a tolerant `from_dict()`;
  `validate_device_id()`; and every pinned-key comparison moved **ahead of** the
  idempotent early return.
- **`app_server.py`** — `ta_pub_b64` required, validated as an on-curve P-256
  point, and canonically re-encoded.
- **`device_link/attested_network.py`** — one line: `ta_sig_b64=msg["ta_sig"]`.

## 4. Cross-side invariants (must stay byte-identical)

| Invariant | Device side | Server side |
|---|---|---|
| Label | `TA_CONFIDENTIAL_IOT_TA_IDENTITY_LABEL`, hashed as `sizeof(label) - 1` | `TA_IDENTITY_LABEL` (20 bytes, no NUL) |
| Pre-image | `label ‖ nonce ‖ server_pub ‖ device_pub ‖ device_id` | same, in `build_ta_identity_preimage()` |
| Signature encoding | raw `r‖s`, 64 bytes, from `TEE_AsymmetricSignDigest` | `int.from_bytes(sig[:32])` / `sig[32:]` → `encode_dss_signature` |
| Public key encoding | raw 65-byte SEC1 `0x04 ‖ X ‖ Y` | `from_encoded_point(SECP256R1(), raw)` |
| `device_id` | sealed bytes, ASCII, no NUL, ≤ 63 | `validate_device_id()`, UTF-8, ≤ 63 |

`device_id` is **last** in the pre-image on purpose: it is the only
variable-length field, so putting it last keeps the encoding injective for any
field lengths without a length prefix that C and Python would both have to agree
on. `"CC-IOT-1"` is the protocol **version** prefix, not a per-device counter —
compare `"CC-IOT-1 device-aead"` and `"CC-IOT-1 server-identity"`, the same
version with different purposes.

## 5. Verification

- **Live QEMU end-to-end** — clean build with the new signing key, fresh device
  provisions and self-registers with `ta_pub_b64`, attests, and streams
  AES-256-GCM readings to the dashboard.
- **63 server tests** — `cd CC_Server && python -m pytest server/tests -q`.
- **The bypass regression** (`test_ta_identity_bypass_with_wrong_key_is_rejected`):
  fully valid quote — real AK signature, real PCR0, correct transcript — with a
  `ta_sig` from an attacker key. Rejected, and no session key is stored. Sibling
  tests cover a substituted `device_ecdh_pub`, a wrong `device_id`, a replayed
  signature from an earlier session, and the same bypass driven through the real
  connection state machine.
- **Those tests were mutation-tested:** neutering check (e) makes all four fail,
  so they are load-bearing rather than incidentally passing.
- **C/Python byte parity is proven, not assumed.** A standalone C program
  replicating the TA's exact digest sequence and blob offsets reproduces the
  known-answer digest asserted in `test_ta_identity_preimage_is_byte_exact`
  (`b34347ceed037083e6678f4ca1ee3306388e8da501cae328cf60c59fac294c96`).

## 6. Three corrections to the handoff spec

Recorded because each would have cost real debugging time:

1. **§4e double-hashed.** It passed the digest to
   `ta_pub.verify(…, ec.ECDSA(hashes.SHA256()))`. `cryptography` hashes whatever
   message it is handed, and the TA signs `SHA-256(pre_image)` via
   `TEE_AsymmetricSignDigest` — so that computes `SHA-256(SHA-256(pre_image))`
   and rejects **every honest device**. Fail-closed, so not a hole, but a total
   outage that would present as "the TA's ECDSA sign is broken". The server
   verifies over the **pre-image**;
   `test_ta_sig_must_be_verified_over_the_preimage_not_the_digest` locks it.
2. **§4d's "extra output param" does not exist.** CMD 3 already used all four GP
   slots. Resolved by sealing `device_id` (no new input) and widening
   `params[3]` to 96 bytes.
3. **Not in the spec at all:** CMD 3 digested straight out of Host-shared
   memory. Harmless while that hash only went back to the Host — but once the TA
   *signs* those bytes, a root Host racing from another thread can overwrite
   `params[0]` after the TA writes `0x04 ‖ X ‖ Y` and obtain a genuine TA
   signature over an attacker-held ECDH key. **That is Gap 2 reopened by its own
   fix.** The TA now copies `nonce`, `server_pub` and `device_pub` into local
   buffers and hashes only those — matching what `authenticate_server()` already
   did.

## 7. Operational consequences

- **PCR0 changes**, because the core's baked-in public key changes. Every
  `expected_pcr` baseline is stale *and* no pre-existing record has a
  `ta_pub_b64`. Full runbook in `docs/RESET_DEVICE_REGISTRY.md`; the short
  version is build → `reset-device-registry.sh --all` → **restart CC_Server** →
  `run-project.sh`, in that order.
- **No backfill.** A pre-binding record re-registering with a TA key gets 409,
  deliberately — allowing it would reopen the trust-on-first-use window on
  already-enrolled devices.
- **Renaming a device now requires wiping its secure storage**, since the
  `device_id` is sealed with the key. It surfaces as `TEE_ERROR_ACCESS_CONFLICT`
  at provisioning time with an actionable message, not as a mystery attestation
  failure later.
- **`TEE_AsymmetricSignDigest` panics** on every error except `SHORT_BUFFER`,
  unlike the verify counterpart. A corrupt sealed key kills the TA instance
  (`TEEC_ERROR_TARGET_DEAD` + `TA panicked` on the secure console) rather than
  returning an error. The blob is length- and shape-checked, an all-zero scalar
  is rejected, and the output buffer is always exactly 64 bytes so
  `SHORT_BUFFER` cannot occur — but a non-zero scalar ≥ the curve order would
  still panic, which the GP API gives a TA no way to detect. Its only realistic
  cause is a corrupt store, whose remedy is a disk wipe.
- **Stale `optee_test` TAs.** On an incremental build the ~51 optee_test TAs keep
  their old default-key signatures and will fail to load until
  `rm -rf .optee-workspace/out-br/{build/optee_test_ext-1.0,per-package/optee_test_ext}`.
  Cosmetic — nothing in this project's flow uses them, and it is deliberately not
  wired into `build-project.sh` because it costs minutes on every build.
