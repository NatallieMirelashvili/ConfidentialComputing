# Project TA signing key

`ciot_ta.pem` is this project's **private** RSA-4096 Trusted Application signing key.
It replaces OP-TEE's shipped default (`keys/default_ta.pem` -> `keys/default.pem`),
whose private half is committed in the upstream OP-TEE tree and is therefore known to
anyone who has ever cloned it.

## Why it exists

OP-TEE verifies every TA's signature at load time (`shdr_verify_signature()`,
`optee_os/core/crypto/signed_hdr.c:70`, called from `core/kernel/ree_fs_ta.c:278`) using
the RSA public key compiled into the core. That verifier is measured into PCR0, so it is
trustworthy — but with the upstream default key, an attacker with root in Normal World can
simply **re-sign a tampered TA** and it loads cleanly.

That same weakness gates a second one: OP-TEE secure storage is scoped to the TA UUID, so
without a private signing key an attacker could load a malicious TA carrying the *same*
UUID and read the sealed `ciot.ta.identity` key that the TA-identity attestation leg
depends on.

## How it is wired in

`scripts/build.sh` exports a single variable:

```bash
export TA_SIGN_KEY="$ROOT_DIR/keys/ciot_ta.pem"
```

Three separate builds have to agree on this key, and all three read it with `?=`, which
defers to an environment-origin value:

| Consumer | Where |
|---|---|
| OP-TEE core — bakes `TA_PUBLIC_KEY` into `ta_pub_key.c`, the in-core verifier | `optee_os/mk/config.mk:248-249`, `optee_os/core/sub.mk:10-14` |
| TA dev-kit export — copies the key into `export-ta_arm64/keys/` | `optee_os/ta/ta.mk:203-211` |
| Every TA link step — signs the `.ta` via `sign_encrypt.py` | `optee_os/ta/link.mk:5-6,120-123` |

One export covers all three, plus the fTPM and the optee_test TAs. Setting the key in an
individual TA's Makefile would **not** work: `ta.mk` only copies `default.pem` into the dev
kit when `TA_SIGN_KEY` is literally `keys/default_ta.pem`, so once the core uses our key,
every *other* TA would resolve `link.mk`'s default to a file that no longer exists and the
image build would fail.

## Verification

`scripts/verify-ta-signing.sh` runs automatically at the end of `scripts/build.sh` and
checks both halves mechanically:

1. regenerates `ta_pub_key.c` from this key and diffs it against what the core compiled in;
2. verifies the installed `.ta`'s signature against this key.

This matters because a mismatch — core baked with key X, TA signed with key Y — is a
**silent build success** in which every TA then fails to load at runtime.

## Caveats

- A bare `make` inside `.optee-workspace/build` (bypassing `scripts/build.sh`) produces a
  full **default-key** build. That is self-consistent and boots fine; it just silently
  lacks this protection. Build through `scripts/build.sh`.
- Changing this key changes the OP-TEE core image, therefore **PCR0**, therefore every
  registered device's `expected_pcr`. Every device has to be enrolled again afterwards:
  `scripts/reset-device-registry.sh --all`, restart the Management Server, then re-run
  `scripts/register-device.sh` per device.
- The private key must never reach the firmware image or the rootfs. It does not today:
  `ta.mk` copies it only into the dev-kit export directory, and the Buildroot package
  installs only `*.ta` files into the target.
- It is committed deliberately. The repo is not on the device, and the security property
  being bought is only "not the universally-known upstream key". If you need a stronger
  posture, move it out of tree and point `TA_SIGN_KEY` at the external path instead.

## Rotation

```bash
openssl genrsa -out keys/ciot_ta.pem 4096   # OP-TEE requires >= 2048 (signed_hdr.c:90)
chmod 600 keys/ciot_ta.pem
scripts/build.sh                            # rebuilds core + all TAs together
```

Then re-provision every device: PCR0 has changed, so all baselines are stale.
