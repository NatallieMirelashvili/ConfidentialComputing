# ciot_rogue_ta — a TA signed with the wrong key, on purpose

Test fixture for `optee_example_confidential_iot_tests` test 1. Not part of the
product; nothing in the normal device flow ever opens it.

## What it is

A minimal, inert TA (`ta/rogue_ta.c` returns `TEE_ERROR_NOT_SUPPORTED` for every
command) signed with **`ta/attacker_ta.pem`** instead of the project key
`keys/ciot_ta.pem`. That single `override TA_SIGN_KEY` line in `ta/Makefile` is the
only thing that differs from its sibling `ciot_probe_ta`, which is signed normally
and loads fine — so when test 1 shows one loading and the other refused, the
signing key is demonstrably the reason.

It models one specific attacker: root in Normal World, who can write anything into
`/lib/optee_armtz` and sign it with a key of their own, but cannot sign with the
project key that OP-TEE's core verifies against (and that is measured into PCR0).

Test 1 uses it twice:

1. opened under its own UUID `…-0003` — must be refused;
2. copied over `/lib/optee_armtz/7d9f6d20-…-0001.ta`, then the **genuine** UUID is
   opened — must also be refused, because the core verifies the signature before it
   ever compares the UUID in the header. That is the UUID-mimicry case.

## `attacker_ta.pem` is deliberately committed and deliberately worthless

It is an RSA-4096 private key with **no security value whatsoever** — it is public,
it is in the repo, and that is exactly what makes it a faithful stand-in for a key
an attacker generated themselves. Do not use it for anything else, and never point
`TA_SIGN_KEY` at it globally.

Regenerate it any time; nothing pins its fingerprint:

```bash
openssl genrsa -out project/optee_examples/ciot_rogue_ta/ta/attacker_ta.pem 4096
```

## Why a separate UUID

The Buildroot hook installs every `*/ta/out/*.ta` into `/lib/optee_armtz`, and the
built filename *is* the UUID (`user-ta-uuid := $(BINARY)` in `ta_dev_kit.mk`). A
fixture built directly at `…-0001` would therefore overwrite the real TA at image
build time. Giving it `…-0003` keeps the shipped image sane; the substitution that
the test actually needs is done at runtime, in RAM, with a backup and a restore —
and the rootfs is an initramfs, so a reboot undoes it regardless.

## Verifying the fixture is what it claims to be

```bash
cd .optee-workspace
python3 optee_os/scripts/sign_encrypt.py verify \
  --uuid 7d9f6d20-5f11-4d0c-9a17-61c9c91c0003 \
  --key ../project/optee_examples/ciot_rogue_ta/ta/attacker_ta.pem \
  --in out-br/target/lib/optee_armtz/7d9f6d20-5f11-4d0c-9a17-61c9c91c0003.ta   # passes

python3 optee_os/scripts/sign_encrypt.py verify \
  --uuid 7d9f6d20-5f11-4d0c-9a17-61c9c91c0003 \
  --key ../keys/ciot_ta.pem \
  --in out-br/target/lib/optee_armtz/7d9f6d20-5f11-4d0c-9a17-61c9c91c0003.ta   # must FAIL
```

If the second command *passes*, the override did not take effect and test 1 is
vacuous — the rogue would load like any other TA. `scripts/verify-ta-signing.sh`
performs the equivalent check for the genuine TA.
