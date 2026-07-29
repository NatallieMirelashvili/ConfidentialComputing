# Resetting device registry entries

Quick reference for `scripts/reset-device-registry.sh`. For *why* this script exists (the
`DeviceKeyMismatch` behavior it's working around), see
[`SELF_REGISTRATION_IMPLEMENTATION.md` §6](SELF_REGISTRATION_IMPLEMENTATION.md#6-the-flip-side-re-provisioning-a-device-for-a-fresh-device-test).

## When you need this

You wiped a QEMU instance's persisted-AK disk to force a brand-new Attestation Key —

```bash
rm -f .device-state/iot-edge-10.img
```

— and the device now sits printing `attestation/session failed; retrying` forever. That's
`CC_Server/server/device_registry.json` still holding that `device_id`'s *old* key: normal
registration refuses to overwrite an existing entry with a different key (by design, §2.2.b), so
the fresh device's self-registration POST gets rejected and it never actually enrolls.

## The other case: a rebuild that changed PCR0

Adopting the project-private TA signing key ([`keys/README.md`](../keys/README.md),
Part A of [`HANDOFF_taIdentityBinding.md`](HANDOFF_taIdentityBinding.md)) bakes a new
public key into the OP-TEE core, which changes the core image, which changes **PCR0**.
Every enrolled device's `expected_pcr` baseline is therefore stale — and no pre-existing
record has the `ta_pub_b64` that attestation now requires. Both mean the same thing:
**every device must be dropped and re-provisioned.**

The server tells you when this has happened. At startup it logs, per affected device:

```
device 'iot-edge-01' was enrolled before TA-identity binding and has no ta_pub_b64,
so it can no longer attest. Run 'scripts/reset-device-registry.sh iot-edge-01', ...
```

and any attestation attempt is rejected with `device has no enrolled TA identity key`.
Note this is *not* fixed by re-registering: a backfill would reopen the trust-on-first-use
window that binding closes, so `register()` answers a changed `ta_pub_b64` with HTTP 409.
Dropping the record is the only path.

Run, in this order:

```bash
scripts/build.sh                            # 1. new signing key; .build-stamp changes
scripts/reset-device-registry.sh --list     # 2. check, then drop everything
scripts/reset-device-registry.sh --all
#                                             3. RESTART CC_Server (see below)
scripts/run-project.sh                      # 4. re-provision + self-register
```

The order matters. Reset before the restart, and restart before the device retries —
otherwise the device self-registers against the stale in-memory registry, gets a 409, and
loops on `attestation/session failed; retrying`, which is the same symptom as above with a
different cause.

Two traps:

- **Do step 2 manually with `--all`.** `scripts/run-project.sh` does wipe the disk and call
  this script when it sees a new `.build-stamp`, but only for the single instance it is
  launching, and only when a previous stamp was recorded. Multi-device setups and the
  first run after adopting this change are not covered.
- **`device_registry.json` is git-ignored**, so it survives every `git pull`. Whoever
  updates without reading this will hit the startup warning above.

## Commands

```bash
scripts/reset-device-registry.sh --list                 # see what's currently enrolled
scripts/reset-device-registry.sh iot-edge-10             # drop one stale entry
scripts/reset-device-registry.sh iot-edge-10 iot-edge-11 # drop several at once
scripts/reset-device-registry.sh --all                   # wipe the whole registry
```

## What it does

Thin wrapper around `python -m server.reset_registry` (`CC_Server/server/reset_registry.py`),
which uses `DeviceRegistry.remove()` / `.clear()` (`CC_Server/server/device_registry.py`) — the
same atomic-write-plus-`chmod 0600` path `register()` itself uses, not a hand-edited JSON file.
Honors `MS_DEVICE_REGISTRY_PATH` if you've set it, exactly like the server does.

## After running it

`DeviceRegistry` loads `device_registry.json` once at process startup and never reloads. If
CC_Server is already running, **restart it** — otherwise the removal has no effect on the live
process, only on the file. The script prints this reminder every time it removes something.
