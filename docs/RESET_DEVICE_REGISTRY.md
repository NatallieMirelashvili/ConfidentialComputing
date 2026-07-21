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
