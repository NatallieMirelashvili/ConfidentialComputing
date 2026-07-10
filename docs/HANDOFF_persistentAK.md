# Handoff: Persist the Attestation Key across reboots

**Goal:** make the device's Attestation Key (AK) survive a QEMU reboot so the
device is enrolled **once**, not re-registered on every boot. This is the
explicit next step called out in `docs/ATTESTATION_DESIGN.md` §5.

This document is written so a fresh Claude Code instance can pick the work up
cold. It records the confirmed root cause, the plan, the exact files/knobs, and
the one acceptance test that matters.

---

## 1. Where things stand (context)

- Remote attestation, session-key exchange, admin-gated registration, and the
  inner-session anti-replay are all implemented and verified end-to-end. See
  `docs/ATTESTATION_DESIGN.md` and `docs/ATTESTATION_TESTING.md`.
- **PCR `sha256:0` is now non-zero and reboot-deterministic** (design doc §2.9):
  firmware measured boot doesn't reach the fTPM on this QEMU/opteed topology, so
  `provision-device.sh` extends PCR0 in Normal World with `SHA-256` of the TA +
  edge binary. Because it's deterministic, **the PCR baseline stays valid across
  reboots** — it is no longer a reason to re-enroll.
- **The one remaining reason the device must re-register every boot is the AK.**
  That is what this handoff fixes.

## 2. The problem

On each boot the device runs `provision-device.sh`, which calls
`tpm2_createek`/`tpm2_createak` and persists the AK to handle `0x8101000A`. The
server (`CC_Server/server/attestation.py` `verify_and_derive`) verifies every
quote's signature against the **registered** AK public key
(`device_registry.py`, keyed `device_id → {ak_pub_pem, expected_pcr}`). Because
the AK is regenerated each boot, `ak_pub_pem` changes, the old registration
goes stale, and an admin must re-`POST /api/devices/register` before the device
can attest again.

## 3. Root cause (confirmed by inspection of `.optee-workspace`)

- OP-TEE secure storage here is **REE-FS**, not RPMB:
  `optee_os/out/arm/conf.mk` has `CFG_REE_FS=y`, `CFG_RPMB_FS=n`. So the fTPM's
  NV objects (including the persisted AK and the fTPM "manufactured" state) are
  written by `tee-supplicant` into a **Normal-World directory**.
- That directory is **`/var/lib/tee`**:
  `optee_client/config.mk` → `CFG_TEE_FS_PARENT_PATH ?= /var/lib/tee`.
- The Normal-World rootfs is an **initrd loaded into RAM**
  (`qemu_v8.mk` `QEMU_BASE_ARGS += -initrd rootfs.cpio.gz`), and there is **no
  persistent mount** (no `/etc/fstab`, no `/data`). So `/var/lib/tee` is RAM →
  wiped every reboot → fTPM re-manufactures → new AK.
- **Why persistence will actually work on QEMU:** REE-FS objects are encrypted
  under a key derived from the HUK, and this build uses a **stable software HUK**
  (`CFG_CORE_HUK_SUBKEY_COMPAT=y`, `CFG_WITH_SOFTWARE_PRNG=y`). The HUK is the
  same every boot, so objects encrypted this boot **decrypt on the next boot**.
  Without that property, persisting the files would be pointless.

## 4. The plan (four coordinated pieces)

### 4.1 Attach a persistent virtual disk to QEMU
- Reuse the `-drive if=none,file=…,format=raw,id=… -device virtio-blk-device,drive=…`
  pattern already present in `qemu_v8.mk` (see the `QEMU_XEN` block ~line 637).
- Inject it via the **existing `QEMU_EXTRA_ARGS` knob** in
  `scripts/run-project.sh` (already threaded through the docker run and into
  `qemu_v8.mk`'s `QEMU_BASE_ARGS += $(QEMU_EXTRA_ARGS)`), so no new patch to the
  generated makefile is needed.
- `run-project.sh` should **create the image file once and reuse it**
  (`qemu-img create -f raw <img> 64M` or `dd`), and use a **distinct file per
  `QEMU_INSTANCE`** (so multi-device runs don't share state). Put it on a
  **host path that survives** and is mounted into the container — e.g. under a
  new git-ignored `ConfidentialComputing/.device-state/iot-edge-0N.img`
  (`$ROOT_DIR` is already bind-mounted into the container). Add it to
  `.gitignore`.

### 4.2 Mount the disk at `/var/lib/tee` before `tee-supplicant` starts
- `tee-supplicant` is started by `/etc/init.d/S30optee` in the rootfs. The mount
  must happen **before** it, so add an init script that runs earlier, e.g.
  `S29tee-storage`:
  - find the virtio block device (`/dev/vda` or by size/label),
  - `mkfs.ext4` it **on first boot only** (detect an unformatted disk),
  - `mount` it at `/var/lib/tee` (create the dir if missing).
- **Reproducibility:** install this script the same tracked way
  `provision-device.sh` is installed — via
  `project/optee_examples/confidential_iot/CMakeLists.txt`
  (`install(PROGRAMS scripts/<name> DESTINATION /etc/init.d)` — check the exact
  destination var; `provision-device.sh` currently installs to
  `${CMAKE_INSTALL_BINDIR}`). Do **not** hand-edit the generated buildroot
  overlay under `.optee-workspace/build/br-ext/board/qemu/overlay` — it is
  regenerated. (There is also a `BR2_ROOTFS_OVERLAY` route; the CMake-install
  route is simpler and matches the existing pattern.)

### 4.3 Make provisioning idempotent against the *persisted* AK
- `provision-device.sh` currently short-circuits on
  `[ -f /etc/confidential_iot/device.conf ]`, but `/etc` is on the ephemeral
  initrd, so that check is always false after a reboot. Change the gate to test
  whether the **AK already exists in the fTPM**, e.g.
  `tpm2_readpublic -c 0x8101000A` succeeds → skip `createek`/`createak`, just
  re-create the small `device.conf` and reprint the record.
- Keep `software_measure_pcr0()` running every boot (it's deterministic and
  guarded — leave it as is).

### 4.4 Server: enroll once
- No server code change. Enroll on the **first** boot; every later reboot reuses
  the same AK **and** the same deterministic PCR0, so the existing registration
  stays valid. `device_registry.register()` already overwrites by `device_id`,
  so a manual re-enroll remains harmless if ever needed.

## 5. Key files, knobs, references

| Thing | Where |
|---|---|
| QEMU args knob | `scripts/run-project.sh` (`QEMU_EXTRA_ARGS`, `QEMU_INSTANCE`); disk pattern to copy in `.optee-workspace/build/qemu_v8.mk` (`QEMU_XEN` block, `QEMU_BASE_ARGS`) |
| Secure-storage backend / path | `optee_os/out/arm/conf.mk` (`CFG_REE_FS=y`), `optee_client/config.mk` (`CFG_TEE_FS_PARENT_PATH=/var/lib/tee`) |
| tee-supplicant start | rootfs `/etc/init.d/S30optee` |
| Provisioning script | `project/optee_examples/confidential_iot/scripts/provision-device.sh` (AK handle `0x8101000A`) |
| Install rule for scripts | `project/optee_examples/confidential_iot/CMakeLists.txt` (`install(PROGRAMS …)`) |
| Server verify / registry | `CC_Server/server/attestation.py`, `CC_Server/server/device_registry.py`, `POST /api/devices/register` in `app_server.py` |
| Reproducibility rule | Everything tracked under `project/…` + `scripts/…`; `.optee-workspace/` is generated (`bootstrap.sh` → `repo sync` → `sync-project.sh`). Never hand-edit the workspace. See design doc §2.4. |

## 6. Acceptance test (the thing that must pass)

1. Fresh build + boot; run `provision-device.sh`; submit the enrollment record
   once via `POST /api/devices/register`; run the edge binary → attestation
   verifies (baseline case, already works today).
2. **Reboot the same QEMU instance** (with the persistent disk attached).
3. Run the edge binary **without** re-provisioning and **without** re-registering.
4. **Pass = attestation still verifies** against the original registration —
   i.e. the AK public key is unchanged (`tpm2_readpublic -c 0x8101000A` matches
   the enrolled `ak_pub_pem`) and PCR0 matches the enrolled baseline.

Also confirm multi-instance: `QEMU_INSTANCE=0` and `=1` use separate disk images
and separate `device_id`s, and each persists independently.

## 7. Gotchas / risks

- **Mount ordering:** the disk must be mounted at `/var/lib/tee` *before*
  `tee-supplicant` (S30optee) opens/creates storage, or the first boot writes to
  RAM and the disk stays empty.
- **First-boot format:** detect an unformatted disk and `mkfs` exactly once;
  don't reformat on later boots (that would wipe the AK — the whole point).
- **fTPM re-manufacture:** verify the fTPM does *not* re-run manufacture after a
  reboot once storage persists (it keys off its NV "manufactured" state, which
  must now survive). The secure-world log at boot shows this.
- **REE-FS rollback warnings:** without RPMB, the boot log shows
  `WARNING (insecure configuration): Failed to get monotonic counter for REE FS,
  using 0` and occasionally `Remove corrupt file`. These are expected on QEMU
  (no anti-rollback hardware) and are not fatal — but watch that a "corrupt
  file" path doesn't silently discard the AK object; if it does, the REE-FS
  hash-tree/dirfile handling on the persistent disk needs a closer look.
- **Disk lifecycle in `run-project.sh`:** create-once/reuse, per-instance file,
  on a host path that is bind-mounted into the container and survives across
  runs; git-ignore it.
- **`/etc/confidential_iot/device.conf`** is regenerated cheaply each boot, so it
  needn't be persisted — but the provisioning idempotency gate must key off the
  fTPM AK (§4.3), not that file.

## 8. Estimated effort

Moderate — roughly a focused half-day. Each piece is small, but they're coupled
(QEMU disk ↔ guest mount ↔ provisioning gate), and the fTPM-reload /
REE-FS-persistence behavior may need an iteration or two to confirm. The HUK
being a stable software key removes the biggest risk (undecryptable storage).
