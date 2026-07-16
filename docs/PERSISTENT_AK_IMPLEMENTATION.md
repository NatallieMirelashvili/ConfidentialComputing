# Persisting the device's Attestation Key across reboots — implementation notes

**Mission:** `docs/HANDOFF_MISSIONS.md` §2.1.a — "The device has to be re-registered on every
reboot (AK not persisted)".
**Original spec this follows:** `docs/HANDOFF_persistentAK.md` (written before this
implementation; still useful for the deeper root-cause writeup of *why* OP-TEE's storage is
ephemeral on this QEMU topology).
**Status:** implemented and verified end-to-end on live QEMU + a real `attested_network`
`CC_Server` instance (see "Verification" below).

This document describes what was actually built, in which files, and why — including a real
Buildroot dependency bug hit and worked around along the way.

---

## 1. The problem, in one paragraph

The device proves its identity to `CC_Server` with a TPM2 quote signed by an fTPM
**Attestation Key (AK)**, generated once by `provision-device.sh` and persisted at TPM handle
`0x8101000A`. OP-TEE's secure storage backing that key (`/var/lib/tee`, REE-FS-backed on this
build) lived on the QEMU guest's **initrd — RAM, wiped every reboot**. So every reboot produced
a brand-new AK, the server's registration for the old key went stale, and an admin had to
`POST /api/devices/register` again before the device could attest. The fix: give `/var/lib/tee`
a real, persistent backing disk.

## 2. Architecture of the fix

```
Host                                    QEMU guest (Normal World)
────                                    ─────────────────────────
.device-state/iot-edge-01.img   ──virtio-blk──►  /dev/vda
  (created + ext4-formatted                        │
   on the HOST, once, by                            ▼ mounted by S29tee-storage
   scripts/run-project.sh)                       /var/lib/tee  (before S30optee/tee-supplicant starts)
                                                       │
                                                       ▼
                                          fTPM's REE-FS secure storage
                                          (dirf.db + numbered object blocks)
                                                       │
                                                       ▼
                                    AK at handle 0x8101000A now survives reboot
                                                       │
                                                       ▼
                              provision-device.sh detects it (tpm2_readpublic succeeds),
                              skips createek/createak, just re-asserts PCR0 and reprints
                              the same enrollment record — no new identity, no re-registration.
```

Four coordinated pieces, one per concern: **(1)** give QEMU a persistent disk, **(2)** mount it
in the guest before secure storage needs it, **(3)** make the provisioning script idempotent
against a key that might already exist, **(4)** nothing needed server-side.

## 3. Files changed

### 3.1 `scripts/run-project.sh` — attach + host-format the persistent disk

```diff
+DEVICE_STATE_DIR="${DEVICE_STATE_DIR:-$ROOT_DIR/.device-state}"
+DEVICE_DISK_IMG="${DEVICE_DISK_IMG:-$DEVICE_STATE_DIR/iot-edge-$(printf '%02d' $((QEMU_INSTANCE + 1))).img}"
+mkdir -p "$DEVICE_STATE_DIR"
+if [[ ! -f "$DEVICE_DISK_IMG" ]]; then
+  truncate -s 64M "$DEVICE_DISK_IMG"
+  mkfs.ext4 -q -F "$DEVICE_DISK_IMG"
+fi
+QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,file=$DEVICE_DISK_IMG,format=raw,id=hd1 -device virtio-blk-device,drive=hd1"
```

- One 64MB raw disk image **per `QEMU_INSTANCE`**, under a new `.device-state/` directory,
  created once and reused on every subsequent run — that reuse is *the entire mechanism* that
  makes persistence work: same instance number → same file → same disk → same AK.
- Attached via the existing `QEMU_XEN` drive pattern already present in the generated
  `qemu_v8.mk` (`-drive if=none,... -device virtio-blk-device,...`), injected through the
  **already-existing** `QEMU_EXTRA_ARGS` knob — no new patch to the generated makefile needed.
- **Formatted on the host**, not in the guest (see §4 for why — this wasn't the original plan).
- Placed *after* the script's own Docker re-exec block, deliberately: `run-project.sh` re-execs
  itself into Docker when not already inside it, and `$ROOT_DIR` (derived from `$BASH_SOURCE`)
  means a different path on each side of that boundary — the host path outside Docker, the
  bind-mounted container path inside. Computing the disk path here guarantees it's always
  correct for wherever QEMU is actually about to run.

### 3.2 `project/optee_examples/confidential_iot/scripts/S29tee-storage` (new file)

```sh
#!/bin/sh
DEV=/dev/vda
MOUNT_POINT=/var/lib/tee

start() {
	mkdir -p "$MOUNT_POINT"
	printf 'Mounting %s at %s: ' "$DEV" "$MOUNT_POINT"
	if mount -t ext4 "$DEV" "$MOUNT_POINT" 2>/dev/null; then
		echo "OK"
		return 0
	fi
	echo "not formatted, formatting"
	mkfs.ext4 -F "$DEV" && mount -t ext4 "$DEV" "$MOUNT_POINT"
}

case "$1" in
	start) start ;;
	stop|restart|reload) ;;
	*) echo "Usage: $0 {start|stop|restart|reload}"; exit 1
esac
```

- A Buildroot-style `/etc/init.d/S##name` script. The `S29` prefix is load-bearing: init
  scripts run in numeric order, and this **must** run before `/etc/init.d/S30optee` (which
  starts `tee-supplicant`) — mounting after secure storage is already in use would be a no-op
  at best, data loss at worst.
- `mount`-then-`mkfs`-on-failure, rather than a separate "is this formatted" probe (e.g. via
  `blkid`) — simpler, no extra tools needed, and correct: an unformatted raw disk always fails
  `mount -t ext4`, a formatted one always succeeds.
- **The in-guest `mkfs.ext4` fallback on line 26 is now effectively dead code** in normal
  operation, since §3.1's host-side formatting means the guest always finds an already-formatted
  disk. It's kept as a defensive fallback (e.g. if someone attaches a disk through some other
  path that skips `run-project.sh`'s formatting) — see §4 for why the guest can't actually run
  it today anyway (no `mkfs.ext4` in the rootfs).

### 3.3 `project/optee_examples/confidential_iot/CMakeLists.txt` — install the init script

```diff
+install(PROGRAMS scripts/S29tee-storage
+	DESTINATION /etc/init.d)
```

Same `install(PROGRAMS ...)` pattern already used two lines above for `provision-device.sh`,
just targeting `/etc/init.d` instead of `${CMAKE_INSTALL_BINDIR}`. This is how a file tracked in
git ends up in the generated Buildroot rootfs, without ever hand-editing anything under
`.optee-workspace/` (which is entirely generated/regenerated by `sync-project.sh` and must never
be touched directly).

### 3.4 `project/optee_examples/confidential_iot/scripts/provision-device.sh` — idempotent AK gate

```diff
-if [ -f "$CONF_FILE" ]; then
-	echo "Already provisioned ($CONF_FILE exists). Enrollment record:" >&2
-	print_enrollment_record
-	exit 0
-fi
-
 mkdir -p "$CONF_DIR"
 cd "$CONF_DIR"
 
-tpm2_createek -c ek.ctx -G ecc -u ek.pub
-tpm2_createak -C ek.ctx -c ak.ctx -G ecc -g sha256 -s ecdsa -u ak.pub -n ak.name
-tpm2_evictcontrol -C o -c ak.ctx "$AK_HANDLE"
-tpm2_readpublic -c ak.ctx -f pem -o ak.pem
+if tpm2_readpublic -c "$AK_HANDLE" -f pem -o ak.pem 2>/dev/null; then
+	echo "AK already persisted at $AK_HANDLE (survived reboot). Enrollment record:" >&2
+else
+	tpm2_createek -c ek.ctx -G ecc -u ek.pub
+	tpm2_createak -C ek.ctx -c ak.ctx -G ecc -g sha256 -s ecdsa -u ak.pub -n ak.name
+	tpm2_evictcontrol -C o -c ak.ctx "$AK_HANDLE"
+	tpm2_readpublic -c ak.ctx -f pem -o ak.pem
+	...
+fi
```

- **The actual bug fix.** The old gate checked `[ -f /etc/confidential_iot/device.conf ]` — but
  that directory lives on the ephemeral initrd, so the check was *always false* after any
  reboot, guaranteeing a fresh AK every time regardless of what secure storage held.
- The new gate probes the fTPM directly: `tpm2_readpublic` only *reads*, it can't create state,
  so it's a safe way to ask "does the AK already exist" — true from the second boot onward once
  `/var/lib/tee` is persisted, always false without it (so this script still works correctly,
  just non-idempotently, on a build without the disk fix).
- Either branch now falls through to the same `cat > "$CONF_FILE"` + `print_enrollment_record`
  tail, so the script always ends by reprinting a valid enrollment record — a fresh one on first
  boot, the unchanged one on every boot after.
- `software_measure_pcr0()` (the PCR0 measured-boot stand-in — a separate, already-existing
  concern, not part of this fix) is untouched, and this matters operationally: **PCR registers
  reset to zero on every reboot** (unlike NV-indexed objects like the AK, which is why
  persisting storage was even necessary), so `provision-device.sh` must still be *invoked* every
  boot to re-extend PCR0 back to its deterministic value — it just becomes a cheap no-op for the
  AK-creation part. `scripts/run-project.sh`'s own automation already does this on every launch;
  it's only manual reboots inside an already-running guest (e.g. via `reboot` at the shell) that
  need `provision-device.sh` re-invoked by hand afterward.

### 3.5 `.gitignore`

```diff
+# Per-instance persistent device disk images (see docs/HANDOFF_persistentAK.md)
+.device-state/
```

### 3.6 `CC_Server` — no code change

Confirmed by reading `CC_Server/server/device_registry.py`: `DeviceRegistry.register()` already
overwrites-by-`device_id` unconditionally, and `AttestationVerifier.verify_and_derive()`
(`attestation.py`) always checks the quote against whatever's *currently* registered. The server
was already correctly designed for "enroll once, reuse forever" — the device side was the only
thing standing in the way.

## 4. A real bug found along the way: the guest has no `mkfs.ext4`

The first implementation attempt formatted the disk **in the guest** (the `mkfs.ext4` line
inside `S29tee-storage`), gated behind adding `BR2_PACKAGE_E2FSPROGS=y` to
`project/buildroot/packages.conf` (the tracked file that injects extra Buildroot package
selections — see its own header comment). Two problems surfaced, in order:

1. **Without that package, the rootfs has no `mkfs.ext4` at all.** The very first live boot
   showed `S29tee-storage: line 26: mkfs.ext4: not found` — the mount silently fell back to
   failing, `/var/lib/tee` was created directly on the ephemeral rootfs by `S30optee`'s own
   `mkdir -p` fallback, and the whole fix was silently defeated (no hard failure, just quietly
   non-functional).
2. **Cross-building `e2fsprogs` to fix that hit a genuine Buildroot bug in this snapshot.**
   `package/e2fsprogs/e2fsprogs.mk` declares `E2FSPROGS_DEPENDENCIES = host-pkgconf util-linux`,
   but this Buildroot version split `libblkid` out of `util-linux` into a separate
   `util-linux-libs` package, which `util-linux` itself only conditionally depends on — and
   `e2fsprogs.mk` was never updated for the split. Result:
   `configure: error: external blkid library not found`, `make: *** [common.mk:344: buildroot]
   Error 2` — a real upstream inconsistency, not something to patch inside the generated,
   never-hand-edit `.optee-workspace/buildroot` tree.

**The fix:** pre-format the disk **on the host** instead. `docker/Dockerfile` gained one line
(`e2fsprogs` in the `apt-get install` list) — a native x86_64 Ubuntu package, no
cross-compilation, no Buildroot dependency graph involved at all. `mkfs.ext4` can format a plain
regular file directly (no loop device, no root needed), so `scripts/run-project.sh` just runs it
right after `truncate`. `project/buildroot/packages.conf` was reverted back to its original
two-line state. The already-built rootfs (with `S29tee-storage` and the idempotent
`provision-device.sh`) didn't need rebuilding at all — only the Docker image did, ~90 seconds
versus a 10+ minute full OP-TEE/Buildroot rebuild.

This is the reason §3.2's guest-side `mkfs.ext4` fallback is presently dead code: the guest
still has no `mkfs.ext4` binary, but it never needs one, because the disk always arrives
pre-formatted.

## 5. New helper script: `scripts/register-device.sh`

A convenience script added after verification, so registering a freshly provisioned device
doesn't require manually copying the printed JSON and hand-writing a `curl` command:

```
scripts/register-device.sh [QEMU_TMUX_SESSION] [API_HOST] [API_PORT]
```

It finds the right running QEMU container by searching for one whose tmux session matches the
given name (works correctly even with multiple concurrent instances, since it doesn't guess a
container ID), polls the Normal World pane for the `{"device_id":...}` enrollment JSON (up to
`REGISTER_TIMEOUT`, default 180s), and `POST`s it to `/api/devices/register` with `curl -sk`
(the `-k` because the default transport is TLS with a self-signed cert).

## 6. Verification performed

Full details and raw command transcript live in the session's plan file; summarized here:

| Step | Result |
|---|---|
| Fresh disk, first boot | `provision-device.sh` created a new AK (correct — never provisioned before); `S29tee-storage` mounted the host-pre-formatted disk directly, no in-guest format needed |
| Registered via `POST /api/devices/register` | `{"ok":true,...}` |
| Baseline attestation | `edge_device: pushed sensor reading` within seconds of registering |
| AK fingerprint before reboot | `tpm2_readpublic -c 0x8101000A -f pem \| md5sum` → `7083b530904900d961a833e43d0fb7b6` |
| Guest `reboot` (same QEMU process, only the guest OS restarts) | `EXT4-fs (vda): mounted filesystem` again, no reformat |
| AK fingerprint after reboot | **identical** `7083b530904900d961a833e43d0fb7b6` — byte-for-byte survival |
| Re-ran `provision-device.sh` post-reboot (still required, to re-extend PCR0 — see §3.4) | `AK already persisted at 0x8101000A (survived reboot).` — idempotent path taken, same enrollment record reprinted |
| Ran edge binary again, **no new registration call made** | Immediate `pushed sensor reading`, zero `attestation/session failed` retries |
| Filesystem-level proof (no boot needed) | `debugfs -R "ls -l /" <image>.img` inside the (now e2fsprogs-equipped) Docker image shows real OP-TEE REE-FS objects (`dirf.db` + numbered hash-tree blocks, owned by the `tee` uid/gid) with mtimes spanning both the first boot **and** the later reboot — proof data was both written and *re-touched* across a reboot, not just created once |
| Multi-instance isolation (`QEMU_INSTANCE=1`) | Verified manually: distinct disk (`.device-state/iot-edge-02.img`), distinct `device_id` (`iot-edge-02`), distinct ports, registered and attested independently of `iot-edge-01` |

**Result: the mission 2.1.a acceptance test passes.** A device is enrolled once and reused
forever across reboots.

## 7. Quick reference — running it yourself

```bash
# 1. A real (non-stub) CC_Server, attested_network mode:
cd CC_Server && MS_DEVICE_LINK=attested_network MS_DEVICE_PORT=9100 MS_API_PORT=8100 python3 -m server.main

# 2. Boot a device (QEMU_INSTANCE picks the disk/device_id; omit for instance 0 / iot-edge-01):
SERVER_PORT=9100 QEMU_INSTANCE=1 QEMU_TMUX_SESSION=my-verify ./scripts/run-project.sh

# 3. Register it (in another terminal, once provisioning has printed its record):
./scripts/register-device.sh my-verify 127.0.0.1 8100

# 4. Reboot test: in the QEMU terminal (Normal World shell) —
#      <Ctrl-C>  (stop the push loop)
#      reboot
#      (wait for buildroot login:, log in as root)
#      provision-device.sh iot-edge-02 10.0.2.2 9100   # re-asserts PCR0, reuses the persisted AK
#      optee_example_confidential_iot_edge              # should attest immediately, no re-registration

# Inspect a disk image's contents without booting anything:
docker run --rm -v "$(pwd)/.device-state:/img:ro" confidential-computing-optee:latest \
  debugfs -R "ls -l /" /img/iot-edge-01.img
```

## 8. Known limitations / possible follow-ups

- The guest-side `mkfs.ext4` fallback in `S29tee-storage` can't actually run (no `mkfs.ext4` in
  the rootfs) — it's a no-op safety net, not a real fallback path, given the current host-format
  design. If the disk-lifecycle logic ever moves out of `run-project.sh` (e.g. a different
  launcher), this would need revisiting.
- No automated test exercises the reboot-persistence behavior (this was verified manually,
  live) — `CC_Server/server/tests/test_attestation.py` covers the server-side protocol but has
  no notion of "the same device across two device-process lifetimes."
- `register-device.sh` assumes TLS mode with a self-signed cert (`curl -k`); it doesn't support
  the AES-GCM user-channel mode (`MS_USER_SECURITY=aesgcm`), which would need an ECDH handshake
  first.
