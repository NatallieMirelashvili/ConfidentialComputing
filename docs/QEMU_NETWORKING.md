# QEMU guest networking — what was changed and why

This documents the change that gave the QEMU edge device network access to
the management server (closing the gap described in
`docs/HANDOFF_qemu_networking.md`). It starts from zero — no prior QEMU or
Docker knowledge assumed — and ends with a short deep dive into the exact
mechanics.

**TL;DR:** two tracked scripts changed (`scripts/run-project.sh`,
`scripts/run-qemu.sh`), nothing else. No C code, no kernel config, no
Buildroot config, no rebuild. After the change, the full attestation flow
was run end-to-end over a real TCP connection and the server showed the
device `attested: true`.

---

## 1. The simple explanation

### 1.1 The three nested layers

When you run `scripts/run-project.sh`, there are three "machines" stacked
inside each other:

```
┌─ Your Linux host ─────────────────────────────────────────┐
│  • the management server (CC_Server) runs here, port 9000 │
│                                                           │
│  ┌─ Docker container ──────────────────────────────────┐  │
│  │  • has the build tools + QEMU installed             │  │
│  │  • exists so nobody has to install those tools      │  │
│  │    on their own machine                              │  │
│  │                                                      │  │
│  │  ┌─ QEMU virtual machine (the "guest") ───────────┐  │  │
│  │  │  • a pretend ARM computer, our "edge device"   │  │  │
│  │  │  • runs OP-TEE (secure world) + Linux (normal  │  │  │
│  │  │    world) + our TA and host application        │  │  │
│  │  └────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────┘
```

- **QEMU** is an emulator: a program that pretends to be a whole other
  computer (here: an ARM board with TrustZone). The OS inside it is called
  the **guest**; the machine running QEMU is the **host**.
- **Docker** is *not* an emulator — a container is just a normal Linux
  process wrapped in isolation, with its own filesystem (so the exact
  right versions of the build tools are always present). By default it
  also gets its own *network* world, which is exactly what bit us (§1.3).

### 1.2 Problem 1: the guest had no network card

A virtual machine only has the hardware QEMU is told to give it. The
default OP-TEE run configuration attaches **no network card (NIC)** — the
guest was a computer with no Ethernet port. No cable, no network, no way
to reach any server, full stop.

**The fix:** ask QEMU for a virtual network card. QEMU accepts extra
hardware on its command line, and the OP-TEE build's makefile conveniently
lets us append arbitrary extra QEMU arguments through a variable called
`QEMU_EXTRA_ARGS`. The run scripts now pass:

```
-netdev user,id=net0 -device virtio-net-pci,netdev=net0
```

which means: "create a network backend in *user mode* (§1.4), and plug a
`virtio` network card wired to it into the guest's PCI slot." The guest
kernel already had the virtio-net driver built in, so the card just shows
up as `eth0` — like plugging a USB network adapter into a laptop that
already has the driver.

### 1.3 Problem 2: "the host" wasn't who we thought

QEMU's user-mode networking has a built-in convention: from inside the
guest, the special IP address **`10.0.2.2` always means "the machine
running QEMU"**. That's how the device is supposed to find the server.

But QEMU runs *inside the Docker container* — so `10.0.2.2` pointed at the
**container**, and the server runs on your real host. The container is a
separate network world; the server's port 9000 wasn't visible in it.

**The fix:** start the container with `--network host`. That Docker option
removes the container's private network world and lets it share the host's
network directly. Now "the machine running QEMU," as seen through
`10.0.2.2`, *is* your real host — and the server on port 9000 is
reachable. One flag, in `run-project.sh`'s `docker run` command.

### 1.4 What "user-mode (SLIRP) networking" means

QEMU can wire a guest NIC to the outside world several ways. The heavier
ways (TAP/bridge) create real network interfaces on the host and need root
privileges. **User-mode networking** (nicknamed SLIRP) needs none of that:
QEMU itself plays router and pretends a little private network for the
guest:

- the guest is `10.0.2.15`
- the "router" (= the machine running QEMU) is `10.0.2.2`
- a built-in DHCP server hands out those addresses automatically
- outbound TCP connections just work; inbound connections don't (fine
  here — our device *dials out* to the server by design, see
  `docs/CONNECTION_INITIATION.md`)

One quirk worth knowing: SLIRP does not forward `ping` (ICMP), so
`ping 10.0.2.2` **failing is normal** and means nothing — always test with
a real TCP connection (see the check in `docs/ATTESTATION_TESTING.md` §4).

### 1.5 Problem 3 that turned out not to exist: bringing up eth0

Linux doesn't automatically configure a network card just because it
exists — something must run a DHCP client to ask for an IP address. The
handoff doc expected us to add that. It turned out the stock OP-TEE rootfs
**already ships a boot script (`S50udhcpc`) that runs the DHCP client
(`udhcpc`) on every boot** — it had just been failing silently all along
because there was no NIC to configure. With the NIC attached, boot now
prints `Starting network (udhcpc): OK` and `eth0` has its address before
you even log in. Zero changes needed.

### 1.6 Why the change is only in `scripts/`

`.optee-workspace/` (where QEMU, the kernel, and the rootfs actually live)
is **generated**: `scripts/bootstrap.sh` recreates it from pinned upstream
sources, and it's git-ignored. Anything edited in there is silently lost
on the next clean bootstrap, and your teammates would never receive it.
That's why the rule for this repo is: changes live in tracked files
(`scripts/`, `project/`, `docs/`) that *inject* into the generated tree at
build/run time. Here, `QEMU_EXTRA_ARGS` is exactly such an injection
point, so the entire fix fits in the two tracked run scripts.

---

## 2. Short deep dive

### 2.1 The full plumbing of one run

```
scripts/run-project.sh
  │  QEMU_EXTRA_ARGS defaults to:
  │    -netdev user,id=net0 -device virtio-net-pci,netdev=net0
  │
  ├─ docker run --network host -e QEMU_EXTRA_ARGS ... \
  │      confidential-computing-optee ./scripts/run-project.sh
  │        (re-runs itself inside the container; --network host makes the
  │         container share the host's network stack)
  │
  └─ (inside container) tmux session running:
       make run-only NcCns=1 QEMU_EXTRA_ARGS='<the NIC args>'
         │
         └─ .optee-workspace/build/qemu_v8.mk:
              QEMU_BASE_ARGS += $(QEMU_EXTRA_ARGS)   ← the injection point
              → qemu-system-aarch64 ... -netdev user,id=net0
                                        -device virtio-net-pci,netdev=net0
```

Guest boot then does the rest on its own:

```
virtio-net-pci enumerates → kernel driver (CONFIG_VIRTIO_NET=y, built in)
  → eth0 exists → init runs /etc/init.d/S50udhcpc → udhcpc (defaults to
  eth0) → SLIRP's DHCP answers → eth0 = 10.0.2.15/24, default route via
  10.0.2.2 → device config (written by provision-device.sh with
  server-host 10.0.2.2) → net_connect() → TCP to 10.0.2.2:9000 → SLIRP
  relays it out of QEMU → container = host network → CC_Server accepts.
```

### 2.2 What exactly changed, file by file

| File | Change |
|---|---|
| `scripts/run-project.sh` | New `QEMU_EXTRA_ARGS` env default (the two NIC args, overridable); `--network host` and `-e QEMU_EXTRA_ARGS` added to the `docker run`; the tmux `make run-only` now passes `QEMU_EXTRA_ARGS` through. |
| `scripts/run-qemu.sh` | Same `QEMU_EXTRA_ARGS` default, passed to both `make run-only` invocations. Note in a comment: this script is typically run from `docker-shell.sh`, whose container is **not** `--network host`, so `10.0.2.2` is the container there — use `run-project.sh` for server work, or start your shell with `--network host`. |
| `docs/ATTESTATION_TESTING.md` | New "Networking setup" subsection in §4: server env vars, `provision-device.sh` host = `10.0.2.2`, the automatic DHCP, the `wget` connectivity check, the ICMP caveat. |

Nothing under `.optee-workspace/` was touched; a clean `bootstrap.sh` +
`build-project.sh` reproduces everything (the scripts only affect how QEMU
is *launched*, not what is built).

### 2.3 Design notes & traps encountered

- **`virtio-net-pci` vs `virtio-net-device`:** the machine type is `virt`
  with PCI, and the kernel has `CONFIG_VIRTIO_PCI=y`, so the PCI flavor was
  tried first and enumerated fine (the MMIO flavor `virtio-net-device` was
  the planned fallback; never needed).
- **The handoff's "rootfs overlay" idea for eth0 was a trap.** Buildroot's
  overlay directory is set in `qemu_v8.mk` as `BR2_ROOTFS_OVERLAY = ...`
  with a plain make `=` assignment — and in GNU make, a makefile assignment
  *overrides* an environment variable of the same name. So injecting
  `BR2_ROOTFS_OVERLAY` through the environment (the way
  `project/buildroot/packages.conf` injects `BR2_PACKAGE_*`) would be
  silently ignored. Fortunately no overlay was needed at all: the stock
  overlay already ships `S50udhcpc` (see §1.5).
- **No `nc` in the rootfs.** The handoff's suggested check
  (`nc -z 10.0.2.2 9000`) can't run — busybox here lacks `nc`. The working
  check is `wget` against the device port: an answer of
  `bad header line: {"ok": false, "error": "invalid JSON"}` is the server
  rejecting HTTP as malformed device-protocol — i.e. *proof* the TCP path
  works end to end.
- **Why not `docker run -p` (port publishing) instead of
  `--network host`?** Publishing maps *inbound* ports host→container; our
  problem was the opposite direction (guest→container→host). `--network
  host` is the one-flag way to make the host's services visible; it's
  Linux-only, which matches this dev setup.
- **Security note:** SLIRP NATs the guest outward — the guest can dial out,
  but nothing can dial in. For this project that's a feature: it matches
  the device-initiated connection model, and the emulated device stays
  unreachable from the network.

### 2.4 Verified end-to-end (2026-07-09)

With a live `MS_DEVICE_LINK=attested_network` server on the host:

1. Boot log: `Starting network (udhcpc): OK`; `eth0` = `10.0.2.15/24`,
   default route via `10.0.2.2` — automatic, no console steps.
2. TCP check from guest: `wget http://10.0.2.2:<port>` answered by the
   server's device link (`invalid JSON` rejection = connectivity proven).
3. Full flow: `provision-device.sh iot-edge-01 10.0.2.2 <port>` →
   enrollment JSON registered via `POST /api/devices/register` → device
   run printed `edge_device: completed stub flow` → server `/api/devices`
   showed `"connected": true, "attested": true`.

(The verification run used port 9100 instead of 9000 only because a
teammate's stub-mode server container was already occupying 9000 on this
machine; the port is just an argument to `provision-device.sh` and
`MS_DEVICE_PORT` — nothing in the networking depends on it.)

Pre-existing, out-of-scope caveats (unchanged, tracked elsewhere): PCR
`sha256:0` reads all zeros (measured-boot chain, see
`docs/ATTESTATION_DESIGN.md` §5), and the AK must be re-provisioned +
re-registered after every QEMU restart (initrd fTPM NV state).
