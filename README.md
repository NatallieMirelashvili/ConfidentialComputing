# Confidential Computing OP-TEE/QEMU

An emulated ARM TrustZone IoT edge device (OP-TEE Secure World + Linux Normal
World in QEMU) that remotely attests itself to a Management Server before it is
trusted with sensor data.

The supported runtime target is a Linux x86_64 Docker host only.

## Table of Contents

- [Demos](#demos)
- [Repository Layout](#repository-layout)
- [Installation Guide](#installation-guide)
  - [Prerequisites](#prerequisites)
  - [1. Build the Docker image](#1-build-the-docker-image)
  - [2. Bootstrap OP-TEE from the pinned manifest](#2-bootstrap-op-tee-from-the-pinned-manifest)
  - [3. Build toolchains, project code, and the QEMU images](#3-build-toolchains-project-code-and-the-qemu-images)
  - [4. Install the Management Server dependencies](#4-install-the-management-server-dependencies)
- [Execution Guide](#execution-guide)
  - [The server terminal](#the-server-terminal)
  - [The device terminals](#the-device-terminals)
  - [The enrollment terminal](#the-enrollment-terminal)
  - [What a successful run looks like](#what-a-successful-run-looks-like)
  - [Viewing the data](#viewing-the-data)
  - [Running the device-side tests](#running-the-device-side-tests)
  - [Stopping a device](#stopping-a-device)
  - [Re-enrolling after a rebuild](#re-enrolling-after-a-rebuild)
- [Updating Project Source](#updating-project-source)
- [Notes](#notes)

## Demos

- **End-to-end execution demo** —
  [watch on Google Drive](https://drive.google.com/file/d/1pQ6uk-V1Zdf2CTdmECA0KWWnWzF33_9T/view)

  The full flow of the [Execution Guide](#execution-guide) below: server start,
  two devices booting and provisioning, enrollment, attestation, and sensor data
  arriving in the UI.

- **Wireshark packet walkthrough** — [watch on Google Drive](https://drive.google.com/file/d/1DJX32im1s3z287aFhN4bnwZhHtsDgfxm/view?usp=sharing)
  
  A frame-by-frame reading of one full attestation, showing what an observer on
  the wire can and cannot see.

  The capture it walks through is in the repository at
  [`docs/demo/attest.pcapng`](docs/demo/attest.pcapng) (6.5 MB) — open it in
  Wireshark to follow along with the video.

## Repository Layout

- `manifests/locked-qemu_v8.xml` - pinned OP-TEE manifest.
- `project/optee_examples/` - project CA/TA source overlaid into OP-TEE.
- `CC_Server/` - the Management Server (FastAPI UI + REST API, device link).
- `keys/` - the project's private TA signing key (see the note in
  [step 3](#3-build-toolchains-project-code-and-the-qemu-images)).
- `docker/Dockerfile` - Linux x86_64 build and QEMU runtime image.
- `scripts/` - Docker, bootstrap, build, source sync, and QEMU run helpers.
- `docs/` - project documentation, plus the packet capture used in the
  Wireshark walkthrough (`docs/demo/`).

Generated OP-TEE content is created under `.optee-workspace/` and ignored by Git.

## Installation Guide

This is a one-time setup. Once it is done, use the
[Execution Guide](#execution-guide) for every run.

### Prerequisites

- Docker, on a Linux x86_64 host.
- Python 3 on the host (the Management Server runs outside the container).
- **Around 20GB of free disk space** — make sure your machine is up to it.

Everything is driven from the repository root. Only the bootstrap step needs an
interactive container shell; the build and run helpers re-enter the container by
themselves.

### 1. Build the Docker image

This creates a reproducible Linux x86_64 environment with the cross-compilers,
OP-TEE dependencies, and QEMU tools needed to build and emulate an ARM
TrustZone system.

```bash
scripts/docker-build.sh
```

If the image already exists on your machine, you can skip this — rebuild it only
when `docker/Dockerfile` changes, and use a different tag if you need to keep the
old one around.

### 2. Bootstrap OP-TEE from the pinned manifest

This downloads the exact upstream OP-TEE components recorded for the project:
the Normal World Linux side, the Secure World OP-TEE OS side, firmware, boot
pieces, and examples. The pinned manifest keeps the emulator stack stable across
machines and over time.
The downloaded repositories and generated workspace files are placed under
`.optee-workspace/`, outside the source tree that should be committed, so the
Git repository stays small.

You only need this when the workspace is missing or intentionally reset.

This is the one step that must run **inside** the container: it needs the `repo`
tool from the image, and unlike the other helpers it does not re-enter the
container on its own. Open a shell, run it, then leave:

```bash
scripts/docker-shell.sh     # on the host: opens a shell in the build image
scripts/bootstrap.sh        # inside the container
exit
```

`scripts/docker-shell.sh` is also how you get a build environment for anything
else you want to run by hand — it bind-mounts the repository at the same path
the other scripts use.

### 3. Build toolchains, project code, and the QEMU images

This copies this repository's example code into the OP-TEE tree, then compiles
the cross-toolchains and the full emulated platform that QEMU will boot.
Conceptually, it creates both sides of the TEE system: Linux in the Normal
World and OP-TEE in the Secure World.

Run it **from the host** — it re-executes itself inside the container
automatically, so there is no need to open a shell first (it also works from
inside one, if you happen to be there):

```bash
scripts/build-project.sh
```

⚠️ Note: Building the project may take 1–2 hours, depending on your system resources. 
We strongly recommend running the build inside a dedicated tmux session to ensure that it continues even if your interactive terminal or SSH session is disconnected.

The build also verifies that the OP-TEE core's baked-in verifier key and the
built `.ta`'s signature are the same project-private key. Don't skip past that
output — a mismatch is otherwise a *silent* build success in which every TA then
fails to load at runtime. You can re-run the check on its own at any time, from
the host or from inside the container:

```bash
scripts/verify-ta-signing.sh
```

> **About the signing key in `keys/`.** `keys/ciot_ta.pem` is a private RSA-4096
> key and it is committed on purpose. OP-TEE's shipped default signing key has
> its private half published upstream, so anyone could re-sign a tampered TA and
> have the core load it; using a project key closes that. Committing it also
> keeps builds reproducible — everyone gets the same core image, hence the same
> PCR0 baseline. The trade-off is deliberate and bounded: the repository never
> reaches the device, and the property being bought is only *"not the
> universally-known upstream key"*. For a stronger posture, generate your own key
> outside the tree and point `TA_SIGN_KEY` at it — note that this changes PCR0,
> so every enrolled device has to be re-enrolled.

### 4. Install the Management Server dependencies

The server runs on the host, in plain Python — not inside the OP-TEE container.

```bash
cd CC_Server
python3 -m pip install -r server/requirements.txt
```

## Execution Guide

A run is made of three kinds of terminal, all on the host, all opened at the
repository root (`ConfidentialComputing/`):

- **The server terminal** — one, running the Management Server.
- **A device terminal** — one *per device*. Each one boots its own QEMU machine
  and attaches to its own tmux session.
- **The enrollment terminal** — one, used to enroll the devices with the server.

The server and device terminals all hold long-running foreground processes, so
enrollment needs a terminal of its own. **N devices therefore need N + 2
terminals.**

The rest of this guide uses **two devices** as the worked example, so four
terminals in total:

| Terminal | What runs there |
|---|---|
| 1 | The Management Server |
| 2 | Device 1 — QEMU + OP-TEE |
| 3 | Device 2 — QEMU + OP-TEE |
| 4 | Enrollment of both devices |

For more devices, add a terminal per device, each with the next `QEMU_INSTANCE`
and its own `QEMU_TMUX_SESSION`, and enroll each one from the same enrollment
terminal.

### The server terminal

Run from `CC_Server/` (the `-m` matters):

```bash
MS_DEVICE_LINK=attested_network MS_DEVICE_HOST=0.0.0.0 MS_DEVICE_PORT=9100 MS_API_HOST=0.0.0.0 MS_API_PORT=8100 python3 -m server.main
```

- `MS_DEVICE_LINK=attested_network` selects the real, attested device link.
  It is **required** — there is no synthetic fallback, and the server refuses
  to start without it.
- `MS_DEVICE_PORT=9100` is the device-facing attestation/data port; every device
  terminal must be pointed at the same number via `SERVER_PORT`.
- `MS_API_PORT=8100` is the browser/admin API port (TLS 1.3), used by the UI and
  by the enrollment terminal via `API_PORT`.
- `MS_API_HOST=0.0.0.0` makes the UI reachable from another machine. It defaults
  to loopback, so without it you would need an SSH tunnel (`-L`) or VS Code's
  Ports panel to open the UI remotely.

> **Why 8100/9100 and not the built-in 8000/9000 defaults?** On a shared machine
> those are frequently already taken by another service. Any free pair works, as
> long as the same numbers are used in every terminal.

### The device terminals

One terminal per device. Power up device 1:

```bash
QEMU_TMUX_SESSION=optee-device1 QEMU_INSTANCE=0 SERVER_PORT=9100 API_PORT=8100 scripts/run-project.sh
```

and device 2, in its own terminal:

```bash
QEMU_TMUX_SESSION=optee-device2 QEMU_INSTANCE=1 SERVER_PORT=9100 API_PORT=8100 scripts/run-project.sh
```

**`QEMU_TMUX_SESSION` must be different for every device.** Each invocation
attaches to its own tmux session and holds the terminal; if two runs share a
name, the second one attaches to the first one's session instead of booting a
new machine. On a machine shared with other people, pick names that won't
collide with their runs either.

**`QEMU_INSTANCE` decides the device id, and it is always +1.** The index also
derives distinct gdbstub/serial/sensor ports so concurrent instances don't
collide, but the visible effect is the device id:

| `QEMU_INSTANCE` | resulting `device_id` |
|---|---|
| `0` | `"device_id": "iot-edge-01"` |
| `1` | `"device_id": "iot-edge-02"` |
| `2` | `"device_id": "iot-edge-03"` |

`SERVER_PORT` and `API_PORT` must match `MS_DEVICE_PORT` and `MS_API_PORT` from
the server terminal. `SERVER_HOST` defaults to `10.0.2.2`, which is how the guest
reaches the machine running QEMU over user-mode networking — leave it alone.

Each invocation opens a tmux session, continues QEMU, waits for the
`buildroot login:` prompt, logs in to the Normal World as `root`, provisions the
device (`provision-device.sh`), pairs the Sensor Module, and finally runs the
edge-device client:

```bash
optee_example_confidential_iot_edge
```

**Boot + auto-provisioning takes a while — don't assume it's stuck.** The fTPM
device node isn't reliably usable the moment the shell prompt appears, so
provisioning retries every 5s for up to 90s. The whole boot-to-enrollment-record
sequence can take a couple of minutes per instance. Wait for the tmux status
message ("Provisioned ... see the enrollment record above") before moving on.

### The enrollment terminal

Enrollment is a deliberate operator step: it hands the server the device's
identity (AK public key, TA identity key, PCR0 baseline) so the server knows
what a genuine device should look like. Until then, the device's `hello` is
answered with "not registered" and it just retries.

One command per device, all from this single terminal:

```bash
# device 1
./scripts/register-device.sh optee-device1 127.0.0.1 8100
# device 2
./scripts/register-device.sh optee-device2 127.0.0.1 8100
```

The three positional parameters are:

| # | Parameter | Value above | Meaning |
|---|---|---|---|
| 1 | `QEMU_TMUX_SESSION` | `optee-device1` | The **tmux session name** you launched that device with — it tells the script which QEMU console to scrape the enrollment record from. **Not** the device id: the id (`iot-edge-01`) comes out of the record itself. |
| 2 | `API_HOST` | `127.0.0.1` | Host of the Management Server's admin API. |
| 3 | `API_PORT` | `8100` | Port of that API — must match `MS_API_PORT` from the server terminal. |

Run it once per device, each with *its own* session name — don't reuse one
device's record for another. The script finds the container running that tmux
session, waits up to 180s for the enrollment JSON to appear, and POSTs it to
`https://<API_HOST>:<API_PORT>/api/devices/register` for you, so there is no
JSON to copy by hand.

**Enrollment is a one-time step per device.** Once it has succeeded, the two
sides know each other and stay bound across power cycles:

- **The server recognises the device** — and specifically its Trusted
  Application. The enrollment record pins three things: the Attestation Key, the
  TA's identity key, and the PCR0 measurement of the boot chain. An attestation
  is only accepted when all three match, so a different device, a different TA,
  or a tampered boot cannot pass as this device.
- **The device recognises its server.** On its first attestation it pins that
  server's identity key (trust on first use) and will not talk to any other one
  afterwards, so its data only ever goes to that server.

Both sides of that binding are persistent — the device's keys live in secure
storage on its own virtual disk, and the server keeps its registry on disk — so
powering a device off and on again does **not** call for another enrollment. The
one thing that does is [a rebuild](#re-enrolling-after-a-rebuild).

### What a successful run looks like

In each device's tmux console window, after enrollment goes through:

```text
edge_device: starting push loop (interval=3s)
edge_device: pushed sensor reading
edge_device: pushed sensor reading
```

The client then runs as a daemon: it keeps a live attested session, re-attesting
only when none exists or the previous one expired, and pushes one AES-GCM-sealed
reading per interval until the process is killed.

### Viewing the data

Open the UI at `https://127.0.0.1:8100` (accept the self-signed certificate
once).

A device starts pushing as soon as
attestation and session-key establishment have succeeded, and the page streams
what arrives over a WebSocket — the badge next to the selectors reads
`● connecting…` until the feed is live, and the Result card shows "waiting for
live data…" until the first reading lands.

`GET /api/devices` lists every enrolled device, so all running instances should
show up as distinct entries.

### Running the device-side tests

These are the security tests that have to run *on* the device, in the Normal
World, against the real Trusted Application — they try to break the guarantees
from the outside, the way an attacker with root on the Host would.

In that device's tmux console window, stop the running push loop with **Ctrl+C**,
then:

```bash
optee_example_confidential_iot_tests
```

Six tests run in order, each printing its own result, ending with a
`N passed, M failed` summary:

| # | What it proves |
|---|---|
| 1 | UUID mimicry — a TA signed with a non-project key must not load |
| 2 | Secure storage is scoped to the TA UUID |
| 3 | Faked attestation — `ta_sig` cannot cover an attacker's ECDH key |
| 4 | A lying Host gains nothing — the gates live in the TA |
| 5 | The sealed device identity cannot be re-badged or reshaped |
| 6 | The sensor key is pulled from the sensor, not injected by the Host |

Run them **after** the device has finished provisioning, as `root` (which is how
the console is already logged in). `-l` lists the tests and `-t N` runs a single
one. Test 1 rewrites the installed TA in `/lib/optee_armtz` and restores it
afterwards; that directory lives in RAM, so a reboot undoes anything it leaves
behind.


### Stopping a device

Detach from the tmux session with **Ctrl+B**, then **D**.

**This powers the device off.** The tmux session lives inside that device's
container, and the container exists only for as long as you are attached to it —
detaching ends the run, so QEMU stops and the emulated machine loses power.

What survives is the device's identity. Its secure storage sits on a persistent
virtual disk under `.device-state/`, so the Attestation Key, the sealed TA
identity, the sensor pairing and the pinned server all come back on the next
power-up. Start it again with the same command as before — same `QEMU_INSTANCE`,
same `QEMU_TMUX_SESSION` — and it re-attests on its own, **with no enrollment step.**

### Re-enrolling after a rebuild

Running `scripts/build-project.sh` again invalidates the existing enrollments,
and the devices have to be enrolled once more afterwards.

The reason is that a rebuild can move the very things enrollment pinned. It
produces a fresh OP-TEE core image, which changes the PCR0 measurement of the
boot chain, and it can rotate the server's identity key — the key each device
pinned on first use. A device pinned to a key that no longer exists could never
attest again, so the project resolves this the safe way rather than leaving you
to debug it: `scripts/build.sh` writes a build stamp, and the next
`scripts/run-project.sh` for an instance notices the stamp changed and resets
that device to a **fresh device** — it wipes the persistent disk (new
Attestation Key, new server pin) and drops the device's entry from the server's
registry.

So after a rebuild, the sequence is:

1. `scripts/build-project.sh`
2. **Restart the Management Server** — it caches the registry it started with.
3. Start each device as usual (`scripts/run-project.sh` …). The reset happens
   automatically here, and each device prints a new enrollment record.
4. Enroll each device again (`scripts/register-device.sh` …).

If devices are still refusing to attest, clear every enrollment explicitly and
repeat from step 2:

```bash
scripts/reset-device-registry.sh --all
```

## Updating Project Source

Edit files under `project/optee_examples/`. The helper scripts sync those files
into `.optee-workspace/optee_examples/` before build and run.

To resync manually, inside the container shell:

```bash
scripts/sync-project.sh
```

This copies changes from `project/optee_examples/` into OP-TEE's generated
workspace without rebuilding everything immediately. Use it when you changed
project source files and want the OP-TEE checkout to reflect those edits.

## Notes

- Do not commit `.optee-workspace/`, `out/`, `out-br/`, `toolchains/`, nested
  upstream `.git/` directories, IDE state, logs, or generated binaries.
