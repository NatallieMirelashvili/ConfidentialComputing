# Confidential Computing OP-TEE/QEMU

The supported runtime target is a Linux x86_64 Docker host only.

## Repository Layout

- `manifests/locked-qemu_v8.xml` - pinned OP-TEE manifest.
- `project/optee_examples/` - project CA/TA source overlaid into OP-TEE.
- `docker/Dockerfile` - Linux x86_64 build and QEMU runtime image.
- `scripts/` - Docker, bootstrap, build, source sync, and QEMU run helpers.
- `docs/` and project notes - design and course documentation. This should be
  updated from time to time.

Generated OP-TEE content is created under `.optee-workspace/` and ignored by Git.

## Quick Start

Build the Docker image:

This creates a reproducible Linux x86_64 environment with the cross-compilers,
OP-TEE dependencies, and QEMU tools needed to build and emulate an ARM
TrustZone system.

```bash
scripts/docker-build.sh
```

Open a container shell:

This puts you inside the prepared build environment so host-machine differences
do not affect the OP-TEE build. From here on, the commands run against the same
toolchain and paths that everyone else on the project uses.

```bash
scripts/docker-shell.sh
```

Inside the container, bootstrap OP-TEE from the pinned manifest:

This downloads the exact upstream OP-TEE components recorded for the project:
the Normal World Linux side, the Secure World OP-TEE OS side, firmware, boot
pieces, and examples. The pinned manifest keeps the emulator stack stable across
machines and over time.
The downloaded repositories and generated workspace files are placed under
`.optee-workspace/`, outside the source tree that should be committed.

```bash
scripts/bootstrap.sh
```

Build toolchains and the OP-TEE/QEMU images:

This compiles the cross-toolchains and then builds the full emulated platform
that QEMU will boot. Conceptually, this creates both sides of the TEE system:
Linux in the Normal World and OP-TEE in the Secure World.

```bash
scripts/build.sh
```

Run QEMU with text consoles:

This starts the virtual ARM machine that emulates the TrustZone hardware used by
OP-TEE. QEMU lets us develop and test TEE code without needing a physical board.

```bash
scripts/run-qemu.sh
```

`run-qemu.sh` starts a tmux session when needed. When QEMU starts, continue
execution with `ctrl + b then 1`, log in to the Normal World console as `root`, then run
the example client:

```bash
optee_example_hello_world
```

The example proves that a Linux process in the Normal World can call into a
Trusted Application running under OP-TEE in the Secure World and receive a
response.

## Run On Zeev

The Docker image is already present on zeev. Rebuild it with a different tag only if it changes.

Open the Docker shell:

This attaches to the existing OP-TEE Docker environment on `zeev` instead of
building directly on the host. Use it so the build runs with the expected
toolchain and filesystem layout.

```bash
./scripts/docker-shell.sh
```

Inside the container, bootstrap once for a fresh checkout:

This creates `.optee-workspace/` and syncs the pinned OP-TEE source tree. You
only need it when the workspace is missing or intentionally reset.
It downloads the upstream OP-TEE repositories, firmware, Linux/QEMU build
inputs, and examples into `.optee-workspace/` so the Git repository stays small.

```bash
scripts/bootstrap.sh
```

Inside the container, compile the project and OP-TEE images:

This copies this repository's example code into the OP-TEE tree and builds the
bootable QEMU images. The output includes the Normal World Linux image and the
Secure World OP-TEE binaries.

```bash
scripts/build.sh
```

Start QEMU:

This boots the compiled virtual TrustZone machine in QEMU and exposes its text
consoles through tmux. The custom ports and session name avoid collisions with
other users or runs on `zeev`.

```bash
QEMU_NW_PORT=55320 QEMU_SW_PORT=55321 QEMU_TMUX_SESSION=optee-qemu scripts/run-qemu.sh
```

`run-qemu.sh` uses tmux. After QEMU starts, switch to the serial-console tmux
window with:

This moves from the QEMU monitor window to the serial consoles where the guest
systems print logs and accept input. In this setup, tmux keeps the emulator
control channel and the emulated machine consoles in separate windows.

```text
Ctrl-b
1
```

The Normal World and Secure World consoles are in that tmux window. If execution
is still stopped at the QEMU monitor in window `0`, switch back with `Ctrl-b`
then `0`, type `c` and press Enter, then switch again with `Ctrl-b` then `1`.

In the Normal World console, log in as:

The Normal World is the regular Linux environment running beside OP-TEE. Logging
in as `root` gives you a shell where you can launch client applications that
request services from Trusted Applications.

```text
root
```

Run the program:

This starts the sample Normal World client, which sends a command through the
TEE client API into the Secure World. A successful response shows that Linux,
OP-TEE, and the Trusted Application can communicate correctly in QEMU.

```bash
optee_example_hello_world
```

Expected output:

```text
Invoking TA to increment 42
TA incremented value to 43
```

## Updating Project Source

Edit files under `project/optee_examples/`. The helper scripts sync those files
into `.optee-workspace/optee_examples/` before build and run.

To resync manually inside the container:

This copies changes from `project/optee_examples/` into OP-TEE's generated
workspace without rebuilding everything immediately. Use it when you changed
project source files and want the OP-TEE checkout to reflect those edits.

```bash
scripts/sync-project.sh
```

## Notes

- Do not commit `.optee-workspace/`, `out/`, `out-br/`, `toolchains/`, nested
  upstream `.git/` directories, IDE state, logs, or generated binaries.
- The original source checkout on `zeev` was used only as a read-only source for
  the initial manifest and example code.
