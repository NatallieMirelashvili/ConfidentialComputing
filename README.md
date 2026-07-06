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

** This takes around 20GB of disk space, make sure that your machine is up to it. **

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

Build toolchains, project code, and the OP-TEE/QEMU images:

This compiles the cross-toolchains and then builds the full emulated platform
that QEMU will boot. Conceptually, this creates both sides of the TEE system:
Linux in the Normal World and OP-TEE in the Secure World.

```bash
scripts/build-project.sh
```

Run the project in QEMU with text consoles:

This starts the virtual ARM machine that emulates the TrustZone hardware used by
OP-TEE. QEMU lets us develop and test TEE code without needing a physical board.
The helper opens the tmux session, continues QEMU from the monitor, switches to
the console window, logs in to the Normal World as `root`, and runs the project
edge-device client.

```bash
scripts/run-project.sh
```

The command it runs inside the Normal World console is:

```bash
optee_example_confidential_iot_edge
```


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
scripts/build-project.sh
```

Start QEMU and run the project:

This boots the compiled virtual TrustZone machine in QEMU and exposes its text
consoles through tmux. The helper continues QEMU, switches to the console
window, logs in as `root`, and runs the project edge-device client. The custom
session name avoids collisions with other users or runs on `zeev`.

```bash
QEMU_TMUX_SESSION=your-name-please-edit scripts/run-project.sh
```

The Normal World and Secure World consoles are shown in the tmux console window.
The helper waits for the `buildroot login:` prompt before typing `root`, then
waits for the root shell prompt before running the project binary.

The project edge-device program:

This starts the Normal World edge-device client, which runs the current project
stub flow and sends sensor data through the TEE client API into the Secure
World. A successful response shows that Linux, OP-TEE, and the project Trusted
Application can communicate correctly in QEMU.

```bash
optee_example_confidential_iot_edge
```

Expected output:

```text
edge_device: completed stub flow
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

