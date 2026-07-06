# Confidential Computing OP-TEE/QEMU

This repository is a lean, Docker-only wrapper around the OP-TEE QEMU v8
development environment used for the project. It does not vendor OP-TEE, Linux,
QEMU, Buildroot, toolchains, or build outputs. Those are recreated from the
pinned manifest in `manifests/locked-qemu_v8.xml`.

The supported runtime target is a Linux x86_64 Docker host. The repository can
be edited on macOS, but full OP-TEE/QEMU builds are not guaranteed on Docker
Desktop for Mac.

## Repository Layout

- `manifests/locked-qemu_v8.xml` - pinned OP-TEE manifest captured from `zeev`.
- `project/optee_examples/` - project CA/TA source overlaid into OP-TEE.
- `docker/Dockerfile` - Linux x86_64 build and QEMU runtime image.
- `scripts/` - Docker, bootstrap, build, source sync, and QEMU run helpers.
- `docs/` and project notes - design and course documentation.

Generated OP-TEE content is created under `.optee-workspace/` and ignored by Git.

## Quick Start

Build the Docker image:

```bash
scripts/docker-build.sh
```

Open a container shell:

```bash
scripts/docker-shell.sh
```

Inside the container, bootstrap OP-TEE from the pinned manifest:

```bash
scripts/bootstrap.sh
```

Build toolchains and the OP-TEE/QEMU images:

```bash
scripts/build.sh
```

Run QEMU with text consoles:

```bash
scripts/run-qemu.sh
```

`run-qemu.sh` starts a tmux session when needed. When QEMU starts, continue
execution with `c`, log in to the Normal World console as `root`, then run:

```bash
optee_example_hello_world
```

## Run On Zeev

The prepared staging checkout on `zeev` is:

```bash
ssh zeev
cd /home/owner/tomerlao/ConfidentialComputing
```

Build the Docker image if it is missing or if `docker/Dockerfile` changed:

```bash
./scripts/docker-build.sh
```

Open the Docker shell:

```bash
./scripts/docker-shell.sh
```

Inside the container, bootstrap once for a fresh checkout:

```bash
scripts/bootstrap.sh
```

Inside the container, compile the project and OP-TEE images:

```bash
scripts/build.sh
```

Start QEMU:

```bash
QEMU_NW_PORT=55320 QEMU_SW_PORT=55321 QEMU_TMUX_SESSION=optee-qemu scripts/run-qemu.sh
```

`run-qemu.sh` uses tmux. After QEMU starts, switch to the serial-console tmux
window with:

```text
Ctrl-b
1
```

The Normal World and Secure World consoles are in that tmux window. If execution
is still stopped at the QEMU monitor in window `0`, switch back with `Ctrl-b`
then `0`, type `c` and press Enter, then switch again with `Ctrl-b` then `1`.

In the Normal World console, log in as:

```text
root
```

Run the program:

```bash
optee_example_hello_world
```

Expected output:

```text
Invoking TA to increment 42
TA incremented value to 43
```

## One-Step Container Build

On a Linux x86_64 Docker host, this runs the Docker image build followed by
OP-TEE bootstrap and build:

```bash
scripts/full-build-in-docker.sh
```

The full OP-TEE build downloads and compiles large upstream projects. Expect many
gigabytes of generated data under `.optee-workspace/`.

## Updating Project Source

Edit files under `project/optee_examples/`. The helper scripts sync those files
into `.optee-workspace/optee_examples/` before build and run.

To resync manually inside the container:

```bash
scripts/sync-project.sh
```

## Notes

- Do not commit `.optee-workspace/`, `out/`, `out-br/`, `toolchains/`, nested
  upstream `.git/` directories, IDE state, logs, or generated binaries.
- The original source checkout on `zeev` was used only as a read-only source for
  the initial manifest and example code.
