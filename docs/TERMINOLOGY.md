# Terminology Glossary

Non-trivial terms used across `docs/ATTESTATION_DESIGN.md` and
`docs/ATTESTATION_TESTING.md`, grouped by area. Each entry explains the
concept and *why it shows up in this project specifically* — not just a
generic definition.

---

## TCG / TPM ecosystem

### TCG (Trusted Computing Group)
The industry standards body (IBM, Microsoft, Intel, AMD, Cisco, HP and
others) that defines the TPM specification, measured boot, and remote
attestation protocols. When this project's code/docs say something is
"the standard" way of doing attestation, this is the standard being
referred to — TCG's specs are what made TPM 2.0 (below) something everyone
implements the same way, instead of every vendor inventing their own.

### TPM (Trusted Platform Module) / TPM 2.0
A dedicated, isolated component (originally always a discrete chip) whose
whole job is: hold cryptographic keys that never leave it, and answer a
small, fixed set of commands (generate a key, sign something, report its
own integrity) without ever exposing the private material to the system it
protects. "TPM 2.0" is the current version of the spec (as opposed to the
older, less flexible TPM 1.2). We do not use a discrete TPM chip — see
**fTPM** below.

### fTPM (firmware TPM)
A *software* implementation of the full TPM 2.0 command set, running
inside an isolated execution environment instead of a physical chip.
**This is what we actually use**: `optee_ftpm` is a port of Microsoft's
reference implementation (`ms-tpm-20-ref`) built to run as a Trusted
Application inside OP-TEE/TrustZone (see below) on the Device Controller.
Why this matters: ARM TrustZone itself does *not* come with a TPM — fTPM is
a deliberate choice to get TPM 2.0's attestation semantics on hardware that
has no discrete TPM chip, by putting the TPM logic inside the same secure
world that already protects our own TA. It is completely unrelated to the
sensor module's `ATECC608A` secure element (a different, discrete chip used
for a different purpose — see **Secure Element** below).

### EK (Endorsement Key)
A TPM's root identity key, generated once from the **EPS** (below) and
effectively permanent for the life of that TPM instance. Not used directly
for signing attestations — it's the parent key that other keys (like the
AK) are created under, chaining trust back to "this specific TPM instance."

### EPS (Endorsement Primary Seed)
The root secret a TPM derives its Endorsement hierarchy from. On real
silicon this is burned in at manufacturing and never leaves the chip. Shows
up in this project because `ms-tpm-20-ref`'s standalone simulator variant
(`Samples/TPMCmd-DeviceID`) derives its EPS from device-unique but
*non-secret* values (MAC address, disk serial) instead of a real hardware
root — explicitly documented upstream as simulation-only, never usable as
an actual secret. We use that simulator purely as a fast local test double,
never as the real attestation root (that's the real fTPM running inside
OP-TEE on the actual boot image).

### AK (Attestation Key)
A signing key created under the EK, restricted to one job: signing TPM
Quotes (below). "Restricted" is a real TPM concept — a restricted key
literally cannot be used to sign arbitrary attacker-chosen data, only
TPM-internal structures like a Quote, which prevents an attacker from
tricking the TPM into producing a signature over something that *looks
like* a quote but isn't. Each device gets its own AK during provisioning
(`scripts/provision-device.sh`); the server's registry stores its public
half per `device_id` and uses it to verify every quote that device ever
sends.

### PCR (Platform Configuration Register)
One of a small bank of registers inside the TPM, each holding a running
hash. PCRs are **not written directly** — they're only ever "extended":
`PCR[n] = Hash(PCR[n] || new_measurement)`. This one-way accumulation is
the whole point: you can add measurements to a PCR but never remove or
directly overwrite one, so its final value is a tamper-evident summary of
everything that was measured into it since the last reset. PCRs reset to a
known value (usually zero) on every power-on. In this project, our fTPM
extends a PCR at TA-init time as part of its own event-log processing; our
attestation protocol quotes `sha256:0` specifically.

### Measured Boot
The general practice of hashing ("measuring") each stage of a boot chain
(bootloader → OS → application) into PCRs as it loads, so that afterward a
PCR quote can prove *what actually ran this boot*, not just "the signing
key exists." This is the property that makes TPM-based attestation
meaningfully stronger than a static signed version string — see
`docs/ATTESTATION_DESIGN.md` §2.1 for why this specific property was the
deciding factor in this project's design.

### Event Log (TCG Event Log)
A log, kept alongside the PCRs, of *what* was measured into them and in
what order — the PCR value alone is just a hash, so you need the event log
to reconstruct/audit "PCR 0 = X because these specific things were
measured." `optee_ftpm`'s README documents that it reads a TPM-compatible
event log and extends PCRs from it during TA initialization
(`CFG_TA_MEASURED_BOOT`).

### Quote (`TPM2_Quote`)
The actual TPM command used for attestation: "sign a structure containing
{selected PCR values, some caller-supplied nonce/qualifying data} with this
restricted AK." The output is a `TPMS_ATTEST` structure (see below) plus a
signature over it. This is the cryptographic core of the whole protocol —
everything else in our design exists to get a nonce to the device, get a
quote back, and verify it.

### TPM2B_ATTEST / TPMS_ATTEST
The TPM 2.0 wire-format structures a Quote produces.
`TPM2B_ATTEST` is just a 2-byte length prefix wrapping a `TPMS_ATTEST`
body; `TPMS_ATTEST` itself contains a magic value (proves "a real TPM
produced this"), the type of attestation (Quote, in our case), the
`extraData` field (our qualifying data — see **Transcript Hash** below),
and — for a Quote — the selected PCRs and their combined digest.
`server/attestation.py`'s `parse_tpms_attest()` hand-parses these exact
bytes per the TPM 2.0 Part 2 spec, since Python has no off-the-shelf
TPM-structure library in this project's dependency set.

### TPMT_SIGNATURE
The wire-format structure holding the signature over a `TPMS_ATTEST`: which
signature algorithm (we use ECDSA), which hash (SHA-256), and the raw
`(r, s)` values. `server/attestation.py`'s `parse_tpmt_signature_ecdsa()`
parses this so the `(r, s)` pair can be handed to Python's `cryptography`
library for verification.

### Qualifying Data / extraData
TPM terminology for "arbitrary caller-supplied data included in and signed
as part of a Quote" — the mechanism that lets a Verifier bind a quote to a
specific challenge (so old quotes can't be replayed). In this project it's
where we put the **Transcript Hash** (below): the device asks the TPM to
quote `SHA-256(nonce ‖ server_ecdh_pub ‖ device_ecdh_pub)` as its
qualifying data.

### Transcript Hash
Not TCG terminology — our own term for
`SHA-256(nonce ‖ server_ecdh_pub ‖ device_ecdh_pub)`, computed independently
by both device and server. On the device it is computed *inside* the
`confidential_iot` TA (via the TEE Internal Core API's SHA-256 digest
operation) and returned to the Host CA together with the ephemeral pubkey;
on the server it's a `hashlib.sha256` call. Putting it in the quote's
qualifying data means a single signature simultaneously proves "this TPM is
genuine and its PCRs match" *and* "this specific key exchange is
authentic," without the fTPM ever needing to know anything about ECDH.

### tpm2-tools / tpm2-tss
The standard open-source, userspace command-line tools (`tpm2-tools`, e.g.
`tpm2_quote`, `tpm2_createak`) and the underlying software stack
(`tpm2-tss`, the TCG Software Stack implementation) used to talk to *any*
TPM 2.0 — real chip or fTPM — from Normal World Linux. Both are already
built into this project's target rootfs; we shell out to `tpm2_quote` /
`tpm2_pcrread` / `tpm2_createek` / `tpm2_createak` rather than hand-writing
TPM2 command marshaling ourselves.

### TCTI (TPM Command Transmission Interface)
The pluggable transport layer `tpm2-tools`/`tpm2-tss` use to actually reach
a TPM — e.g. the `device` TCTI talks to a kernel `/dev/tpmrm0` node, while
the `mssim` TCTI talks to a software simulator over a TCP socket. Mentioned
here because it's *why* a local software TPM simulator (like
`ms-tpm-20-ref`'s standalone `TPMCmd-DeviceID` build) can be used for fast
local testing with the exact same `tpm2-tools` CLI, just pointed at a
different TCTI, instead of the real `/dev/tpmrm0` device.

---

## OP-TEE / TrustZone ecosystem

### TEE (Trusted Execution Environment)
A general term for an isolated execution environment on the *same* chip as
the main OS, protected from it in hardware. ARM TrustZone (below) is the
specific hardware mechanism this project uses to implement a TEE.

### ARM TrustZone
The ARM CPU feature that splits execution into two worlds — **Secure
World** and **Normal World** — enforced by the hardware itself, not by
software. Normal World (the "Rich OS", Linux in our case) cannot read
Secure World memory no matter what runs in it; this is the actual root of
the whole threat model's assumption that "the attacker can fully compromise
Normal World but not OP-TEE or the TA."

### OP-TEE (Open Portable Trusted Execution Environment)
The open-source Secure World operating system this project runs inside
TrustZone. It's the specific "OS" that our own TA and the separate
`optee_ftpm` TA both run under.

### TA (Trusted Application)
A piece of code that runs *inside* the Secure World, under OP-TEE. Our own
`confidential_iot` TA and the separate `optee_ftpm` TA are both TAs, each
with its own isolated memory — see `docs/ATTESTATION_DESIGN.md` §2.2 for why
that isolation is the reason the session key is derived in our own TA
rather than the fTPM.

### Host / Host CA (Client Application, "CA")
The Normal World program that talks to a TA. "CA" is the GlobalPlatform
term (Client Application); this project's code and docs mostly say "Host"
or "Host CA" for the same thing — `edge_device.c`/`main.c` is the Host CA
for our TA. The Host is explicitly *not* trusted (it's Normal World), so it
only ever shuttles opaque bytes to/from the TA; no cryptographic secret is
ever computed in Host code.

### TEEC / TEE Client API
The GlobalPlatform-standard API (`TEEC_InitializeContext`,
`TEEC_OpenSession`, `TEEC_InvokeCommand`, ...) a Host uses to talk to a TA.
`edge_device.c` opens one persistent `TEEC_Session` and reuses it across
the whole attestation handshake — necessary because our TA's per-session
ECDH state (the whole reason the handshake works) only survives as long as
that session stays open.

### GlobalPlatform TEE Internal Core API
The standard API a TA itself uses for cryptography and storage
(`TEE_GenerateKey`, `TEE_DeriveKey`, `TEE_AEEncryptFinal`, ...). Our TA uses
this directly for ECDH, HKDF, and AES-GCM — deliberately, so that no
external crypto library needs to be pulled into the TA build at all.

### TCB (Trusted Computing Base)
The set of everything a system's security depends on being correct/
uncompromised — everything *outside* the TCB is something the attacker is
assumed able to fully control. This project's spec explicitly lists OP-TEE
OS, the TA, and the server as inside the TCB, and Normal World Linux as
outside it — which is the reason the ECDH/session-key logic had to move
into the TA rather than staying in the Host CA.

---

## Cryptography

### ECDH (Elliptic Curve Diffie-Hellman)
A key-agreement algorithm: two parties each generate a keypair, exchange
public keys, and each independently computes the *same* shared secret from
their own private key + the other's public key — without that secret ever
crossing the network. Used twice in this codebase: once for the existing
browser↔server channel (`crypto.py`), and now again for the device↔server
channel, with the device's half computed inside the TA.

### ECDSA (Elliptic Curve Digital Signature Algorithm)
A signature algorithm (different purpose from ECDH, even though both use
elliptic curves) — used here for the TPM's AK signing a Quote, and verified
server-side against the registered AK public key.

### P-256 / secp256r1 / NIST P-256
The specific elliptic curve used throughout this project (both the
existing browser channel and our new device channel) for ECDH and ECDSA.
"P-256," "secp256r1," and "NIST P-256" are three names for the exact same
curve, used interchangeably across different libraries' documentation
(GlobalPlatform's TEE API, Python's `cryptography`, and TPM 2.0 all name it
slightly differently).

### HKDF (HMAC-based Key Derivation Function)
Takes a not-necessarily-uniform secret (like a raw ECDH shared value) and
stretches/mixes it into a proper, uniform-looking symmetric key, using a
`salt` and `info` label for domain separation — so the *same* underlying
secret produces a *different* key in a different context. In our protocol,
`salt` = the attestation nonce (binds the derived key to one specific
attested session) and `info` = a fixed label distinct from the browser
channel's own label, so the two channels' keys can never collide even if
somehow the same raw secret were ever reused.

### AEAD / AES-GCM
"Authenticated Encryption with Associated Data" — encryption that also
detects tampering (as opposed to plain encryption, which hides data but
doesn't prove it wasn't modified). AES-GCM is the specific AEAD algorithm
used for both the browser channel and, now, the device channel's `data`
messages. "Associated Data" (`aad`) is authenticated but not encrypted; we
use the `device_id` as `aad` so a ciphertext can't be silently replayed
under a different device's identity.

### Nonce
A value used *once* per session/message specifically to prevent replay —
"number used once." Two different nonces show up in this project: the
12-byte AES-GCM nonce (a fresh one per encrypted message) and the
32-byte attestation nonce the server issues per challenge (fresh per
attestation attempt, embedded in the quote's qualifying data).

### Prover / Verifier
The two roles in any remote-attestation protocol: the **Prover** is the
party proving its own integrity (the Device, here); the **Verifier**
checks that proof and decides whether to trust it (the Server). Explicitly
named this way in the course spec's own threat model.

---

## Project / build-system specific

### Buildroot
The build system that assembles the Normal World Linux root filesystem
(kernel config, userspace packages like `tpm2-tools`, and our own compiled
binaries) into the bootable image QEMU runs. Its package/Kconfig mechanism
is why enabling something like a kernel driver is a matter of a config
flag rather than hand-patching source.

### mbedTLS
A small, widely-used, embedded-friendly TLS/crypto C library. It appears
**twice** in this project, as two completely separate builds: (1) OP-TEE
core compiles its own copy in as the Secure-World crypto backend — this is
what actually executes when our TA calls `TEE_ALG_SHA256`/`TEE_ALG_ECDH_P256`
etc.; (2) a second, Normal-World copy is built by Buildroot
(`BR2_PACKAGE_MBEDTLS`, see `project/buildroot/packages.conf`) so the Host
CA can link `libmbedcrypto` for base64 encoding/decoding. The two builds
share source lineage but are not linkable across the world boundary —
which is *why* enabling the Buildroot package was necessary at all.

### cJSON
An "ultra-lightweight, single-file, ANSI-C" JSON parser/builder (MIT
license), enabled as the Buildroot package `BR2_PACKAGE_CJSON`. The Host CA
uses it to build and parse the newline-delimited JSON messages of the
device↔server protocol — replacing an earlier hand-rolled minimal JSON
helper, per the course's "use a vetted library" requirement (see
`docs/ATTESTATION_DESIGN.md` §2.5). Chosen over Buildroot's other JSON
options (json-c, jansson) as the lightest one that covers this project's
flat, fixed-shape messages.

### `.mk` file
A GNU Make **include-fragment**: a plain text file of Make variable
assignments (`srcs-y += foo.c`, `global-incdirs-y += include`,
`CFG_TA_MEASURED_BOOT=y`) meant to be pulled into another Makefile via
`include foo.mk`. It's pure build tooling — which files to compile, which
include paths to add, which config flags to set — with **no runtime
meaning at all**. This is *not* an interface-definition mechanism: OP-TEE
has no equivalent of SGX's `.edl` (Enclave Definition Language) files or
its `sgx_edger8r` code generator. The TA↔Host boundary here is just a
hand-written shared header (`confidential_iot_ta.h`) declaring a UUID and
command-ID integers, with a fixed, generic 4-slot parameter convention
(`TEEC_Operation.params[4]`) that both sides have to manually agree on by
convention — no schema, no generated marshaling stubs.

### `CFG_*` (OP-TEE build-configuration variables)
OP-TEE's own family of build-time feature switches — plain Make variables
with conventional `?=` defaults (e.g. `CFG_CRYPTO_ECC ?= y`,
`CFG_CRYPTO_HKDF ?= y`, `CFG_TA_MEASURED_BOOT=y`), *not* a real Kconfig
system (no menuconfig UI, no dependency resolution — just a literal string
comparison against `"y"` in a Makefile `ifeq`). A single `CFG_*` variable
typically controls two things at once: which `.c` files get compiled in
(via a Makefile conditional) and which C preprocessor `#ifdef`s activate.
**Why it matters here:** it's how we confirmed, just by reading these
files, that ECC/HKDF/AES-GCM support and Measured Boot were already
enabled by default — no build changes were needed to get the crypto this
project relies on.

### The `y` / `m` / `n` convention ("tristate")
The "enabled" spelling above (`y`) is borrowed from the Linux kernel's
Kconfig system: `y` = built directly in, `m` = built as a separately
loadable module, unset/`n` = not built at all. This project's build
touches **three different systems** that all follow this same spelling by
convention, even though only two of them are a real Kconfig:
- `CONFIG_*` — the actual Linux kernel Kconfig
  (`CONFIG_TCG_FTPM_TEE=y` in the kernel `.config` — specifically `y`, not
  `m`, which is *why* the fTPM driver needed no modprobe step: it's
  compiled straight into the kernel Image).
- `BR2_*` — Buildroot's own Kconfig (`BR2_PACKAGE_LINUX_FTPM_MOD_EXT`).
- `CFG_*` — OP-TEE's simpler, non-Kconfig imitation of the same idea (see
  above).

### `srcs-y` / kbuild-style conditional source lists
The actual mechanism that *consumes* a `CFG_*`/`CONFIG_*` value to decide
what gets compiled. `srcs-y += file.c` (seen in every `sub.mk` in this
project, e.g. `edge_device/ta/sub.mk`) unconditionally adds `file.c` to the
build — the `y` here is a literal, meaning "for every configuration."
`srcs-$(CFG_CRYPTO_HKDF) += tee_cryp_hkdf.c` (the real line from
`optee_os/core/tee/sub.mk`) is the *same* mechanism, just parameterized:
Make expands `$(CFG_CRYPTO_HKDF)` first, so this line literally becomes
`srcs-y += tee_cryp_hkdf.c` if the variable is `y`, or a harmless
do-nothing line otherwise. One idiom, two uses — hardcoded (always) vs.
parameterized (conditional on a `CFG_*`/`CONFIG_*` variable).

### Manifest / `repo` tool
Google's `repo` tool (originally built for Android) checks out a *set* of
git repositories at pinned versions, described by an XML "manifest" file.
`manifests/locked-qemu_v8.xml` is this project's pinned manifest — it's why
`.optee-workspace/` can be regenerated identically by anyone, any time,
from a clean checkout.

### QEMU
The machine emulator used to run an ARM system (with TrustZone support)
without needing physical hardware — this project's whole Device Controller
is "an ARM board" only in the sense that QEMU emulates one.

### TF-A (Trusted Firmware-A)
ARM's reference secure firmware, the first code that runs on boot before
handing off to OP-TEE and Linux. Relevant here mainly as *part of* the
measured-boot chain in principle (see **Measured Boot** above) — this
project's current design measures at the fTPM TA's own init, not all the
way back through TF-A, which is one of the documented simplifications.

### Secure Element (e.g. `ATECC608A`)
A small, discrete cryptographic chip used in the **Sensor Module** (not the
Device Controller) to hold the sensor's identity secret and answer an
HMAC-SHA256 challenge-response. Called out here specifically because it is
**unrelated** to everything else in this glossary — it's a different piece
of hardware, protecting a different link (Sensor↔Device, not Device↔Server),
and out of scope for the attestation/key-exchange work described in
`docs/ATTESTATION_DESIGN.md`.
