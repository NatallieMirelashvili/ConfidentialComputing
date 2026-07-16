# Device↔Server Remote Attestation, Key Exchange & Registration — Design

This document explains **what was added, why it was designed this way, and
where each piece lives**. It covers the Device/TA side
(`project/optee_examples/confidential_iot/`) and the Server side
(`CC_Server`).

See also: `docs/ATTESTATION_TESTING.md` for how to build, run, and test all
of this.

## 1. Mission and starting point

Per the course spec (`docs/פרויקט סוף קורס...pdf`), the system is:

```
Sensor Module → Device Controller (QEMU ARM + OP-TEE/TrustZone) → Management Server
```

The Device is the **Prover**, the Server is the **Verifier**. Before this
work:

- The device side (`project/optee_examples/confidential_iot/`) was a pure
  stub: every TA/Host function returned `TEE_SUCCESS`/`0` unconditionally,
  no networking existed at all.
- The server side (`CC_Server`, built by a peer) had a fully working
  browser↔server channel (TLS or app-layer ECDH+HKDF+AES-GCM), but its
  device-facing link (`device_link/network.py`) was an explicitly-flagged
  placeholder: it accepted plaintext JSON over TCP and **trusted whatever
  `attested: true/false` the device claimed about itself** — no signature,
  no nonce, no device registry of any kind.

The goal of this work: real remote attestation, the session-key exchange it
gates, and a device registration mechanism — replacing that trust-on-say-so
placeholder with something cryptographically real.

## 2. Key design decisions (and why)

### 2.1 TPM2 quote via the fTPM, not a bespoke signed report

Two designs were considered:

- **Option A (rejected):** the TA itself holds a signing keypair and signs
  `{nonce, static version string}`. Simple, but a compile-time "measurement"
  constant is the same across every reboot — it can't express *what actually
  booted this time*.
- **Option B (chosen):** use the software TPM already wired into this
  project's OP-TEE build (`optee_ftpm`, a port of Microsoft's
  `ms-tpm-20-ref`) to produce a real `TPM2_Quote`: a signature over
  {current PCR values, a nonce} using a TPM-resident Attestation Key (AK).

The deciding factor: **TPM attestation is fundamentally tied to measured
boot.** PCRs reset to zero every power-on and get freshly extended through
the boot chain during that specific boot. A quote over live PCR state proves
*this boot's* code identity, and it inherently forces re-attestation after
every reboot — a replayed quote from a previous boot won't match a fresh
nonce, and the PCR state itself resets. A static signed value cannot express
either property.

This was also a pragmatic choice, not just an ideal one — direct inspection
of the build tree confirmed the fTPM path was nearly free:

- `optee_ftpm` (TA UUID `bc50d971-d4c9-42c4-82cb-343fb7f37896`) is a **hard
  dependency of the standard top-level build**
  (`build/common.mk`: `optee-os-common: ftpm`), with
  `CFG_TA_MEASURED_BOOT=y` on by default.
- `tpm2-tools`/`tpm2-tss` (the full userspace TPM2 command-line stack) are
  **already built into the Normal World rootfs**.
- `build/kconfigs/qemu.conf` (part of the clean, upstream `build` repo,
  reproducible from the pinned manifest) already sets
  `CONFIG_TCG_TPM=y` / `CONFIG_TCG_FTPM_TEE=y`, **built directly into the
  kernel** (not a loadable module — no modprobe/udev work needed either).

So: **no build-system changes were needed to get the TPM2 stack** — only
protocol/application code. (The Host CA's later switch to real
base64/JSON libraries did need two extra Buildroot packages — see §2.5.)

### 2.2 Two TAs, cleanly separated (why the session key never touches the fTPM)

`optee_ftpm` (third-party, not modified) and this project's own
`confidential_iot` TA are **separate TAs**. OP-TEE TAs cannot share memory
or call each other directly — anything crossing between them passes through
untrusted Normal World. That constrains the design:

- The **fTPM is used narrowly, only as a signing oracle**: it quotes a hash
  of *public* transcript data (nonce + both ephemeral ECDH public keys) —
  never anything secret.
- The **ECDH key exchange and session-key derivation happen entirely inside
  the `confidential_iot` TA**, using OP-TEE's native GlobalPlatform TEE
  Internal API (`TEE_ALG_ECDH_P256` + `TEE_ALG_HKDF_SHA256_DERIVE_KEY` +
  `TEE_ALG_AES_GCM`, plus the `TEE_ALG_SHA256` transcript digest — no
  external crypto library needed in the TA). The session key
  never leaves this TA's secure-world memory for its entire lifetime.

This keeps the one thing that must stay secret (the session key) inside a
single TA's isolated memory throughout, while still getting a genuine
integrity proof from the fTPM. (How PCR0 is actually measured on this QEMU
image — and why it is a Normal-World software stand-in rather than the firmware
measured-boot chain — is covered in §2.9.)

### 2.3 Admin-gated registration, not self-registration

A device must be **enrolled** (its Attestation Key + PCR baseline recorded
in the server's registry) before it can attest. Enrollment happens through
the existing, already-authenticated User↔Server channel
(`POST /api/devices/register`, protected by whatever transport mode is
active — TLS or AES-GCM) — **never** over the open device-facing TCP port,
which has no admin authentication. This matches the project's own threat
model: the attacker has no trusted credentials, so an unauthenticated
self-registration path would let an attacker enroll a fake device.

### 2.4 Reproducibility constraint

`ConfidentialComputing/.optee-workspace/` is entirely generated
(`repo sync` from the pinned `manifests/locked-qemu_v8.xml`) and
git-ignored. **Every change lives in a tracked location**
(`project/optee_examples/...`) that `scripts/sync-project.sh` copies into
the workspace before every build — nothing was hand-edited inside
`.optee-workspace` itself, so a clean `scripts/bootstrap.sh` +
`scripts/build-project.sh` reproduces everything from scratch.

The same constraint covers Buildroot's package selection: the generated
`.config` under `out-br/` can't be hand-edited in a way that survives.
Instead, the tracked fragment `project/buildroot/packages.conf` lists the
extra `BR2_PACKAGE_*` options, and `scripts/build.sh` exports them into the
environment of the OP-TEE `make` — whose `common.mk` folds every `BR2_*`
environment variable into `out-br/extra.conf`, the last-and-winning
defconfig fragment fed to Buildroot. Deterministic on every build, zero
edits inside the workspace.

### 2.5 Real libraries instead of hand-rolled helpers

The Host CA needs SHA-256 (transcript hash), base64, and JSON for the wire
protocol. The first implementation hand-rolled all three (no library was
linkable from the Normal-World build at the time); that violated the
course's "use a vetted library, don't self-implement crypto/encoding" rule
and has been replaced:

- **SHA-256 → inside the TA.** The transcript hash is now computed by the
  `confidential_iot` TA itself via the GP TEE Internal Core API
  (`TEE_ALG_SHA256` digest operation, backed by the mbedTLS build already
  inside OP-TEE core), and returned to the Host alongside the ephemeral
  pubkey. The digest is over public data only, so returning it to Normal
  World gives up nothing; and this needed zero new build infrastructure.
- **base64 → mbedTLS** (`mbedtls_base64_encode/decode` from
  `libmbedcrypto`), via the Buildroot package `BR2_PACKAGE_MBEDTLS`. This
  is a *second*, Normal-World build of mbedTLS — separate from the copy
  compiled into OP-TEE core as the Secure-World crypto backend, which is
  not linkable from Normal World.
- **JSON → cJSON** (`BR2_PACKAGE_CJSON`): single-file, MIT-licensed,
  ANSI-C JSON parser/builder — the lightest of Buildroot's JSON options
  (json-c and jansson are multi-file libraries with no feature this
  project's flat, fixed-shape messages need).

`net.c` stays: it is a thin wrapper over POSIX sockets (already the
standard libc interface), not a self-implementation of anything.

### 2.6 Sensor-authentication gate (enforcement now, real check later)

The spec's normal-operation flow has the Sensor Module authenticate itself
to the Device (a Secure-Element HMAC-SHA256 challenge-response) before its
data is trusted. That challenge-response is **out of scope** for this work —
but a subtle trap had to be handled up front rather than left for later: if
the **Host CA** (untrusted Normal World) were the thing that decided "the
sensor authenticated, proceed," an attacker who controls Normal World could
simply patch that decision out. The security therefore can't come from the
Host choosing to call the check — it has to come from the TA refusing to do
anything useful until its *own* state says the check passed.

So the **enforcement** was built now, even though the check itself is still
a stub:

- `struct confidential_iot_session` gained a `sensor_authenticated` flag,
  initialized `false` at every session open (= every boot).
- `ta_authenticate_sensor` is the only thing that sets it `true`. Today it
  is a stub that unconditionally succeeds; when the real HMAC
  challenge-response is implemented it **must** verify inside the TA and set
  the flag only on a genuine match — never trust a Host-supplied "it
  matched" result.
- `ta_protect_sensor_data` (and `ta_process_sensor_data`) return
  `TEE_ERROR_BAD_STATE` unless `sensor_authenticated` is true.
  `ta_protect_sensor_data` requires *both* it **and** `session_key_valid` —
  the two independent trust gates (Sensor↔Device and Device↔Server).
- The Host calls `edge_authenticate_sensor()` once per boot (in `main()`,
  right after init). But because the verdict and its enforcement live in the
  TA, a tampered Host that deletes that call gains nothing: the data path
  stays closed.

This is the same principle as the Server↔Device relationship one layer up —
the Verifier never trusts the Prover's self-report; here the TA never trusts
the Host's self-report.

**What is deliberately *not* final yet:** the *parameter interface* of the
`AUTHENTICATE_SENSOR` command is a placeholder (no parameters), matching the
stub. A real challenge-response can't be parameterless — because the
emulated Secure Element (`sensor_module/secure_element.c`) runs in Normal
World, the TA can't reach it directly, so the challenge/response must be
relayed through the Host (TA emits a challenge → Host relays it to the SE →
response comes back → Host passes it into the TA → TA verifies). That will
require real parameters (and most likely a second command). So when the real
check lands, the command's params and `edge_authenticate_sensor()`'s body
will need real code — but the gate itself (the flag, the enforcement in
protect/process, the per-boot call) is shaped correctly and will not change.

### 2.7 Inner-session anti-replay (authenticated sequence number)

The attestation nonce already gives *session-level* freshness: a whole session
replayed from a previous run fails, because each attestation derives a new
per-session key and an old session's `data` won't decrypt under it. What that
does **not** stop is a replay *within* a live session — an attacker capturing
one valid `data` message and re-sending it byte-for-byte. GCM's tag proves a
message was validly encrypted under the key; it does **not** prove the message
hasn't been seen before. So this needed a separate mechanism.

The mechanism is an **authenticated monotonic sequence number**, deliberately
kept distinct from the GCM nonce (which keeps its one job — uniqueness for the
cipher — via the random 96-bit value; see the note below):

- The TA holds a per-session counter (`send_seq`), incremented for every
  `PROTECT_SENSOR_DATA` message. The counter is **authenticated as the GCM
  AAD** (8-byte big-endian), and returned to the Host so it can travel on the
  wire as the `data` message's `seq` field.
- The server (`AttestationVerifier.check_and_advance_seq`) accepts a `seq`
  only if it is **strictly greater** than the highest it has already accepted
  for that device's current session, then records it as the new high-water
  mark. A replayed or out-of-order message is rejected.
- Order matters: the server verifies the **GCM tag first** (which binds the
  seq, because it's the AAD), and only then applies the monotonic check. This
  is why the seq is authenticated rather than sent in the clear — an attacker
  can't renumber a captured message to a fresh, higher `seq` to dodge the
  replay check, because changing the seq breaks the tag and the message is
  rejected at decryption.
- The counter is reset to 0 on both sides whenever a **new session key** is
  derived (`ta_handshake_complete` on the device, `verify_and_derive` on the
  server), so a fresh attestation restarts the sequence in lockstep. A replay
  of a message from *before* a re-attestation also fails independently, since
  it was encrypted under the now-replaced key.

**Why a sequence number, and not "track the nonce" or "use a counter as the
nonce":** the GCM nonce and the anti-replay label are two different jobs, and
merging them is a classic footgun. The nonce must guarantee *cipher
uniqueness* (and stays random — a server-side nonce check cannot undo the
on-the-wire damage of a nonce reuse, which happens at encryption time). The
sequence number provides *ordering / replay rejection* and must be
*authenticated* to be meaningful. Keeping them separate lets each do its job:
random nonce for uniqueness, monotonic seq-in-AAD for anti-replay.

**Why the AAD is just `seq` (not `device_id ‖ seq`):** device identity is
already bound cryptographically — the session key is derived per-device from
that device's ephemeral ECDH key and its attestation nonce, and the server
looks the key up by `device_id`. A different device has an entirely different
key, so binding `device_id` in the AAD too would be redundant. (This also
avoids threading `device_id` into the TA's fixed four-parameter command
interface, which has no free slot for it alongside the seq output.)

### 2.8 Concurrent multi-device support

The server side (`CC_Server`) was already fully multi-device-safe by design — every piece of
per-device state (attestation challenges, session keys, the §2.7 anti-replay counter, the device
registry) is a dict keyed by `device_id`, and the device-facing listener is a threaded TCP server
handling one connection per thread. What was missing was entirely on the QEMU/device-runner side:
`scripts/run-project.sh` always launched QEMU with one hardcoded gdbstub port (`-s` = `tcp::1234`,
baked unconditionally into the upstream `qemu_v8.mk`) and never gave the auto-launched device a
distinct `device_id` — so a 2nd concurrent instance either failed outright (port collision) or
silently collided with the first instance's identity in the server's per-`device_id` state.

The fix adds one new knob, `QEMU_INSTANCE` (default `0`): it derives a distinct gdbstub port, pair
of serial-console ports, and default `device_id` (`iot-edge-01`, `iot-edge-02`, ...) per instance.
The tmux automation now also runs `provision-device.sh` for that `device_id` automatically before
starting the edge binary, retrying it for up to ~90s — the fTPM device node is not reliably usable
the instant the shell prompt appears, an observed timing issue unrelated to any specific action
(running the edge binary first doesn't change it). See `docs/ATTESTATION_TESTING.md` §5 for the
full multi-device runbook. The actual `POST /api/devices/register` admin step stays manual, per
§2.3 — automating it would mean embedding admin credentials into an unattended script, which the
admin-gated design deliberately avoids.

### 2.9 Measured-boot PCR0: real firmware chain attempted, Normal-World stand-in used on QEMU

§2.1 relies on PCR0 reflecting *what actually booted*. Producing a real,
non-degenerate PCR0 turned out to need work, and on this QEMU topology a
compromise.

**The firmware chain was enabled but does not reach the fTPM on QEMU.**
Measured boot is a three-link chain, and by default only the last link was on:

1. **TF-A** produces the TCG event log and measures BL31/BL32/BL33 — needs
   `MEASURED_BOOT=1` (was **off**).
2. **OP-TEE core** forwards that log to the fTPM — needs
   `CFG_CORE_TPM_EVENT_LOG=y` (was **off**).
3. **The fTPM** replays the log to extend PCRs — `CFG_TA_MEASURED_BOOT=y`,
   already **on**.

Links 1–2 are now enabled reproducibly by two idempotent `sed` patches in
`scripts/sync-project.sh` (TF-A: `MEASURED_BOOT=1 EVENT_LOG_LEVEL=20
TPM_HASH_ALG=sha256 MBEDTLS_DIR=$(ROOT)/mbedtls`; OP-TEE core: `CFG_DT=y
CFG_CORE_TPM_EVENT_LOG=y`). TF-A v2.14 builds its event-log library
(`libeventlog.a`) with **cmake**, which the base build image lacked, so `cmake`
was added to `docker/Dockerfile`. With all three links on, the image builds and
boots — **but PCR0 still reads all-zeros.**

The reason is a topology gap. This build uses the **opteed (non-FFA) SPD**, and
in that mode OP-TEE core reads the event log from the **Normal-World device
tree**, not the secure manifest
(`core/arch/arm/kernel/boot.c`: `#ifdef CFG_CORE_FFA … tpm_map_log_area(get_manifest_dt())
#else … tpm_map_log_area(get_external_dt())`). TF-A never populates the
`arm,tpm_event_log` node in that Normal-World DT, so core logs
`TPM: Fail to find TPM node` / `TPM Event log size: 0 Bytes`, the System PTA
(`PTA_SYSTEM_GET_TPM_EVENT_LOG`) returns nothing, and the fTPM's
`process_eventlog()` extends nothing. Fixing it for real would mean injecting
that DT node or switching to the SPMC/FFA topology (where core reads the
manifest DT TF-A *does* populate via `qemu_set_tos_fw_info`) — a firmware/DT
detour. **This also corrects an earlier hypothesis in this doc** that the wrong
PCR *index* was being quoted: TF-A's QEMU metadata
(`plat/qemu/qemu/qemu_measured_boot.c`) maps every image to `PCR_0`, so
`sha256:0` was always the correct index — the broken chain, not the index, was
the problem.

**The stand-in.** `provision-device.sh` now performs a **Normal-World software
measurement**: `software_measure_pcr0()` extends PCR0 once per boot with
`SHA-256` of the security-relevant runtime artifacts — the `confidential_iot`
TA (`/lib/optee_armtz/7d9f6d20-…-0001.ta`), then the edge Host binary
(`/usr/bin/optee_example_confidential_iot_edge`), in fixed order via
`tpm2_pcrextend`. It is guarded to run only while PCR0 is still all-zero, so it
is idempotent within a boot (safe against the provisioning retry loop and the
"already provisioned" reprint path) and **automatically defers** to firmware
measured boot should that ever start extending PCR0. It runs before the
enrollment baseline is read, so the baseline and the edge binary's later quote
observe the same value. Result: a PCR0 that is **non-zero, identical across
reboots of the same image, and different if either artifact is tampered** —
exactly what the enrollment baseline (§3d) and quote need. Verified on the real
image: the value is non-zero and stable across reboots.

**Security caveat (also stated in the script).** This extension happens in
Normal World, so unlike real measured boot it is **not hardware-rooted** — a
Normal-World attacker could extend the "good" hashes while running tampered
code. On real hardware the TF-A→OP-TEE→fTPM chain provides this property with a
hardware root of trust; the stand-in exists only because that chain is not
wired end-to-end under QEMU. Note that PCRs measure *code identity*, so an
identical PCR0 across identical devices is correct and expected — device
identity comes from the per-device AK (§2.3), never from the PCR value.

## 3. The protocol

Newline-delimited JSON over the existing device-facing TCP port (matches
`CC_Server`'s existing wire-framing style), all within one continuous TCP
connection:

```
1. device → server   {"type":"hello","device_id":"..."}
2. server → device   {"type":"attest_challenge","nonce":"<b64>","server_ecdh_pub":"<b64>"}
3. device → server   {"type":"attest_response","device_id":"...",
                       "device_ecdh_pub":"<b64>","quote":"<b64>",
                       "signature":"<b64>","pcr_values":"<text>"}
4. server → device   {"type":"attest_result","ok":true,"session_ttl":3600}
                      | {"ok":false,"error":"..."}
5. device → server   {"type":"data","device_id":"...","seq":<int>,"nonce":"<b64>","ciphertext":"<b64>"}
   server → device   {"ok":true} | {"ok":false,"error":"..."}   (repeatable)
```

`seq` is a per-session, monotonically increasing message counter used for
inner-session anti-replay — see §2.7.

### Device side, step 3 in detail

1. Ask the TA (`TA_CONFIDENTIAL_IOT_CMD_GENERATE_ATTESTATION_EVIDENCE`) for
   a fresh ephemeral ECDH keypair, passing in the server's nonce and
   `server_ecdh_pub`; get back the public half **and**
   `transcript_hash = SHA-256(nonce ‖ server_ecdh_pub ‖ device_ecdh_pub)`,
   computed inside the TA via the TEE Internal Core API (all inputs are
   public, so returning the digest to Normal World is safe — see §2.5).
2. Run `tpm2_quote` against the fTPM (`/dev/tpmrm0`) with `transcript_hash`
   as the qualifying data, under the device's provisioned AK. Also
   `tpm2_pcrread` for the raw PCR values.
3. Send `device_ecdh_pub`, the quote, its signature, and the raw PCR text.

### Server verification, step 3→4 (see `attestation.py`)

On `attest_response`, the server:

a. **Recomputes the PCR digest** from the reported `pcr_values` text and
   checks it matches the `pcrDigest` field embedded *inside* the signed
   quote — the device can't report PCR values out-of-band from what was
   actually signed.
b. **Verifies the signature** over the quote using the device's registered
   AK public key (ECDSA/P-256/SHA-256).
c. **Recomputes the transcript hash** from its own issued nonce +
   `server_ecdh_pub` + the reported `device_ecdh_pub`, and checks it matches
   the quote's embedded qualifying data — this is the freshness/anti-replay
   check: a replayed quote from a previous session won't match this
   session's nonce or ephemeral keys.
d. **Compares** the verified PCR digest against the registry's
   `expected_pcr` baseline captured at enrollment time — this is the
   integrity check (was this the registered, untampered device).

Only if all four pass does the server derive the session key:
`HKDF-SHA256(ECDH(server_priv, device_ecdh_pub), salt=nonce, info=b"CC-IOT-1 device-aead")`
— the same primitives `CC_Server`'s existing browser↔server AES-GCM channel
already uses, just with a distinct HKDF info label so the two channels can
never collide.

From then on, `data` messages are AES-256-GCM envelopes carrying an
authenticated per-message sequence number (`aad = seq` as 8-byte big-endian —
see §2.7) instead of plaintext, replacing the old
`attested = bool(msg.get("attested", True))` trust-on-say-so line entirely.

## 4. What changed, file by file

### Device / TA (`project/optee_examples/confidential_iot/`)

| File | What changed |
|---|---|
| `edge_device/ta/include/confidential_iot_ta.h` | Added `TA_CONFIDENTIAL_IOT_CMD_HANDSHAKE_COMPLETE`; repointed `CMD_GENERATE_ATTESTATION_EVIDENCE`'s semantics to "handshake phase 1" — takes the server's nonce + ECDH pubkey as inputs, returns the device's ephemeral ECDH pubkey + the 32-byte transcript hash (not a self-signed report). Documented `CMD_AUTHENTICATE_SENSOR` and its gating role (§2.6), and `CMD_PROTECT_SENSOR_DATA`'s new `params[3].value.a` seq output; added `TA_CONFIDENTIAL_IOT_SEQ_AAD_SIZE` (§2.7). |
| `edge_device/ta/trusted_app.c` / `.h` | Real logic: per-session state (`struct confidential_iot_session`), ECDH keypair generation, SHA-256 transcript-hash computation (`TEE_ALG_SHA256` digest — see §2.5), ECDH shared-secret derivation, HKDF-SHA256 session-key derivation, AES-256-GCM `ta_protect_sensor_data`. All via native TEE Internal API. Added the sensor-authentication gate (§2.6): a `sensor_authenticated` session flag, set by the `ta_authenticate_sensor` stub, enforced as a precondition in `ta_protect_sensor_data`/`ta_process_sensor_data`. Added the inner-session anti-replay counter (§2.7): a `send_seq` session field, authenticated as the GCM AAD in `ta_protect_sensor_data` and returned to the Host, reset to 0 on each fresh key in `ta_handshake_complete`. |
| `edge_device/host/edge_device.c` / `.h` | Real `edge_attest_to_server()` (drives the whole hello→attest_result exchange, calls the TA + `attestation.c`), `edge_handshake()` (TA handshake-complete call), `edge_send_sensor_data_to_server()` (splits the TA's combined nonce+ciphertext output into the wire protocol's fields and attaches the `seq` the TA authenticated — §2.7), a persistent TEEC context/session (opened once, reused — required so the TA's per-session ECDH state survives between the two handshake calls), `edge_authenticate_sensor()` (triggers the per-boot sensor-auth check — §2.6), and local device config loading (`/etc/confidential_iot/device.conf` + `CIOT_*` env overrides). Base64 via mbedTLS (`mbedtls_base64_encode/decode`), JSON building/parsing via cJSON — see §2.5. |
| `edge_device/host/net.c` / `.h` | New: a small TCP client matching `CC_Server`'s newline-JSON framing — a thin wrapper over POSIX sockets, the one local helper that isn't a library's job. (The original hand-rolled `sha256.c`/`base64.c`/`json_min.c` helpers that sat alongside it were removed in favor of the TA-computed hash + mbedTLS + cJSON, per §2.5.) |
| `attestation/attestation.c` / `.h` | `create_attestation_report()`: shells out to `tpm2_quote`/`tpm2_pcrread`, base64-encodes the raw quote/signature (via mbedTLS) for JSON transport. `verify_attestation_report()` removed — verification is server-side only (device is Prover, not Verifier). |
| `scripts/provision-device.sh` (new) | One-time `tpm2_createek`/`createak`/`evictcontrol`/`readpublic`/`pcrread`, writes the local device config, prints the enrollment record (JSON) for the admin to submit. Also runs `software_measure_pcr0()` on every invocation (guarded to extend at most once per boot): a Normal-World PCR0 software-measurement stand-in that `tpm2_pcrextend`s `sha256:0` with `SHA-256` of the `confidential_iot` TA + edge binary, so the quote baseline is non-zero and reboot-deterministic — see §2.9. |
| `main.c` | Buffer size bump (base64 expansion needs more room than the original stub's placeholder size) + `edge_device_init()`/`edge_device_shutdown()` calls bracketing the existing flow, and an `edge_authenticate_sensor()` call right after init (once per boot, before any sensor data is handled — §2.6). |
| `Makefile`, `CMakeLists.txt` | Added the new host source files and the `mbedcrypto`/`cjson` link dependencies; **removed** the dead `server/` C stub (superseded by `CC_Server`, confirmed out of scope). |
| `project/buildroot/packages.conf` (new) | Tracked Buildroot config fragment enabling `BR2_PACKAGE_MBEDTLS` + `BR2_PACKAGE_CJSON` for the Normal-World rootfs (see §2.4 for how it survives workspace regeneration). |
| `scripts/build.sh` | Exports the `BR2_*` lines from `packages.conf` into the OP-TEE `make` environment before every build. |

### Run/build scripts (`scripts/`)

| File | What changed |
|---|---|
| `scripts/sync-project.sh` | Added an idempotent `sed` patch (same technique as the existing `optee_examples_ext.mk` dependency patch) that parameterizes `qemu_v8.mk`'s hardcoded gdbstub port (`-s` → `-gdb tcp::$(QEMU_GDB_PORT)`, default `1234`) so concurrent QEMU instances don't collide on it — see §2.8. Added two more idempotent `qemu_v8.mk` patches enabling firmware measured boot — TF-A `MEASURED_BOOT=1 EVENT_LOG_LEVEL=20 TPM_HASH_ALG=sha256 MBEDTLS_DIR=$(ROOT)/mbedtls`, and OP-TEE core `CFG_DT=y CFG_CORE_TPM_EVENT_LOG=y` — see §2.9. |
| `scripts/run-project.sh` | Added `QEMU_INSTANCE` (derives per-instance NW/SW/GDB ports by a fixed offset and a default `device_id`), plus an auto-provisioning step (retries `provision-device.sh` until the fTPM settles) inserted into the existing tmux automation before the edge binary launches — see §2.8. |
| `docker/Dockerfile` | Added `cmake` to the apt install list — TF-A v2.14's measured-boot event-log library (`libeventlog.a`) builds via cmake, which the base image lacked; without it the `MEASURED_BOOT=1` build fails at BL2 and no FIP is produced — see §2.9. |

### Server (`CC_Server`)

| File | What changed |
|---|---|
| `server/constants.py` | Added `INFO_DEVICE_AEAD`, `DEVICE_SESSION_TTL_SECONDS`, `ATTEST_NONCE_LEN`, `ATTEST_CHALLENGE_TTL_SECONDS`, `DEVICE_ECDH_PUBKEY_LEN`, `DEVICE_LINK_ATTESTED_NETWORK`. |
| `server/config.py` | Added `device_registry_path` (`MS_DEVICE_REGISTRY_PATH` env var). |
| `server/device_registry.py` (new) | Persistent `{device_id → ak_pub_pem, expected_pcr, pcr_bank}` JSON-file store; `register()`/`lookup()`/`list()`. |
| `server/attestation.py` (new) | `AttestationVerifier`: challenge issuance/tracking, TPM2B_ATTEST/TPMT_SIGNATURE binary parsing (TPM 2.0 Part 2 structures), signature verification, transcript-hash recompute, PCR-digest recompute/compare, session-key derivation + storage. Tracks a per-session `last_seq` and exposes `check_and_advance_seq()` for inner-session anti-replay (§2.7). |
| `server/device_link/attested_network.py` (new) | `AttestedNetworkDeviceLink(DeviceLink)`: the real hello/challenge/response/data state machine per TCP connection, replacing the old plaintext-trust behavior for this new link type. Each `data` message uses its `seq` (8-byte big-endian) as the AEAD AAD and is dropped if the seq is a replay/out-of-order (§2.7). |
| `server/device_link/__init__.py` | Wired in `attested_network` as a new `MS_DEVICE_LINK=attested_network` option (kept alongside the existing `stub`/`network` for backward compatibility with existing demos). |
| `server/app_server.py` | New `POST /api/devices/register` endpoint — gated behind the existing authenticated User↔Server channel. |
| `server/tests/test_attestation.py` (new) | 8 tests covering the full protocol with real ECDSA/ECDH/HKDF/AES-GCM cryptography, including inner-session replay rejection (§2.7) — see Testing guide. |

Scope note on the Secure-Element↔Sensor challenge-response (steps 6-7 of the
spec's normal-operation flow): the **verification logic itself** — the real
HMAC-SHA256 challenge-response, and the Secure Element emulation in
`sensor_module.c`/`secure_element.c` — remains a stub, out of scope for this
mission. What *was* added here is only the **enforcement scaffolding** around
it (§2.6): the `sensor_authenticated` gate in the TA and the per-boot trigger
from the Host, so that when the real check lands it plugs into an
already-correct trust boundary. Likewise `edge_get_sensor_data` /
`ta_process_sensor_data` remain stubs.

## 5. Known gaps / verification status

The full flow **has now been run end to end** on the real QEMU image
(fresh boot → `provision-device.sh` → admin registration via
`POST /api/devices/register` → `optee_example_confidential_iot_edge`
against a live `MS_DEVICE_LINK=attested_network` server): attestation
verifies, the session key derives on both sides, encrypted `data` messages
flow, and a second run on a new connection re-attests successfully. That
run settled the gaps this section used to list:

- **`tpm2_quote`/`tpm2_pcrread` CLI flags** — verified working as written
  against the target image's tpm2-tools 5.7, with one real fix found:
  `tpm2_quote -m` writes the raw `TPMS_ATTEST` body with *no* size prefix,
  while the server parses a `TPM2B_ATTEST` — so `attestation.c` now
  prepends the 2-byte big-endian size before base64-encoding (the
  signature covers only the body, so nothing changes cryptographically).
- **Boot/TPM stack** — `/dev/tpm0` + `/dev/tpmrm0` appear at boot with no
  modprobe step, and EK/AK provisioning at handle `0x8101000A` works.

Resolved since:

- **PCR `sha256:0` no longer reads all zeros.** Root-caused and fixed — see
  §2.9. The firmware measured-boot chain was enabled (TF-A `MEASURED_BOOT`,
  OP-TEE core `CFG_CORE_TPM_EVENT_LOG`, plus `cmake` in the build image) but
  does not deliver the event log to the fTPM on the QEMU opteed (non-FFA)
  topology (`TPM: Fail to find TPM node`). PCR0 is now made non-zero and
  reboot-deterministic by a Normal-World software-measurement stand-in
  (`software_measure_pcr0()` in `provision-device.sh`). The earlier "wrong PCR
  index, repoint `sha256:0`" hypothesis was **incorrect** — `sha256:0` was
  always the right index. (Caveat: the stand-in is not hardware-rooted — §2.9.)

Next required step (must be done):

- **Persist the Attestation Key across reboots.** In this QEMU setup the rootfs
  is an initrd and OP-TEE secure storage is REE-FS backed by `/var/lib/tee`,
  which lives in RAM — so the fTPM's NV state (and the persisted AK at
  `0x8101000A`) is wiped on every reboot and `provision-device.sh` regenerates
  a **fresh AK each boot**, forcing a re-`POST /api/devices/register` every
  time. Now that PCR0 is reboot-deterministic (above), the PCR baseline is no
  longer a reason to re-enroll — **the AK is the sole remaining driver.** The
  device should persist `/var/lib/tee` on a virtual disk so the AK survives a
  reboot, making enrollment a one-time step. The QEMU HUK is a stable software
  key here, so persisted secure-storage objects will decrypt on later boots.
  Full root-cause analysis and implementation plan:
  **`docs/HANDOFF_persistentAK.md`.**

Everything else — the TA's cryptographic logic, the Host CA's protocol
orchestration, and the entire server side — is verified as described in
`docs/ATTESTATION_TESTING.md`.
