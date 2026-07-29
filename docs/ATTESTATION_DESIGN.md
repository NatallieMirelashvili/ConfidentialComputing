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

### 2.6 Sensor-authentication gate (enforcement now, real check later) — **superseded, see `docs/SENSOR_PATH_IMPLEMENTATION.md`**

**Update:** the real check has since landed, and turned out *better* than
this section anticipated: rather than relaying the challenge/response
through the untrusted Host (the plan below), a secure-only UART + pseudo-TA
means the Host never sees those bytes at all — see
`docs/SENSOR_PATH_IMPLEMENTATION.md`. The rest of this section is kept as a
historical record of the enforcement-scaffolding design (still accurate for
`sensor_authenticated`'s role and the two-gate structure below), but its
"parameter interface is deliberately not final" / "must relay through the
Host" paragraph at the end no longer describes the shipped design.

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

### 2.10 Server-authenticated attestation (device pins the server, TOFU)

Everything above makes the device prove itself to the server. It says nothing
about the *reverse*: the device had no way to know it was talking to the real
server. Since port 9000/9100 has no TLS and the qualifying data is all public,
a compromised Host that redirects `SERVER_HOST`/`SERVER_PORT` could point the
device at an impostor that just speaks the JSON protocol and always answers
`"ok": true` — the device would derive a real session key with the attacker and
stream genuine encrypted readings it can decrypt. This subsection closes that
gap; the full rationale and the alternatives considered are in
**`docs/HANDOFF_serverAuthentication.md`** (mirrors how
`docs/SENSOR_PATH_IMPLEMENTATION.md` is referenced from §2.6).

The fix is **Trust-On-First-Use (TOFU) server pinning**:

- **A dedicated server-identity key.** The server holds an ECDSA **P-256**
  keypair (`ensure_server_identity_key()` in `crypto.py`, persisted at
  `server_identity_key_path` in the same `server-certs` volume as the TLS key,
  generated once and **never** regenerated). It is deliberately separate from
  the RSA TLS cert (consistency with every other P-256 key here; a 64-byte
  `r‖s` signature and lighter TEE verify than RSA) — see the handoff §3.
- **Two-phase, like TLS.** The 65-byte raw identity public key travels early in
  `attest_challenge` (`server_identity_pub`, like a certificate in
  `ServerHello`); proof-of-possession travels late in `attest_result`
  (`server_sig`, like `CertificateVerify`). `server_sig` is a raw 64-byte
  `r‖s` ECDSA-P256 signature over a **labelled, domain-separated** transcript
  `SHA-256("CC-IOT-1 server-identity" ‖ nonce ‖ server_ecdh_pub ‖
  device_ecdh_pub)` — a distinct label from the device's own quote transcript
  so the two signatures can never be confused (cross-protocol confusion). The
  server DER→raw re-encodes so the TA never parses ASN.1.
- **The verdict lives in the TA.** `ta_handshake_complete` now authenticates
  the server *before* deriving the session key. It recomputes that digest
  inside the TA (reconstructing `device_ecdh_pub` from its still-live ephemeral
  keypair), opens the persistent object `ciot.server.pubkey`
  (`TEE_STORAGE_PRIVATE`), and:
  - **first use** (`TEE_ERROR_ITEM_NOT_FOUND`) → verify `server_sig` against the
    *presented* key with `TEE_AsymmetricVerifyDigest(TEE_ALG_ECDSA_P256)`; only
    if it checks out, pin the key (`TEE_CreatePersistentObject`, no OVERWRITE —
    first-write-wins). TOFU skips the *comparison*, never the *verification* — a
    garbage first-use signature is still rejected.
  - **every later use** → compare the presented key against the pinned one
    first; any mismatch is an immediate `TEE_ERROR_ACCESS_CONFLICT` (don't even
    verify against the wrong key); on a match, verify `server_sig` against the
    pinned key.
  - either failure → the session key is **not** derived (`session_key_valid`
    stays `false`), the command returns `TEE_ERROR_SIGNATURE_INVALID` /
    `TEE_ERROR_ACCESS_CONFLICT`, and no `data` messages ever flow. Because a
    compromised Host cannot make the TA trust a bad verdict, this is the same
    "the TA never trusts the Host's self-report" principle as §2.6, one layer up.

This is the same TPM-style two-gate structure as the rest of the system: the
Device↔Server session key is now gated on *both* the server verifying the
device's quote *and* the device verifying the server's identity signature.

**Fresh TOFU on rebuild (dev convenience, deliberately coupled to the AK).**
The pinned key lives in secure storage on the persistent per-instance disk
(`.device-state/*.img`, §2.1.a / `docs/PERSISTENT_AK_IMPLEMENTATION.md`), so it
survives reboots by design — but a rebuild can rotate the server-identity key,
which would permanently lock a pinned device out. So `scripts/build.sh` writes
a per-build stamp and `scripts/run-project.sh` compares it: on a genuine
rebuild it **wipes the whole disk to a fresh device** (new AK + fresh TOFU) and
drops the stale server-registry entry (`scripts/reset-device-registry.sh`) so
the new AK can re-register. A plain relaunch or a guest `reboot` (unchanged
stamp) keeps the pin. Wiping the pin is deliberately coupled to destroying the
AK — matching the handoff's "not a quiet bypass" principle — rather than a
surgical delete a compromised Host could trigger to force a re-TOFU. Like the
PCR0 stand-in (§2.9), the *automatic* reset is a QEMU/dev convenience: on real
hardware, re-pinning would be an operator-controlled re-provision.

### 2.11 Binding attestation to the genuine TA (server pins the TA, TOFU)

§2.10 made the **server** prove itself to the **device**. This subsection is its
mirror image: making the **TA** prove itself to the **server**. Full rationale in
**`docs/HANDOFF_taIdentityBinding.md`**; the implementation walkthrough is in
`docs/TA_IDENTITY_IMPLEMENTATION.md`.

**The gap.** Everything in §2.1–2.9 proves the *device* (its AK) and the
*firmware* (PCR0). None of it proves that the genuine `confidential_iot` TA ran
the crypto, for two independent reasons:

- The **AK belongs to the fTPM, not to the TA**, and it is persisted at
  `0x8101000A` with no auth value and no policy — any Normal-World process that
  can open `/dev/tpmrm0` can drive it.
- The **quote is assembled by the untrusted Host** (`system("tpm2_quote …")` in
  `attestation.c`); the TA never talks to the fTPM. Nothing forced the quoted
  `device_ecdh_pub` to have come from the TA.

So an attacker with root can **bypass the TA entirely**: generate its own ECDH
keypair in Normal World, have the real fTPM quote it under the real PCR0,
complete the handshake itself, and feed the server fabricated readings. All four
of checks a–d pass. Tampering with the TA binary changes neither PCR0 (the app
TA is not a boot image, so it is not measured) nor the AK.

**The fix has two parts, and the first gates the second.**

- **(A) Sign the TA with a project-private key.** The build previously used
  OP-TEE's shipped default (`TA_SIGN_KEY ?= keys/default_ta.pem` →
  `default.pem`), whose private half is committed upstream — so root could
  re-sign a tampered TA and it would load. Now `scripts/build.sh` exports
  `TA_SIGN_KEY=keys/ciot_ta.pem` (RSA-4096), which reaches all three consumers
  that must agree on it: the core's baked-in `ta_pub_key.c` verifier, the
  dev-kit key export, and every TA link step. `scripts/verify-ta-signing.sh`
  asserts the core and the TA agree at the end of every build — a mismatch is
  otherwise a silent build success where every TA fails to load at runtime.
- **(B) Give the TA its own sealed identity key.** `CMD 6
  GENERATE_TA_IDENTITY` generates an ECDSA P-256 keypair **inside** the TA
  (`TEE_GenerateKey`) and seals it in `ciot.ta.identity`
  (`TEE_STORAGE_PRIVATE`, first-write-wins) together with the `device_id` it is
  bound to. Only the 65-byte public point is ever exported; `provision-device.sh`
  puts it in the enrollment record as `ta_pub_b64`, and the server pins it
  immutably alongside the AK. Every session, `CMD 3` signs
  `SHA-256("CC-IOT-1 ta-identity" ‖ nonce ‖ server_ecdh_pub ‖ device_ecdh_pub ‖ device_id)`,
  and the server verifies it before deriving anything (check (e)).

**Why A gates B:** OP-TEE secure storage is scoped to the **TA UUID**. Without a
private signing key, root could load a *malicious TA with the same UUID* and
simply read the sealed identity key. Part A is what makes the sealed key in Part
B trustworthy. Ship them together — a private signing key alone leaves the
bypass open, and the identity key alone is readable.

Three design points worth recording:

- **Binding `device_ecdh_pub` is the crux.** A signature over the nonce alone
  could be replayed alongside a substituted key. Including the session's
  ephemeral public key is what forces it to be the TA's own. The nonce gives
  freshness; `device_id` binds the signature to one enrolled device.
- **Domain separation.** The label is distinct from `"CC-IOT-1 server-identity"`
  and the pre-image is disjoint from the quote's qualifying data over the same
  session, so the three signatures can never be confused. `"CC-IOT-1"` is the
  protocol **version** prefix, not a per-device counter — per-device binding
  comes from `device_id` inside the pre-image, placed **last** because it is the
  only variable-length field, which keeps the encoding unambiguous without a
  length prefix that the C and Python sides would both have to agree on.
- **`device_id` is sealed, not passed per session.** The GP API caps a command
  at four parameters and `CMD 3` already used all four, so `CMD 3` returns
  `transcript_hash(32) ‖ ta_sig(64)` in one memref and takes the `device_id`
  from secure storage. The security side effect is worth more than the
  parameter it saved: the Host cannot assert a different identity per session,
  and a copied `.device-state/*.img` cannot be presented under another
  `device_id`. The cost is that renaming a device requires wiping its secure
  storage, which surfaces as `TEE_ERROR_ACCESS_CONFLICT` at provisioning time.

**End state — three independent legs, all enforced server-side:**
**AK → correct device · PCR0 → genuine firmware · `ta_sig` → genuine TA.**

## 3. The protocol

Newline-delimited JSON over the existing device-facing TCP port (matches
`CC_Server`'s existing wire-framing style), all within one continuous TCP
connection:

```
1. device → server   {"type":"hello","device_id":"..."}
2. server → device   {"type":"attest_challenge","nonce":"<b64>","server_ecdh_pub":"<b64>",
                       "server_identity_pub":"<b64>"}
3. device → server   {"type":"attest_response","device_id":"...",
                       "device_ecdh_pub":"<b64>","quote":"<b64>",
                       "signature":"<b64>","pcr_values":"<text>",
                       "ta_sig":"<b64>"}
4. server → device   {"type":"attest_result","ok":true,"session_ttl":3600,"server_sig":"<b64>"}
                      | {"ok":false,"error":"..."}
5. device → server   {"type":"data","device_id":"...","seq":<int>,"nonce":"<b64>","ciphertext":"<b64>"}
   server → device   {"ok":true} | {"ok":false,"error":"..."}   (repeatable)
```

`seq` is a per-session, monotonically increasing message counter used for
inner-session anti-replay — see §2.7. `server_identity_pub` / `server_sig`
carry the server's TOFU-pinned identity proof — see §2.10. `ta_sig` carries the
mirror-image proof in the other direction: the TA's own identity signature over
this session — see §2.11.

### Device side, step 3 in detail

1. Ask the TA (`TA_CONFIDENTIAL_IOT_CMD_GENERATE_ATTESTATION_EVIDENCE`) for
   a fresh ephemeral ECDH keypair, passing in the server's nonce and
   `server_ecdh_pub`; get back the public half **and** a 96-byte evidence
   block holding
   `transcript_hash = SHA-256(nonce ‖ server_ecdh_pub ‖ device_ecdh_pub)`
   followed by `ta_sig` (§2.11), both computed inside the TA via the TEE
   Internal Core API (all inputs are public, so returning them to Normal World
   is safe — see §2.5).
2. Run `tpm2_quote` against the fTPM (`/dev/tpmrm0`) with `transcript_hash`
   as the qualifying data, under the device's provisioned AK. Also
   `tpm2_pcrread` for the raw PCR values. The quote covers the transcript hash
   only — the first 32 bytes of the block — so this step is unchanged.
3. Send `device_ecdh_pub`, the quote, its signature, the raw PCR text, and
   `ta_sig`.

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
e. **Verifies `ta_sig`** against the registry's pinned `ta_pub_b64`, over
   `"CC-IOT-1 ta-identity" ‖ nonce ‖ server_ecdh_pub ‖ device_ecdh_pub ‖ device_id`
   — the "did the genuine **TA** do this?" check (§2.11). Checks a–d all pass
   for a root-compromised Host that bypasses the TA entirely, because the AK
   belongs to the fTPM and the quote is assembled in Normal World. This is the
   one check the Host cannot influence.

Only if all five pass does the server derive the session key:
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
| `edge_device/ta/include/confidential_iot_ta.h` | Added `TA_CONFIDENTIAL_IOT_CMD_HANDSHAKE_COMPLETE`; repointed `CMD_GENERATE_ATTESTATION_EVIDENCE`'s semantics to "handshake phase 1" — takes the server's nonce + ECDH pubkey as inputs, returns the device's ephemeral ECDH pubkey + the 32-byte transcript hash (not a self-signed report). Documented `CMD_AUTHENTICATE_SENSOR` and its gating role (§2.6), and `CMD_PROTECT_SENSOR_DATA`'s new `params[3].value.a` seq output; added `TA_CONFIDENTIAL_IOT_SEQ_AAD_SIZE` (§2.7). **Server-auth (§2.10):** extended `HANDSHAKE_COMPLETE`'s params[2]/[3] to carry `server_identity_pub` (65B) + `server_sig` (64B), added `TA_CONFIDENTIAL_IOT_SERVER_SIG_SIZE`, `..._SERVER_IDENTITY_LABEL`, `..._SERVER_PUBKEY_OBJID`, and documented the new failure codes. **TA-identity (§2.11):** added `CMD 6 GENERATE_TA_IDENTITY`, rewrote `CMD 3`'s documented output shape (`params[3]` is now the 96-byte `transcript_hash ‖ ta_sig` evidence block), and added `..._TA_SIG_SIZE`, `..._EVIDENCE_BLOCK_SIZE`, `..._TA_IDENTITY_LABEL`, `..._TA_IDENTITY_OBJID`, `..._DEVICE_ID_MAX`, `..._TA_IDENTITY_BLOB_SIZE`, `..._NONCE_MAX`. |
| `edge_device/ta/trusted_app.c` / `.h` | Real logic: per-session state (`struct confidential_iot_session`), ECDH keypair generation, SHA-256 transcript-hash computation (`TEE_ALG_SHA256` digest — see §2.5), ECDH shared-secret derivation, HKDF-SHA256 session-key derivation, AES-256-GCM `ta_protect_sensor_data`. All via native TEE Internal API. Added the sensor-authentication gate (§2.6): a `sensor_authenticated` session flag, set by the `ta_authenticate_sensor` stub, enforced as a precondition in `ta_protect_sensor_data`/`ta_process_sensor_data`. Added the inner-session anti-replay counter (§2.7): a `send_seq` session field, authenticated as the GCM AAD in `ta_protect_sensor_data` and returned to the Host, reset to 0 on each fresh key in `ta_handshake_complete`. **Server-auth (§2.10):** new `authenticate_server()` — recomputes the labelled server-identity digest, opens/compares/pins the `ciot.server.pubkey` persistent object (TOFU), and does the first TA-side ECDSA verify (`TEE_ALG_ECDSA_P256` / `TEE_AsymmetricVerifyDigest`); called from `ta_handshake_complete` before ECDH+HKDF, gating `session_key_valid`. **TA-identity (§2.11):** new `ta_generate_ta_identity()` (CMD 6 — first `TEE_GenerateKey` on an ECDSA keypair, sealed to `ciot.ta.identity` with the bound `device_id`, first-write-wins) and `sign_ta_identity()` (first *signing* operation in this codebase — `TEE_MODE_SIGN` / `TEE_AsymmetricSignDigest`), called from `ta_generate_attestation_evidence`. That function now also copies `nonce`/`server_pub`/`device_pub` into TA-local buffers before hashing, because signing bytes that live in Host-shared memory would let a racing root Host swap the public point after the TA writes it. |
| `edge_device/host/edge_device.c` / `.h` | Real `edge_attest_to_server()` (drives the whole hello→attest_result exchange, calls the TA + `attestation.c`), `edge_handshake()` (TA handshake-complete call), `edge_send_sensor_data_to_server()` (splits the TA's combined nonce+ciphertext output into the wire protocol's fields and attaches the `seq` the TA authenticated — §2.7), a persistent TEEC context/session (opened once, reused — required so the TA's per-session ECDH state survives between the two handshake calls), `edge_authenticate_sensor()` (triggers the per-boot sensor-auth check — §2.6), and local device config loading (`/etc/confidential_iot/device.conf` + `CIOT_*` env overrides). Base64 via mbedTLS (`mbedtls_base64_encode/decode`), JSON building/parsing via cJSON — see §2.5. **Server-auth (§2.10):** parses `server_identity_pub` from `attest_challenge` and `server_sig` from `attest_result`, caches both, and threads them into `edge_handshake()`'s params[2]/[3]. **TA-identity (§2.11):** `ta_handshake_init()` now receives the 96-byte evidence block and `edge_attest_to_server()` splits it — the first 32 bytes go to `create_attestation_report()` unchanged, the last 64 become `attest_response.ta_sig`. New `edge_provision_ta_identity()` (both halves of the `CONFIDENTIAL_IOT_NATIVE` split) drives CMD 6. |
| `edge_device/host/net.c` / `.h` | New: a small TCP client matching `CC_Server`'s newline-JSON framing — a thin wrapper over POSIX sockets, the one local helper that isn't a library's job. (The original hand-rolled `sha256.c`/`base64.c`/`json_min.c` helpers that sat alongside it were removed in favor of the TA-computed hash + mbedTLS + cJSON, per §2.5.) |
| `attestation/attestation.c` / `.h` | `create_attestation_report()`: shells out to `tpm2_quote`/`tpm2_pcrread`, base64-encodes the raw quote/signature (via mbedTLS) for JSON transport. `verify_attestation_report()` removed — verification is server-side only (device is Prover, not Verifier). |
| `scripts/provision-device.sh` (new) | One-time `tpm2_createek`/`createak`/`evictcontrol`/`readpublic`/`pcrread`, writes the local device config, prints the enrollment record (JSON) for the admin to submit. Also runs `software_measure_pcr0()` on every invocation (guarded to extend at most once per boot): a Normal-World PCR0 software-measurement stand-in that `tpm2_pcrextend`s `sha256:0` with `SHA-256` of the `confidential_iot` TA + edge binary, so the quote baseline is non-zero and reboot-deterministic — see §2.9. |
| `main.c` | Buffer size bump (base64 expansion needs more room than the original stub's placeholder size) + `edge_device_init()`/`edge_device_shutdown()` calls bracketing the existing flow, and an `edge_authenticate_sensor()` call right after init (once per boot, before any sensor data is handled — §2.6). **TA-identity (§2.11):** new `--provision-ta-identity` mode that prints the TA's identity public key as base64 on stdout **and nothing else**, so `provision-device.sh` can capture it with `$(...)`. |
| `Makefile`, `CMakeLists.txt` | Added the new host source files and the `mbedcrypto`/`cjson` link dependencies; **removed** the dead `server/` C stub (superseded by `CC_Server`, confirmed out of scope). |
| `project/buildroot/packages.conf` (new) | Tracked Buildroot config fragment enabling `BR2_PACKAGE_MBEDTLS` + `BR2_PACKAGE_CJSON` for the Normal-World rootfs (see §2.4 for how it survives workspace regeneration). |
| `scripts/build.sh` | Exports the `BR2_*` lines from `packages.conf` into the OP-TEE `make` environment before every build. |

### Run/build scripts (`scripts/`)

| File | What changed |
|---|---|
| `scripts/sync-project.sh` | Added an idempotent `sed` patch (same technique as the existing `optee_examples_ext.mk` dependency patch) that parameterizes `qemu_v8.mk`'s hardcoded gdbstub port (`-s` → `-gdb tcp::$(QEMU_GDB_PORT)`, default `1234`) so concurrent QEMU instances don't collide on it — see §2.8. Added two more idempotent `qemu_v8.mk` patches enabling firmware measured boot — TF-A `MEASURED_BOOT=1 EVENT_LOG_LEVEL=20 TPM_HASH_ALG=sha256 MBEDTLS_DIR=$(ROOT)/mbedtls`, and OP-TEE core `CFG_DT=y CFG_CORE_TPM_EVENT_LOG=y` — see §2.9. |
| `scripts/run-project.sh` | Added `QEMU_INSTANCE` (derives per-instance NW/SW/GDB ports by a fixed offset and a default `device_id`), plus an auto-provisioning step (retries `provision-device.sh` until the fTPM settles) inserted into the existing tmux automation before the edge binary launches — see §2.8. **Server-auth (§2.10):** a host-side rebuild-detection block that diffs `.build-stamp` against a per-instance stored stamp and, on a genuine rebuild, wipes the device disk to a fresh device (new AK + fresh TOFU) and drops the stale registry entry via `reset-device-registry.sh`. |
| `scripts/build.sh` | Exports `packages.conf`'s `BR2_*` lines into the OP-TEE `make` environment (§2.4). **Server-auth (§2.10):** writes a fresh `.build-stamp` after each successful build so `run-project.sh` can tell a rebuild from a relaunch. **TA-identity (§2.11):** exports `TA_SIGN_KEY=keys/ciot_ta.pem` (one export reaches the core, the dev-kit export and every TA link step, since all three read it with `?=`) and runs `verify-ta-signing.sh` before writing the stamp. |
| `scripts/verify-ta-signing.sh` (new) | **TA-identity (§2.11):** asserts the OP-TEE core's baked-in verifier key and the built `.ta`'s signature are the same project-private key — mechanically, by regenerating `ta_pub_key.c` and diffing it, then running `sign_encrypt.py verify`. A mismatch is otherwise a silent build success in which every TA fails to load at runtime. |
| `keys/ciot_ta.pem` + `keys/README.md` (new) | **TA-identity (§2.11):** the project-private RSA-4096 TA signing key replacing OP-TEE's shipped default, whose private half is committed upstream. Never enters the firmware image or rootfs. |
| `docker/Dockerfile` | Added `cmake` to the apt install list — TF-A v2.14's measured-boot event-log library (`libeventlog.a`) builds via cmake, which the base image lacked; without it the `MEASURED_BOOT=1` build fails at BL2 and no FIP is produced — see §2.9. |

### Server (`CC_Server`)

| File | What changed |
|---|---|
| `server/constants.py` | Added `INFO_DEVICE_AEAD`, `DEVICE_SESSION_TTL_SECONDS`, `ATTEST_NONCE_LEN`, `ATTEST_CHALLENGE_TTL_SECONDS`, `DEVICE_ECDH_PUBKEY_LEN`, `DEVICE_LINK_ATTESTED_NETWORK`. |
| `server/config.py` | Added `device_registry_path` (`MS_DEVICE_REGISTRY_PATH` env var). **Server-auth (§2.10):** added `server_identity_key_path` (in `certs_dir`, alongside the TLS key). |
| `server/crypto.py` | **Server-auth (§2.10):** added `ensure_server_identity_key()` (load-or-generate the persisted P-256 identity key, never regenerate), `public_point_raw()`, and `sign_server_identity_raw()` (ECDSA-P256-SHA256, DER→raw 64-byte `r‖s`). |
| `server/device_registry.py` (new) | Persistent `{device_id → ak_pub_pem, expected_pcr, pcr_bank}` JSON-file store; `register()`/`lookup()`/`list()`. **TA-identity (§2.11):** added the pinned `ta_pub_b64` field plus a tolerant `from_dict()` (a strict `DeviceRecord(**rec)` would make an older registry file crash the server at startup), moved every pinned-key comparison *ahead* of the idempotent early return (an `ak_pub`-only check would wave through a changed `ta_pub` as "already registered"), and added `validate_device_id()`. |
| `server/attestation.py` (new) | `AttestationVerifier`: challenge issuance/tracking, TPM2B_ATTEST/TPMT_SIGNATURE binary parsing (TPM 2.0 Part 2 structures), signature verification, transcript-hash recompute, PCR-digest recompute/compare, session-key derivation + storage. Tracks a per-session `last_seq` and exposes `check_and_advance_seq()` for inner-session anti-replay (§2.7). **Server-auth (§2.10):** loads the identity key once, advertises `server_identity_pub` in `issue_challenge`, and `verify_and_derive` now signs the labelled transcript and returns the raw `server_sig`. **TA-identity (§2.11):** added `TA_IDENTITY_LABEL`, `build_ta_identity_preimage()`, `compute_ta_identity_msg()`, and check (e) in `verify_and_derive` — placed before key derivation so a failure leaves no session behind. Verification passes the **pre-image**, not the digest: `cryptography` hashes whatever it is given, so verifying the digest would hash twice and reject every honest device. |
| `server/device_link/attested_network.py` (new) | `AttestedNetworkDeviceLink(DeviceLink)`: the real hello/challenge/response/data state machine per TCP connection, replacing the old plaintext-trust behavior for this new link type. Each `data` message uses its `seq` (8-byte big-endian) as the AEAD AAD and is dropped if the seq is a replay/out-of-order (§2.7). **Server-auth (§2.10):** puts `server_identity_pub` on `attest_challenge` and `server_sig` on `attest_result`. **TA-identity (§2.11):** passes `msg["ta_sig"]` through to the verifier — subscripted, not `.get()`, so a Host that skips the TA and omits the field hits the existing `KeyError` handler and fails closed with no new code path. |
| `server/device_link/__init__.py` | Wired in `attested_network` as a new `MS_DEVICE_LINK=attested_network` option (kept alongside the existing `stub`/`network` for backward compatibility with existing demos). |
| `server/app_server.py` | New `POST /api/devices/register` endpoint — gated behind the existing authenticated User↔Server channel. **TA-identity (§2.11):** requires `ta_pub_b64`, validates it is a real on-curve P-256 point, and re-encodes its base64 canonically so cosmetic encoding differences cannot masquerade as a key change (a spurious 409 would look exactly like an attack). |
| `server/tests/test_register_endpoint.py` (new) | **TA-identity (§2.11):** first tests for `POST /api/devices/register` — valid/missing/short/off-curve/compressed `ta_pub_b64`, the 409 on a changed TA key, base64 canonicalisation, and `device_id` validation. |
| `server/tests/test_attestation.py` (new) | 9 tests covering the full protocol with real ECDSA/ECDH/HKDF/AES-GCM cryptography, including inner-session replay rejection (§2.7) and, for server-auth (§2.10), that `attest_result`'s raw-64 `server_sig` verifies against the advertised `server_identity_pub` over the labelled transcript and fails under a wrong key/transcript — see Testing guide. |

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

> **Status note (later missions).** Two items above have since been superseded
> and are kept only as a record of the path taken. The Normal-World
> `software_measure_pcr0()` stand-in was **removed** in favour of a real,
> firmware-rooted measured-boot chain under the FF-A / S-EL1 SPMC topology
> (`DESIGN.md` §8), and the Attestation Key **is** now persisted across reboots
> (`docs/PERSISTENT_AK_IMPLEMENTATION.md`). Read §2.9 as history, not as the
> current design.

### TA-identity binding (§2.11) — status

Implemented and verified end to end. Beyond the live QEMU run:

- **63 server-side tests pass** (`cd CC_Server && python -m pytest server/tests -q`),
  including the bypass regression itself: a fully valid quote — real AK
  signature, real PCR0, correct transcript — with a `ta_sig` from the wrong key
  is rejected, and no session key is stored.
- Those bypass tests were **mutation-tested**: neutering check (e) makes all
  four of them fail, so they are load-bearing rather than incidentally passing.
- The **C/Python byte-parity risk is retired by construction.** A standalone C
  program replicating the TA's exact `TEE_DigestUpdate` sequence and sealed-blob
  offsets reproduces the known-answer digest asserted in
  `test_ta_identity_preimage_is_byte_exact`
  (`b34347ce…`). If anyone changes the pre-image on either side, that test
  fails and names the reason.

Two residual caveats, both stated in `DESIGN.md` §18: the TA signing key is
committed to the repo (private relative to the world, not to repo-holders), and
the TA-identity guarantee inherits the trust-on-first-use bound that already
applies to the AK — it prevents silent takeover of an established identity, not
enrollment by a device that was never genuine.
