# Handoff: remaining missions, mapped to peers

We finished the device↔server attestation core (remote attestation, session-key
exchange, admin-gated registration, inner-session anti-replay, QEMU networking).
This document hands off what's left. Read the orientation below first, then find
your section.

Format for every mission: **problem → solution (if we've discussed one) → where
in the code.**

> Path note: `CC_Server` is being moved into this repo so it can be committed;
> server paths below are written relative to the repo root as
> `CC_Server/server/...`. Device/TA paths are under
> `project/optee_examples/confidential_iot/...`.

---

## How the system works (and where it's written down)

Read these before touching anything — they explain the *why*, not just the *what*:

- **[`ATTESTATION_DESIGN.md`](ATTESTATION_DESIGN.md)** — the core. TPM2-quote remote
  attestation via the fTPM, the ECDH + HKDF session key derived and kept **inside
  the TA**, admin-gated device registration, the authenticated anti-replay
  sequence number, and the measured-boot / PCR0 story (§2.9). If you read one
  doc, read this.
- **[`CONNECTION_INITIATION.md`](CONNECTION_INITIATION.md)** — who dials whom. The
  device dials out, the server drives attestation, and the device then **streams
  readings on a timer** into a per-`device_id` server buffer; the UI's "collect"
  reads that buffer (it does **not** message the device). Also flags timer-push
  vs. on-demand as an open design choice.
- **[`QEMU_NETWORKING.md`](QEMU_NETWORKING.md)** — how the emulated device reaches
  the server (`QEMU_EXTRA_ARGS` NIC + `--network host`, SLIRP `10.0.2.2`).
- **[`ATTESTATION_TESTING.md`](ATTESTATION_TESTING.md)** — build / run / test
  runbook, including the multi-device setup.
- **[`HANDOFF_persistentAK.md`](HANDOFF_persistentAK.md)** — the fully-specced next
  step for mission 2.1.a below.
- **[`SENSOR_PATH_IMPLEMENTATION.md`](SENSOR_PATH_IMPLEMENTATION.md)** — the sensor
  path: secure-only UART2, the `sensor_link` PTA, real HMAC-SHA256 sensor
  authentication, and why the Host CA never sees sensor plaintext.
- **[`HANDOFF_serverAuthentication.md`](HANDOFF_serverAuthentication.md)** — the
  fully-specced next step for mission 2.4 below: the device↔server handshake
  is currently unilateral (device proves itself, server proves nothing), so a
  compromised Host can redirect attestation to a malicious server and get it
  to decrypt real sensor data.
- **[`TERMINOLOGY.md`](TERMINOLOGY.md)** — glossary if any term below is unfamiliar.

**End-to-end flow in one line:** sensor authenticates to the device (real
HMAC-SHA256, over a Normal-World-invisible UART) → TA pulls the reading over
that same UART and seals it with AES-256-GCM (plaintext never leaves secure
world, never touches the Host) → host push loop sends it over the attested
session → server verifies the quote, decrypts, and buffers the reading → UI
"collect" reads the buffer and shows the trust verdict.

---

## Anyone can take these

### 2.1.a — The device has to be re-registered on every reboot (AK not persisted)

- **Problem:** the fTPM's NV state — including the Attestation Key persisted at
  handle `0x8101000A` — lives in RAM-backed REE-FS secure storage. It is wiped on
  every reboot, so `provision-device.sh` generates a **fresh AK each boot**, the
  registered `ak_pub_pem` goes stale, and an admin must re-`POST
  /api/devices/register` before the device can attest again.
- **Solution:** persist `/var/lib/tee` on a per-instance virtual disk, mount it
  before `tee-supplicant` starts, and make provisioning idempotent off the fTPM AK
  (skip `createek`/`createak` if `tpm2_readpublic -c 0x8101000A` already works).
  The HUK is a stable software key here, so objects persisted one boot decrypt on
  the next. **This is fully planned already — follow
  [`HANDOFF_persistentAK.md`](HANDOFF_persistentAK.md) end to end.**
- **Where:** every file/knob is listed in that handoff (§4–5); the one acceptance
  test that matters is its §6 (reboot → attest without re-registering).

### 2.1.b — The UI's attestation/encryption status is a stub by default; needs real data + stress tests — **RESOLVED (stub removed 2026-07-17), stress tests still open**

- **Resolution:** `StubDeviceLink` and `MS_DEVICE_LINK=stub` no longer exist —
  `CC_Server/server/device_link/stub.py` is deleted, `constants.DEVICE_LINK_STUB`
  is gone, and `get_device_link()` now raises at startup unless `MS_DEVICE_LINK`
  is explicitly `network` or `attested_network`. There is no synthetic fallback
  left to mask the real verdict, so solution steps 1 and 3 below no longer need
  doing — they're structurally impossible to get wrong now. `create_app()` gained
  an optional `device_link` param so callers (tests) can inject a real link
  instance. `CC_Server/server/tests/test_poc.py`'s E2E tests now require a live
  attested edge device (QEMU or hardware) and skip if none is connected — no
  code path exercises the fabricated-verdict behavior anymore.
- **Still open:** solution step 2 — dedicated **stress tests** against the
  AES-256-GCM sensor path (high volume, replay, out-of-order/renumbered `seq`,
  tampered ciphertext/tag under load). `test_attestation.py` already covers the
  correctness of each of these individually; what's missing is volume/stress,
  not correctness.
- **Original problem (for context):** the server used to default to
  `MS_DEVICE_LINK=stub` (`CC_Server/server/config.py`),
  and the stub link fabricates everything — it hardcodes `attested=True,
  integrity="ok", measurement_ok=True` and synthetic sensor samples
  (`CC_Server/server/device_link/stub.py`, docstring: "synthetic, always-attested
  data"). So the UI's green trust chips are true regardless of any real device.
  The only *real* encryption indicator in the UI is the browser↔server transport
  badge (TLS / app-layer AES-GCM) — **not** the device's AES-GCM sensor channel,
  which the UI never surfaces (no PCR values, no session detail — just three
  booleans).
- **Solution:**
  1. Run/demo with **`MS_DEVICE_LINK=attested_network`** so the chips come from
     real TPM-quote verification + AEAD-verified data, not the stub.
  2. Write **real stress tests** against the AES-256-GCM sensor path: high message
     volume, replayed messages, out-of-order / renumbered `seq`, tampered
     ciphertext or tag — assert the server rejects each. Extend the existing suite
     (`CC_Server/server/tests/test_attestation.py`, already 8 tests with real
     ECDSA/ECDH/HKDF/AES-GCM).
  3. Confirm the UI shows the **real** verdict end-to-end (attested_network), not
     the stub's canned "ok."
- **Where:** `CC_Server/server/device_link/stub.py`,
  `CC_Server/server/device_link/attested_network.py`,
  `CC_Server/server/attestation.py` (`verify_and_derive`),
  `CC_Server/server/tests/test_attestation.py`, UI chips in
  `CC_Server/server/web/app.js`.
  **Caveat to verify:** `CC_Server/server/attestation.py` notes the raw
  `TPM2B_ATTEST` / `TPMT_SIGNATURE` byte parsing was never validated against a
  real captured quote — worth confirming while stress-testing.

---

## Maxim

### 2.2.a — "Collect" reports a successful attestation even when the device is disconnected

- **Problem (confirmed):** when a device's connection drops, the server's
  per-connection handler `_handle_connection` just returns with **no cleanup**
  (`CC_Server/server/device_link/attested_network.py`). Consequences:
  `self._verdict[device_id]` is never cleared (keeps `attested: True` forever),
  `status()` **hardcodes `"connected": True`** for any device ever seen, and the
  derived session key only expires on the 1-hour TTL. So after a device that
  attested once disconnects, `collect()` still returns `attested: True` (with an
  empty sample set) and the UI still shows the device online + attested.
- **Solution:** on connection teardown, **discard the session**: clear
  `_verdict[device_id]` and that device's buffer, and invalidate the derived
  session key in `AttestationVerifier` (`CC_Server/server/attestation.py`). Make
  `status()` / `collect()` report **real liveness** (track the set of currently
  connected `device_id`s) instead of hardcoded `connected: True`. Then a
  "collect" against a disconnected device shows **no attestation / offline** in
  the UI, and the stale key is gone. (This is exactly the "press collect with no
  connection → close the session and discard the session key" behavior we want.)
- **Where:** `CC_Server/server/device_link/attested_network.py` — `_verdict` init,
  `_handle_connection` (add a teardown/`finally`), `_on_data`, `collect`,
  `status`; `CC_Server/server/attestation.py` — the session store + a
  clear/invalidate hook; UI verdict chips in `CC_Server/server/web/app.js`.
- You can split this into sub-tasks (e.g. server teardown first, then the
  `status()` liveness change, then the UI "offline" state).

### 2.2.b — A registration can be silently overridden by a plain re-POST

- **Problem:** `device_registry.register()` does an unconditional overwrite keyed
  by `device_id` — "last writer wins" — rewriting the trusted `ak_pub_pem` and
  `expected_pcr` baseline (`CC_Server/server/device_registry.py`). And `POST
  /api/devices/register` has **no admin authorization** beyond the general
  User↔Server channel (`CC_Server/server/app_server.py`); "admin-only" is only a
  docstring, not enforced. So anyone who can reach the endpoint can replace a
  device's trusted identity.
- **Solution:** make normal registration **reject an already-registered
  `device_id`** (no silent overwrite). Because override is genuinely needed
  *today* — the AK regenerates every boot (see 2.1.a) — add a **guarded "admin
  workaround" override** that is *not* a plain POST: a distinct admin
  credential/token, or an explicit `force` flag that only takes effect behind that
  credential. **Once 2.1.a lands, the override is no longer needed for normal
  operation** (enroll once, reuse forever), so keep it clearly marked as a
  test/admin escape hatch.
- **Where:** `CC_Server/server/device_registry.py` (`register()` — add the
  exists-check and a separate override path), `CC_Server/server/app_server.py`
  (`POST /api/devices/register` — add the admin gate).

### 2.2.c — "Wasteful while loop in handle_connection" — investigated, not a real problem

- **Finding:** it is **not** a busy-wait and does **not** spin the CPU. The
  `while True` in `_handle_connection`
  (`CC_Server/server/device_link/attested_network.py`) blocks on
  `readline()` → `self.rfile.readline()`, a blocking kernel socket read, with one
  thread per connection (`ThreadingTCPServer`). There's no `sleep`, but none is
  needed — the thread parks in the kernel until bytes arrive. The inner `while`
  only skips blank lines and immediately re-blocks.
- **Verdict:** **low priority / not critical.** The only real cost is one OS
  thread per open connection — a routine scaling concern, not waste. If the
  earlier concern was CPU spin, it doesn't apply to the code as written (either it
  was already addressed, or the comment was really about thread-per-connection).
  No fix required; recorded here so nobody re-chases it.

---

## Natalie / Emily — the sensor path — **RESOLVED**

- **Resolution:** the whole Sensor↔Device half is now real, not mock/stub.
  `ta_authenticate_sensor` runs a genuine HMAC-SHA256 challenge-response,
  verified inside the TA via `TEE_MACCompareFinal()` against a pre-shared
  secret held in TA secure storage (never compiled into source — provisioned
  by the new `scripts/pair-sensor.sh`). The old `ta_process_sensor_data` +
  `ta_protect_sensor_data` pair is collapsed into a single
  `ta_read_and_protect` (command `READ_AND_PROTECT`) with **no plaintext
  input parameter at all** — both requirements below are now met by
  construction, not by convention. `edge_get_sensor_data` (the dead stub)
  and `sensor_module/secure_element.c`/`sensor_module.c` (empty stubs) are
  deleted; `sensor_module/sensor_daemon.c` is the real Sensor Module
  companion process. Full design, the QEMU/PTA mechanism that makes
  Requirement 1 physically true (not just structurally true), and the
  positive/negative-path verification performed: **`docs/SENSOR_PATH_IMPLEMENTATION.md`.**
- **Original problem (for context):** this section used to document two
  hard requirements and hand off the stub code that didn't yet meet them —
  Requirement 1 (sensor plaintext must stay inside the TA; the Host must
  never see it) and Requirement 2 (explaining the `g_mock_value` mock
  counter standing in for a real reading). Both requirements, and the
  mission's two sub-tasks (2.3.a "replace the sensor mock/stub code," 2.3.b
  "the Secure-Element emulation itself"), are superseded by the resolution
  above — see `docs/SENSOR_PATH_IMPLEMENTATION.md` for exactly how each was
  addressed, including the buffer-size ripple this section warned about
  (resolved by capping the reading at 256 bytes, which fits every existing
  downstream buffer unchanged) and the multi-device `TODO` on the old
  `g_mock_value` counter (moot — that counter no longer exists, readings
  come from the sensor_link PTA per TA session).

---

## Anyone can take this

### 2.4 — Device↔server attestation is unilateral: the device never verifies the server's identity

- **Problem:** the device (Prover) proves itself to the server (Verifier) via
  a TPM quote, but nothing proves the server's identity to the device. The
  quote's qualifying data (`SHA256(nonce ‖ server_ecdh_pub ‖ device_ecdh_pub)`)
  is over public values and doesn't bind to a specific trusted server, and
  the ECDH session key is derived with *whoever* supplied `server_ecdh_pub` —
  there's no wrong-party failure mode in ECDH, only a real shared secret with
  whoever you exchanged keys with. Port 9000/9100 has no TLS/server-cert
  check by design. **Consequence:** a compromised Host (or anyone who can
  redirect `SERVER_HOST`/`SERVER_PORT`) can point the device at a server it
  controls; the fake server needs no cryptography at all — just speak the
  JSON protocol and always answer `ok: true` — and it will receive genuine,
  decryptable sensor data. This is independent of and predates the sensor
  path (`docs/SENSOR_PATH_IMPLEMENTATION.md`).
- **Solution:** trust-on-first-use — the device pins the server's public key
  into TA secure storage on the first genuine attestation after deployment,
  then requires a valid signature against that pinned key on every
  attestation after, refusing to derive a session key otherwise. The key is a
  **dedicated ECDSA P-256 identity keypair**, generated once and persisted
  server-side — deliberately *not* the server's existing RSA-2048 TLS
  certificate (`transport/tls.py`, which keeps serving TLS on port 8000
  unchanged), for consistency with every other key in this project and to
  avoid RSA inside the TEE. Verification must happen **inside the TA**, not
  the Host CA, for the same reason every other trust gate in this project
  does (§2.6 of `ATTESTATION_DESIGN.md`). Full spec, including exact protocol
  message changes and a testing plan: **`docs/HANDOFF_serverAuthentication.md`.**
- **Where:** `CC_Server/server/crypto.py`/`attestation.py`/
  `device_link/attested_network.py` (server-side signing + new protocol
  fields), `edge_device/host/edge_device.c` (thread the new fields through),
  `edge_device/ta/trusted_app.c`/`.h`, `confidential_iot_ta.h`
  (`ta_handshake_complete` — pin/compare/verify before session-key
  derivation).
