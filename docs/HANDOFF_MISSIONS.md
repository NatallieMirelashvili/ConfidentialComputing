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
- **[`TERMINOLOGY.md`](TERMINOLOGY.md)** — glossary if any term below is unfamiliar.

**End-to-end flow in one line:** sensor → TA generates the reading and seals it
with AES-256-GCM (plaintext never leaves secure world) → host push loop sends it
over the attested session → server verifies the quote, decrypts, and buffers the
reading → UI "collect" reads the buffer and shows the trust verdict.

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

### 2.1.b — The UI's attestation/encryption status is a stub by default; needs real data + stress tests

- **Problem:** the server defaults to `MS_DEVICE_LINK=stub` (`CC_Server/server/config.py`),
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

## Natalie / Emily — the sensor path

This is where most of our C code is still **mock/stub**. Two hard requirements
frame everything below; read them first.

**Requirement 1 — sensor plaintext must stay inside the TA; the Host must never
see it.** Today `ta_process_sensor_data` builds the reading in secure world and
`ta_protect_sensor_data` seals it with AES-256-GCM, and `ta_protect_sensor_data`
**deliberately ignores** the Host-supplied `params[0]` plaintext — the value must
originate *inside* the TA (`project/optee_examples/confidential_iot/edge_device/ta/trusted_app.c`).
A real sensor must preserve this: if the sensor hands plaintext to the Host
first, the property breaks. **Known gap to design around:** sensor plaintext
currently transits the Host on the way *in*; the real design needs a secure
peripheral / PTA path so Normal World never sees it (see `ATTESTATION_DESIGN.md`
§2.6, the relay model).

**Requirement 2 — the mock counter, explained.** `g_mock_value` in
`.../ta/trusted_app.c` is a file-scope `static uint32_t`, incremented once per
`PROCESS_SENSOR_DATA` call and formatted as
`{"samples":[{"value":N,"unit":"count"}]}`. It lives in the TA so the value is
generated in secure world and only leaves as ciphertext. It is **distinct from
`send_seq`** (the per-session anti-replay counter) and resets only on TA-instance
restart (reboot). Note the existing `TODO(multi-device)`: a single static counter
is fine for one device; several devices need per-session state.

### 2.3.a — Replace the sensor mock/stub code (and mind the ripples)

- **Problem:** the whole Sensor↔Device half is stubbed. The stubbed pieces:
  - `ta_authenticate_sensor` — **stub**, unconditionally sets
    `sensor_authenticated = true` (`.../ta/trusted_app.c`). The real Secure-Element
    HMAC-SHA256 challenge-response must verify **inside the TA** and set the flag
    only on a genuine match — never trust a Host-supplied "it matched."
  - `ta_process_sensor_data` — produces the **mock counter**, not a real reading.
  - `edge_get_sensor_data` — **superseded stub**, returns 0
    (`.../edge_device/host/edge_device.c`).
  - `edge_authenticate_sensor` — **stub trigger**, parameterless; carries the note
    *"REMEMBER TO CHANGE THIS IF YOU ADD PARAMETERS (EMILY)"* (`.../host/edge_device.c`).
  - `edge_call_ta` — `TODO`; only `PROTECT_SENSOR_DATA` is wired, AUTHENTICATE /
    PROCESS are out of scope there (`.../host/edge_device.c`).
  - The `AUTHENTICATE_SENSOR` command interface is a **placeholder (no params)**
    (`.../ta/include/confidential_iot_ta.h`). A real challenge-response can't be
    parameterless — expect real params and **likely a second command** (TA emits a
    challenge → Host relays it to the Secure Element → response comes back → Host
    passes it to the TA → TA verifies). See `ATTESTATION_DESIGN.md` §2.6.
- **Struct change (this ripples!):** the reading buffer is `char mock_reading[64]`
  + `mock_reading_len` in `struct confidential_iot_session`
  (`.../ta/trusted_app.h`). Real sensor data — larger, and a different schema —
  means **changing this struct**, which changes buffer sizes all down the path.
- **⚠ Non-mock functions that will break with real/larger sensor data** (this is
  the "look for functions that aren't mock but need to change after your
  additions" ask — **yes, `ta_protect_sensor_data` is one of them**):
  - `ta_protect_sensor_data` (`.../ta/trusted_app.c`) — seals exactly
    `sess->mock_reading` / `mock_reading_len` and checks
    `params[2].memref.size < mock_reading_len + tag`. Its *shape* stays correct,
    but every buffer sized for the tiny mock JSON must grow with the struct.
  - Its caller `ta_protect_and_encode` (`.../host/edge_device.c`) — `uint8_t
    ciphertext[512]`, the `combined[]` buffer, and the
    `input_size > sizeof(ciphertext) - 16` guard.
  - `edge_send_sensor_data_to_server` (`.../host/edge_device.c`) — `uint8_t
    raw[600]`, `char ct_b64[900]`.
  - `main.c` (`.../host/main.c`) — `char protected_data[512]`.
  - The **JSON schema** emitted by `ta_process_sensor_data` must stay in sync with
    the server's expected sample shape / aggregation
    (`CC_Server/server/service.py`) — changing the reading changes *both* ends.
  - All of the above are sized for the mock counter; a real or high-bandwidth
    payload (e.g. camera frames) overflows them. Revisit them **together** with
    the struct change.

### 2.3.b — Also on your plate

- The **Secure-Element emulation itself** (`sensor_module/secure_element.c`,
  `sensor_module.c`) is still a stub and must implement the real HMAC-SHA256
  challenge-response that `ta_authenticate_sensor` will verify.
- Confirm the **relay path** keeps plaintext out of Normal World: the Host may
  relay the challenge/response bytes, but must never learn the sensor plaintext —
  the verification verdict lives in the TA (see `ATTESTATION_DESIGN.md` §2.6). If
  a real sensor delivers data through the Host, that's the gap in Requirement 1
  above and needs a secure-peripheral / PTA design, not just a code swap.
