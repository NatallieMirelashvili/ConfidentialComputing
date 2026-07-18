# Architecture Overview

Onboarding doc for a new session picking up this project. For deep dives on
individual subsystems, see the other files in `docs/` — this file's job is
to give the big picture and, in particular, explain exactly how the device
and server talk to each other on the wire.

## What this project is

A university course project implementing **remote attestation for an IoT
edge device** using TrustZone (OP-TEE) on QEMU. A simulated sensor device
proves — cryptographically, via a TPM/fTPM quote — that it's running
untampered firmware before a management server will accept encrypted data
from it. Two machines are involved:

- **Edge device**: a QEMU `aarch64` VM running Linux (Buildroot) + OP-TEE.
  A Normal-World "Host" app talks to a Trusted Application (TA) running
  inside the TEE.
- **CC_Server**: a Python management server (FastAPI) that verifies
  attestation, registers devices, and receives their encrypted data. Has a
  small web dashboard for humans.

## Component map

```
project/optee_examples/confidential_iot/
├── ta/trusted_app.c        Trusted Application (runs inside the TEE, EL0-S)
├── host/main.c              Normal-World Host app ("edge_device") — CA
├── host/edge_device.c       device orchestration: session, attest, send
├── host/net.c                raw TCP socket helpers
├── attestation/               fTPM quote/signature generation
└── sensor_module/sensor_daemon.c   Sensor Module companion process (see
                                     docs/SENSOR_PATH_IMPLEMENTATION.md) —
                                     runs OUTSIDE the QEMU guest

project/optee_os_ext/core/pta/sensor_link.c   the sensor_link PTA (owns the
                                                secure UART2, see above)

CC_Server/server/
├── app_server.py             FastAPI app — admin/browser API, port 8000
├── device_link/
│   ├── attested_network.py   REAL device<->server protocol, port 9000
│   ├── network.py             legacy plaintext demo link (unattested)
│   └── base.py
├── attestation.py            server-side attestation verification + KDF
├── crypto.py                  shared crypto primitives (ECDH, HKDF, AEAD)
├── device_registry.py + device_registry.json   persisted device identities
├── transport/tls.py           browser-facing TLS 1.3 (port 8000, only mode)
└── web/                        dashboard static assets
```

Everything runs via `scripts/run-project.sh`: `docker run --network host`
launches a container that boots QEMU (virtio-net + SLIRP, guest sees the
host as `10.0.2.2`) and drives login/provisioning over tmux.

## Two independent channels — this is the part to not conflate

The server exposes **two ports with two completely different security
models**. Mixing them up is the most common source of confusion.

### Port 8000 — browser/admin API — real TLS

`app_server.py`, served by uvicorn with a pinned **TLS 1.3-only**
`SSLContext` (`transport/tls.py`) and a self-signed cert
(`server/certs/server_cert.pem`). Binds `127.0.0.1:8000` by default. Used
for:
- Admin/browser REST calls (e.g. `POST /api/devices/register`, which the
  edge device itself also calls via `curl` — BusyBox `wget` has no HTTPS
  support, hence the `curl` dependency).
- `/ws/collect`, a WebSocket for the dashboard's live sensor feed. It
  auto-reconnects on drop (`web/app.js`), so a packet capture on this port
  can show several TLS handshakes even for one browsing session — that's
  expected, not a bug.

TLS is the only `UserChannel` mode implemented (`--security tls`); the
interface is pluggable (`transport/base.py`) for adding another later, but
there's no app-layer alternative in the codebase today.

**On the wire:** a normal TLS 1.3 handshake (`Client Hello` → `Server
Hello, Certificate` → `Application Data`), fully opaque after the
handshake.

### Port 9000 — device link — plain TCP, application-layer encryption

`device_link/attested_network.py`. **No TLS here at all** — deliberately.
It's a raw TCP socket (`net.c` on the device side) carrying
newline-delimited JSON. Encryption is applied to the *payload*, not the
transport. Each TCP connection is one self-contained session:

```
device -> server   {"type": "hello", "device_id": "..."}
server -> device   {"type": "attest_challenge", "nonce": ..., "server_ecdh_pub": ...}
device -> server   {"type": "attest_response", "device_ecdh_pub": ..., "quote": ..., "signature": ...}
server -> device   {"type": "attest_result", "ok": true, ...}
device -> server   {"type": "data", "seq": N, "nonce": "<b64>", "ciphertext": "<b64>"}
server -> device   {"ok": true}   (per-message ack)
```

Key derivation (matches on both sides — `crypto.py` on the server,
`trusted_app.c` inside the TA on the device):

1. TA generates an ephemeral **P-256 ECDH** keypair
   (`TA_CONFIDENTIAL_IOT_CMD_GENERATE_ATTESTATION_EVIDENCE`), sent as
   `device_ecdh_pub` in `attest_response`, alongside a transcript hash
   `SHA-256(nonce || server_ecdh_pub || device_ecdh_pub)` and the fTPM
   quote/signature proving device integrity.
2. Once the server accepts the attestation, both sides compute the ECDH
   shared secret and run it through **HKDF-SHA256**, salted with the
   original challenge `nonce`, with a fixed info label
   (`INFO_DEVICE_AEAD`) — this derives a 32-byte **AES-256** session key.
   On the device this happens TA-side
   (`TA_CONFIDENTIAL_IOT_CMD_HANDSHAKE_COMPLETE`); the raw key never
   leaves the TEE.
3. Every sensor reading is encrypted TA-side
   (`TA_CONFIDENTIAL_IOT_CMD_PROTECT_SENSOR_DATA`) with **AES-256-GCM**: a
   fresh random 12-byte nonce per message, and the 8-byte big-endian
   sequence number (`seq`) as AAD — binding ciphertexts to their position
   in the stream and preventing reordering/replay.

**On the wire:** the `hello`/`attest_challenge`/`attest_result` framing is
plaintext JSON (deliberately — it's the negotiation, nothing secret in
it). The `data` messages' `nonce`/`ciphertext` fields are opaque
high-entropy bytes — that's the actual encrypted payload. A Wireshark
capture on this port will show readable structure around a payload that
isn't readable, which is a good way to *demonstrate* the app-layer
encryption model (see `docs/ATTESTATION_TESTING.md` if a capture-based
walkthrough is useful).

## Attestation / trust chain

- The device proves integrity via an fTPM (OP-TEE's software TPM) quote
  over PCR0, signed by a persistent **Attestation Key (AK)** at a fixed
  handle.
- **PCR0 is a software stand-in, not real hardware measured boot.** Full
  TF-A → OP-TEE core → fTPM event-log measured boot isn't wired on this
  QEMU topology (see `docs/ATTESTATION_DESIGN.md` / prior investigation
  notes); instead `provision-device.sh`'s `software_measure_pcr0()`
  extends PCR0 once per boot over hashes of the TA binary + edge host
  binary, giving a deterministic, tamper-sensitive (but Normal-World-run,
  not hardware-rooted) value.
- The AK **persists across QEMU reboots** via a virtio-blk disk mounted at
  `/var/lib/tee` before `tee-supplicant` starts (`scripts/run-project.sh`
  + `S29tee-storage`), so a device doesn't need re-registration every boot.
  See `docs/PERSISTENT_AK_IMPLEMENTATION.md`.
- Device identity is tracked in `CC_Server/server/device_registry.json`.
  Self-registration: an unseen `device_id` is enrolled automatically on
  first contact (device POSTs its enrollment record to
  `/api/devices/register` over the TLS port); the same `device_id` with a
  *different* key is rejected (`DeviceKeyMismatch` → HTTP 409), preventing
  silent identity takeover. See `docs/SELF_REGISTRATION_IMPLEMENTATION.md`.

## Sensor path — RESOLVED

The Host previously saw sensor plaintext (`edge_get_sensor_data` staged it
in a Host buffer before handing it to `PROTECT_SENSOR_DATA` as an input
parameter), and `ta_authenticate_sensor` was a stub that always succeeded.
Both are now real: a secure-only UART2 (Normal-World-invisible, same
mechanism as OP-TEE's own console UART) connects a new `sensor_link`
pseudo-TA to an external Sensor Module process (`sensor_daemon`), which
holds a hardcoded-but-not-compiled-in pre-shared secret. Sensor
authentication is a real HMAC-SHA256 challenge-response verified inside the
TA (`TEE_MACCompareFinal`), and the inverted `READ_AND_PROTECT` command has
no plaintext input parameter at all — the Host CA only ever triggers TA
commands and receives AES-256-GCM ciphertext back. See
`docs/SENSOR_PATH_IMPLEMENTATION.md` for the full design and the
positive/negative-path verification performed.

## Where to go deeper

| Topic | File |
|---|---|
| Full attestation/key-exchange design rationale | `docs/ATTESTATION_DESIGN.md` |
| Build/run/test walkthrough | `docs/ATTESTATION_TESTING.md` |
| Why the device speaks first in the protocol | `docs/CONNECTION_INITIATION.md` |
| Remaining work items, owned by whom | `docs/HANDOFF_MISSIONS.md` |
| AK persistence implementation | `docs/PERSISTENT_AK_IMPLEMENTATION.md` |
| Sensor path (secure UART + PTA + real HMAC auth) implementation | `docs/SENSOR_PATH_IMPLEMENTATION.md` |
| QEMU guest networking setup | `docs/QEMU_NETWORKING.md` |
| Self-registration implementation | `docs/SELF_REGISTRATION_IMPLEMENTATION.md` |
| Clearing stale registry entries for a fresh-device test | `docs/RESET_DEVICE_REGISTRY.md` |
| Term glossary | `docs/TERMINOLOGY.md` |
| Recorded live-test transcripts | `docs/verify/*.md` |
