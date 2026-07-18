# Device↔Server Attestation — Usage & Testing Guide

Companion to `docs/ATTESTATION_DESIGN.md` (read that first for the *why*).
This is the *how*: building, running, and testing what was added.

## 1. Fast loop: server-side tests (no QEMU, no hardware, run these first)

These run entirely in Python and don't need the ARM image at all — they're
the quickest way to check the attestation logic is sound before touching
the slow QEMU build.

```bash
cd /home/Michael/ConfidentialComputing/CC_Server
python3 -m pip install --user pytest fastapi httpx uvicorn websockets cryptography
python3 -m pytest server/tests -v
```

Expect **16 passed**: the 9 pre-existing tests plus 6 new ones in
`server/tests/test_attestation.py`:

| Test | What it proves |
|---|---|
| `test_attestation_full_roundtrip` | A genuine, correctly-signed attestation succeeds; both sides derive the *identical* AES-256 key independently; that key actually encrypts/decrypts a sample data payload. |
| `test_attestation_rejects_unregistered_device` | An unenrolled `device_id` can't even get a challenge. |
| `test_attestation_rejects_bad_signature` | A quote signed by the wrong key is rejected. |
| `test_attestation_rejects_pcr_mismatch` | A quote over PCR values that don't match the enrolled baseline is rejected. |
| `test_attestation_rejects_replayed_response` | The same response can't be replayed against a stale/already-consumed challenge. |
| `test_attested_network_link_full_protocol` | Drives `AttestedNetworkDeviceLink`'s actual per-connection state machine (hello → attest_challenge → attest_response → attest_result → data) end to end. |

These tests build syntactically-correct TPM2B_ATTEST/TPMT_SIGNATURE bytes
in pure Python (real ECDSA signing via `cryptography`, no real TPM
involved) — they validate the server's parsing/verification logic
independent of whatever the real `tpm2_quote` CLI syntax turns out to need.

If you change `server/attestation.py`, `device_registry.py`, or
`device_link/attested_network.py`, re-run this before anything else.

## 2. Fast loop: Host CA syntax checks (no OP-TEE toolchain needed)

The Host CA's base64/SHA-256/JSON needs are covered by real libraries
(mbedTLS via `libmbedcrypto`, cJSON — see `docs/ATTESTATION_DESIGN.md`
§2.5), so there are no hand-rolled helpers left to unit-test in isolation;
only `net.c` (a thin POSIX-sockets wrapper) remains local.

You can still syntax-check the whole Host CA in "native" mode (no TEE
client library) to catch obvious compile errors before a full ARM
cross-build. The mbedTLS/cJSON headers must come from somewhere: either
install the dev packages on the machine (`libmbedtls-dev` + `libcjson-dev`
on Debian/Ubuntu), or — after at least one full build — point at the
Buildroot staging tree, which has the exact versions the image uses:

```bash
cd /home/Michael/ConfidentialComputing/project/optee_examples/confidential_iot
SYSROOT=../../../.optee-workspace/out-br/host/aarch64-buildroot-linux-gnu/sysroot
gcc -Wall -Wextra -DCONFIDENTIAL_IOT_NATIVE -fsyntax-only \
  -I edge_device/host -I sensor_module -I attestation -I edge_device/ta/include \
  -I "$SYSROOT/usr/include" \
  edge_device/host/edge_device.c edge_device/host/main.c attestation/attestation.c
```

And the TA itself against this project's *real* generated TA dev-kit
headers (this is how a real `TEE_MODE_DERIVE_KEY` → `TEE_MODE_DERIVE` typo
was caught before ever touching QEMU):

```bash
cd /home/Michael/ConfidentialComputing
TA_INC=.optee-workspace/optee_os/out/arm/export-ta_arm64/include
gcc -Wall -Wextra -fsyntax-only -I "$TA_INC" \
  -I project/optee_examples/confidential_iot/edge_device/ta/include \
  -I project/optee_examples/confidential_iot/edge_device/ta \
  project/optee_examples/confidential_iot/edge_device/ta/trusted_app.c
```

(Requires having run `scripts/bootstrap.sh` + at least one build already,
so `optee_os/out/...` exists.)

## 3. Full loop: build and boot the real image

From the project root (`ConfidentialComputing/`):

```bash
scripts/docker-build.sh          # once, or when the Dockerfile changes
scripts/docker-shell.sh           # enter the build container
scripts/bootstrap.sh              # once, or to reset .optee-workspace
scripts/build-project.sh          # rebuilds project sources + OP-TEE/QEMU images
```

`build-project.sh` calls `scripts/sync-project.sh` first (copies
`project/optee_examples/` into `.optee-workspace/optee_examples/`), so any
edits under `project/optee_examples/confidential_iot/` are picked up
automatically — you never need to touch `.optee-workspace` by hand.

Then boot it:

```bash
scripts/run-project.sh
```

This opens a tmux session, continues QEMU, logs in as `root` in the Normal
World console, and runs `optee_example_confidential_iot_edge` automatically.


## 4. Running several devices concurrently 

Each device is a separate QEMU instance, so it needs its own terminal (`scripts/run-project.sh`
attaches to its own tmux session and holds the terminal). A typical run needs:

| Terminal | What runs there |
|---|---|
| 1 | The management server |
| 2 | Device 1 (`scripts/run-project.sh`) |
| 3 | Device 2 (`scripts/run-project.sh`) |
| ... | One more terminal per additional device |
| N+1 | A free terminal for `curl` (admin registration) — terminals 1-N are all occupied by long-running foreground processes |

**Terminal 1 — the server** (pick any free ports; defaults are `9000`/`8000`):

```bash
cd /home/Michael/ConfidentialComputing/CC_Server
MS_DEVICE_LINK=attested_network MS_DEVICE_HOST=0.0.0.0 MS_DEVICE_PORT=9100 MS_API_PORT=8100 python3 -m server.main
```

`MS_API_HOST` still defaults to `127.0.0.1` (loopback) regardless of `MS_API_PORT` — if you're
opening the UI from a different machine than the one running the server, forward that port (SSH
`-L`, VS Code's Ports panel, etc.) or add `MS_API_HOST=0.0.0.0`.

**Terminals 2, 3, ... — one device each.** `QEMU_INSTANCE` (0, 1, 2, ...) gives each instance
distinct gdbstub/serial ports and a distinct default `device_id` (`iot-edge-01`, `iot-edge-02`,
...) so they don't collide; pass `SERVER_PORT` if you changed it from the default `9000` above:

```bash
QEMU_TMUX_SESSION=optee-qemu-1 QEMU_INSTANCE=0 SERVER_PORT=9100 scripts/run-project.sh
QEMU_TMUX_SESSION=optee-qemu-2 QEMU_INSTANCE=1 SERVER_PORT=9100 scripts/run-project.sh
```

**Boot + auto-provisioning takes a while — don't assume it's stuck.** Each instance boots Linux,
logs in, then automatically runs `provision-device.sh` for its device_id. The fTPM device node
isn't reliably usable the instant the shell prompt appears, so provisioning retries every 5s for
up to 90s before giving up; the whole boot-to-enrollment-record sequence can take a couple of
minutes per instance. Wait for the tmux status message ("Provisioned ... see the enrollment record
above") before looking for the JSON.

**Terminal N+1 — register each device.** Grab the enrollment JSON printed in each device's own
console (scroll that instance's tmux pane, or `tmux capture-pane -pt optee-qemu-1:1.0 -S -50 -p |
grep device_id`), then register it — once per device, each with *its own* JSON (don't reuse one
device's record for another):

```bash
curl -k -X POST https://127.0.0.1:8100/api/devices/register \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"iot-edge-01","ak_pub_pem_b64":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFT0d6UnFZZXFUSzlMN2VCWDkzZU9xS2liSC9JWQptZW1JL0kzVUhwczQzL2x1L3hmU0I1bEl0OXFqbU5OV2lEQjhLTklLZ0FDNDF1alVwTHk2cGFwN3VRPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","expected_pcr":"  sha256:\n    0 : 0x0000000000000000000000000000000000000000000000000000000000000000\n","pcr_bank":"sha256:0"}'
```

Once registered, each instance's already-running `optee_example_confidential_iot_edge` attests
independently against the one server — check `GET /api/devices` to see both show up as distinct
entries.

## 6. If something doesn't work — where to look first

Per the design doc's "known gaps" section, the most likely failure points
on first real-hardware run, in order of likelihood:

1. **`tpm2_quote`/`tpm2_pcrread` CLI flags** (in
   `attestation/attestation.c` and `scripts/provision-device.sh`). Run
   `tpm2_quote --help` / `tpm2_pcrread --help` in the Normal World console
   and compare against the `system()` calls in `attestation.c`. The
   qualifying-data (`-q`) argument format (raw hex vs. a `file:`/`hex:`
   prefix) is the most likely thing to need adjusting.
2. **PCR bank/index mismatch** — confirm what the fTPM actually extends by
   reading `optee_ftpm/platform/fTPM_event_log.c`, and that
   `scripts/provision-device.sh`'s `tpm2_pcrread sha256:0` (used both at
   enrollment and at every attestation) targets the same index.
3. **`/dev/tpmrm0` missing at boot** — run `ls /dev/tpm*` in the Normal
   World console. Per the design doc, the kernel driver
   (`CONFIG_TCG_FTPM_TEE=y`) is built in, not a module, so this should just
   appear; if it doesn't, check `dmesg` for TEE/TPM driver probe errors.
4. **AK handle mismatch** — `provision-device.sh` persists the AK at a
   fixed handle (`0x8101000A`) and writes it to
   `/etc/confidential_iot/device.conf`; if `edge_device.c`'s config loading
   picks up a stale/different value (e.g. `CIOT_AK_HANDLE` env var
   overriding it unexpectedly), `tpm2_quote -c <handle>` will fail to find
   the key.
5. **Server/device transcript-hash mismatch** — if attestation always fails
   at the "quote does not match this session's transcript" check, add a
   temporary log line on both sides printing the hex of
   `nonce || server_ecdh_pub || device_ecdh_pub` before hashing, and diff
   them — this pins down whether it's a byte-order/encoding mismatch rather
   than a real protocol bug.
6. **`sensor authentication failed` after re-running the edge binary in the
   same boot** — expected, not a bug. `optee_example_confidential_iot_edge`
   is meant to run **once per boot**. The Sensor Module (`sensor_daemon`)
   streams readings on the shared secure UART once authenticated, and that
   stream is tied to the QEMU-boot connection, not the edge-process lifetime.
   Ctrl-C'ing the edge binary and starting it again leaves the previous run's
   unconsumed reading backlog (and PL011 RX-FIFO overflow) in the link, which
   desyncs the next challenge/response so `ta_authenticate_sensor` fails
   closed. **Reboot the guest to re-run the edge client** (a fresh QEMU boot
   resets the sensor connection). Fixing it in-place would mean draining/
   resyncing the UART in the Secure-World `sensor_link` PTA — deliberately not
   done, since one-run-per-boot is the intended flow.

For all of the above, the Python test suite (§1) staying green tells you
the *server-side logic* is fine — so a real-hardware failure almost always
means one of the C-side/tpm2-tools specifics above, not the verification
logic itself.
