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

Expect **63 passed, 2 skipped** (the 2 are `test_poc.py`, which self-skips
unless a real QEMU device attests within 15 s).

Core attestation coverage (`server/tests/test_attestation.py`):

| Test | What it proves |
|---|---|
| `test_attestation_full_roundtrip` | A genuine, correctly-signed attestation succeeds; both sides derive the *identical* AES-256 key independently; that key actually encrypts/decrypts a sample data payload. |
| `test_attestation_rejects_unregistered_device` | An unenrolled `device_id` can't even get a challenge. |
| `test_attestation_rejects_bad_signature` | A quote signed by the wrong key is rejected. |
| `test_attestation_rejects_pcr_mismatch` | A quote over PCR values that don't match the enrolled baseline is rejected. |
| `test_attestation_rejects_replayed_response` | The same response can't be replayed against a stale/already-consumed challenge. |
| `test_attested_network_link_full_protocol` | Drives `AttestedNetworkDeviceLink`'s actual per-connection state machine (hello → attest_challenge → attest_response → attest_result → data) end to end. |

TA-identity binding (`docs/TA_IDENTITY_IMPLEMENTATION.md`). The first one is
**the** test for the whole feature — everything else exists to keep it honest:

| Test | What it proves |
|---|---|
| `test_ta_identity_bypass_with_wrong_key_is_rejected` | The compromised-Host bypass: a **fully valid** quote — real AK signature, real PCR0, correct transcript — is still rejected when `ta_sig` comes from anything but the sealed TA key. No session key is stored. |
| `test_ta_identity_bypass_with_missing_ta_sig_is_rejected` | The same bypass by omission, plus a control run proving `ta_sig` is the *only* difference between accept and reject. |
| `test_ta_sig_over_a_different_device_pub_is_rejected` | A genuine TA signature replayed alongside a substituted ECDH key is rejected — this is why `device_ecdh_pub` is in the pre-image. |
| `test_ta_sig_over_a_different_device_id_is_rejected` | The per-device binding, in executable form. |
| `test_ta_sig_from_an_earlier_session_is_rejected` | Freshness, independent of the quote's own transcript check. |
| `test_ta_identity_preimage_is_byte_exact` | Known-answer test for the exact bytes the TA hashes — the C/Python parity lock (see below). |
| `test_ta_sig_must_be_verified_over_the_preimage_not_the_digest` | Guards the double-hash trap: verifying the digest instead of the pre-image would reject every honest device. |
| `test_ta_identity_is_domain_separated_from_the_other_signatures` | The TA pre-image can never collide with the quote's qualifying data or the server-identity pre-image. |
| `test_attested_network_rejects_attest_response_without_ta_sig` | The bypass driven through the real connection state machine, not just the verifier. |
| `test_verify_rejects_record_with_empty_ta_pub` | A device enrolled before this feature loads, but cannot attest. |

Registry and endpoint coverage lives in `test_device_registry.py` (pinned-key
immutability, including the case where the AK matches but the TA key changed)
and `test_register_endpoint.py` (point validation, base64 canonicalisation, 409
on a changed TA key, `device_id` validation).

These tests build syntactically-correct TPM2B_ATTEST/TPMT_SIGNATURE bytes
in pure Python (real ECDSA signing via `cryptography`, no real TPM
involved) — they validate the server's parsing/verification logic
independent of whatever the real `tpm2_quote` CLI syntax turns out to need.

**Two things worth knowing about these tests as a suite.** The bypass tests were
*mutation-tested* — neutering check (e) in `attestation.py` makes all four fail,
so they are load-bearing rather than incidentally passing; re-do that if you ever
refactor the check. And `test_ta_identity_preimage_is_byte_exact` pins a
known-answer digest computed from the wire spec alone, so a TA developer can
compute the same value in C and compare directly instead of bisecting a
byte-parity bug across the C/Python boundary.

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

## 2a. Device-side TA security tests (in the guest, needs a built image)

Everything in §1 tests the **server**: that its verifier rejects forged evidence.
`optee_example_confidential_iot_tests` is the mirror image — it runs **inside the
guest**, as root, and attacks the TA the way a root-compromised Normal World would,
proving the device never *produces* forgeable evidence. Source lives in
`project/optee_examples/confidential_iot/tests/host/`.

It is deliberately not built on `edge_device.c`: it is simulating a hostile Host, so
it opens its own TEEC session, invokes commands out of order and with malformed
parameters, substitutes keys it generated itself, and rewrites `/lib/optee_armtz`. It
plays the *server's* verifying role locally with mbedTLS, so no server and no network
are involved.

Run it after boot and provisioning, with the edge daemon stopped (Ctrl-C — it is
one-run-per-boot by design, see §6.6; the tests do not restart it):

```sh
optee_example_confidential_iot_tests          # all 5
optee_example_confidential_iot_tests -t 3     # just one
optee_example_confidential_iot_tests -l       # list them
```

Expect `CIOT_TESTS_DONE=0` on the last line; the exit code is the number of failed
checks, and the sentinel matches `provision-device.sh`'s `CIOT_PROVISION_DONE=`
convention so a tmux-driven runner can wait on it.

| Test | What it proves |
|---|---|
| 1. UUID mimicry | A TA signed with anything but `keys/ciot_ta.pem` will not load — under its own UUID, planted at the genuine UUID's path, or byte-flipped. This is Part A, executable. |
| 2. Storage scoping | `ciot.ta.identity`, `ciot.sensor.psk` and `ciot.server.pubkey` are `ITEM_NOT_FOUND` from a *different* TA UUID, with a self round-trip under the prober's own `ciot.probe.control` as the control. The premise behind "Part A gates Part B". Also asserts the `sensor_link` PTA refuses a Normal-World caller, so the Host cannot read sensor plaintext off the secure UART directly. |
| 3. Faked attestation | `ta_sig` verifies over the TA's own ECDH key and **not** over an attacker-generated one, another device's id, or a previous session. The compromised-Host bypass, from the device end. |
| 4. Lying Host | `READ_AND_PROTECT` without a session, `HANDSHAKE_COMPLETE` without evidence, and a forged server-identity signature are all refused TA-side, and no session key is derived. |
| 5. Identity immutability | The sealed identity re-exports idempotently, refuses to rebind to another `device_id`, and survives every malformed parameter with a clean GP error rather than a panic. |

Three things worth knowing before reading a result:

- **Test 1 rewrites `/lib/optee_armtz` and restores it.** That is safe by
  construction: the rootfs is an initramfs (`out-br/images/rootfs.cpio.gz`), so the
  writes are RAM-only and a reboot undoes them regardless. It backs the genuine TA up
  to `/tmp/ciot-genuine-ta.bak` first and re-opens it at the end as a control, so a
  failed restore can never read as a pass. If that last control fails, reboot.
- **Test 4 never presents a validly-signed attacker server key.** The server identity
  is pinned Trust-On-First-Use, so doing that while nothing is pinned would pin the
  attacker's key and permanently break the device. The signature is always random and
  the return code discriminates the state without risking a write:
  `ACCESS_CONFLICT` = already pinned, impersonation rejected on sight;
  `SIGNATURE_INVALID` = nothing pinned yet, rejected at verification before the pin.
  Both are passes, and the test reports which it saw.
- **Tests 3 and 5 refuse to run on an unprovisioned device.** They drive `CMD 6`,
  which seals the TA identity first-write-wins, so a guessed `device_id` would be
  sealed permanently and every later `provision-device.sh` run would then fail with
  `TEE_ERROR_ACCESS_CONFLICT` until the secure storage is wiped. If
  `/etc/confidential_iot/device.conf` has no `device_id` and `CIOT_DEVICE_ID` is
  unset, they report that and stop rather than guess.

Test 3 opens with a **known-answer check on its own pre-image builders**, using the
same vectors `test_ta_identity_preimage_is_byte_exact` pins on the server. So the
C/Python parity lock now runs on the device too, and a byte-parity bug reports itself
as "known-answer digest mismatch" instead of masquerading as a broken TA signature.

### The two TA fixtures

Test 1 and 2 need TAs, and the Buildroot hook builds exactly one per top-level example
dir (`*/ta/Makefile`), so each gets its own:

| Dir | UUID | Signed with | Must |
|---|---|---|---|
| `project/optee_examples/ciot_probe_ta` | `…-0004` | the project key | load, and fail to see another TA's objects |
| `project/optee_examples/ciot_rogue_ta` | `…-0003` | `ta/attacker_ta.pem` (committed, publicly known, worthless) | **not** load |

**Before adding another UUID in the `7d9f6d20-5f11-4d0c-9a17-61c9c91c00xx` range,
read the allocation table in `ciot_probe_ta/ta/include/ciot_probe_ta.h` — and check
`project/optee_os_ext/` too, not just the TAs.** `…-0002` is the `sensor_link` PTA.
The prober was originally built at that UUID and *silently did not work*: OP-TEE
resolves pseudo-TAs before user TAs, so the PTA shadowed the `.ta` file completely and
the session open was refused by the PTA's own caller check — `ACCESS_DENIED` with
origin `TRUSTED_APP`, from a fixture that was built, installed and correctly signed but
never consulted. Nothing in the build warns about this.

The signing key is the *only* difference between them — one `override TA_SIGN_KEY`
line in `ciot_rogue_ta/ta/Makefile`, which beats the `TA_SIGN_KEY` that
`scripts/build.sh` exports. Both install to `/lib/optee_armtz` under their own
filenames, so neither can collide with the genuine TA; the mimicry happens at runtime.
`project/optee_examples/ciot_rogue_ta/README.md` has the commands to confirm each
fixture really is signed with the key it claims — worth running if test 1 ever passes
suspiciously easily, since a rogue that accidentally carries a valid project signature
would make the whole test vacuous.

Every failing line prints the raw `TEEC_Result` and, for session opens, the error
origin. A fixture that is **present but will not load** is called out as such, and the
reason is on the secure console (tmux window 0) — a fixture failing to load is an
infrastructure problem with the test, not a finding about the real TA, and the two
should never be confused.

### Checking the suite is load-bearing

Same idea as the mutation testing done on the server tests. Each of these should make
the named test **fail**:

- remove the `override TA_SIGN_KEY` line from `ciot_rogue_ta/ta/Makefile` → test 1
  (the rogue then loads like any other TA);
- change `sign_ta_identity()` to sign over anything other than the key the TA just
  generated — e.g. hash `params[2]` (the server's key) in place of `device_pub` → test 3;
- make `authenticate_server()` return `TEE_SUCCESS` unconditionally, or remove
  `ta_handshake_complete()`'s `sess->ecdh_keypair == TEE_HANDLE_NULL` check → test 4.

Note that removing the `!sess->session_key_valid` guard in `ta_read_and_protect()` would
**not** fail test 4: the `!sess->sensor_authenticated` check precedes it and returns the
same `TEE_ERROR_BAD_STATE`, so `CMD 1` never reaches the session-key gate in a test
session that has not authenticated a sensor.

**Not covered by any test: the shared-memory race.** `ta_generate_attestation_evidence()`
copies `nonce`, `server_pub` and `device_pub` into TA-local buffers before hashing them,
because a root Host can rewrite the `params[]` memrefs from another thread while the
command runs (correction #3 in `docs/TA_IDENTITY_IMPLEMENTATION.md` §6). Reverting those
copies would **not** fail test 3 — the test is single-threaded and never touches the
buffers mid-call, so it would still see a correct signature. Exercising it needs a
concurrent writer racing `CMD 3`, which the suite does not do.

While the suite runs, the secure console (tmux window 0) should show TA
signature/hash verification failures during test 1 — `shdr_verify_signature` for the
attacker-signed legs, a payload hash mismatch for the byte-flipped one — and **no**
`TA panicked` anywhere.

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

**The build ends with `scripts/verify-ta-signing.sh`**, which asserts the OP-TEE
core's baked-in verifier key and the built `.ta`'s signature are the same
project-private key (`keys/ciot_ta.pem`). Don't skip past its output: a mismatch
is otherwise a *silent* build success in which every TA then fails to load at
runtime, which looks like anything but a key problem. You can run it standalone
after a build.

To check Part A's actual guarantee (a tampered TA won't load), flip a byte in
`/lib/optee_armtz/7d9f6d20-5f11-4d0c-9a17-61c9c91c0001.ta` inside the guest —
OP-TEE core must refuse to load it (`shdr_verify_signature` failure on the
secure console). A clean rebuild loads normally.

Then boot it:

```bash
scripts/run-project.sh
```

This opens a tmux session, continues QEMU, logs in as `root` in the Normal
World console, and runs `optee_example_confidential_iot_edge` automatically.

> **If you are updating an existing checkout**, the TA signing key change moves
> PCR0, so every enrolled device's baseline is stale *and* no existing registry
> record has a `ta_pub_b64`. Both symptoms look like a device that just won't
> attest. Follow the runbook in `docs/RESET_DEVICE_REGISTRY.md` — the short
> version is build → `scripts/reset-device-registry.sh --all` → **restart
> CC_Server** → `run-project.sh`, in that order.


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

7. **`bad enrollment record: 'ta_pub_b64'`** at registration, on both the
   device console and the `register-device.sh` output — the guest image
   predates TA-identity binding. Confirm with
   `grep -c ta_pub_b64 .optee-workspace/out-br/target/usr/bin/provision-device.sh`
   (0 means stale). Rebuild; the new `provision-device.sh` and edge binary land
   in the rootfs. Then follow the reset runbook, because the same rebuild also
   moves PCR0.
8. **`device has no enrolled TA identity key`** in the server log — the
   *registry* is stale rather than the image. The server also warns about this
   per device at startup. Re-registering will **not** fix it (409 by design, to
   avoid reopening the trust-on-first-use window); drop the record with
   `scripts/reset-device-registry.sh <device_id>` and restart the server.
9. **`TA panicked`** on the secure console during the first attestation after a
   fresh provision — most likely the sealed TA identity object is corrupt.
   `TEE_AsymmetricSignDigest` panics rather than returning an error on anything
   except `SHORT_BUFFER`, so this is what a bad key looks like. Wipe the
   device's disk (`.device-state/<device_id>.img`) and re-provision. If it
   persists, raise `TA_STACK_SIZE` in `user_ta_header_defines.h` before
   suspecting the crypto — a stack overflow presents identically.
10. **TA-identity verification fails for every device**, with valid quotes —
    suspect a pre-image mismatch between the TA and the server, not the ECDSA
    itself. Don't bisect it by hand: `test_ta_identity_preimage_is_byte_exact`
    pins a known-answer digest derived from the wire spec, so compute the same
    digest in C over the same fixed inputs and compare. (`xtest 4006`/`4011`
    independently exercise this build's ECDSA keygen/sign/verify — but note the
    optee_test TAs may need a one-time rebuild to load after the signing-key
    change; see `docs/TA_IDENTITY_IMPLEMENTATION.md` §7.)

For all of the above, the Python test suite (§1) staying green tells you
the *server-side logic* is fine — so a real-hardware failure almost always
means one of the C-side/tpm2-tools specifics above, not the verification
logic itself.
