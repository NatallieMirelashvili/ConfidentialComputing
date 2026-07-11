# Verify: a mismatched key is rejected, not silently overwritten

Proves the core fix for `docs/HANDOFF_MISSIONS.md` §2.2.b: if a `device_id`
is already registered and a *different* key is submitted for the same ID
(e.g. a second/rogue device claiming an identity that's already taken), the
server rejects it instead of silently replacing the trusted identity. Also
confirms the "admin/sudo" protection — `device_registry.json` is owner-only
(`0600`) — actually landed.

**Correction (found during live verification):** the reproduction method
below uses a direct `curl` POST, not the QEMU device itself. An earlier
version of this doc tried to trigger this by wiping the device's persistent
disk (forcing a fresh AK under the same `device_id`) and expecting the
device's own self-registration to get rejected. That doesn't work: the
server's "not registered" check (`AttestationVerifier.issue_challenge()`) is
a pure `device_id`-existence check, blind to the AK — since `iot-edge-10`
is *already* in the registry, `hello` always gets a valid challenge
regardless of which key the device holds, so the device never even
attempts self-registration. Instead the device's quote fails the signature
check at actual attestation time (an existing, unrelated failure path) and
it just retries `edge_device: attestation/session failed; retrying`
forever — a real, correct failure mode, just not this one. Exercising
`DeviceKeyMismatch` for real requires a caller that reaches
`POST /api/devices/register` directly with a conflicting key for an
existing `device_id` (a rogue device, a second device misconfigured with
the same ID, or - as below - `curl`) - which is exactly the threat §2.2.b
is about anyway.

**Prerequisite:** `iot-edge-10` already registered (run
`fresh_device_self_registers.md` first). Keep Terminal 1 (the server)
running.

## Terminal 1 — management server (if not already running)

```bash
cd /home/Michael/ConfidentialComputing/CC_Server
MS_DEVICE_LINK=attested_network MS_DEVICE_HOST=0.0.0.0 MS_DEVICE_PORT=9100 MS_API_HOST=0.0.0.0 MS_API_PORT=8100 python3 -m server.main
```

Keep this terminal visible — a rejected registration logs a `WARNING` line
here.

## Terminal 2 — note the current key + file permissions

```bash
cd /home/Michael/ConfidentialComputing
ls -la CC_Server/server/device_registry.json
python3 -m json.tool CC_Server/server/device_registry.json | grep -A2 iot-edge-10
```

Expect `-rw-------` (owner-only, `0600`) — if it's still `-rw-rw-r--`, the
`os.chmod` fix in `device_registry.py`'s `_save()` didn't take effect. Note
the current `ak_pub_pem` value to compare against later.

## Terminal 3 — POST a conflicting key for the same device_id

Build an enrollment record with the same `device_id` but any different
`ak_pub_pem_b64` (any valid base64 works for this test — the endpoint
doesn't try to verify it's a real key, only that it differs from what's
stored):

```bash
cd /home/Michael/ConfidentialComputing
cat > /tmp/mismatch_record.json <<'EOF'
{"device_id":"iot-edge-10","ak_pub_pem_b64":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KZmFrZS1rZXktZm9yLXRlc3Rpbmc9PQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0K","expected_pcr":"  sha256:\n    0 : 0xDEADBEEF\n","pcr_bank":"sha256:0"}
EOF

curl -sk -X POST https://127.0.0.1:8100/api/devices/register \
  -H 'Content-Type: application/json' \
  -d @/tmp/mismatch_record.json \
  -w '\nHTTP_STATUS=%{http_code}\n'
```

Expect:

```
{"ok":false,"error":"device 'iot-edge-10' is already registered with a different key"}
HTTP_STATUS=409
```

## Terminal 1 — confirm the server logged it

Scroll Terminal 1's output for a line like:

```
WARNING:server.app_server:rejected registration for iot-edge-10: device 'iot-edge-10' is already registered with a different key
```

## Terminal 2 (again) — confirm the registry is unchanged

```bash
python3 -m json.tool CC_Server/server/device_registry.json | grep -A2 iot-edge-10
```

`ak_pub_pem` must be **identical** to what you noted before — the rejected
attempt did not overwrite it.

## Manual admin override (the escape hatch)

`docs/HANDOFF_MISSIONS.md` §2.2.b asks for a way to intentionally accept a
new key when a genuine re-provision is needed. There's no new tool for
this — the file is plain JSON, and access to it (as the OS user running
`CC_Server`, or via `sudo`) is the entire admin mechanism.

**Important (found during live verification): the server must be
restarted after a manual edit.** `DeviceRegistry` reads
`device_registry.json` once at startup and keeps everything in memory —
it does not watch the file or reload it. Editing the file while the
server keeps running has **no effect** until it restarts; the live process
keeps serving the old in-memory record regardless of what's on disk.

```bash
cd /home/Michael/ConfidentialComputing/CC_Server
python3 - <<'EOF'
import json
path = "server/device_registry.json"
with open(path) as f:
    data = json.load(f)
del data["iot-edge-10"]          # forces a clean re-enroll on the device's next attempt
with open(path, "w") as f:
    json.dump(data, f, indent=2)
EOF
```

Then, in Terminal 1, stop the server (Ctrl-C) and start it again with the
same command. Only after the restart does the deletion take effect — if
you have a real QEMU device still retrying against `iot-edge-10` at this
point, it will pick up the change on its next retry (within
`CIOT_PUSH_INTERVAL`, default 3s) and self-register cleanly, since
`iot-edge-10` is unseen again.

## Cleanup

```bash
tmux kill-session -t optee-verify-fresh
```
