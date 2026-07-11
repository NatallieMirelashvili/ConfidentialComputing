# Verify: a reboot with a matching key skips re-registration

Proves that once a device is registered, rebooting it (same persistent AK,
per `docs/PERSISTENT_AK_IMPLEMENTATION.md`) does **not** re-trigger the
self-registration pipeline — the server sees a matching key and treats it
as a no-op ("already registered, continue").

**Prerequisite:** run `fresh_device_self_registers.md` first (or already
have a registered instance) — this doc reuses that same `iot-edge-10`
device and its `.device-state/iot-edge-10.img` disk. Keep Terminal 1 (the
server) running from that doc, or restart it with the same command.

## Terminal 1 — management server (if not already running)

```bash
cd /home/Michael/ConfidentialComputing/CC_Server
MS_DEVICE_LINK=attested_network MS_DEVICE_HOST=0.0.0.0 MS_DEVICE_PORT=9100 MS_API_HOST=0.0.0.0 MS_API_PORT=8100 python3 -m server.main
```

## Terminal 2 — note the current registry entry

```bash
cd /home/Michael/ConfidentialComputing
python3 -m json.tool CC_Server/server/device_registry.json | grep -A5 iot-edge-10
```

Write down (or `diff` against later) the `ak_pub_pem` and `created_at`
values shown.

## Terminal 3 — reboot the same instance

Kill any existing tmux session for it and relaunch with the **same**
`QEMU_INSTANCE` (so it reuses the existing `.device-state/iot-edge-10.img`
disk — do **not** delete that file, that's what keeps the AK the same):

```bash
cd /home/Michael/ConfidentialComputing
tmux kill-session -t optee-verify-fresh 2>/dev/null
QEMU_TMUX_SESSION=optee-verify-fresh QEMU_INSTANCE=9 SERVER_PORT=9100 API_PORT=8100 scripts/run-project.sh
```

Wait for boot + provisioning + the edge binary to start (same as before).
Watch its console. Expect it to attest **directly** — no registration-pipeline
log lines at all:

```
edge_device: pushed sensor reading
```

should appear with **no** preceding `edge_device: not registered,
attempting self-registration...` line. If that line shows up, either the
disk wasn't actually reused (check the instance number and that the `.img`
file wasn't deleted) or the "already registered, no-op" path regressed.

## Terminal 2 (again) — confirm the registry is unchanged

```bash
python3 -m json.tool CC_Server/server/device_registry.json | grep -A5 iot-edge-10
```

`ak_pub_pem` and `created_at` must be **identical** to what you noted
before the reboot — proving the server took the "matching key → no-op"
path, not a rewrite.

## Cleanup

```bash
tmux kill-session -t optee-verify-fresh
```
