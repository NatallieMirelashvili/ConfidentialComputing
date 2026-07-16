# Verify: a never-registered device registers itself

Proves that a brand-new device enrolls itself with `CC_Server` with **no**
manual `scripts/register-device.sh` / `curl` step — `main()`'s loop detects
"not registered" and runs the registration pipeline automatically (see the
plan: device self-registration, `docs/HANDOFF_MISSIONS.md` §2.2.b).

Needs 3 terminals, all starting in `/home/Michael/ConfidentialComputing`.

**Prerequisite — rebuild first.** If you've pulled or made source changes
under `project/optee_examples/` or `project/buildroot/packages.conf`, run
`scripts/build-project.sh` before booting QEMU. `.optee-workspace/` is a
generated mirror that only picks up source changes on an explicit rebuild —
booting a stale image silently runs old code with no error. (This is also
why self-registration needs `curl`, added via
`project/buildroot/packages.conf` — the guest's BusyBox `wget` has no
HTTPS support at all in this rootfs, and the server's TLS transport is
pinned to TLS 1.3 only, which a minimal client couldn't negotiate anyway.
If you see `wget: not an http or ftp url` in the console instead of the
expected output below, the running image predates this fix — rebuild.)

## Terminal 1 — management server

```bash
cd /home/Michael/ConfidentialComputing/CC_Server
MS_DEVICE_LINK=attested_network MS_DEVICE_HOST=0.0.0.0 MS_DEVICE_PORT=9100 MS_API_HOST=0.0.0.0 MS_API_PORT=8100 python3 -m server.main
```

Leave it running; watch its console during Terminal 2's boot for the log
lines noted below.

**Don't assume a running server is this one.** There may already be an
unrelated server on this box (e.g. a teammate's long-running Docker
container bound to the *default* ports 8000/9000 — check `docker ps` /
`ss -tlnp`). If the device keeps printing `edge_device: attestation/session
failed; retrying` with no `not registered` line at all, that usually means
nothing is listening on port 9100 yet — this command didn't actually get
run, or it died. The push loop retries every `CIOT_PUSH_INTERVAL` (default
3s), so once you start the server correctly there's no need to reboot QEMU
— it'll pick the connection up on its next retry.

## Terminal 2 — a fresh device instance

Pick a `QEMU_INSTANCE` you know has never been used before (or delete its
disk to force a brand-new AK — same effect, a device the server has never
seen). This example uses instance `9` (→ `device_id=iot-edge-10`):

```bash
cd /home/Michael/ConfidentialComputing
rm -f .device-state/iot-edge-10.img   # ensure a truly fresh AK
QEMU_TMUX_SESSION=optee-verify-fresh QEMU_INSTANCE=9 SERVER_PORT=9100 API_PORT=8100 scripts/run-project.sh
```

This attaches you to the tmux session. Boot + auto-provisioning takes a
couple of minutes (see `docs/ATTESTATION_TESTING.md` §4) — wait for the
"Provisioned ... see the enrollment record above" status message, after
which `optee_example_confidential_iot_edge` starts automatically. **Do not**
run `scripts/register-device.sh` or any `curl` command for this device.

Watch the edge binary's own console output (same tmux window). Expect, in
order:

```
edge_device: not registered, attempting self-registration...
edge_device: registered with the management server
edge_device: pushed sensor reading
```

If instead you see `edge_device: attestation/session failed; retrying`
repeating forever with no "self-registration" line, the feature isn't
triggering — check `edge_ensure_session()`/`edge_attest_to_server()` in
`edge_device.c`.

## Terminal 3 — confirm the registry

```bash
cd /home/Michael/ConfidentialComputing
python3 -m json.tool CC_Server/server/device_registry.json | grep -A5 iot-edge-10
```

Expect a new entry for `iot-edge-10` with a populated `ak_pub_pem` and a
`created_at` timestamp close to "now" — added without anyone having called
`POST /api/devices/register` by hand.

## Cleanup

```bash
tmux kill-session -t optee-verify-fresh
```

(Leave Terminal 1's server running if you're chaining into
`reboot_skips_reregistration.md` next — it reuses this same device.)
