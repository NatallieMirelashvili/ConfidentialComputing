# Management Server — User↔Server side (PoC)

Confidential Computing project (Group 4) — the **user-facing** half of the
Management Server: an HTML UI + REST API, protected by **TLS 1.3** for the
User↔Server channel. Transport security is pluggable (`UserChannel`); TLS is
the only mode implemented today.

Sensor data reaches the server through the **`DeviceLink` seam**, backed by a
real edge device over TCP — either `network` (plaintext, self-reported
attestation) or `attested_network` (remote attestation + AES-256-GCM sensor
channel). There is no synthetic fallback: `MS_DEVICE_LINK` must select one or
the server refuses to start.

> **Visual docs** (open in a browser):
> - `docs/architecture.html` — structure: transport security, the data-flow, module/class map.
> - `docs/runtime.html` — function-level trace of what runs when you open the server,
>   click Collect, and get the response (sequence diagrams, call graph, object lifetimes).

## What's here
```
config.py        Config class — the ONE place env vars are read (MS_* → CONFIG)
constants.py     pure constants (modes, crypto params, windows, aggregations)
main.py          runner: pick the security mode, start uvicorn
app_server.py    thin FastAPI app: UI + REST routes (transport-agnostic)
service.py       CollectionService — business logic (DeviceLink → store → processing)
transport/       TLS 1.3 module (pluggable UserChannel; only mode today)
crypto.py        shared crypto (P-256 ECDH, HKDF, AES-GCM) for the Device<->Server channel
store.py         in-memory sample store        processing.py  aggregations
web/             the HTML/JS/CSS UI
device_link/     data-source seam: DeviceLink interface + network/attested_network links
docs/            architecture.html — visual docs
tests/           unit + E2E
```

## Run it (Windows, pure Python — no WSL)
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r server/requirements.txt
```

`MS_DEVICE_LINK` is required — there's no synthetic fallback, so the server
refuses to start without it:
```powershell
$env:MS_DEVICE_LINK = "attested_network"    # or "network"; see device_link/README.md
python -m server.main --security tls
# open https://localhost:8000  (accept the self-signed cert once)
```

Then in the UI: pick a device, **Last hour**, **Weighted average**, click
**Collect** → you get the value plus the verification verdict
(`attested / integrity / measurement`). This needs a real edge device
(QEMU or hardware) pushing data — see `docs/ATTESTATION_TESTING.md` to run
one end-to-end.

## Tests
```powershell
python -m pytest server/tests -q     # run from the project root (the -m matters)
```
Covers AEAD roundtrip + tamper, P-256 ECDH agreement, weighted-average, the
attestation protocol (simulated device identity, no hardware needed), and a
full E2E pass in TLS mode. The E2E tests need a real attested edge device
(QEMU or hardware) connected — they're skipped otherwise.

## Choosing / adding a transport
`--security tls` (or env `MS_USER_SECURITY`) — TLS is the only mode
implemented today. Each mode is a separate module under `transport/` behind
the `UserChannel` interface, so adding a new one (e.g. mutual-TLS, or an
app-layer AEAD mode) is a new file + one branch in `transport/__init__.py`.

## Device data source
Sensor data comes from a real edge device via the `DeviceLink` seam
(`device_link/`) — `NetworkDeviceLink` or `AttestedNetworkDeviceLink`,
selected by `MS_DEVICE_LINK`. See `device_link/README.md`.
