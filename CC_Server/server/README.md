# Management Server — User↔Server side (PoC)

Confidential Computing project (Group 4) — the **user-facing** half of the
Management Server: an HTML UI + REST API, with **selectable transport security**
for the User↔Server channel (**TLS 1.3** or **application-layer AES-256-GCM**).

Sensor data reaches the server through the **`DeviceLink` seam** — here a
synthetic **stub**. The real Server↔Device link is a separate part of the project
and is not included in this (User↔Server) codebase.

> **Visual docs** (open in a browser):
> - `docs/architecture.html` — structure: both transport modes, the data-flow, module/class map.
> - `docs/runtime.html` — function-level trace of what runs when you open the server,
>   click Collect, and get the response (sequence diagrams, call graph, object lifetimes).

## What's here
```
config.py        Config class — the ONE place env vars are read (MS_* → CONFIG)
constants.py     pure constants (modes, crypto params, windows, aggregations)
main.py          runner: pick the security mode, start uvicorn
app_server.py    thin FastAPI app: UI + REST routes (transport-agnostic)
service.py       CollectionService — business logic (DeviceLink → store → processing)
transport/       TLS 1.3 and AES-GCM modules (swappable) — the two channel options
crypto.py        user-side crypto (P-256 ECDH, HKDF, AES-GCM) for AES-GCM mode
store.py         in-memory sample store        processing.py  aggregations
web/             the HTML/JS/CSS UI (WebCrypto for AES-GCM mode)
device_link/     data-source seam: DeviceLink interface + synthetic stub
docs/            architecture.html — visual docs
tests/           unit + E2E (both modes, incl. tamper rejection)
```

## Run it (Windows, pure Python — no WSL)
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r server/requirements.txt
```

**Option A — TLS 1.3 (default):**
```powershell
python -m server.main --security tls
# open https://localhost:8000  (accept the self-signed cert once)
```

**Option B — application-layer AES-256-GCM:**
```powershell
python -m server.main --security aesgcm
# open http://localhost:8000  (browser auto-does the ECDH handshake)
```

Then in the UI: pick a device, **Last hour**, **Weighted average**, click
**Collect** → you get the value plus the verification verdict
(`attested / integrity / measurement`). In AES-GCM mode, open devtools → Network
and confirm request/response bodies are just `{iv, ct}` (ciphertext on the wire).

> Demo the "rejected" verdict without the real device: the stub treats any
> `device_id` containing `tampered` as a failed attestation.

## Tests
```powershell
python -m pytest server/tests -q     # run from the project root (the -m matters)
```
Covers AEAD roundtrip + tamper, P-256 ECDH agreement, weighted-average, the stub
link, and full E2E in both TLS and AES-GCM modes (including a tampered-envelope
rejection → HTTP 400).

## Choosing / adding a transport
`--security {tls|aesgcm}` (or env `MS_USER_SECURITY`). Each mode is a separate
module under `transport/` behind the `UserChannel` interface, so adding a new one
(e.g. mutual-TLS) is a new file + one line in `transport/__init__.py`.

## Device data source
Sensor data comes from `StubDeviceLink` (`device_link/`) via the `DeviceLink`
seam. The real Server↔Device link is out of scope for this codebase.
