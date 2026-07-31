"""FastAPI application: serves the UI and the user REST API.

Thin HTTP layer. Routes delegate to `CollectionService` (business logic) and the
selected `UserChannel` (transport security). Endpoints are transport-agnostic —
they receive/return plain JSON and never mention encryption.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import os

from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import constants as C
from .device_link import DeviceLink
from .device_registry import (
    DeviceKeyMismatch,
    get_device_registry,
    validate_device_id,
)
from .service import CollectionService
from .transport import UserChannel, get_user_channel

_WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
_logger = logging.getLogger(__name__)


def create_app(mode: str, device_link: DeviceLink | None = None) -> tuple[FastAPI, UserChannel]:
    """Build the FastAPI app for a given security mode.

    Called once at startup. Creates the singletons (channel + service), registers
    the routes, mounts the static UI, and lets the transport wire itself in.

    Args:
        mode: "tls" (validated by `get_user_channel`; the only mode today).
        device_link: explicit data source (e.g. a shared link reused across
            tests). Defaults to CONFIG.device_link's real link if omitted.

    Returns:
        (app, channel) — the ASGI app and the chosen UserChannel (main.py needs
        the channel to fetch its SSL context).
    """
    app = FastAPI(title="Trusted IoT — Management Server", version="0.2.0")
    channel = get_user_channel(mode)     # transport security (singleton)
    service = CollectionService(device_link=device_link)  # business logic + shared store

    # Serve the browser UI (index.html, app.js, styles.css) under /web.
    app.mount("/web", StaticFiles(directory=_WEB_DIR), name="web")

    @app.get("/")
    async def index():
        """Serve the single-page UI."""
        return FileResponse(os.path.join(_WEB_DIR, "index.html"))

    # ---- clear (bootstrap/transport) endpoints ---------------------------
    @app.get("/api/health")
    async def health():
        """Liveness probe."""
        return {"ok": True}

    @app.get("/api/security")
    async def security():
        """Tell the browser which transport mode is active (so app.js adapts)."""
        return channel.describe()

    # ---- secured (app) endpoints -----------------------------------------
    @app.get("/api/devices")
    async def devices():
        """List known devices + their status (for the UI dropdown)."""
        return service.devices()

    @app.post("/api/devices/register")
    async def register_device(request: Request):
        """Device enrollment: submit a device's attestation identity
        (produced once by scripts/provision-device.sh) so it's allowed to
        complete remote attestation. Gated behind this same TLS-protected
        channel - never exposed on the device-facing TCP port, which has no
        authentication at all.

        Self-service and idempotent, not admin-gated: an unseen device_id is
        enrolled; a resubmission with the same key is a no-op ("already
        registered"); a resubmission with a *different* key is rejected
        rather than silently replacing the trusted identity (see
        docs/HANDOFF_MISSIONS.md §2.2.b). Authorization beyond the transport
        channel is intentionally out of scope - the registry file itself is
        the protection boundary (chmod 0600, see device_registry.py).

        Body: {device_id, ak_pub_pem_b64, ta_pub_b64, expected_pcr, pcr_bank?}

        `ta_pub_b64` (base64 of the TA's raw 65-byte uncompressed SEC1 identity
        point) is REQUIRED, not optional-with-later-pin. A record without it can
        never attest, and letting it be filled in later would leave a permanent
        trust-on-first-use window on already-enrolled devices: this endpoint is
        self-service, so root on a compromised device could resubmit the honest
        ak_pub alongside a TA key of its own and pin that — reopening exactly
        the hole docs/HANDOFF_taIdentityBinding.md closes. The private TA
        signing key (Part A) changes PCR0, so every device is being
        re-provisioned anyway.
        """
        body = await request.json()
        try:
            device_id = validate_device_id(str(body["device_id"]))
            ak_pub_pem = base64.b64decode(body["ak_pub_pem_b64"]).decode("utf-8")
            expected_pcr = str(body["expected_pcr"])
            pcr_bank = str(body.get("pcr_bank", "sha256:0"))
            # Validated as a real P-256 point here so junk can never enter the
            # registry (from_encoded_point rejects an off-curve point), then
            # re-encoded canonically so register()'s immutability check stays a
            # plain string compare that cosmetic base64 differences — padding,
            # embedded newlines — cannot turn into a spurious 409.
            ta_pub_raw = base64.b64decode(body["ta_pub_b64"])
            if len(ta_pub_raw) != C.TA_IDENTITY_PUBKEY_LEN or ta_pub_raw[0] != 0x04:
                raise ValueError(
                    "ta_pub_b64 must be a 65-byte uncompressed SEC1 point "
                    "(0x04 || X || Y)"
                )
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ta_pub_raw)
            ta_pub_b64 = base64.b64encode(ta_pub_raw).decode("ascii")
        except (KeyError, ValueError, binascii.Error, UnicodeDecodeError) as exc:
            return JSONResponse({"error": f"bad enrollment record: {exc}"}, status_code=400)

        if not device_id:
            return JSONResponse({"error": "device_id required"}, status_code=400)

        try:
            record, newly = get_device_registry().register(
                device_id=device_id,
                ak_pub_pem=ak_pub_pem,
                expected_pcr=expected_pcr,
                pcr_bank=pcr_bank,
                ta_pub_b64=ta_pub_b64,
            )
        except DeviceKeyMismatch as exc:
            _logger.warning("rejected registration for %s: %s", device_id, exc)
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=409)

        return {
            "ok": True,
            "device_id": record.device_id,
            "created_at": record.created_at,
            "already_registered": not newly,
        }

    @app.post("/api/collect")
    async def collect(request: Request):
        """Run one collect. Body: {device_id, window, aggregation} (all optional)."""
        body = await request.json()
        try:
            return await service.collect(
                device_id=str(body.get("device_id") or C.DEFAULT_DEVICE_ID),
                window=str(body.get("window") or C.DEFAULT_WINDOW),
                aggregation=str(body.get("aggregation") or C.DEFAULT_AGGREGATION),
            )
        except ValueError as exc:
            # Bad window/aggregation -> 400 with a message the UI can show.
            return JSONResponse({"error": str(exc)}, status_code=400)

    @app.websocket("/ws/collect")
    async def collect_ws(websocket: WebSocket):
        """Live feed: repeats POST /api/collect on a timer over one socket.

        Params (query string, same names/defaults as /api/collect's body):
        device_id, window, aggregation. Carries the same trust/result data
        /api/collect returns, protected the same way: TLS at the transport
        layer.
        """
        await websocket.accept()
        q = websocket.query_params
        device_id = q.get("device_id") or C.DEFAULT_DEVICE_ID
        window = q.get("window") or C.DEFAULT_WINDOW
        aggregation = q.get("aggregation") or C.DEFAULT_AGGREGATION
        try:
            while True:
                try:
                    await websocket.send_json(
                        await service.collect(device_id, window, aggregation)
                    )
                except ValueError as exc:
                    # Bad window/aggregation -> tell the client, then stop.
                    await websocket.send_json({"error": str(exc)})
                    break
                except Exception:
                    # Anything else (e.g. a malformed sample from a real device)
                    # must not silently kill the socket - that reads to the
                    # browser as an unexpected disconnect ("offline") and it
                    # keeps retrying into the same crash. Log it and tell the
                    # client, but keep the loop (and the connection) alive so
                    # the next tick can recover once the bad data has passed.
                    _logger.exception(
                        "collect_ws: collect() failed for device_id=%r window=%r "
                        "aggregation=%r", device_id, window, aggregation,
                    )
                    await websocket.send_json({"error": "internal error, see server log"})
                await asyncio.sleep(C.WS_COLLECT_POLL_SECONDS)
        except WebSocketDisconnect:
            pass

    # ---- let the transport mode wire itself in ---------------------------
    # TLS: no-op today; kept so a future app-layer mode can register its own
    # routes/middleware here without touching the routes above. Done last so
    # any such middleware would wrap all routes above.
    channel.install(app)

    return app, channel
