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

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import constants as C
from .device_registry import DeviceKeyMismatch, get_device_registry
from .service import CollectionService
from .transport import UserChannel, get_user_channel

_WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
_logger = logging.getLogger(__name__)


def create_app(mode: str) -> tuple[FastAPI, UserChannel]:
    """Build the FastAPI app for a given security mode.

    Called once at startup. Creates the singletons (channel + service), registers
    the routes, mounts the static UI, and lets the transport wire itself in.

    Args:
        mode: "tls" or "aesgcm" (validated by `get_user_channel`).

    Returns:
        (app, channel) — the ASGI app and the chosen UserChannel (main.py needs
        the channel to fetch its SSL context).
    """
    app = FastAPI(title="Trusted IoT — Management Server", version="0.2.0")
    channel = get_user_channel(mode)     # TLS or AES-GCM transport (singleton)
    service = CollectionService()        # business logic + shared store (singleton)

    # Serve the browser UI (index.html, app.js, styles.css) under /web.
    app.mount("/web", StaticFiles(directory=_WEB_DIR), name="web")

    @app.get("/")
    async def index():
        """Serve the single-page UI."""
        return FileResponse(os.path.join(_WEB_DIR, "index.html"))

    # ---- clear (bootstrap/transport) endpoints ---------------------------
    # These stay in cleartext even in AES-GCM mode (see constants.CLEAR_PATHS).
    @app.get("/api/health")
    async def health():
        """Liveness probe."""
        return {"ok": True}

    @app.get("/api/security")
    async def security():
        """Tell the browser which transport mode is active (so app.js adapts)."""
        return channel.describe()

    # ---- secured (app) endpoints -----------------------------------------
    # In AES-GCM mode these bodies are transparently decrypted/encrypted by the
    # middleware; the handlers themselves only ever see plain JSON.
    @app.get("/api/devices")
    async def devices():
        """List known devices + their status (for the UI dropdown)."""
        return service.devices()

    @app.post("/api/devices/register")
    async def register_device(request: Request):
        """Device enrollment: submit a device's attestation identity
        (produced once by scripts/provision-device.sh) so it's allowed to
        complete remote attestation. Gated behind this same authenticated
        channel (TLS or AES-GCM) - never exposed on the device-facing TCP
        port, which has no authentication at all.

        Self-service and idempotent, not admin-gated: an unseen device_id is
        enrolled; a resubmission with the same key is a no-op ("already
        registered"); a resubmission with a *different* key is rejected
        rather than silently replacing the trusted identity (see
        docs/HANDOFF_MISSIONS.md §2.2.b). Authorization beyond the transport
        channel is intentionally out of scope - the registry file itself is
        the protection boundary (chmod 0600, see device_registry.py).

        Body: {device_id, ak_pub_pem_b64, expected_pcr, pcr_bank?}
        """
        body = await request.json()
        try:
            device_id = str(body["device_id"])
            ak_pub_pem = base64.b64decode(body["ak_pub_pem_b64"]).decode("utf-8")
            expected_pcr = str(body["expected_pcr"])
            pcr_bank = str(body.get("pcr_bank", "sha256:0"))
        except (KeyError, ValueError, binascii.Error, UnicodeDecodeError) as exc:
            return JSONResponse({"error": f"bad enrollment record: {exc}"}, status_code=400)

        if not device_id:
            return JSONResponse({"error": "device_id required"}, status_code=400)

        try:
            record, newly = get_device_registry().register(
                device_id, ak_pub_pem, expected_pcr, pcr_bank
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
        device_id, window, aggregation. Not covered by the AES-GCM app-layer
        transport (that middleware only wraps ASGI "http" scopes) - fine here,
        since this only ever carries the same non-secret trust/result data
        /api/collect already returns in the clear over TLS.
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
    # TLS: no-op. AES-GCM: registers POST /api/handshake + the envelope
    # middleware. Done last so the middleware wraps all routes above.
    channel.install(app)

    return app, channel
