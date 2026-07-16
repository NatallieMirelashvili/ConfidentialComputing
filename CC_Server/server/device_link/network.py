"""NetworkDeviceLink — receive sensor data pushed by a (real or mock) edge device.

This is the device-facing side of the Management Server. It runs a small TCP
server on a background thread; an edge device connects and pushes sensor samples,
which are buffered per device. `collect()` then hands the newly received samples
to the app (store -> processing -> UI), exactly like the stub did — only now the
data comes from the network instead of being fabricated.

Wire protocol (newline-delimited JSON, device -> server):

    {"device_id": "iot-edge-01",
     "attested": true,                     # trusted as-is for now (see NOTE)
     "note": "optional string",
     "samples": [{"value": 23.5, "unit": "C", "ts": 1720000000.0,
                  "sensor_id": "..."}, ...]}   # ts/sensor_id optional

The server replies with one line: {"ok": true} or {"ok": false, "error": "..."}.

NOTE: `attested` is currently taken at face value. Real remote attestation + AEAD
verification (the device proving it is genuine and the payload being decrypted/
verified) replace this later. This class is the *connectivity* layer that makes
the pipe work end to end; the crypto is layered on top afterwards.
"""

from __future__ import annotations

import json
import socketserver
import threading
import time
from collections import defaultdict, deque

from .. import constants as C
from ..config import CONFIG
from .base import Batch, DeviceLink, Sample

_MAX_BUFFER = 100_000


class NetworkDeviceLink(DeviceLink):
    """Buffers samples pushed by edge devices over TCP."""

    def __init__(self) -> None:
        # device_id -> not-yet-collected samples, and last-seen verdict.
        self._buf: dict[str, deque[Sample]] = defaultdict(lambda: deque(maxlen=_MAX_BUFFER))
        self._verdict: dict[str, dict] = {}
        self._lock = threading.Lock()

        # Start the TCP listener on a daemon thread so it dies with the process.
        self._server = _make_server(CONFIG.device_host, CONFIG.device_port, self._on_message)
        threading.Thread(
            target=self._server.serve_forever, name="device-link", daemon=True
        ).start()

    # -- called from the listener thread for each received message ----------
    def _on_message(self, msg: dict) -> None:
        device_id = str(msg.get("device_id") or "unknown")
        attested = bool(msg.get("attested", True))
        note = str(msg.get("note", "")) or "received over network"
        now = time.time()

        samples: list[Sample] = []
        for s in msg.get("samples", []):
            try:
                samples.append(
                    Sample(
                        ts=float(s.get("ts", now)),
                        value=float(s["value"]),
                        sensor_id=str(s.get("sensor_id", f"{device_id}:sensor")),
                        unit=str(s.get("unit", "unit")),
                    )
                )
            except (KeyError, ValueError, TypeError):
                continue  # skip malformed samples, keep the rest

        with self._lock:
            self._buf[device_id].extend(samples)
            self._verdict[device_id] = {
                "attested": attested,
                "integrity": "ok" if attested else "fail",
                "note": note,
                "last_seen": now,
            }

    # -- DeviceLink interface ----------------------------------------------
    async def collect(self, device_id: str, window: str) -> Batch:
        """Return (and clear) the samples received for this device since the last
        collect. Draining avoids double-counting when the app re-stores them."""
        with self._lock:
            new = list(self._buf.get(device_id, ()))
            if device_id in self._buf:
                self._buf[device_id].clear()
            verdict = self._verdict.get(device_id)

        if verdict is None:
            return Batch(
                device_id=device_id, window=window, samples=[],
                attested=False, integrity="fail", measurement_ok=False,
                note="no data received from this device yet",
            )
        return Batch(
            device_id=device_id, window=window, samples=new,
            attested=verdict["attested"],
            integrity=verdict["integrity"],
            measurement_ok=verdict["attested"],
            note=verdict["note"],
        )

    def status(self) -> dict:
        with self._lock:
            seen = sorted(set(self._verdict) | {C.DEFAULT_DEVICE_ID})
            devices = [
                {
                    "device_id": d,
                    "connected": d in self._verdict,
                    "attested": bool(self._verdict.get(d, {}).get("attested")),
                }
                for d in seen
            ]
        return {
            "link": "network",
            "listening": f"{CONFIG.device_host}:{CONFIG.device_port}",
            "devices": devices,
        }


def _make_server(host: str, port: int, on_message) -> socketserver.TCPServer:
    """Build a threaded TCP server whose handler parses newline-JSON messages."""

    class _Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            for raw in self.rfile:                 # one JSON object per line
                line = raw.strip()
                if not line:
                    continue
                try:
                    on_message(json.loads(line))
                    resp = {"ok": True}
                except (ValueError, TypeError) as exc:
                    resp = {"ok": False, "error": str(exc)}
                try:
                    self.wfile.write((json.dumps(resp) + "\n").encode())
                    self.wfile.flush()
                except OSError:
                    break

    server = socketserver.ThreadingTCPServer((host, port), _Handler)
    server.daemon_threads = True
    server.allow_reuse_address = True
    return server
