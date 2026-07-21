"""AttestedNetworkDeviceLink — the real Device<->Server link: remote
attestation + key exchange gate access, then sensor data travels as
AES-256-GCM envelopes instead of the plaintext + self-reported `attested`
flag that `network.py`'s NetworkDeviceLink uses (that one stays as a
lightweight demo/back-compat mode; see its own docstring).

Wire protocol (newline-delimited JSON, one persistent TCP connection):

    device -> server   {"type": "hello", "device_id": "..."}
    server -> device    {"type": "attest_challenge", "nonce": "<b64>",
                          "server_ecdh_pub": "<b64>",
                          "server_identity_pub": "<b64>"}
    device -> server    {"type": "attest_response", "device_id": "...",
                          "device_ecdh_pub": "<b64>", "quote": "<b64>",
                          "signature": "<b64>", "pcr_values": "<text>"}
    server -> device    {"type": "attest_result", "ok": true|false,
                          "session_ttl"?: <int>, "server_sig"?: "<b64>",
                          "error"?: "..."}

`server_identity_pub` (65-byte SEC1 point) and `server_sig` (raw 64-byte r||s)
let the device authenticate the SERVER: it pins server_identity_pub on first
use and thereafter requires server_sig to verify under the pinned key before
trusting the session - see docs/HANDOFF_serverAuthentication.md.
    device -> server    {"type": "data", "device_id": "...", "seq": <int>,
                          "nonce": "<b64>", "ciphertext": "<b64>"}
                          (repeatable, AEAD-wrapped JSON {"samples": [...]};
                          aad = seq as 8-byte big-endian)
    server -> device    {"ok": true|false, "error"?: "..."}  (per data message)

`seq` is a per-session monotonic counter authenticated as the GCM AAD. The
server verifies the tag (which binds seq) and then rejects any seq it has
already accepted -> inner-session anti-replay. Device identity is already
bound by the per-device session key, so it need not also be in the AAD.

See ../attestation.py for the verification logic and
project/optee_examples/confidential_iot/edge_device/host/edge_device.c for
the device side.
"""

from __future__ import annotations

import json
import logging
import socketserver
import threading
import time
from collections import defaultdict, deque

from .. import constants as C
from ..attestation import AttestationError, AttestationVerifier
from ..config import CONFIG
from ..crypto import InvalidTag, aead_decrypt, b64d, b64e
from .base import Batch, DeviceLink, Sample

_MAX_BUFFER = 100_000
_logger = logging.getLogger(__name__)


class AttestedNetworkDeviceLink(DeviceLink):
    """Buffers samples pushed by attested edge devices over TCP."""

    def __init__(self) -> None:
        self._buf: dict[str, deque[Sample]] = defaultdict(lambda: deque(maxlen=_MAX_BUFFER))
        self._verdict: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._verifier = AttestationVerifier()

        self._server = _make_server(
            CONFIG.device_host, CONFIG.device_port, self._handle_connection
        )
        threading.Thread(
            target=self._server.serve_forever, name="attested-device-link",
            daemon=True,
        ).start()

    # -- per-connection protocol state machine ------------------------------
    def _handle_connection(self, readline, writeline) -> None:
        device_id: str | None = None
        try:
            while True:
                line = readline()
                if line is None:
                    return

                try:
                    msg = json.loads(line)
                except (ValueError, TypeError):
                    writeline({"ok": False, "error": "invalid JSON"})
                    continue

                msg_type = msg.get("type")

                if msg_type == "hello":
                    device_id = str(msg.get("device_id") or "")
                    try:
                        challenge = self._verifier.issue_challenge(device_id)
                    except AttestationError as exc:
                        _logger.warning("hello rejected for device_id=%r: %s", device_id, exc)
                        writeline({"type": "error", "error": str(exc)})
                        device_id = None
                        continue
                    challenge["type"] = "attest_challenge"
                    writeline(challenge)

                elif msg_type == "attest_response":
                    if not device_id:
                        writeline({"type": "attest_result", "ok": False,
                                   "error": "send hello first"})
                        continue
                    try:
                        server_sig = self._verifier.verify_and_derive(
                            device_id=device_id,
                            device_ecdh_pub_b64=msg["device_ecdh_pub"],
                            quote_b64=msg["quote"],
                            signature_b64=msg["signature"],
                            pcr_values_text=msg["pcr_values"],
                        )
                    except (AttestationError, KeyError) as exc:
                        _logger.warning(
                            "attest_response rejected for device_id=%r: %s", device_id, exc
                        )
                        writeline({"type": "attest_result", "ok": False,
                                   "error": str(exc)})
                        continue
                    writeline({"type": "attest_result", "ok": True,
                               "session_ttl": C.DEVICE_SESSION_TTL_SECONDS,
                               "server_sig": b64e(server_sig)})

                elif msg_type == "data":
                    if not device_id:
                        writeline({"ok": False, "error": "send hello first"})
                        continue
                    self._on_data(device_id, msg)
                    writeline({"ok": True})

                else:
                    writeline({"ok": False, "error": f"unknown type {msg_type!r}"})
        finally:
            # However this connection ends (clean EOF, reset, or an
            # unhandled exception - see _make_server's catch-all) the device
            # is no longer live. Overwrite the cached verdict so the
            # dashboard doesn't keep showing a stale "ok" for a device
            # that's gone; a subsequent reconnect's own data naturally
            # overwrites this again.
            if device_id:
                with self._lock:
                    self._verdict[device_id] = {
                        "attested": False,
                        "integrity": "fail",
                        "note": "device disconnected",
                        "last_seen": time.time(),
                    }

    def _on_data(self, device_id: str, msg: dict) -> None:
        now = time.time()
        key = self._verifier.session_key(device_id)

        if key is None:
            with self._lock:
                self._verdict[device_id] = {
                    "attested": False,
                    "integrity": "fail",
                    "note": "no valid attested session - attest first",
                    "last_seen": now,
                }
            return

        try:
            nonce = b64d(msg["nonce"])
            ciphertext = b64d(msg["ciphertext"])
            seq = msg["seq"]
            if isinstance(seq, bool) or not isinstance(seq, int) \
                    or seq <= 0 or seq > 0xFFFFFFFF:
                raise ValueError("missing or out-of-range seq")
            # AAD binds the seq to this ciphertext: a tampered/renumbered seq
            # fails the tag here, before the anti-replay check below.
            aad = seq.to_bytes(8, "big")
            plaintext = aead_decrypt(key, nonce, ciphertext, aad=aad)
        except (KeyError, ValueError, TypeError, InvalidTag) as exc:
            with self._lock:
                self._verdict[device_id] = {
                    "attested": True,
                    "integrity": "fail",
                    "note": f"decrypt/verify failed: {exc}",
                    "last_seen": now,
                }
            return

        # Tag verified -> the seq is authentic. Enforce inner-session
        # anti-replay: reject a seq already seen (replay) or that regresses.
        if not self._verifier.check_and_advance_seq(device_id, seq):
            with self._lock:
                self._verdict[device_id] = {
                    "attested": True,
                    "integrity": "fail",
                    "note": f"replayed or out-of-order message (seq={seq})",
                    "last_seen": now,
                }
            return

        try:
            payload = json.loads(plaintext)
        except (ValueError, TypeError) as exc:
            with self._lock:
                self._verdict[device_id] = {
                    "attested": True,
                    "integrity": "fail",
                    "note": f"decrypt/verify failed: {exc}",
                    "last_seen": now,
                }
            return

        samples: list[Sample] = []
        for s in payload.get("samples", []):
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
                "attested": True,
                "integrity": "ok",
                "note": "attested session, AEAD-verified",
                "last_seen": now,
            }

    # -- DeviceLink interface ------------------------------------------------
    async def collect(self, device_id: str, window: str) -> Batch:
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
        # The device pushes continuously over its attested session; a collect
        # reports the device's *current* reading, i.e. the most recent sample
        # buffered since the last collect (the highest mock counter value).
        latest = new[-1:]
        return Batch(
            device_id=device_id, window=window, samples=latest,
            attested=verdict["attested"],
            integrity=verdict["integrity"],
            measurement_ok=verdict["attested"],
            note=verdict["note"],
        )

    def status(self) -> dict:
        with self._lock:
            devices = [
                {
                    "device_id": d,
                    "connected": True,
                    "attested": bool(v.get("attested")),
                }
                for d, v in self._verdict.items()
            ]
        return {
            "link": "attested_network",
            "listening": f"{CONFIG.device_host}:{CONFIG.device_port}",
            "devices": devices,
        }


def _make_server(host: str, port: int, on_connection) -> socketserver.TCPServer:
    """Threaded TCP server; each connection's whole lifetime (hello through
    however many data messages) is handled by one `on_connection` call."""

    class _Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            def readline():
                while True:
                    raw = self.rfile.readline()
                    if not raw:
                        return None
                    line = raw.strip()
                    if line:
                        return line

            def writeline(obj: dict) -> None:
                try:
                    self.wfile.write((json.dumps(obj) + "\n").encode())
                    self.wfile.flush()
                except OSError:
                    pass

            try:
                on_connection(readline, writeline)
            except Exception:
                # Never let one misbehaving connection kill the listener.
                pass

    server = socketserver.ThreadingTCPServer((host, port), _Handler)
    server.daemon_threads = True
    server.allow_reuse_address = True
    return server
