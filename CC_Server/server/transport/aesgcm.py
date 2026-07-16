"""AES-GCM application-layer transport-security mode.

The server runs plain HTTP (WebCrypto is allowed on http://localhost). Encryption
is done in the application:

  1. Browser generates a P-256 ECDH keypair and POSTs its public key to
     /api/handshake. The server generates its own P-256 keypair, computes the
     ECDH shared secret, derives an AES-256-GCM key via HKDF-SHA256, and returns
     its public key + a session_id.
  2. For every "secure" endpoint, the browser sends an encrypted envelope
     {iv, ct} (base64) with an `X-Session-Id` header; the server transparently
     decrypts the request and encrypts the response via an ASGI middleware.

Cleartext-on-the-wire never happens for secure endpoints — you can confirm in
devtools that request/response bodies are just {iv, ct}.

Key-agreement parameters (MUST match web/app.js):
    curve  = P-256 (secp256r1), public keys = 65-byte uncompressed points
    HKDF   = SHA-256, salt = client_pub || server_pub, info = INFO_USER_AEAD
    AEAD   = AES-256-GCM, 12-byte random iv per message, tag appended to ct
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any

from fastapi import FastAPI, Request

from .. import constants as C
from .. import crypto
from .base import UserChannel


class _Session:
    """One browser session: the derived AES key + an expiry time."""

    __slots__ = ("key", "expires")

    def __init__(self, key: bytes, ttl: int) -> None:
        self.key = key
        self.expires = time.time() + ttl


class AesGcmUserChannel(UserChannel):
    """AES-GCM mode: negotiate a key per browser, then encrypt bodies in a
    middleware. Holds the map of active sessions (session_id -> key)."""

    mode = C.USER_SECURITY_AESGCM

    def __init__(self) -> None:
        # session_id -> _Session. In-memory only (fine for a local PoC).
        self._sessions: dict[str, _Session] = {}

    # -- SSL: none, we run plain HTTP --------------------------------------
    def ssl_context(self):  # noqa: D401 - see base
        """No transport-layer TLS in this mode -> plain HTTP."""
        return None

    def describe(self) -> dict:
        """Everything app.js needs to encrypt: the mode, curve, session header,
        and which paths are cleartext."""
        return {
            "mode": self.mode,
            "encrypt_app_layer": True,
            "curve": "P-256",
            "session_header": "X-Session-Id",
            "clear_paths": list(C.CLEAR_PATHS),
        }

    # -- session key management --------------------------------------------
    def session_key(self, sid: str | None) -> bytes | None:
        """Look up the AES key for a session id, or None if missing/expired.

        Expired sessions are dropped on access (lazy cleanup).
        """
        if not sid:
            return None
        s = self._sessions.get(sid)
        if s is None:
            return None
        if s.expires < time.time():
            self._sessions.pop(sid, None)  # expired -> forget it
            return None
        return s.key

    def _handshake(self, client_pub_b64: str) -> dict[str, Any]:
        """Do the server side of the ECDH handshake and create a session.

        Given the browser's P-256 public key, generate our own, compute the
        shared secret, derive an AES-256 key, store it under a new random
        session id, and return our public key + that id.
        """
        client_pub = crypto.b64d(client_pub_b64)
        priv, server_pub = crypto.p256_generate()          # our ephemeral keypair
        shared = crypto.p256_shared(priv, client_pub)      # ECDH shared secret
        # HKDF -> AES key. salt binds the key to both public keys (order matters;
        # app.js concatenates in the same order: client || server).
        key = crypto.hkdf(shared, salt=client_pub + server_pub, info=C.INFO_USER_AEAD)
        sid = secrets.token_hex(16)                        # opaque session id
        self._sessions[sid] = _Session(key, C.USER_SESSION_TTL_SECONDS)
        return {"session_id": sid, "server_pub": crypto.b64e(server_pub)}

    # -- wiring into the app -----------------------------------------------
    def install(self, app: FastAPI) -> None:
        """Register the handshake route + the envelope middleware."""
        channel = self

        @app.post("/api/handshake")
        async def handshake(request: Request):  # noqa: ANN202 - FastAPI route
            """Cleartext ECDH handshake: {client_pub} -> {server_pub, session_id}."""
            body = await request.json()
            client_pub = body.get("client_pub")
            if not client_pub:
                return {"error": "client_pub required"}
            return channel._handshake(client_pub)

        # Wrap the whole app so every non-clear request/response is enveloped.
        app.add_middleware(_AeadASGIMiddleware, channel=channel)


def _is_clear(path: str) -> bool:
    """True if `path` should bypass encryption (see constants.CLEAR_PATHS)."""
    return path in C.CLEAR_PATHS or path.startswith(C.CLEAR_PATH_PREFIXES)


async def _read_body(receive) -> bytes:
    """Drain and concatenate the full ASGI request body (it can arrive in
    chunks). Returns the raw bytes."""
    chunks: list[bytes] = []
    while True:
        msg = await receive()
        if msg["type"] == "http.request":
            chunks.append(msg.get("body", b""))
            if not msg.get("more_body", False):  # last chunk
                break
        elif msg["type"] == "http.disconnect":
            break
    return b"".join(chunks)


async def _send_json(send, status: int, obj: dict) -> None:
    """Send a plain-JSON ASGI response (used for the middleware's error paths,
    which are intentionally NOT encrypted)."""
    body = json.dumps(obj).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class _AeadASGIMiddleware:
    """Pure-ASGI middleware: decrypt secure requests, encrypt secure responses.

    Pure ASGI (not BaseHTTPMiddleware) so we can fully rewrite the request body
    that the endpoint sees and the response body that goes on the wire.
    """

    def __init__(self, app, channel: AesGcmUserChannel) -> None:
        self.app = app          # the inner ASGI app (FastAPI)
        self.channel = channel  # holds the session keys

    async def __call__(self, scope, receive, send):
        # Only intercept HTTP requests to secured paths; everything else
        # (websockets, clear paths, static files) passes straight through.
        if scope["type"] != "http" or _is_clear(scope.get("path", "")):
            return await self.app(scope, receive, send)

        # Identify the session from the X-Session-Id header and get its key.
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        sid = headers.get(b"x-session-id", b"").decode() or None
        key = self.channel.session_key(sid)
        if key is None:
            # No handshake yet / expired -> 401 (cleartext error is fine).
            return await _send_json(send, 401, {"error": "no valid session; handshake first"})

        # --- decrypt the request body (if any) ----------------------------
        raw = await _read_body(receive)
        if raw:
            try:
                env = json.loads(raw)                       # {iv, ct}
                plaintext = crypto.aead_decrypt(
                    key, crypto.b64d(env["iv"]), crypto.b64d(env["ct"]), b""
                )
            except (crypto.InvalidTag, KeyError, ValueError, json.JSONDecodeError):
                # Tampered/garbled ciphertext -> reject (this is the integrity check).
                return await _send_json(send, 400, {"error": "request decrypt failed"})
        else:
            plaintext = b""                                 # e.g. a GET with no body

        # Hand the DECRYPTED body to the route via a replacement `receive`
        # channel, so the FastAPI handler just sees normal JSON.
        sent = False

        async def receive_wrapped():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": plaintext, "more_body": False}
            return {"type": "http.disconnect"}

        # Fix Content-Length/Type on the request the route sees to match the
        # decrypted body (not the encrypted envelope we received).
        new_scope = dict(scope)
        new_scope["headers"] = _rewrite_length(scope.get("headers", []), len(plaintext))

        # --- buffer the response, then encrypt it -------------------------
        start: dict | None = None       # remembers the route's response.start
        out_chunks: list[bytes] = []    # collects the route's response body

        async def send_wrapped(message):
            nonlocal start
            if message["type"] == "http.response.start":
                # Hold the start message; we send our own headers at the end.
                start = message
            elif message["type"] == "http.response.body":
                out_chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    # Full body collected -> encrypt it into an {iv, ct} envelope.
                    full = b"".join(out_chunks)
                    iv = crypto.random_bytes(C.AEAD_NONCE_LEN)   # fresh nonce
                    ct = crypto.aead_encrypt(key, iv, full, b"")
                    env = json.dumps(
                        {"iv": crypto.b64e(iv), "ct": crypto.b64e(ct)}
                    ).encode("utf-8")
                    status = start["status"] if start else 200
                    # Emit our own start (JSON envelope) + body, preserving status.
                    await send(
                        {
                            "type": "http.response.start",
                            "status": status,
                            "headers": [
                                (b"content-type", b"application/json"),
                                (b"content-length", str(len(env)).encode()),
                            ],
                        }
                    )
                    await send(
                        {"type": "http.response.body", "body": env, "more_body": False}
                    )

        # Run the actual route with our wrapped receive/send.
        await self.app(new_scope, receive_wrapped, send_wrapped)


def _rewrite_length(headers: list, new_len: int) -> list:
    """Return `headers` with content-length/type replaced to match a JSON body of
    `new_len` bytes (used when swapping the encrypted body for the plain one)."""
    out = [
        (k, v)
        for (k, v) in headers
        if k.lower() not in (b"content-length", b"content-type")
    ]
    out.append((b"content-length", str(new_len).encode()))
    out.append((b"content-type", b"application/json"))
    return out
