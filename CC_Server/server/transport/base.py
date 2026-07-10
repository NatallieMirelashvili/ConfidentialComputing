"""UserChannel — the pluggable User<->Server transport-security interface.

Two implementations live beside this file (tls.py, aesgcm.py). The app picks one
at launch. Keeping them behind one interface means app_server.py's endpoints are
written once and never mention encryption.
"""

from __future__ import annotations

import ssl
from abc import ABC, abstractmethod

from fastapi import FastAPI


class UserChannel(ABC):
    """Interface both transport modes implement.

    The three hooks are the entire contract:
      - ssl_context(): transport-layer encryption (TLS) or None (app-layer/none)
      - install():     register any routes/middleware the mode needs
      - describe():    tell the browser how to talk to us
    Because the app only touches this interface, adding a new mode = one new file.
    """

    #: short mode name, echoed to the browser via /api/security
    mode: str = "none"

    def ssl_context(self) -> ssl.SSLContext | None:
        """SSLContext for uvicorn (TLS mode), or None to run plain HTTP.

        The default (None) suits app-layer modes; TLS overrides it.
        """
        return None

    def install(self, app: FastAPI) -> None:
        """Hook to register any middleware / routes this mode needs.

        TLS mode: nothing (encryption is at the transport layer).
        AES-GCM mode: the /api/handshake route + the envelope middleware.
        Default is a no-op so simple modes don't have to override it.
        """

    @abstractmethod
    def describe(self) -> dict:
        """Return the JSON the browser reads from /api/security (mode + params)."""

    @property
    def scheme(self) -> str:
        """URL scheme implied by this mode: https if there's a TLS context."""
        return "https" if self.ssl_context() is not None else "http"
