"""Runtime configuration.

The single place in the codebase that reads environment variables. Everything
else imports the `CONFIG` instance (or receives values from it), so there is one
obvious source of truth for anything tunable at launch.

Environment variables:
    MS_API_HOST        (default 127.0.0.1)   user-facing bind host
    MS_API_PORT        (default 8000)        user-facing bind port
    MS_USER_SECURITY   (default tls)         "tls" (only mode currently implemented)
    MS_CERTS_DIR       (default server/certs) where the TLS self-signed cert lives
    MS_DEVICE_LINK     (required)            "network" | "attested_network" (data source)
    MS_DEVICE_HOST     (default 0.0.0.0)     bind host for the device TCP listener
    MS_DEVICE_PORT     (default 9000)        port the edge device connects to (network link)
    MS_DEVICE_REGISTRY_PATH (default server/device_registry.json) enrolled device identities
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import constants as C

_PKG_DIR = os.path.dirname(__file__)


@dataclass(frozen=True)
class Config:
    """Immutable settings resolved at launch.

    `frozen=True` makes instances read-only, so nothing can mutate config after
    startup. Fields hold the defaults; `from_env()` builds the real instance by
    overlaying environment variables.
    """

    api_host: str = "127.0.0.1"                 # interface the HTTP/HTTPS server binds
    api_port: int = 8000                        # port the UI + API listen on
    user_security: str = C.USER_SECURITY_TLS    # "tls" — only mode implemented (see transport/)
    # certs_dir uses default_factory because its default is computed (a path),
    # not a constant literal.
    certs_dir: str = field(default_factory=lambda: os.path.join(_PKG_DIR, "certs"))
    # Device-facing side. No default: get_device_link() rejects anything that
    # isn't a real link, so an empty string here means "not configured".
    device_link: str = ""                       # data source: "network" | "attested_network"
    device_host: str = "0.0.0.0"                # where the device TCP listener binds
    device_port: int = 9000                     # port the edge device connects to
    # device_registry_path uses default_factory for the same reason as certs_dir.
    device_registry_path: str = field(
        default_factory=lambda: os.path.join(_PKG_DIR, "device_registry.json")
    )

    @classmethod
    def from_env(cls) -> "Config":
        """Build a Config from environment variables (falling back to defaults)."""
        return cls(
            api_host=os.environ.get("MS_API_HOST", "127.0.0.1"),
            api_port=int(os.environ.get("MS_API_PORT", "8000")),
            user_security=os.environ.get("MS_USER_SECURITY", C.USER_SECURITY_TLS),
            certs_dir=os.environ.get("MS_CERTS_DIR", os.path.join(_PKG_DIR, "certs")),
            device_link=os.environ.get("MS_DEVICE_LINK", ""),
            device_host=os.environ.get("MS_DEVICE_HOST", "0.0.0.0"),
            device_port=int(os.environ.get("MS_DEVICE_PORT", "9000")),
            device_registry_path=os.environ.get(
                "MS_DEVICE_REGISTRY_PATH", os.path.join(_PKG_DIR, "device_registry.json")
            ),
        )

    @property
    def tls_cert_path(self) -> str:
        """Full path to the TLS certificate file (used only in TLS mode)."""
        return os.path.join(self.certs_dir, "server_cert.pem")

    @property
    def tls_key_path(self) -> str:
        """Full path to the TLS private-key file (used only in TLS mode)."""
        return os.path.join(self.certs_dir, "server_key.pem")


#: Process-wide configuration, read once from the environment at import time.
#: Import this (`from .config import CONFIG`) instead of reading os.environ.
CONFIG = Config.from_env()
