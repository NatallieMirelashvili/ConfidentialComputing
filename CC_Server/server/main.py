"""Entry point: choose the User<->Server security mode and run the server.

    python -m server.main --security tls       # HTTPS, TLS 1.3 (default)
    python -m server.main --security aesgcm    # HTTP + application-layer AES-GCM

Env overrides: MS_USER_SECURITY, MS_API_HOST, MS_API_PORT, MS_CERTS_DIR.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import uvicorn

from . import constants as C
from .app_server import create_app
from .config import CONFIG


def main() -> None:
    """Parse args, build the app for the chosen security mode, run uvicorn."""
    # --- 1. command-line arguments (defaults come from CONFIG / env) ---------
    parser = argparse.ArgumentParser(description="Management Server (user side)")
    parser.add_argument(
        "--security",
        choices=C.USER_SECURITY_MODES,
        default=CONFIG.user_security,
        help="User<->Server transport security (default: %(default)s)",
    )
    parser.add_argument("--host", default=CONFIG.api_host)
    parser.add_argument("--port", type=int, default=CONFIG.api_port)
    args = parser.parse_args()

    # --- 2. Windows event-loop fix ------------------------------------------
    # On Windows the default Proactor loop logs a noisy (harmless)
    # "ConnectionResetError: [WinError 10054]" when a TLS connection is torn
    # down. The Selector loop doesn't, so switch to it before uvicorn starts.
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # --- 3. build the app + get the transport's SSL context ------------------
    # create_app wires the whole server for this mode; ssl_ctx is a real context
    # in TLS mode and None in AES-GCM mode.
    app, channel = create_app(args.security)
    ssl_ctx = channel.ssl_context()

    # --- 4. configure uvicorn ------------------------------------------------
    config_kwargs = dict(app=app, host=args.host, port=args.port, log_level="info")
    if ssl_ctx is not None:
        # Passing cert/key makes uvicorn treat this as an HTTPS server
        # (is_ssl == True, "https" in the banner). We then override the context
        # it builds with our strict TLS-1.3-only one below.
        config_kwargs.update(ssl_certfile=CONFIG.tls_cert_path, ssl_keyfile=CONFIG.tls_key_path)

    config = uvicorn.Config(**config_kwargs)
    config.load()                 # builds config.ssl from the cert/key (if any)
    if ssl_ctx is not None:
        config.ssl = ssl_ctx      # replace it -> enforce TLS 1.3 only

    # --- 5. run (blocks until Ctrl+C) ---------------------------------------
    print(
        f"\n  Management Server up - security={args.security} - "
        f"{channel.scheme}://{args.host}:{args.port}\n"
    )
    uvicorn.Server(config).run()


if __name__ == "__main__":
    # Only runs when invoked as `python -m server.main`.
    main()
