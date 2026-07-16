"""TLS 1.3 transport-security mode (ready-library encryption).

Encryption happens at the transport layer: the browser speaks https:// and the
application sees plain JSON. We generate a self-signed localhost certificate on
first run and build a strict SSLContext with minimum_version = TLS 1.3.

Because the cert is self-signed, the browser shows a one-time warning locally
(expected for a PoC). To silence it you could trust certs/server_cert.pem.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .. import constants as C
from ..config import CONFIG
from .base import UserChannel


class TlsUserChannel(UserChannel):
    """TLS mode: the server's HTTPS identity + a strict TLS-1.3 context.

    Doesn't touch requests/responses at all — uvicorn + OpenSSL do the
    encryption at the socket, so `install()`/`describe()` have nothing to add.
    """

    mode = C.USER_SECURITY_TLS

    def __init__(self) -> None:
        # Make sure a cert/key exist before we try to load them (created once).
        ensure_self_signed_cert(CONFIG.tls_cert_path, CONFIG.tls_key_path)

    def ssl_context(self) -> ssl.SSLContext:
        """Build the SSLContext uvicorn will use (TLS 1.3 only)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Pin to exactly TLS 1.3 (reject 1.2 and below).
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        # Load our certificate + matching private key.
        ctx.load_cert_chain(certfile=CONFIG.tls_cert_path, keyfile=CONFIG.tls_key_path)
        return ctx

    def describe(self) -> dict:
        # encrypt_app_layer=False tells app.js to just use plain fetch over https.
        return {"mode": self.mode, "encrypt_app_layer": False}


def ensure_self_signed_cert(cert_path: str, key_path: str) -> None:
    """Create a self-signed localhost cert + key if they don't already exist.

    Generates a 2048-bit RSA key and a 1-year self-signed X.509 certificate for
    CN=localhost, valid for `localhost` and `127.0.0.1` (SubjectAltName). Idempotent:
    returns immediately if both files are already present.
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
