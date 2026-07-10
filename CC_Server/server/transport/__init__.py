"""User<->Server transport-security modules (pluggable).

Pick one at launch. Both satisfy the `UserChannel` interface, so the app code is
identical regardless of which is active.
"""

from __future__ import annotations

from .. import constants as C
from .base import UserChannel


def get_user_channel(mode: str) -> UserChannel:
    """Return the UserChannel for `mode` ("tls" | "aesgcm").

    Imports are done lazily inside each branch so that the unused transport module
    (and its dependencies, e.g. crypto.py for aesgcm) is never imported. Raises
    ValueError on an unknown mode.
    """
    mode = (mode or "").lower()
    if mode == C.USER_SECURITY_TLS:
        from .tls import TlsUserChannel

        return TlsUserChannel()
    if mode == C.USER_SECURITY_AESGCM:
        from .aesgcm import AesGcmUserChannel

        return AesGcmUserChannel()
    raise ValueError(
        f"unknown user-security mode {mode!r}; expected one of {C.USER_SECURITY_MODES}"
    )


__all__ = ["UserChannel", "get_user_channel"]
