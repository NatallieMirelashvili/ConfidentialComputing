"""User<->Server transport-security modules (pluggable).

Pick one at launch. Every mode satisfies the `UserChannel` interface, so the
app code is identical regardless of which is active. TLS is the only
implementation today; adding another is one new file + one branch here.
"""

from __future__ import annotations

from .. import constants as C
from .base import UserChannel


def get_user_channel(mode: str) -> UserChannel:
    """Return the UserChannel for `mode` ("tls").

    Imports are done lazily inside each branch so that an unused transport
    module is never imported. Raises ValueError on an unknown mode.
    """
    mode = (mode or "").lower()
    if mode == C.USER_SECURITY_TLS:
        from .tls import TlsUserChannel

        return TlsUserChannel()
    raise ValueError(
        f"unknown user-security mode {mode!r}; expected one of {C.USER_SECURITY_MODES}"
    )


__all__ = ["UserChannel", "get_user_channel"]
