"""Server <-> Device seam (data source for the user-facing server).

The user-facing code only ever gets sensor data through a `DeviceLink`. There
is no synthetic fallback: `MS_DEVICE_LINK` must name a real link, or the
server refuses to start.

  - "network"           `NetworkDeviceLink` — a TCP listener fed by a real
                                              edge device (plaintext, trusts a
                                              self-reported `attested` flag).
  - "attested_network"  `AttestedNetworkDeviceLink` — a TCP listener fed by a
                                              real edge device, gated by remote
                                              attestation + an encrypted
                                              sensor channel.
"""

from __future__ import annotations

from .. import constants as C
from ..config import CONFIG
from .base import Batch, DeviceLink, Sample

__all__ = ["DeviceLink", "Batch", "Sample", "get_device_link"]


def get_device_link() -> DeviceLink:
    """Return the data-source link selected by CONFIG.device_link (MS_DEVICE_LINK).

    Raises if MS_DEVICE_LINK is unset or names anything other than a real link
    — there's no synthetic fallback, so a misconfigured server fails loudly at
    startup instead of silently serving fake data.
    """
    if CONFIG.device_link == C.DEVICE_LINK_ATTESTED_NETWORK:
        from .attested_network import AttestedNetworkDeviceLink

        return AttestedNetworkDeviceLink()
    if CONFIG.device_link == C.DEVICE_LINK_NETWORK:
        from .network import NetworkDeviceLink

        return NetworkDeviceLink()
    raise RuntimeError(
        f"MS_DEVICE_LINK={CONFIG.device_link!r} is not a real device link. "
        f"Set it to {C.DEVICE_LINK_NETWORK!r} or {C.DEVICE_LINK_ATTESTED_NETWORK!r} "
        "— there is no synthetic/stub fallback."
    )
