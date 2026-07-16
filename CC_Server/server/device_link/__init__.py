"""Server <-> Device seam (data source for the user-facing server).

The user-facing code only ever gets sensor data through a `DeviceLink`. Two
implementations exist, selected by `MS_DEVICE_LINK`:

  - "stub"    (default) `StubDeviceLink`   — synthetic, self-contained data.
  - "network"           `NetworkDeviceLink` — a TCP listener fed by a real or
                                              mock edge device (see mock_device.py).

The full attestation + encrypted sensor channel is layered on top of the network
link later; today the network link is the plaintext connectivity layer.
"""

from __future__ import annotations

from .. import constants as C
from ..config import CONFIG
from .base import Batch, DeviceLink, Sample
from .stub import StubDeviceLink

__all__ = ["DeviceLink", "Batch", "Sample", "StubDeviceLink", "get_device_link"]


def get_device_link() -> DeviceLink:
    """Return the data-source link selected by CONFIG.device_link (MS_DEVICE_LINK)."""
    if CONFIG.device_link == C.DEVICE_LINK_ATTESTED_NETWORK:
        from .attested_network import AttestedNetworkDeviceLink

        return AttestedNetworkDeviceLink()
    if CONFIG.device_link == C.DEVICE_LINK_NETWORK:
        from .network import NetworkDeviceLink

        return NetworkDeviceLink()
    return StubDeviceLink()
