"""CLI: remove stale entries from device_registry.json.

Registration is intentionally one-way (see device_registry.py's
DeviceKeyMismatch / docs/HANDOFF_MISSIONS.md §2.2.b): once a device_id is
enrolled, a re-POST with a *different* key is rejected rather than silently
overwriting the trusted identity. That's correct for real devices, but it
means a "fresh device" test run — e.g. wiping a QEMU instance's persisted AK
disk (.device-state/*.img) to force a brand-new Attestation Key — will get
stuck retrying attestation forever, because the registry still holds the
device's *old* key under the same device_id. This CLI is the admin-side fix:
delete the stale entry so the device can self-register again.

Usage (from CC_Server/):
    python -m server.reset_registry iot-edge-10 [iot-edge-11 ...]
    python -m server.reset_registry --all
    python -m server.reset_registry --list

Prefer scripts/reset-device-registry.sh from the repo root, which wraps this.
"""

from __future__ import annotations

import argparse
import sys
import time

from .config import CONFIG
from .device_registry import DeviceRegistry


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "device_ids", nargs="*", help="device_id(s) to remove from the registry"
    )
    parser.add_argument(
        "--all", action="store_true", help="remove every enrolled device"
    )
    parser.add_argument(
        "--list", action="store_true", help="print enrolled devices, change nothing"
    )
    args = parser.parse_args()

    if not args.list and not args.all and not args.device_ids:
        parser.print_help()
        sys.exit(1)

    registry = DeviceRegistry(path=CONFIG.device_registry_path)

    if args.list:
        records = registry.list()
        if not records:
            print(f"No enrolled devices in {CONFIG.device_registry_path}")
            return
        for r in sorted(records, key=lambda r: r.device_id):
            print(f"{r.device_id}\tenrolled {time.ctime(r.created_at)}")
        return

    removed: list[str] = []
    if args.all:
        records = registry.list()
        removed = [r.device_id for r in records]
        registry.clear()
    else:
        for device_id in args.device_ids:
            if registry.remove(device_id):
                removed.append(device_id)
            else:
                print(f"{device_id}: not enrolled, nothing to do", file=sys.stderr)

    if removed:
        print(f"Removed from {CONFIG.device_registry_path}: {', '.join(removed)}")
        print(
            "NOTE: the running server (if any) loaded this file once at startup "
            "and never reloads it — restart CC_Server for this to take effect.",
            file=sys.stderr,
        )
    elif not args.all:
        sys.exit(1)


if __name__ == "__main__":
    main()
