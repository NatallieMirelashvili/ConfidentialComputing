"""Mock edge device — pushes synthetic sensor samples to the server's device port.

Stands in for the OP-TEE/QEMU edge device so you can test the network DeviceLink
end to end with no hardware. It is also the reference for what the real edge CA
must send (see the wire protocol in device_link/network.py).

Usage (server must be running with MS_DEVICE_LINK=network):

    python -m server.mock_device                        # 60 samples to 127.0.0.1:9000
    python -m server.mock_device --host 10.0.2.2 --port 9000 --device-id iot-edge-01
    python -m server.mock_device --n 120 --window 24h
    python -m server.mock_device --attested false       # simulate a failed verdict
"""

from __future__ import annotations

import argparse
import json
import math
import random
import socket
import time


def build_message(device_id: str, window: str, n: int, attested: bool) -> dict:
    """Create a batch of synthetic samples spread over the window, ending now."""
    seconds = 86400 if window == "24h" else 3600
    now = time.time()
    step = seconds / max(1, n)
    base = 22.0
    drift = random.uniform(-1.0, 1.0)

    samples = []
    for i in range(n):
        ts = now - (n - 1 - i) * step
        value = round(base + drift + 3.0 * math.sin(i / 6.0) + random.uniform(-0.4, 0.4), 3)
        samples.append({"ts": ts, "value": value, "unit": "C"})

    return {
        "device_id": device_id,
        "attested": attested,
        "note": "mock edge device",
        "samples": samples,
    }


def send(host: str, port: int, message: dict, timeout: float = 5.0) -> str:
    """Send one newline-JSON message and return the server's reply line."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall((json.dumps(message) + "\n").encode())
        sock.settimeout(timeout)
        return sock.recv(4096).decode(errors="replace").strip()


def main() -> None:
    ap = argparse.ArgumentParser(description="Mock edge device (pushes sensor data)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--device-id", default="iot-edge-01")
    ap.add_argument("--window", choices=["1h", "24h"], default="1h")
    ap.add_argument("--n", type=int, default=60, help="number of samples to send")
    ap.add_argument("--attested", choices=["true", "false"], default="true")
    args = ap.parse_args()

    msg = build_message(args.device_id, args.window, args.n, args.attested == "true")
    reply = send(args.host, args.port, msg)
    print(f"sent {len(msg['samples'])} samples to {args.host}:{args.port} -> {reply}")


if __name__ == "__main__":
    main()
