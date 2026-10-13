"""Run the actual Go binaries, assert fixture round-trip, and shut down."""

import json
import socket
import subprocess
import time
from urllib.request import ProxyHandler, build_opener


def main():
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    opener = build_opener(ProxyHandler({}))
    controller = subprocess.Popen(["bin/controller", "--listen", f"127.0.0.1:{port}"])
    try:
        for _ in range(100):
            if controller.poll() is not None:
                raise RuntimeError("controller exited before becoming ready")
            try:
                with opener.open(base + "/healthz", timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("controller did not become ready")
        output = subprocess.check_output(
            ["bin/endpoint-agent", "--controller", base], text=True, timeout=15
        )
        accepted = json.loads(output)
        with opener.open(base + "/v1/devices/demo-device", timeout=5) as response:
            stored = json.load(response)
        assert stored["evidence_digest"] == accepted["evidence_digest"]
        assert stored["telemetry"]["source"] == "fixture"
        assert stored["health"] == "unknown"
        print("PASS: endpoint fixture -> controller -> stored telemetry; model status unknown")
    finally:
        controller.terminate()
        try:
            controller.wait(timeout=7)
        except subprocess.TimeoutExpired:
            controller.kill()
            controller.wait()


if __name__ == "__main__":
    main()
