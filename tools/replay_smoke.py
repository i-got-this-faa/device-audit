"""Assert replay rejection at the actual controller, not the contract test fake."""

import json
import os
from pathlib import Path
import socket
import subprocess
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener


def main():
    suffix = ".exe" if os.name == "nt" else ""
    controller_bin = str(Path("bin", "controller" + suffix))
    replay_bin = str(Path("bin", "endpoint-replay" + suffix))
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    opener = build_opener(ProxyHandler({}))
    controller = subprocess.Popen([controller_bin, "--listen", f"127.0.0.1:{port}"])
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
        replay = subprocess.run(
            [replay_bin, "--controller", base, "--profile", "scaffold", "--scenario", "all"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        report = json.loads(replay.stdout)
        if report["fixture"] is not True or report["profile"] != "scaffold":
            raise RuntimeError("replay report does not identify scaffold fixtures")
        responses = [row for row in report["results"] if row["sent"]]
        expected_pairs = {
            (family, scenario)
            for family in ("telemetry", "diagnostics", "federated")
            for scenario in ("valid", "malformed", "interrupted")
        }
        if len(responses) != 9 or {
            (row["family"], row["scenario"]) for row in responses
        } != expected_pairs:
            raise RuntimeError("replay did not exercise all family/scenario pairs")
        for row in responses:
            expected = 400 if row["family"] == "telemetry" else 404
            if (
                row["status"] != expected
                or row["expected_status"] != expected
                or row["outcome"] != "expected_unsupported"
            ):
                raise RuntimeError(f"unexpected actual-controller response: {row}")
        cancelled = [row for row in report["results"] if not row["sent"]]
        if len(cancelled) != 3 or any(
            row["scenario"] != "interrupted"
            or row["outcome"] != "cancelled_before_submission"
            or row["status"] is not None
            for row in cancelled
        ):
            raise RuntimeError("replay cancellation evidence is incomplete")
        if report["device_id"] != "fixture-replay-device":
            raise RuntimeError("unexpected fixture device identity")
        try:
            with opener.open(base + "/v1/devices/fixture-replay-device", timeout=5):
                raise RuntimeError("signed fixture unexpectedly stored as legacy telemetry")
        except HTTPError as error:
            if error.code != 404:
                raise
        mismatch = subprocess.run(
            [
                replay_bin, "--controller", base, "--profile", "scaffold",
                "--scenario", "valid", "--expect", "telemetry.valid=202",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        mismatch_report = json.loads(mismatch.stdout)
        telemetry = next(
            row for row in mismatch_report["results"] if row["family"] == "telemetry"
        )
        if (
            mismatch.returncode != 1
            or telemetry["status"] != 400
            or telemetry["expected_status"] != 202
            or telemetry["outcome"] != "status_mismatch"
        ):
            raise RuntimeError("CLI did not fail a deliberately wrong expected response")
        print("PASS: CLI exits 1 when expected telemetry 202 receives actual 400")
        print(replay.stdout, end="")
        print(
            "PASS: actual controller rejects signed telemetry (400), diagnostics and "
            "federation (404) across valid/malformed/interrupted fixtures. "
            "No signed admission or real-device capability is established."
        )
    finally:
        controller.terminate()
        try:
            controller.wait(timeout=7)
        except subprocess.TimeoutExpired:
            controller.kill()
            controller.wait()


if __name__ == "__main__":
    main()
