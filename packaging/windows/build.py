#!/usr/bin/env python3
"""Build the release ZIP and detached-signature input from an exact Git commit."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import zipfile

REPOSITORY = "https://github.com/i-got-this-faa/device-audit"
SCHEMA = "device-audit.windows-release.v1"
ARCHIVE = "device-audit-windows-amd64.zip"
MODEL_FILES = ("artifact.json", "evaluation.json", "manifest.json", "publisher.pem")


def build(revision, output, model):
    repo = Path(__file__).resolve().parents[2]
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"], cwd=repo, text=True
    ).strip()
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory)
        exported = subprocess.check_output(["git", "archive", commit], cwd=repo)
        with tarfile.open(fileobj=io.BytesIO(exported)) as archive:
            archive.extractall(source, filter="data")
        version = re.search(r"^go (\d+\.\d+\.\d+)$", (source / "go.mod").read_text(), re.M)
        if not version:
            raise ValueError("go.mod must pin a Go patch version")
        toolchain = f"go{version[1]}"
        env = dict(os.environ, GOENV="off", GOFLAGS="", GOEXPERIMENT="", GOWORK="off",
                   GOTOOLCHAIN=toolchain, GOOS="windows", GOARCH="amd64",
                   GOAMD64="v1", CGO_ENABLED="0", GODEBUG="")
        subprocess.run(
            ["go", "build", "-mod=readonly", "-buildvcs=false", "-trimpath", "-ldflags=-buildid=",
             "-o", "endpoint-agent.exe", "./apps/endpoint-agent"],
            cwd=source, env=env, check=True,
        )

        files = {"endpoint-agent.exe": source / "endpoint-agent.exe"}
        for name in ("Install-EndpointService.ps1", "Uninstall-EndpointService.ps1"):
            files[name] = source / "tools" / "service" / name
        if model:
            files.update({f"model/{name}": model / name for name in MODEL_FILES})

        # Fixed metadata and stored entries keep the bytes independent of
        # filesystem timestamps, checkout location and compression versions.
        output.mkdir(parents=True)
        path = output / ARCHIVE
        with zipfile.ZipFile(path, "x") as bundle:
            for name, file in sorted(files.items()):
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 0
                bundle.writestr(entry, file.read_bytes())

        provenance = {
            "schema_version": SCHEMA,
            "source_repository": REPOSITORY,
            "source_commit": commit,
            "archive_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "target": "windows/amd64",
            "go_toolchain": toolchain,
            "runtime": "native-endpoint-agent",
            "model_included": model is not None,
        }
        state_version = source / "apps" / "endpoint-agent" / "endpoint-state-version.txt"
        if state_version.exists():
            version_bytes = state_version.read_bytes()
            if not re.fullmatch(rb"[1-9][0-9]*\n", version_bytes):
                raise ValueError("endpoint state version must contain one positive integer and a newline")
            provenance["endpoint_state_version"] = int(version_bytes)
        (output / "provenance.json").write_bytes(
            (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True, type=Path, help="new output directory")
    parser.add_argument("--model-dir", type=Path, help="directory with the approved inference bundle")
    args = parser.parse_args()
    build(args.revision, args.output, args.model_dir)
