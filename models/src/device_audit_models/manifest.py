"""CT10 #101 model manifest, the Python reference.

``packages/contracts/model-manifest-v1.md`` defines the rules and
``model_manifest_v1.go`` is the Go reference. This module checks everything
except the Ed25519 signature, because ``models`` takes no cryptography
dependency. A caller must verify ``signature`` over ``signing_bytes`` with its
trusted publisher key before it activates anything this module accepts.
"""
from __future__ import annotations

import hashlib
import re
import struct

from . import features

SCHEMA = "device-audit.model-manifest.v1"
PURPOSES = ("inference", "training")
MAX_PARAMETERS = 4096
MAX_FEATURES = 64

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"ed25519:[0-9a-f]{64}")
_SIGNATURE = re.compile(r"[0-9a-f]{128}")
_FIELDS = frozenset({"schema_version", "model_version", "artifact_sha256", "architecture", "parameter_count",
                     "runtime_name", "runtime_version", "feature_version", "features", "purposes",
                     "signing_key_id", "signature"})
_DOMAIN = b"device-audit/signature/v1\x00"


class ManifestRejection(ValueError):
    """A manifest cannot activate. ``code`` matches the Go ``ModelRejection``."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def _is_id(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _validate_body(manifest: object) -> None:
    """Check the signed fields' shape; a feature version or order may still be unsupported."""
    if not isinstance(manifest, dict) or manifest.keys() != _FIELDS:
        raise ManifestRejection("invalid_manifest", f"object must have fields {sorted(_FIELDS)}")
    if manifest["schema_version"] != SCHEMA:
        raise ManifestRejection("unsupported_manifest_version", str(manifest["schema_version"]))
    ids = ("model_version", "architecture", "runtime_name", "runtime_version", "feature_version")
    if not all(_is_id(manifest[field]) for field in ids):
        raise ManifestRejection("invalid_manifest", "invalid identifier")
    count = manifest["parameter_count"]
    if (not isinstance(manifest["artifact_sha256"], str) or not _SHA256.fullmatch(manifest["artifact_sha256"])
            or type(count) is not int or not 1 <= count <= MAX_PARAMETERS
            or not isinstance(manifest["signing_key_id"], str) or not _KEY_ID.fullmatch(manifest["signing_key_id"])):
        raise ManifestRejection("invalid_manifest", "invalid digest, parameter count or key ID")
    names = manifest["features"]
    if not isinstance(names, list) or not 1 <= len(names) <= MAX_FEATURES or not all(_is_id(n) for n in names):
        raise ManifestRejection("invalid_manifest", "features are required, named and limited to 64")
    purposes = manifest["purposes"]
    if (not isinstance(purposes, list) or not 1 <= len(purposes) <= len(PURPOSES)
            or not all(p in PURPOSES for p in purposes) or len(set(purposes)) != len(purposes)):
        raise ManifestRejection("invalid_manifest", "purposes must list inference and/or training once")


def validate(manifest: object) -> None:
    """Check structure, then that the feature version is implemented and in the frozen order."""
    _validate_body(manifest)
    if not isinstance(manifest["signature"], str) or not _SIGNATURE.fullmatch(manifest["signature"]):
        raise ManifestRejection("invalid_manifest", "signature must be lowercase hex of 64 bytes")
    if manifest["feature_version"] != features.FEATURE_VERSION:
        raise ManifestRejection("unsupported_feature_version", manifest["feature_version"])
    if manifest["features"] != [name for name, _ in features.FEATURES]:
        raise ManifestRejection("feature_order_mismatch")


def signing_bytes(manifest: object) -> bytes:
    """The bytes the publisher signs. Lists are a decimal count then their entries."""
    _validate_body(manifest)
    fields = [manifest["schema_version"], manifest["model_version"], manifest["artifact_sha256"],
              manifest["architecture"], str(manifest["parameter_count"]), manifest["runtime_name"],
              manifest["runtime_version"], manifest["feature_version"], manifest["signing_key_id"],
              str(len(manifest["features"])), *manifest["features"],
              str(len(manifest["purposes"])), *manifest["purposes"]]
    message = _DOMAIN
    for field in fields:
        data = field.encode("utf-8")
        message += struct.pack(">I", len(data)) + data
    return message


def check_compatibility(manifest: object, *, runtime_name: str, runtime_version: str,
                        architectures: list[str], purpose: str, artifact: bytes) -> None:
    """Refuse a manifest this runtime cannot load for ``purpose``. Signatures are not checked."""
    validate(manifest)
    if (runtime_name, runtime_version) != (manifest["runtime_name"], manifest["runtime_version"]):
        raise ManifestRejection("runtime_mismatch")
    if manifest["architecture"] not in architectures:
        raise ManifestRejection("unsupported_architecture")
    if purpose not in manifest["purposes"]:
        raise ManifestRejection("purpose_unsupported")
    if hashlib.sha256(artifact).hexdigest() != manifest["artifact_sha256"]:
        raise ManifestRejection("digest_mismatch")
