"""The manifest: the signed statement "this artifact is exactly these bytes",
per 02_TECHNICAL_ARCHITECTURE.md section 3.3.

This is the core M1 deliverable. `verify_manifest_envelope` implements
check V6 from 03_SECURITY_AND_ACCESS.md section 6: signature under an
authorized key, canonical-form payload, digest match, embedded
publisher/name/version match against what was requested (so a compromised
resolution step can never remap a reference to a different, legitimately
signed manifest), and, from M2, a per-artifact rollback high-water mark.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import cas, dsse
from .canonical import canonicalize
from .chunking import CHUNK_SIZE, iter_chunks, compute_file_digest
from .errors import DigestMismatchError, InternalError, RollbackError, SignatureError
from .hashing import b3_hex
from .timeutil import utc_now_iso

MANIFEST_TYPE = "manifest/v1"


def _validate_relative_path(rel_posix: str) -> None:
    if not rel_posix or rel_posix.startswith("/"):
        raise InternalError(f"unsafe path in artifact: {rel_posix!r}")
    parts = rel_posix.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise InternalError(f"unsafe path in artifact: {rel_posix!r}")


def _iter_relative_files(source_dir: Path) -> list[str]:
    paths: list[str] = []
    for root, dirs, files in os.walk(source_dir):
        dirs.sort()
        for filename in sorted(files):
            abs_path = Path(root) / filename
            rel_posix = abs_path.relative_to(source_dir).as_posix()
            _validate_relative_path(rel_posix)
            paths.append(rel_posix)
    paths.sort()
    return paths


def build_manifest(
    source_dir: Path,
    home: Path,
    *,
    publisher: str,
    name: str,
    version: str,
    seq: int,
    artifact_type: str,
    created: str | None = None,
) -> dict:
    """Chunk and hash every file under `source_dir`, writing each chunk into
    the CAS at `home`, and assemble the signed-manifest shape (unsigned).
    """
    file_entries = []
    total_size = 0
    for rel_path in _iter_relative_files(source_dir):
        abs_path = source_dir / rel_path
        chunk_digests: list[str] = []
        size = 0
        for chunk in iter_chunks(abs_path):
            cas.write_verified(home, chunk.digest, chunk.data)
            chunk_digests.append(chunk.digest)
            size += len(chunk.data)
        file_digest = compute_file_digest(chunk_digests)
        file_entries.append(
            {
                "path": rel_path,
                "size": size,
                "chunk_size": CHUNK_SIZE,
                "chunks": chunk_digests,
                "digest": file_digest,
            }
        )
        total_size += size

    return {
        "tessera": MANIFEST_TYPE,
        "publisher": publisher,
        "name": name,
        "version": version,
        "seq": seq,
        "type": artifact_type,
        "created": created or utc_now_iso(),
        "files": file_entries,
        "total_size": total_size,
        "record_index": None,
        "provenance": None,
    }


def manifest_digest(manifest: dict) -> str:
    return b3_hex(canonicalize(manifest))


def sign_manifest(manifest: dict, private_key: Ed25519PrivateKey, key_id: str) -> dict:
    """Return a DSSE envelope over the manifest's canonical bytes."""
    return dsse.sign(canonicalize(manifest), private_key, key_id)


def verify_manifest_envelope(
    envelope: dict,
    *,
    authorized_keys: dict[str, bytes],
    expected_digest: str,
    publisher: str,
    name: str,
    version: str,
    min_seq: int = 0,
) -> dict:
    """Implements V6, including (from M2) the per-artifact rollback
    sub-check: a manifest whose `seq` is below `min_seq`, the consumer's
    persisted high-water mark for this artifact, is rejected. Returns the
    verified manifest dict on success.
    """
    payload = dsse.verify(envelope, authorized_keys)

    try:
        parsed = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as e:
        raise SignatureError("manifest payload is not valid JSON") from e

    if canonicalize(parsed) != payload:
        # The signature is valid over these exact bytes, but the bytes are
        # not the canonical encoding of their own parsed content -- reject
        # rather than let a non-canonical signed payload compute a different
        # digest than every other verifier would derive for the same data.
        raise SignatureError("manifest payload is not canonical JSON")

    digest = b3_hex(payload)
    if digest != expected_digest:
        raise DigestMismatchError(
            f"manifest digest mismatch: expected {expected_digest}, got {digest}",
            expected=expected_digest,
            actual=digest,
        )

    if (
        parsed.get("publisher") != publisher
        or parsed.get("name") != name
        or parsed.get("version") != version
    ):
        raise SignatureError(
            "manifest publisher/name/version does not match the requested reference"
        )

    seq = parsed.get("seq", 0)
    if seq < min_seq:
        raise RollbackError(
            f"{name} seq {seq} is older than the previously seen seq {min_seq}",
            seen=min_seq,
            offered=seq,
        )

    return parsed
