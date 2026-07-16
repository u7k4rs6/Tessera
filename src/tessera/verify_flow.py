"""`verify PATH --ref REF`, per 02_TECHNICAL_ARCHITECTURE.md section 7 and
03_SECURITY_AND_ACCESS.md section 6: V1, V2, V6 (manifest from cache or
network), then V8 and V9 recomputed over local bytes already on disk.
Never mutates `verified/` -- this command answers "is this file the signed
artifact?", it does not materialize anything.

Deliberately does NOT enforce the rollback high-water marks `fetch_flow.py`
does: `verify` checks a specific, named reference against what the
publisher signed for it, which is a legitimate thing to ask about an old
version long after a newer one exists (e.g. auditing an old backup). hwm
enforcement is about "give me the current, freshest artifact" -- `fetch`'s
job, not this one -- so `verify` never calls
`trust_store.check_and_advance_*` and always passes the default
`min_version=0`/`min_seq=0`.

Only the network-fallback path (nothing cached, a client was given) runs
V4/V5 (`freshness.py`) to resolve an uncached reference via the signed
snapshot, exactly like `fetch_flow.py` -- there is no other mechanism left
to do that resolution now that the M1 `/current` bridge is gone. The
common case (a reference already fetched once) stays fully offline and
never touches V4/V5 at all.
"""

from __future__ import annotations

from pathlib import Path

from . import freshness
from .chunking import compute_file_digest, iter_chunks
from .errors import DigestMismatchError, ExitCode, NetworkError, ReferenceNotFoundError, TesseraError, UsageError
from .fetch_flow import parse_ref
from .httpclient import OriginClient
from .manifest import verify_manifest_envelope
from .quarantine import quarantine_file
from .result import build_result, check_fail, check_ok
from .root import authorized_keys_for_role, verify_root_doc
from .trust_store import (
    cache_manifest,
    cache_root_envelope,
    load_cached_manifest,
    load_cached_root_envelope,
    load_pin,
)


def _check_local_file(home: Path, file_entry: dict, file_path: Path) -> None:
    """Recompute chunk and file digests over local bytes. Raises
    DigestMismatchError (with quarantine evidence) on any mismatch.
    """
    if not file_path.exists():
        raise DigestMismatchError(f"{file_path} does not exist", expected=file_entry["digest"], actual=None)

    chunk_digests: list[str] = []
    mismatch_index: int | None = None
    for chunk in iter_chunks(file_path):
        chunk_digests.append(chunk.digest)
        if mismatch_index is None:
            if chunk.index >= len(file_entry["chunks"]) or chunk.digest != file_entry["chunks"][chunk.index]:
                mismatch_index = chunk.index

    length_mismatch = len(chunk_digests) != len(file_entry["chunks"])
    if mismatch_index is None and not length_mismatch:
        return

    recomputed = compute_file_digest(chunk_digests)
    qdir = quarantine_file(
        home,
        code=ExitCode.DIGEST_MISMATCH,
        path=file_path,
        expected=file_entry["digest"],
        actual=recomputed,
        reason="local content does not match signed manifest",
        extra={"first_bad_chunk": mismatch_index},
    )
    detail = f"file digest mismatch: expected {file_entry['digest']}, got {recomputed}"
    if mismatch_index is not None:
        detail += f" (first bad chunk: {mismatch_index})"
    raise DigestMismatchError(detail, evidence=qdir, expected=file_entry["digest"], actual=recomputed)


async def _resolve_manifest_over_network(
    home: Path, client: OriginClient, publisher_name: str, fingerprint: str, artifact: str, version: str
) -> tuple[str, dict]:
    """V4 + V5 + snapshot lookup, used only when nothing is cached. Returns
    (expected_digest, manifest_envelope). Note: this does advance the
    publisher-wide timestamp high-water mark (freshness.py's job) -- that's
    fine, since it's about detecting a stale/equivocating overall snapshot
    pointer, not about which specific artifact version is being checked.
    The per-artifact manifest seq rollback check is deliberately skipped
    (see module docstring): `verify_manifest_envelope` is called below with
    no `min_seq`, so verifying an intentionally old reference never fails
    just because a newer version has since been fetched.
    """
    root_envelope = await client.get_root(fingerprint, 1)
    if root_envelope is None:
        raise NetworkError(f"origin has no root document for {fingerprint}", peer=client.base_url)
    root_doc = verify_root_doc(root_envelope, pinned_fingerprint=fingerprint)

    authorized_timestamp = authorized_keys_for_role(root_doc, "timestamp")
    timestamp_stmt = await freshness.fetch_verified_timestamp(
        home, client, publisher_name, fingerprint, authorized_timestamp
    )
    snapshot_doc = await freshness.fetch_verified_snapshot(client, fingerprint, timestamp_stmt["snapshot"])

    artifact_entry = snapshot_doc.get("artifacts", {}).get(artifact)
    version_entry = artifact_entry.get("versions", {}).get(version) if artifact_entry else None
    if version_entry is None:
        raise ReferenceNotFoundError(f"{artifact}@{version} not found in snapshot for {fingerprint}")
    expected_digest = version_entry["manifest_digest"]

    manifest_envelope = await client.get_manifest(expected_digest)
    if manifest_envelope is None:
        raise NetworkError(f"manifest {expected_digest} not found at origin", peer=client.base_url)
    return expected_digest, manifest_envelope


async def verify(home: Path, path: Path, ref: str, client: OriginClient | None = None) -> dict:
    checks: list[dict] = []

    try:
        publisher_name, artifact, version = parse_ref(ref)
    except TesseraError as e:
        check_fail(checks, "V1", e)
        return build_result("verify", ref, False, e.exit_code, checks)

    # V1
    try:
        pin = load_pin(home, publisher_name)
    except TesseraError as e:
        check_fail(checks, "V1", e)
        return build_result("verify", ref, False, e.exit_code, checks)
    fingerprint = pin["fingerprint"]
    check_ok(checks, "V1", f"{publisher_name} -> {fingerprint}")

    # V2: prefer a cached root document; fall back to network if a client was given.
    try:
        root_envelope = load_cached_root_envelope(home, publisher_name)
        if root_envelope is None:
            if client is None:
                raise NetworkError("no cached root document and no network client available")
            root_envelope = await client.get_root(fingerprint, 1)
            if root_envelope is None:
                raise NetworkError(f"origin has no root document for {fingerprint}", peer=client.base_url)
        root_doc = verify_root_doc(root_envelope, pinned_fingerprint=fingerprint)
    except TesseraError as e:
        check_fail(checks, "V2", e)
        return build_result("verify", ref, False, e.exit_code, checks)
    cache_root_envelope(home, publisher_name, root_envelope)
    check_ok(checks, "V2", f"root v{root_doc['root_version']}")

    # V6: manifest from cache; V4+V5+snapshot lookup only on a cache miss.
    try:
        cached = load_cached_manifest(home, publisher_name, artifact, version)
        if cached is not None:
            expected_digest, manifest_envelope, source = cached["digest"], cached["envelope"], "cached"
        else:
            if client is None:
                raise NetworkError("no cached manifest and no network client available")
            expected_digest, manifest_envelope = await _resolve_manifest_over_network(
                home, client, publisher_name, fingerprint, artifact, version
            )
            source = "network"

        authorized_release = authorized_keys_for_role(root_doc, "release")
        manifest = verify_manifest_envelope(
            manifest_envelope,
            authorized_keys=authorized_release,
            expected_digest=expected_digest,
            publisher=fingerprint,
            name=artifact,
            version=version,
        )
    except TesseraError as e:
        check_fail(checks, "V6", e)
        return build_result("verify", ref, False, e.exit_code, checks)
    if source == "network":
        cache_manifest(home, publisher_name, artifact, version, expected_digest, manifest_envelope)
    check_ok(checks, "V6", f"{expected_digest} ({source})")

    # V8 + V9: recompute chunk and file digests over local bytes at `path`.
    files = manifest["files"]
    try:
        if len(files) == 1 and path.is_file():
            targets = [(files[0], path)]
        elif path.is_dir():
            targets = [(fe, path / fe["path"]) for fe in files]
        else:
            raise UsageError(
                f"{path}: manifest for {artifact}@{version} has {len(files)} file(s); PATH must be a directory"
            )
        for file_entry, file_path in targets:
            _check_local_file(home, file_entry, file_path)
    except TesseraError as e:
        check_fail(checks, "V8", e)
        return build_result("verify", ref, False, e.exit_code, checks)
    check_ok(checks, "V8", f"{len(targets)} file(s) content verified")
    check_ok(checks, "V9", f"artifact digest {expected_digest} confirmed")

    return build_result(
        "verify",
        ref,
        True,
        ExitCode.OK,
        checks,
        artifact={"digest": expected_digest, "seq": manifest.get("seq")},
    )
