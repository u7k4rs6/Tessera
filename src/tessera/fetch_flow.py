"""The flagship consumer flow: `fetch`, per 02_TECHNICAL_ARCHITECTURE.md
section 7 and 03_SECURITY_AND_ACCESS.md section 6.

M1 implements V1 (pin), V2 (root, degraded single-doc form), V6 (manifest),
V8 (per-chunk hash-before-write), and V9 (assembly). V3 (revocations -- M1
never has any), V4/V5 (timestamp/snapshot -- superseded here by the
`resolve.py` bridge), V7 (transparency log), and V10 (provenance) are M2/M3.
Single peer only: a chunk digest mismatch fails the fetch immediately
rather than retrying against another mirror (no scheduler yet). The
materialization gate holds regardless: nothing is renamed into `verified/`
until every file's V9 check has passed.
"""

from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path

from . import cas
from .chunking import compute_file_digest, iter_chunks
from .errors import DigestMismatchError, ExitCode, NetworkError, TesseraError, UsageError
from .httpclient import OriginClient
from .manifest import verify_manifest_envelope
from .quarantine import quarantine_file
from .resolve import resolve_manifest_digest
from .result import build_result, check_fail, check_ok
from .root import authorized_keys_for_role, verify_root_doc
from .store import verified_dir
from .trust_store import cache_manifest, cache_root_envelope, load_pin

REF_RE = re.compile(r"^(?P<publisher>[^/@]+)/(?P<artifact>[^/@]+)@(?P<version>[^/@]+)$")


def parse_ref(ref: str) -> tuple[str, str, str]:
    m = REF_RE.match(ref)
    if not m:
        raise UsageError(f"malformed reference {ref!r}, expected NAME/ARTIFACT@VERSION")
    return m["publisher"], m["artifact"], m["version"]


def _reset_staging_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _materialize(staging_root: Path, final_path: Path) -> None:
    final_path.parent.mkdir(parents=True, exist_ok=True)
    if final_path.exists():
        shutil.rmtree(final_path)
    os.replace(staging_root, final_path)


async def fetch(home: Path, client: OriginClient, ref: str) -> dict:
    """Run the full M1 fetch pipeline against a single peer. Always returns a
    result/v1 dict (never raises) -- failures are recorded as a failing
    check entry with the appropriate exit code.
    """
    started = time.monotonic()
    checks: list[dict] = []
    total_bytes = 0

    try:
        publisher_name, artifact, version = parse_ref(ref)
    except TesseraError as e:
        check_fail(checks, "V1", e)
        return build_result("fetch", ref, False, e.exit_code, checks)

    # V1: pin lookup
    try:
        pin = load_pin(home, publisher_name)
    except TesseraError as e:
        check_fail(checks, "V1", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    fingerprint = pin["fingerprint"]
    check_ok(checks, "V1", f"{publisher_name} -> {fingerprint}")

    # V2: root document (degraded single-doc form -- no chain walk yet)
    try:
        root_envelope = await client.get_root(fingerprint, 1)
        if root_envelope is None:
            raise NetworkError(f"origin has no root document for {fingerprint}", peer=client.base_url)
        root_doc = verify_root_doc(root_envelope, pinned_fingerprint=fingerprint)
    except TesseraError as e:
        check_fail(checks, "V2", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    cache_root_envelope(home, publisher_name, root_envelope)
    check_ok(checks, "V2", f"root v{root_doc['root_version']}, 0 revocations apply")

    # M1 bridge: resolve name@version -> manifest digest (not a trust boundary)
    try:
        expected_digest = await resolve_manifest_digest(client, fingerprint, artifact, version)
    except TesseraError as e:
        check_fail(checks, "V6", e)
        return build_result("fetch", ref, False, e.exit_code, checks)

    # V6: manifest fetch + verify
    try:
        manifest_envelope = await client.get_manifest(expected_digest)
        if manifest_envelope is None:
            raise NetworkError(f"manifest {expected_digest} not found at origin", peer=client.base_url)
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
        return build_result("fetch", ref, False, e.exit_code, checks)
    cache_manifest(home, publisher_name, artifact, version, expected_digest, manifest_envelope)
    check_ok(checks, "V6", f"{expected_digest} sig ok, name/version match")

    # V8: fetch + verify every chunk before it ever touches the CAS
    staging_root = verified_dir(home) / ".staging" / publisher_name / artifact / version
    try:
        _reset_staging_dir(staging_root)
        for file_entry in manifest["files"]:
            file_path = staging_root / file_entry["path"]
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "wb") as out:
                for chunk_digest in file_entry["chunks"]:
                    data = await client.get_chunk(chunk_digest)
                    if data is None:
                        raise NetworkError(f"chunk {chunk_digest} not found at origin", peer=client.base_url)
                    cas.write_verified(home, chunk_digest, data, peer=client.base_url)
                    out.write(data)
                    total_bytes += len(data)
    except TesseraError as e:
        check_fail(checks, "V8", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    total_chunks = sum(len(f["chunks"]) for f in manifest["files"])
    check_ok(checks, "V8", f"{total_chunks}/{total_chunks} chunks verified")

    # V9: assembly -- re-read what actually landed on disk and confirm every
    # file digest independently of the in-memory bytes checked at V8.
    try:
        for file_entry in manifest["files"]:
            file_path = staging_root / file_entry["path"]
            on_disk_chunk_digests = [c.digest for c in iter_chunks(file_path)]
            recomputed_digest = compute_file_digest(on_disk_chunk_digests)
            if recomputed_digest != file_entry["digest"] or on_disk_chunk_digests != file_entry["chunks"]:
                qdir = quarantine_file(
                    home,
                    code=ExitCode.DIGEST_MISMATCH,
                    path=file_path,
                    expected=file_entry["digest"],
                    actual=recomputed_digest,
                    peer=client.base_url,
                    reason="assembled file digest mismatch",
                )
                raise DigestMismatchError(
                    f"assembled file digest mismatch for {file_entry['path']}",
                    evidence=qdir,
                    expected=file_entry["digest"],
                    actual=recomputed_digest,
                )
    except TesseraError as e:
        check_fail(checks, "V9", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    check_ok(checks, "V9", f"{len(manifest['files'])} files, artifact digest {expected_digest}")

    final_path = verified_dir(home) / publisher_name / artifact / version
    _materialize(staging_root, final_path)

    elapsed = time.monotonic() - started
    return build_result(
        "fetch",
        ref,
        True,
        ExitCode.OK,
        checks,
        artifact={"digest": expected_digest, "seq": manifest.get("seq")},
        materialized=str(final_path),
        timing={"wall_s": round(elapsed, 3), "bytes": total_bytes},
    )
