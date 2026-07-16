"""On-disk layout for an origin's published state, layered on top of the
shared CAS (`store.py`/`cas.py`).

Chunks are content-addressed and therefore publisher-agnostic, living in the
shared `objects/` tree. Manifest envelopes are served by
`GET /v1/manifest/{digest}` with no publisher segment in the route
(02_TECHNICAL_ARCHITECTURE.md section 6.1), so they are stored flat, keyed
only by the manifest digest -- any publisher's manifest is reachable by its
digest alone, matching the route exactly. Root documents, the timestamp,
and the snapshot ARE namespaced by publisher (the root key fingerprint,
since there is no naming authority per section 2) because their routes
carry a `{publisher}` segment.

`current_pointer_path`/`write_current_pointer`/`read_current_pointer` are
the on-disk bookkeeping `publish` writes for every release (per-artifact
"what does this version's manifest digest look like"). In M1 these were
also served directly over HTTP as a trust-free resolution bridge; from M2
that HTTP route is gone (superseded by the signed snapshot) and this data
is purely internal input for `origin reissue-timestamp` to enumerate when
building a snapshot -- see `list_artifacts`/`list_versions`.

Snapshot bytes are written and read RAW (`atomic_write_bytes`/
`.read_bytes()`), never through `atomic_write_json`/`read_json`, per the
byte-exactness requirement in `snapshot.py`'s docstring: re-serializing
through `json.dumps` would silently change the bytes a digest was computed
over.
"""

from __future__ import annotations

from pathlib import Path

from .errors import InternalError
from .hashing import is_valid_digest
from .store import atomic_write_bytes, atomic_write_json, locked, read_json


def validate_path_component(value: str, field: str) -> None:
    if not value or "/" in value or "\\" in value or value in (".", ".."):
        raise InternalError(f"unsafe {field}: {value!r}")


def manifests_dir(store: Path) -> Path:
    return store / "manifests"


def manifest_envelope_path(store: Path, digest: str) -> Path:
    if not is_valid_digest(digest):
        raise InternalError(f"not a valid digest: {digest!r}")
    return manifests_dir(store) / f"{digest}.json"


def publisher_dir(store: Path, fingerprint: str) -> Path:
    validate_path_component(fingerprint, "publisher fingerprint")
    return store / "publisher" / fingerprint


def root_doc_path(store: Path, fingerprint: str, version: int) -> Path:
    return publisher_dir(store, fingerprint) / "root" / f"{int(version)}.json"


def current_pointer_path(store: Path, fingerprint: str, artifact: str, version: str) -> Path:
    validate_path_component(artifact, "artifact name")
    validate_path_component(version, "version")
    return publisher_dir(store, fingerprint) / "current" / artifact / f"{version}.json"


def seq_counter_path(store: Path, fingerprint: str, artifact: str) -> Path:
    validate_path_component(artifact, "artifact name")
    return publisher_dir(store, fingerprint) / "seq" / f"{artifact}.json"


def timestamp_path(store: Path, fingerprint: str) -> Path:
    return publisher_dir(store, fingerprint) / "timestamp.json"


def timestamp_seq_path(store: Path, fingerprint: str) -> Path:
    return publisher_dir(store, fingerprint) / "timestamp-seq.json"


def snapshot_path(store: Path, fingerprint: str, digest: str) -> Path:
    if not is_valid_digest(digest):
        raise InternalError(f"not a valid digest: {digest!r}")
    return publisher_dir(store, fingerprint) / "snapshot" / f"{digest}.json"


def current_dir(store: Path, fingerprint: str) -> Path:
    return publisher_dir(store, fingerprint) / "current"


def write_root_doc(store: Path, fingerprint: str, version: int, envelope: dict) -> None:
    atomic_write_json(root_doc_path(store, fingerprint, version), envelope)


def read_root_doc(store: Path, fingerprint: str, version: int) -> dict | None:
    path = root_doc_path(store, fingerprint, version)
    return read_json(path) if path.exists() else None


def write_manifest_envelope(store: Path, digest: str, envelope: dict) -> None:
    atomic_write_json(manifest_envelope_path(store, digest), envelope)


def read_manifest_envelope(store: Path, digest: str) -> dict | None:
    path = manifest_envelope_path(store, digest)
    return read_json(path) if path.exists() else None


def write_current_pointer(store: Path, fingerprint: str, artifact: str, version: str, digest: str) -> None:
    atomic_write_json(current_pointer_path(store, fingerprint, artifact, version), {"digest": digest})


def read_current_pointer(store: Path, fingerprint: str, artifact: str, version: str) -> dict | None:
    path = current_pointer_path(store, fingerprint, artifact, version)
    return read_json(path) if path.exists() else None


def next_seq(store: Path, fingerprint: str, artifact: str) -> int:
    """Allocate and persist the next per-artifact monotonic seq number.
    Lock-protected: two concurrent `publish` invocations must never
    allocate the same seq twice.
    """
    path = seq_counter_path(store, fingerprint, artifact)
    with locked(path):
        current = read_json(path)["seq"] if path.exists() else 0
        new_seq = current + 1
        atomic_write_json(path, {"seq": new_seq})
        return new_seq


def write_timestamp(store: Path, fingerprint: str, envelope: dict) -> None:
    """DSSE-enveloped -- safe to round-trip through JSON like the root doc."""
    atomic_write_json(timestamp_path(store, fingerprint), envelope)


def read_timestamp(store: Path, fingerprint: str) -> dict | None:
    path = timestamp_path(store, fingerprint)
    return read_json(path) if path.exists() else None


def next_timestamp_seq(store: Path, fingerprint: str) -> int:
    """Allocate and persist the next publisher-wide monotonic timestamp seq.
    Lock-protected, same reasoning as `next_seq`.
    """
    path = timestamp_seq_path(store, fingerprint)
    with locked(path):
        current = read_json(path)["seq"] if path.exists() else 0
        new_seq = current + 1
        atomic_write_json(path, {"seq": new_seq})
        return new_seq


def write_snapshot(store: Path, fingerprint: str, digest: str, canonical_bytes: bytes) -> None:
    """Raw bytes, NOT JSON -- see module and snapshot.py docstrings."""
    atomic_write_bytes(snapshot_path(store, fingerprint, digest), canonical_bytes)


def read_snapshot_bytes(store: Path, fingerprint: str, digest: str) -> bytes | None:
    path = snapshot_path(store, fingerprint, digest)
    return path.read_bytes() if path.exists() else None


def list_artifacts(store: Path, fingerprint: str) -> list[str]:
    """Every artifact name this publisher has ever published under, from the
    `current/` bookkeeping `publish` writes. Used by `origin
    reissue-timestamp` to enumerate what belongs in a fresh snapshot.
    """
    base = current_dir(store, fingerprint)
    if not base.is_dir():
        return []
    return sorted(p.name for p in base.iterdir() if p.is_dir())


def list_versions(store: Path, fingerprint: str, artifact: str) -> list[str]:
    validate_path_component(artifact, "artifact name")
    base = current_dir(store, fingerprint) / artifact
    if not base.is_dir():
        return []
    return sorted(p.stem for p in base.iterdir() if p.is_file() and p.suffix == ".json")
