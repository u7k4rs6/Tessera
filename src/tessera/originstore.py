"""On-disk layout for an origin's published state, layered on top of the
shared CAS (`store.py`/`cas.py`).

Chunks are content-addressed and therefore publisher-agnostic, living in the
shared `objects/` tree. Manifest envelopes are served by
`GET /v1/manifest/{digest}` with no publisher segment in the route
(02_TECHNICAL_ARCHITECTURE.md section 6.1), so they are stored flat, keyed
only by the manifest digest -- any publisher's manifest is reachable by its
digest alone, matching the route exactly. Root documents and the M1
current-version bridge ARE namespaced by publisher (the root key
fingerprint, since there is no naming authority per section 2) because
their routes carry a `{publisher}` segment.
"""

from __future__ import annotations

from pathlib import Path

from .errors import InternalError
from .hashing import is_valid_digest
from .store import atomic_write_json, read_json


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
    """Allocate and persist the next per-artifact monotonic seq number."""
    path = seq_counter_path(store, fingerprint, artifact)
    current = read_json(path)["seq"] if path.exists() else 0
    new_seq = current + 1
    atomic_write_json(path, {"seq": new_seq})
    return new_seq
