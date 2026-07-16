"""M1 bridge from a version reference to a manifest digest.

This stands in for the snapshot/timestamp resolution flow
(02_TECHNICAL_ARCHITECTURE.md section 4.2) that M2 introduces. It carries
NO trust weight of its own: the value returned here is just a pointer used
to fetch a manifest by digest, and `manifest.verify_manifest_envelope` (V6)
independently confirms that manifest's signature, digest, and embedded
publisher/name/version. A malicious or wrong value from this bridge can
therefore only cause a failed or absent fetch -- never an accepted bad
artifact. Superseded wholesale by the signed snapshot/timestamp flow in M2;
nothing else in `fetch_flow.py` depends on this module's internals beyond
"returns a manifest digest to be independently verified."
"""

from __future__ import annotations

from .errors import ReferenceNotFoundError
from .hashing import is_valid_digest
from .httpclient import OriginClient


async def resolve_manifest_digest(
    client: OriginClient, publisher_fingerprint: str, artifact: str, version: str
) -> str:
    pointer = await client.get_current(publisher_fingerprint, artifact, version)
    if pointer is None:
        raise ReferenceNotFoundError(f"{artifact}@{version} not found for publisher {publisher_fingerprint}")

    digest = pointer.get("digest") if isinstance(pointer, dict) else None
    if not digest or not is_valid_digest(digest):
        raise ReferenceNotFoundError("origin returned a malformed current-version pointer")
    return digest
