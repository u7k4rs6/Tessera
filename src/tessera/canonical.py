"""JSON canonicalization, per 02_TECHNICAL_ARCHITECTURE.md section 3.5 (Decision D4).

All signed payloads are canonicalized per RFC 8785 (JCS) before signing or
digesting. This removes an entire class of signature-bypass bugs where two
semantically-equal but byte-different JSON encodings would produce different
signatures/digests.
"""

from __future__ import annotations

import rfc8785


def canonicalize(obj) -> bytes:
    """Return the RFC 8785 canonical JSON encoding of `obj` as bytes."""
    return rfc8785.dumps(obj)
