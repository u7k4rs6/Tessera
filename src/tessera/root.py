"""Root trust document, per 02_TECHNICAL_ARCHITECTURE.md section 4.1.

A publisher's identity IS the fingerprint of its root public key
(`publisher` field == the root key's `id`). M1 implements the degraded
form of check V2 (03_SECURITY_AND_ACCESS.md section 6): a single root
document, self-signed, checked against the locally pinned fingerprint and
its own expiry. There is no version chain to walk yet (root rotation is
M3) -- but the document shape already matches the full spec (`root_version`,
`threshold`, `revoked`) so M3's chain-walking logic can extend this without
a wire-format break.

The fingerprint comparison happens BEFORE any signature cryptography runs:
a lookalike publisher signing with a different key is rejected by pin
mismatch (exit 43) without ever needing to validate their signature. This
is the direct implementation of threat T4A: "the local pin fails against
any other key."
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import dsse
from .canonical import canonicalize
from .errors import PinMismatchError, SignatureError

ROOT_TYPE = "root/v1"
CLOCK_SKEW = timedelta(minutes=10)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def _key_entry(key_id: str, pub: bytes) -> dict:
    return {"id": key_id, "pub": _b64(pub)}


def default_root_expires(*, days: int = 365) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_root_doc(
    *,
    root_key_id: str,
    root_pub: bytes,
    release_keys: list[tuple[str, bytes]] = (),
    timestamp_keys: list[tuple[str, bytes]] = (),
    root_version: int = 1,
    expires: str | None = None,
) -> dict:
    return {
        "tessera": ROOT_TYPE,
        "publisher": root_key_id,
        "root_version": root_version,
        "keys": {
            "root": [_key_entry(root_key_id, root_pub)],
            "release": [_key_entry(kid, pub) for kid, pub in release_keys],
            "timestamp": [_key_entry(kid, pub) for kid, pub in timestamp_keys],
        },
        "threshold": {"root": 1},
        "revoked": [],
        "expires": expires or default_root_expires(),
    }


def sign_root_doc(doc: dict, root_private_key: Ed25519PrivateKey, root_key_id: str) -> dict:
    return dsse.sign(canonicalize(doc), root_private_key, root_key_id)


def _parse_expires(expires: str) -> datetime:
    return datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def verify_root_doc(envelope: dict, *, pinned_fingerprint: str) -> dict:
    """Implements the M1-degraded V2 check. Returns the verified root document."""
    if not isinstance(envelope, dict) or "payload" not in envelope:
        raise SignatureError("malformed root document envelope")

    try:
        raw_payload = _b64d(envelope["payload"])
        claimed = json.loads(raw_payload)
    except Exception as e:
        raise SignatureError("malformed root document payload") from e

    root_keys = claimed.get("keys", {}).get("root", []) if isinstance(claimed, dict) else []
    if not root_keys or root_keys[0].get("id") != pinned_fingerprint:
        raise PinMismatchError(
            f"served root key does not match pinned fingerprint {pinned_fingerprint}",
            pinned=pinned_fingerprint,
        )

    try:
        root_pub = _b64d(root_keys[0]["pub"])
    except Exception as e:
        raise SignatureError("malformed root key encoding") from e

    payload = dsse.verify(envelope, {pinned_fingerprint: root_pub})

    parsed = json.loads(payload)
    if canonicalize(parsed) != payload:
        raise SignatureError("root document payload is not canonical JSON")

    if parsed.get("publisher") != pinned_fingerprint:
        raise PinMismatchError("root document publisher field does not match pinned fingerprint")

    expires = parsed.get("expires")
    try:
        expires_at = _parse_expires(expires)
    except Exception as e:
        raise SignatureError(f"root document has an unparseable expiry: {expires!r}") from e
    if datetime.now(timezone.utc) - CLOCK_SKEW > expires_at:
        raise SignatureError(f"root document expired at {expires}")

    return parsed


def authorized_keys_for_role(root_doc: dict, role: str) -> dict[str, bytes]:
    """Extract keyid -> raw public key bytes for every key of `role` listed
    in a verified root document (used to authorize manifest/attestation
    signatures).
    """
    entries = root_doc.get("keys", {}).get(role, [])
    return {entry["id"]: _b64d(entry["pub"]) for entry in entries}
