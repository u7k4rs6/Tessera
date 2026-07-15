"""DSSE (Dead Simple Signing Envelope) over Ed25519, per
02_TECHNICAL_ARCHITECTURE.md section 3.5 (Decision D4).

JCS-canonicalized payloads are wrapped in a DSSE envelope and signed over
DSSE's pre-authentication encoding (PAE), rather than over the raw payload
bytes directly -- PAE binds the payload type into what gets signed, so a
manifest can never be replayed as if it were a different kind of document.
DSSE is the small, well-reviewed envelope used by in-toto and sigstore; using
it here means leaning on prior art instead of inventing a signing format.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import SignatureError

PAYLOAD_TYPE = "application/vnd.tessera.v1+json"


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding: DSSEv1 LEN(type) type LEN(body) body."""
    pt = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(pt)).encode("ascii")
        + b" "
        + pt
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def sign(payload: bytes, private_key: Ed25519PrivateKey, key_id: str, *, payload_type: str = PAYLOAD_TYPE) -> dict:
    """Sign `payload` and return a DSSE envelope dict."""
    message = pae(payload_type, payload)
    signature = private_key.sign(message)
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}
        ],
    }


def add_signature(envelope: dict, private_key: Ed25519PrivateKey, key_id: str) -> dict:
    """Append another signature to an existing envelope over the same payload+type."""
    payload = base64.b64decode(envelope["payload"], validate=True)
    message = pae(envelope["payloadType"], payload)
    signature = private_key.sign(message)
    envelope = dict(envelope)
    envelope["signatures"] = list(envelope["signatures"]) + [
        {"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}
    ]
    return envelope


def verify(envelope: dict, authorized_keys: dict[str, bytes]) -> bytes:
    """Verify `envelope` has at least one valid signature from a key in
    `authorized_keys` (keyid -> raw 32-byte Ed25519 public key). Returns the
    decoded payload bytes on success; raises SignatureError otherwise.
    """
    if not isinstance(envelope, dict):
        raise SignatureError("malformed DSSE envelope: not an object")

    payload_type = envelope.get("payloadType")
    payload_b64 = envelope.get("payload")
    signatures = envelope.get("signatures")
    if not isinstance(payload_type, str) or not isinstance(payload_b64, str):
        raise SignatureError("malformed DSSE envelope: missing payloadType or payload")
    if not isinstance(signatures, list) or not signatures:
        raise SignatureError("malformed DSSE envelope: no signatures present")

    try:
        payload = base64.b64decode(payload_b64, validate=True)
    except Exception as e:
        raise SignatureError("malformed DSSE envelope: payload is not valid base64") from e

    message = pae(payload_type, payload)

    for entry in signatures:
        if not isinstance(entry, dict):
            continue
        keyid = entry.get("keyid")
        sig_b64 = entry.get("sig")
        if keyid not in authorized_keys or not isinstance(sig_b64, str):
            continue
        try:
            signature = base64.b64decode(sig_b64, validate=True)
            public_key = Ed25519PublicKey.from_public_bytes(authorized_keys[keyid])
            public_key.verify(signature, message)
            return payload
        except (InvalidSignature, ValueError):
            continue

    raise SignatureError("no valid signature from an authorized key")
