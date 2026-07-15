import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tessera.errors import PinMismatchError, SignatureError
from tessera.keys import key_id, public_bytes
from tessera.root import (
    authorized_keys_for_role,
    build_root_doc,
    sign_root_doc,
    verify_root_doc,
)


def _root_fixture(**overrides):
    root_sk = Ed25519PrivateKey.generate()
    root_pub = public_bytes(root_sk.public_key())
    root_kid = key_id(root_pub)

    release_sk = Ed25519PrivateKey.generate()
    release_pub = public_bytes(release_sk.public_key())
    release_kid = key_id(release_pub)

    doc = build_root_doc(
        root_key_id=root_kid,
        root_pub=root_pub,
        release_keys=[(release_kid, release_pub)],
        **overrides,
    )
    envelope = sign_root_doc(doc, root_sk, root_kid)
    return doc, envelope, root_kid, root_sk, release_kid, release_pub


def test_verify_root_doc_success():
    doc, envelope, root_kid, _, release_kid, release_pub = _root_fixture()
    verified = verify_root_doc(envelope, pinned_fingerprint=root_kid)
    assert verified == doc
    authorized = authorized_keys_for_role(verified, "release")
    assert authorized == {release_kid: release_pub}


def test_verify_root_doc_rejects_fingerprint_mismatch_before_signature_check():
    # T4A: a lookalike publisher signs with an entirely different key.
    _, envelope, root_kid, _, _, _ = _root_fixture()
    wrong_fingerprint = "b3:" + "0" * 64
    with pytest.raises(PinMismatchError):
        verify_root_doc(envelope, pinned_fingerprint=wrong_fingerprint)


def test_verify_root_doc_rejects_corrupted_self_signature():
    doc, envelope, root_kid, _, _, _ = _root_fixture()
    import base64

    bad_sig = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
    bad_sig[0] ^= 0xFF
    envelope["signatures"][0]["sig"] = base64.b64encode(bytes(bad_sig)).decode()

    with pytest.raises(SignatureError):
        verify_root_doc(envelope, pinned_fingerprint=root_kid)


def test_verify_root_doc_rejects_expired():
    doc, envelope, root_kid, _, _, _ = _root_fixture(expires="2000-01-01T00:00:00Z")
    with pytest.raises(SignatureError):
        verify_root_doc(envelope, pinned_fingerprint=root_kid)


def test_verify_root_doc_rejects_malformed_envelope():
    with pytest.raises(SignatureError):
        verify_root_doc({}, pinned_fingerprint="b3:" + "0" * 64)
    with pytest.raises(SignatureError):
        verify_root_doc({"payload": "not-base64!!"}, pinned_fingerprint="b3:" + "0" * 64)


def test_authorized_keys_for_role_empty_when_no_keys():
    doc, envelope, root_kid, _, _, _ = _root_fixture()
    verified = verify_root_doc(envelope, pinned_fingerprint=root_kid)
    assert authorized_keys_for_role(verified, "timestamp") == {}
