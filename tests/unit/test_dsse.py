import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tessera.dsse import PAYLOAD_TYPE, pae, sign, verify
from tessera.errors import SignatureError
from tessera.keys import key_id, public_bytes


def test_pae_byte_exactness():
    result = pae("application/vnd.tessera.v1+json", b"hello")
    expected = b"DSSEv1 31 application/vnd.tessera.v1+json 5 hello"
    assert result == expected


def test_pae_empty_body():
    result = pae("t", b"")
    assert result == b"DSSEv1 1 t 0 "


def test_sign_and_verify_round_trip():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)

    payload = b'{"hello":"world"}'
    envelope = sign(payload, sk, kid)
    assert envelope["payloadType"] == PAYLOAD_TYPE
    assert envelope["signatures"][0]["keyid"] == kid

    recovered = verify(envelope, {kid: pub})
    assert recovered == payload


def test_verify_rejects_unauthorized_key():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b"payload", sk, kid)

    other_pub = public_bytes(Ed25519PrivateKey.generate().public_key())
    with pytest.raises(SignatureError):
        verify(envelope, {"b3:someoneelse": other_pub})


def test_verify_rejects_tampered_payload():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b'{"a":1}', sk, kid)

    import base64

    tampered = dict(envelope)
    tampered["payload"] = base64.b64encode(b'{"a":2}').decode()
    with pytest.raises(SignatureError):
        verify(tampered, {kid: pub})


def test_verify_rejects_tampered_signature():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b"payload", sk, kid)

    import base64

    bad_sig = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
    bad_sig[0] ^= 0xFF
    envelope["signatures"][0]["sig"] = base64.b64encode(bytes(bad_sig)).decode()

    with pytest.raises(SignatureError):
        verify(envelope, {kid: pub})


def test_verify_rejects_malformed_envelope():
    with pytest.raises(SignatureError):
        verify({}, {})
    with pytest.raises(SignatureError):
        verify({"payloadType": "t", "payload": "not-base64!!", "signatures": [{"keyid": "x", "sig": "eA=="}]}, {"x": b"\x00" * 32})
    with pytest.raises(SignatureError):
        verify({"payloadType": "t", "payload": "aGk=", "signatures": []}, {})
