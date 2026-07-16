import asyncio

import pytest
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tessera import cas as cas_mod
from tessera import originstore
from tessera import store as store_mod
from tessera.errors import NetworkError
from tessera.hashing import b3_hex
from tessera.httpclient import OriginClient
from tessera.httpserver import build_app
from tessera.keys import key_id, public_bytes
from tessera.root import build_root_doc, sign_root_doc

pytestmark = pytest.mark.asyncio


@pytest.fixture
def store(tmp_path):
    store_mod.ensure_layout(tmp_path)
    return tmp_path


@pytest.fixture
async def running_server(store):
    server = TestServer(build_app(store))
    await server.start_server()
    try:
        yield server
    finally:
        await server.close()


async def test_chunk_round_trip_and_404(store, running_server):
    data = b"chunk bytes for the wire"
    digest = b3_hex(data)
    cas_mod.write_verified(store, digest, data)

    async with OriginClient(str(running_server.make_url(""))) as client:
        fetched = await client.get_chunk(digest)
        assert fetched == data

        missing = await client.get_chunk("b3:" + "0" * 64)
        assert missing is None


async def test_chunk_rejects_malformed_digest(store, running_server):
    async with OriginClient(str(running_server.make_url(""))) as client:
        with pytest.raises(NetworkError):
            await client.get_chunk("not-a-digest")


async def test_manifest_round_trip_and_404(store, running_server):
    digest = "b3:" + "a" * 64
    envelope = {"payloadType": "t", "payload": "cGF5bG9hZA==", "signatures": [{"keyid": "x", "sig": "eA=="}]}
    originstore.write_manifest_envelope(store, digest, envelope)

    async with OriginClient(str(running_server.make_url(""))) as client:
        fetched = await client.get_manifest(digest)
        assert fetched == envelope

        missing = await client.get_manifest("b3:" + "b" * 64)
        assert missing is None


async def test_root_round_trip_and_404(store, running_server):
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    doc = build_root_doc(root_key_id=kid, root_pub=pub)
    envelope = sign_root_doc(doc, sk, kid)
    originstore.write_root_doc(store, kid, 1, envelope)

    async with OriginClient(str(running_server.make_url(""))) as client:
        fetched = await client.get_root(kid, 1)
        assert fetched == envelope

        missing = await client.get_root(kid, 2)
        assert missing is None


async def _raw_get_status(server: TestServer, raw_path: str) -> int:
    """Send a request with a literal raw path, bypassing yarl's client-side
    URL normalization (which would otherwise collapse `..` segments before
    the request is even sent -- normal aiohttp clients can never reproduce
    the raw path traversal attempt this is meant to test). This is exactly
    how a non-yarl HTTP client (or a deliberately malicious one) could reach
    the server, which is why `httpserver.py` validates path components
    itself instead of relying on client-side normalization.
    """
    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        request = f"GET {raw_path} HTTP/1.1\r\nHost: {server.host}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()
        status_line = await reader.readline()
        return int(status_line.decode().split(" ")[1])
    finally:
        writer.close()


async def test_root_rejects_unsafe_publisher_component(store, running_server):
    status = await _raw_get_status(running_server, "/v1/%2e%2e/meta/root/1")
    assert status == 400


async def test_chunk_rejects_path_traversal_digest(store, running_server):
    status = await _raw_get_status(running_server, "/v1/chunk/%2e%2e%2f%2e%2e%2fetc%2fpasswd")
    assert status == 400


async def test_current_round_trip_and_404(store, running_server):
    fingerprint = "b3:" + "c" * 64
    manifest_digest = "b3:" + "d" * 64
    originstore.write_current_pointer(store, fingerprint, "bert-tiny", "1.2.0", manifest_digest)

    async with OriginClient(str(running_server.make_url(""))) as client:
        pointer = await client.get_current(fingerprint, "bert-tiny", "1.2.0")
        assert pointer == {"digest": manifest_digest}

        missing = await client.get_current(fingerprint, "bert-tiny", "9.9.9")
        assert missing is None


async def test_current_rejects_unsafe_component(store, running_server):
    fingerprint = "b3:" + "e" * 64
    status = await _raw_get_status(running_server, f"/v1/{fingerprint}/current/%2e%2e/1.0.0")
    assert status == 400
