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
    doc = build_root_doc(publisher=kid, root_keys=[(kid, pub)])
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


async def test_current_bridge_route_is_gone(store, running_server):
    # M1's /current bridge is superseded by the signed snapshot (D16); the
    # route itself no longer exists, so any request to it 404s at the
    # router level (no handler ever runs).
    fingerprint = "b3:" + "c" * 64
    originstore.write_current_pointer(store, fingerprint, "bert-tiny", "1.2.0", "b3:" + "d" * 64)
    status = await _raw_get_status(running_server, f"/v1/{fingerprint}/current/bert-tiny/1.2.0")
    assert status == 404


async def test_timestamp_round_trip_and_404(store, running_server):
    fingerprint = "b3:" + "c" * 64
    envelope = {"payloadType": "t", "payload": "cGF5bG9hZA==", "signatures": [{"keyid": "k", "sig": "s"}]}
    originstore.write_timestamp(store, fingerprint, envelope)

    async with OriginClient(str(running_server.make_url(""))) as client:
        fetched = await client.get_timestamp(fingerprint)
        assert fetched == envelope

        missing = await client.get_timestamp("b3:" + "e" * 64)
        assert missing is None


async def test_timestamp_rejects_unsafe_publisher_component(store, running_server):
    status = await _raw_get_status(running_server, "/v1/%2e%2e/meta/timestamp")
    assert status == 400


async def test_snapshot_round_trip_and_404(store, running_server):
    fingerprint = "b3:" + "c" * 64
    canonical_bytes = b'{"artifacts":{},"publisher":"b3:c","tessera":"snapshot/v1"}'
    digest = b3_hex(canonical_bytes)
    originstore.write_snapshot(store, fingerprint, digest, canonical_bytes)

    async with OriginClient(str(running_server.make_url(""))) as client:
        fetched = await client.get_snapshot(fingerprint, digest)
        assert fetched == canonical_bytes  # exact bytes, not re-serialized

        missing = await client.get_snapshot(fingerprint, "b3:" + "f" * 64)
        assert missing is None


async def test_snapshot_rejects_malformed_digest(store, running_server):
    fingerprint = "b3:" + "c" * 64
    async with OriginClient(str(running_server.make_url(""))) as client:
        with pytest.raises(NetworkError):
            await client.get_snapshot(fingerprint, "not-a-digest")
