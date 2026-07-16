"""In-process fake-peer fixtures for the T-series adversarial tests, per
03_SECURITY_AND_ACCESS.md section 9: "a tampering mirror... are all test
fixtures", built from real Tessera code (not mocks) so the attacks are
deterministic and exercise the actual wire format.
"""

from __future__ import annotations

import base64
import json

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tessera import originstore
from tessera import store as store_mod
from tessera.httpserver import build_app
from tessera.keys import key_id, public_bytes
from tessera.manifest import build_manifest, manifest_digest, sign_manifest
from tessera.root import build_root_doc, sign_root_doc


@pytest.fixture
def origin_store(tmp_path):
    origin = tmp_path / "origin"
    store_mod.ensure_layout(origin)
    return origin


@pytest.fixture
def published_artifact(tmp_path, origin_store):
    """A real, fully-signed one-artifact origin store: honest baseline that
    the T2A/T4A fixtures below attack.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "weights.bin").write_bytes(b"artifact bytes for adversarial testing, " * 100)

    root_sk = Ed25519PrivateKey.generate()
    root_pub = public_bytes(root_sk.public_key())
    root_kid = key_id(root_pub)

    release_sk = Ed25519PrivateKey.generate()
    release_pub = public_bytes(release_sk.public_key())
    release_kid = key_id(release_pub)

    root_doc = build_root_doc(root_key_id=root_kid, root_pub=root_pub, release_keys=[(release_kid, release_pub)])
    root_envelope = sign_root_doc(root_doc, root_sk, root_kid)
    originstore.write_root_doc(origin_store, root_kid, 1, root_envelope)

    manifest = build_manifest(
        src, origin_store, publisher=root_kid, name="bert-tiny", version="1.2.0", seq=1, artifact_type="model"
    )
    digest = manifest_digest(manifest)
    envelope = sign_manifest(manifest, release_sk, release_kid)
    originstore.write_manifest_envelope(origin_store, digest, envelope)
    originstore.write_current_pointer(origin_store, root_kid, "bert-tiny", "1.2.0", digest)

    return {
        "fingerprint": root_kid,
        "manifest_digest": digest,
        "chunk_digest": manifest["files"][0]["chunks"][0],
        "src_file": src / "weights.bin",
        "root_sk": root_sk,
        "root_pub": root_pub,
    }


@pytest.fixture
async def fake_origin(origin_store, published_artifact):
    """An honest, running origin server for `published_artifact`."""
    server = TestServer(build_app(origin_store))
    await server.start_server()
    try:
        yield server
    finally:
        await server.close()


class TamperingProxy:
    """An in-process on-path attacker (T2A): proxies every request to a real
    upstream origin, corrupting the response body whenever the request path
    contains `tamper_digest`.
    """

    def __init__(self, upstream_base_url: str, tamper_digest: str):
        self.upstream = upstream_base_url.rstrip("/")
        self.tamper_digest = tamper_digest
        self._server: TestServer | None = None

    async def _handler(self, request: web.Request) -> web.Response:
        async with aiohttp.ClientSession() as session:
            async with session.get(self.upstream + request.path_qs) as resp:
                body = await resp.read()
                status = resp.status
                content_type = resp.content_type

        if status == 200 and self.tamper_digest and self.tamper_digest in request.path and body:
            mutated = bytearray(body)
            mutated[0] ^= 0xFF
            body = bytes(mutated)

        return web.Response(body=body, status=status, content_type=content_type)

    async def start(self) -> "TamperingProxy":
        app = web.Application()
        app.router.add_route("GET", "/{tail:.*}", self._handler)
        self._server = TestServer(app)
        await self._server.start_server()
        return self

    async def stop(self) -> None:
        if self._server is not None:
            await self._server.close()

    def base_url(self) -> str:
        return str(self._server.make_url(""))


@pytest.fixture
async def tampering_proxy_factory(fake_origin):
    """Call as `await tampering_proxy_factory(tamper_digest)` to get a
    running proxy in front of `fake_origin` that corrupts any response whose
    request path contains `tamper_digest`.
    """
    proxies: list[TamperingProxy] = []

    async def _make(tamper_digest: str) -> TamperingProxy:
        proxy = TamperingProxy(str(fake_origin.make_url("")), tamper_digest)
        await proxy.start()
        proxies.append(proxy)
        return proxy

    yield _make

    for proxy in proxies:
        await proxy.stop()


def decode_envelope_payload(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"], validate=True))
