"""Origin HTTP server, per 02_TECHNICAL_ARCHITECTURE.md section 6.1.

Every route is either content-addressed (chunk, manifest) or namespaced
under a publisher's own fingerprint (root, current-version bridge); nothing
served here is trusted for being "from" the origin -- the transport carries
zero trust, consumers verify everything locally. This module is also the
in-process fake-peer substrate the T2A/T4A adversarial tests build on
(03_SECURITY_AND_ACCESS.md section 9): tests wrap this same `build_app`
in `aiohttp.test_utils.TestServer` and interpose a tampering proxy in front
of it.

`GET /v1/{publisher}/current/{name}/{version}` is an M1-only bridge from a
version reference to a manifest digest, standing in for the snapshot/
timestamp resolution flow that M2 introduces. It carries no trust weight of
its own: `fetch_flow.py` treats its response as an unauthenticated hint and
independently verifies the manifest it points to (V6) -- a wrong or
malicious value here can only cause a failed/absent fetch, never an
accepted bad artifact.
"""

from __future__ import annotations

from pathlib import Path

from aiohttp import web

from . import cas, originstore
from .hashing import is_valid_digest

STORE_KEY = web.AppKey("store", Path)


def _validate_digest(digest: str) -> None:
    if not is_valid_digest(digest):
        raise web.HTTPBadRequest(text="invalid digest")


def _validate_component(value: str) -> None:
    if not value or "/" in value or "\\" in value or value in (".", ".."):
        raise web.HTTPBadRequest(text="invalid path component")


def build_app(store: Path) -> web.Application:
    app = web.Application()
    app[STORE_KEY] = store
    app.add_routes(
        [
            web.get("/v1/{publisher}/meta/root/{n}", handle_root),
            web.get("/v1/manifest/{digest}", handle_manifest),
            web.get("/v1/chunk/{digest}", handle_chunk),
            web.get("/v1/{publisher}/current/{name}/{version}", handle_current),
        ]
    )
    return app


async def handle_root(request: web.Request) -> web.Response:
    publisher = request.match_info["publisher"]
    _validate_component(publisher)
    try:
        version = int(request.match_info["n"])
    except ValueError:
        raise web.HTTPBadRequest(text="invalid root version")

    store: Path = request.app[STORE_KEY]
    envelope = originstore.read_root_doc(store, publisher, version)
    if envelope is None:
        raise web.HTTPNotFound(text="root document not found")
    return web.json_response(envelope)


async def handle_manifest(request: web.Request) -> web.Response:
    digest = request.match_info["digest"]
    _validate_digest(digest)

    store: Path = request.app[STORE_KEY]
    envelope = originstore.read_manifest_envelope(store, digest)
    if envelope is None:
        raise web.HTTPNotFound(text="manifest not found")
    return web.json_response(envelope)


async def handle_chunk(request: web.Request) -> web.Response:
    digest = request.match_info["digest"]
    _validate_digest(digest)

    store: Path = request.app[STORE_KEY]
    if not cas.has_object(store, digest):
        raise web.HTTPNotFound(text="chunk not found")
    data = cas.open_object(store, digest)
    return web.Response(body=data, content_type="application/octet-stream")


async def handle_current(request: web.Request) -> web.Response:
    publisher = request.match_info["publisher"]
    name = request.match_info["name"]
    version = request.match_info["version"]
    _validate_component(publisher)
    _validate_component(name)
    _validate_component(version)

    store: Path = request.app[STORE_KEY]
    pointer = originstore.read_current_pointer(store, publisher, name, version)
    if pointer is None:
        raise web.HTTPNotFound(text="reference not found")
    return web.json_response(pointer)
