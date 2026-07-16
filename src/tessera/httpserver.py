"""Origin HTTP server, per 02_TECHNICAL_ARCHITECTURE.md section 6.1.

Every route is either content-addressed (chunk, manifest) or namespaced
under a publisher's own fingerprint (root, current-version bridge); nothing
served here is trusted for being "from" the origin -- the transport carries
zero trust, consumers verify everything locally. This module is also the
in-process fake-peer substrate the T2A/T4A adversarial tests build on
(03_SECURITY_AND_ACCESS.md section 9): tests wrap this same `build_app`
in `aiohttp.test_utils.TestServer` and interpose a tampering proxy in front
of it.

`GET /v1/{publisher}/meta/timestamp` and `GET /v1/{publisher}/meta/snapshot/{digest}`
are the M2 freshness layer (architecture doc section 4.2), superseding
M1's `/current` bridge (removed). The timestamp route serves a DSSE
envelope like the root document; the snapshot route serves RAW bytes via
`web.Response`, never `web.json_response` -- the snapshot's digest is
computed over its exact wire bytes (Decision D6, no signature of its own),
so re-serializing through aiohttp's JSON encoder would silently break
every snapshot fetch.
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
            web.get("/v1/{publisher}/meta/timestamp", handle_timestamp),
            web.get("/v1/{publisher}/meta/snapshot/{digest}", handle_snapshot),
            web.get("/v1/manifest/{digest}", handle_manifest),
            web.get("/v1/chunk/{digest}", handle_chunk),
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


async def handle_timestamp(request: web.Request) -> web.Response:
    publisher = request.match_info["publisher"]
    _validate_component(publisher)

    store: Path = request.app[STORE_KEY]
    envelope = originstore.read_timestamp(store, publisher)
    if envelope is None:
        raise web.HTTPNotFound(text="timestamp not found")
    return web.json_response(envelope)


async def handle_snapshot(request: web.Request) -> web.Response:
    publisher = request.match_info["publisher"]
    digest = request.match_info["digest"]
    _validate_component(publisher)
    _validate_digest(digest)

    store: Path = request.app[STORE_KEY]
    data = originstore.read_snapshot_bytes(store, publisher, digest)
    if data is None:
        raise web.HTTPNotFound(text="snapshot not found")
    # Raw bytes, NOT web.json_response -- see module docstring.
    return web.Response(body=data, content_type="application/json")
