import pytest
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tessera import originstore, store as store_mod
from tessera.errors import NetworkError, RollbackError, StaleError
from tessera.freshness import fetch_verified_snapshot, fetch_verified_timestamp
from tessera.httpclient import OriginClient
from tessera.httpserver import build_app
from tessera.keys import key_id, public_bytes
from tessera.snapshot import build_and_digest_snapshot
from tessera.timestamp import build_timestamp_statement, sign_timestamp

pytestmark = pytest.mark.asyncio


@pytest.fixture
def origin_store(tmp_path):
    store_mod.ensure_layout(tmp_path)
    return tmp_path


@pytest.fixture
def consumer_home(tmp_path):
    home = tmp_path / "consumer"
    store_mod.ensure_layout(home)
    return home


def _publish_timestamp(origin_store, fingerprint, ts_sk, ts_kid, *, seq):
    _doc, canonical, digest = build_and_digest_snapshot(publisher=fingerprint, artifacts={})
    originstore.write_snapshot(origin_store, fingerprint, digest, canonical)
    stmt = build_timestamp_statement(publisher=fingerprint, seq=seq, snapshot_digest=digest)
    envelope = sign_timestamp(stmt, ts_sk, ts_kid)
    originstore.write_timestamp(origin_store, fingerprint, envelope)
    return digest


@pytest.fixture
def timestamp_key():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    return sk, pub, key_id(pub)


@pytest.fixture
async def server(origin_store):
    s = TestServer(build_app(origin_store))
    await s.start_server()
    try:
        yield s
    finally:
        await s.close()


FP = "b3:" + "9" * 64


async def test_fetch_verified_timestamp_success(consumer_home, origin_store, server, timestamp_key):
    ts_sk, ts_pub, ts_kid = timestamp_key
    _publish_timestamp(origin_store, FP, ts_sk, ts_kid, seq=1)

    async with OriginClient(str(server.make_url(""))) as client:
        statement = await fetch_verified_timestamp(consumer_home, client, "acme-lab", FP, {ts_kid: ts_pub})
    assert statement["seq"] == 1
    assert statement["publisher"] == FP


async def test_fetch_verified_timestamp_missing_is_stale(consumer_home, origin_store, server, timestamp_key):
    ts_sk, ts_pub, ts_kid = timestamp_key
    async with OriginClient(str(server.make_url(""))) as client:
        with pytest.raises(StaleError):
            await fetch_verified_timestamp(consumer_home, client, "acme-lab", FP, {ts_kid: ts_pub})


async def test_fetch_verified_timestamp_rollback_rejected(consumer_home, origin_store, server, timestamp_key):
    ts_sk, ts_pub, ts_kid = timestamp_key
    _publish_timestamp(origin_store, FP, ts_sk, ts_kid, seq=3)

    async with OriginClient(str(server.make_url(""))) as client:
        await fetch_verified_timestamp(consumer_home, client, "acme-lab", FP, {ts_kid: ts_pub})

    # Origin regresses to an older, individually-valid statement (T2b).
    _publish_timestamp(origin_store, FP, ts_sk, ts_kid, seq=1)

    async with OriginClient(str(server.make_url(""))) as client:
        with pytest.raises(RollbackError):
            await fetch_verified_timestamp(consumer_home, client, "acme-lab", FP, {ts_kid: ts_pub})


async def test_fetch_verified_snapshot_success(server, origin_store):
    doc, canonical, digest = build_and_digest_snapshot(publisher=FP, artifacts={"bert-tiny": {"current_version": "1.0.0", "versions": {}}})
    originstore.write_snapshot(origin_store, FP, digest, canonical)

    async with OriginClient(str(server.make_url(""))) as client:
        verified = await fetch_verified_snapshot(client, FP, digest)
    assert verified == doc


async def test_fetch_verified_snapshot_missing_is_network_error(server, origin_store):
    async with OriginClient(str(server.make_url(""))) as client:
        with pytest.raises(NetworkError):
            await fetch_verified_snapshot(client, FP, "b3:" + "0" * 64)
