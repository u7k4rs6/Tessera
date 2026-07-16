import pytest
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tessera import fetch_flow, originstore, store as store_mod, trust_store, verify_flow
from tessera.hashing import b3_hex
from tessera.httpclient import OriginClient
from tessera.httpserver import build_app
from tessera.keys import key_id, public_bytes
from tessera.manifest import build_manifest, manifest_digest, sign_manifest
from tessera.root import build_root_doc, sign_root_doc

pytestmark = pytest.mark.asyncio


@pytest.fixture
def origin_store(tmp_path):
    origin = tmp_path / "origin"
    store_mod.ensure_layout(origin)
    return origin


@pytest.fixture
def consumer_home(tmp_path):
    home = tmp_path / "consumer"
    store_mod.ensure_layout(home)
    return home


@pytest.fixture
def published_artifact(tmp_path, origin_store):
    """Publish one small artifact to `origin_store`; returns fingerprint + ref."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "weights.bin").write_bytes(b"published artifact bytes" * 100)

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

    return {"fingerprint": root_kid, "manifest_digest": digest, "src_file": src / "weights.bin"}


@pytest.fixture
async def origin_server(origin_store):
    server = TestServer(build_app(origin_store))
    await server.start_server()
    try:
        yield server
    finally:
        await server.close()


async def test_fetch_success_materializes_byte_identical_artifact(consumer_home, published_artifact, origin_server):
    trust_store.add_pin(consumer_home, "acme-lab", published_artifact["fingerprint"])

    async with OriginClient(str(origin_server.make_url(""))) as client:
        result = await fetch_flow.fetch(consumer_home, client, "acme-lab/bert-tiny@1.2.0")

    assert result["ok"] is True
    assert result["exit_code"] == 0
    assert {c["id"] for c in result["checks"]} == {"V1", "V2", "V6", "V8", "V9"}
    assert all(c["ok"] for c in result["checks"])
    assert result["artifact"]["digest"] == published_artifact["manifest_digest"]

    materialized = consumer_home / "verified" / "acme-lab" / "bert-tiny" / "1.2.0" / "weights.bin"
    assert materialized.read_bytes() == published_artifact["src_file"].read_bytes()


async def test_fetch_unknown_publisher_exit_43(consumer_home, published_artifact, origin_server):
    async with OriginClient(str(origin_server.make_url(""))) as client:
        result = await fetch_flow.fetch(consumer_home, client, "acme-lab/bert-tiny@1.2.0")
    assert result["ok"] is False
    assert result["exit_code"] == 43
    assert result["checks"][0]["id"] == "V1"
    assert result["checks"][0]["ok"] is False


async def test_fetch_unknown_version_exit_21(consumer_home, published_artifact, origin_server):
    trust_store.add_pin(consumer_home, "acme-lab", published_artifact["fingerprint"])
    async with OriginClient(str(origin_server.make_url(""))) as client:
        result = await fetch_flow.fetch(consumer_home, client, "acme-lab/bert-tiny@9.9.9")
    assert result["ok"] is False
    assert result["exit_code"] == 21


async def test_fetch_then_verify_offline_using_cache(consumer_home, published_artifact, origin_server):
    trust_store.add_pin(consumer_home, "acme-lab", published_artifact["fingerprint"])
    async with OriginClient(str(origin_server.make_url(""))) as client:
        fetch_result = await fetch_flow.fetch(consumer_home, client, "acme-lab/bert-tiny@1.2.0")
    assert fetch_result["ok"] is True

    materialized_dir = consumer_home / "verified" / "acme-lab" / "bert-tiny" / "1.2.0"
    verify_result = await verify_flow.verify(consumer_home, materialized_dir, "acme-lab/bert-tiny@1.2.0", client=None)

    assert verify_result["ok"] is True
    assert verify_result["exit_code"] == 0
    assert {c["id"] for c in verify_result["checks"]} == {"V1", "V2", "V6", "V8", "V9"}


async def test_verify_detects_tampered_local_file(consumer_home, published_artifact, origin_server):
    trust_store.add_pin(consumer_home, "acme-lab", published_artifact["fingerprint"])
    async with OriginClient(str(origin_server.make_url(""))) as client:
        await fetch_flow.fetch(consumer_home, client, "acme-lab/bert-tiny@1.2.0")

    tampered = consumer_home / "tampered.bin"
    data = bytearray(published_artifact["src_file"].read_bytes())
    data[0] ^= 0xFF
    tampered.write_bytes(bytes(data))

    result = await verify_flow.verify(consumer_home, tampered, "acme-lab/bert-tiny@1.2.0", client=None)
    assert result["ok"] is False
    assert result["exit_code"] == 40
    fail_check = next(c for c in result["checks"] if not c["ok"])
    assert fail_check["id"] == "V8"
    assert "evidence" in fail_check


async def test_fetch_rejects_tampered_chunk_and_quarantines(consumer_home, published_artifact, origin_store, origin_server):
    # Corrupt the chunk on the origin's disk directly (simulating a compromised mirror).
    from tessera import cas as cas_mod

    manifest_env = originstore.read_manifest_envelope(origin_store, published_artifact["manifest_digest"])
    import base64
    import json

    payload = json.loads(base64.b64decode(manifest_env["payload"]))
    chunk_digest = payload["files"][0]["chunks"][0]
    obj_path = cas_mod.object_path(origin_store, chunk_digest)
    data = bytearray(obj_path.read_bytes())
    data[0] ^= 0xFF
    obj_path.write_bytes(bytes(data))

    trust_store.add_pin(consumer_home, "acme-lab", published_artifact["fingerprint"])
    async with OriginClient(str(origin_server.make_url(""))) as client:
        result = await fetch_flow.fetch(consumer_home, client, "acme-lab/bert-tiny@1.2.0")

    assert result["ok"] is False
    assert result["exit_code"] == 40
    fail_check = next(c for c in result["checks"] if not c["ok"])
    assert fail_check["id"] == "V8"
    assert "evidence" in fail_check

    # Materialization gate: nothing should have been written under verified/.
    assert not (consumer_home / "verified" / "acme-lab").exists()
