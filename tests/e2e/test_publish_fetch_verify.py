"""End-to-end scripted scenario, driven through the real `tessera` CLI
surface (per the M1 plan): keygen -> publisher init -> delegate -> publish
-> origin serve -> trust add -> fetch -> verify, plus a tampering variant.

`origin serve` itself blocks forever (`aiohttp.web.run_app`), so rather than
invoke that specific subcommand we serve the published store directly via
`aiohttp.test_utils.TestServer` wrapping the same `httpserver.build_app` the
command uses -- an explicitly sanctioned substitution for determinism, not a
different code path. Every other step goes through `CliRunner` against the
actual `tessera` command group. CLI invocations run in a worker thread via
`asyncio.to_thread`, because `fetch`/`verify` call `asyncio.run()`
internally and this test itself needs its own event loop alive (for the
TestServer) throughout.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
from aiohttp.test_utils import TestServer
from click.testing import CliRunner

from tessera.chunking import CHUNK_SIZE
from tessera.cli.main import main
from tessera.httpserver import build_app

pytestmark = pytest.mark.asyncio


def _passphrase_fd(passphrase: str) -> int:
    r, w = os.pipe()
    os.write(w, (passphrase + "\n").encode())
    os.close(w)
    return r


async def invoke(runner: CliRunner, args: list[str], passphrase: str | None = None):
    full_args = list(args)
    if passphrase is not None:
        full_args += ["--passphrase-fd", str(_passphrase_fd(passphrase))]
    return await asyncio.to_thread(runner.invoke, main, full_args, catch_exceptions=False)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    home = tmp_path / "home"
    origin = tmp_path / "origin"
    keys_dir = tmp_path / "keys"
    src = tmp_path / "src"
    keys_dir.mkdir()
    src.mkdir()
    monkeypatch.setenv("TESSERA_HOME", str(home))
    return {"home": home, "origin": origin, "keys": keys_dir, "src": src}


async def _publish_fixture_artifact(runner: CliRunner, workspace: dict) -> str:
    """Run keygen -> publisher init -> delegate -> publish through the real
    CLI. Returns the publisher fingerprint.
    """
    keys_dir = workspace["keys"]
    origin = workspace["origin"]
    src = workspace["src"]

    # One multi-chunk file and one single-chunk file, to exercise both the
    # multi-chunk and single-chunk manifest/assembly paths.
    (src / "big.bin").write_bytes(b"A" * (CHUNK_SIZE + 12345))
    (src / "small.bin").write_bytes(b"small file contents")

    result = await invoke(runner, ["keygen", "--role", "root", "--out", str(keys_dir / "root.key")], passphrase="rootpass")
    assert result.exit_code == 0, result.output

    result = await invoke(runner, ["keygen", "--role", "release", "--out", str(keys_dir / "release.key")], passphrase="releasepass")
    assert result.exit_code == 0, result.output

    result = await invoke(
        runner,
        ["publisher", "init", "acme-lab", "--root-key", str(keys_dir / "root.key"), "--store", str(origin)],
        passphrase="rootpass",
    )
    assert result.exit_code == 0, result.output
    fingerprint = result.output.split("->")[1].split()[0].strip()

    result = await invoke(
        runner,
        [
            "publisher", "delegate", "--role", "release",
            "--key", str(keys_dir / "release.key.pub"),
            "--root-key", str(keys_dir / "root.key"),
            "--store", str(origin),
        ],
        passphrase="rootpass",
    )
    assert result.exit_code == 0, result.output

    result = await invoke(
        runner,
        [
            "publish", str(src),
            "--name", "bert-tiny", "--version", "1.2.0", "--type", "model",
            "--release-key", str(keys_dir / "release.key"), "--store", str(origin),
        ],
        passphrase="releasepass",
    )
    assert result.exit_code == 0, result.output

    return fingerprint


async def test_publish_fetch_verify_end_to_end(runner, workspace):
    fingerprint = await _publish_fixture_artifact(runner, workspace)
    origin = workspace["origin"]
    src = workspace["src"]

    server = TestServer(build_app(origin))
    await server.start_server()
    try:
        base_url = str(server.make_url(""))

        result = await invoke(runner, ["trust", "add", "acme-lab", fingerprint, "--mirror", base_url])
        assert result.exit_code == 0, result.output

        result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-tiny@1.2.0"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["ok"] is True
        assert {c["id"] for c in payload["checks"]} == {"V1", "V2", "V6", "V8", "V9"}
        assert all(c["ok"] for c in payload["checks"])

        materialized = Path(payload["materialized"])
        assert (materialized / "big.bin").read_bytes() == (src / "big.bin").read_bytes()
        assert (materialized / "small.bin").read_bytes() == (src / "small.bin").read_bytes()

        result = await invoke(runner, ["--json", "verify", str(materialized), "--ref", "acme-lab/bert-tiny@1.2.0"])
        assert result.exit_code == 0, result.output
        verify_payload = json.loads(result.output)
        assert verify_payload["ok"] is True
        assert verify_payload["artifact"]["digest"] == payload["artifact"]["digest"]
    finally:
        await server.close()


async def test_publish_fetch_tampered_origin_fails_closed(runner, workspace):
    fingerprint = await _publish_fixture_artifact(runner, workspace)
    origin = workspace["origin"]

    # Corrupt one byte of one chunk directly on the origin's disk, between
    # publish and fetch -- simulating a compromised mirror serving altered
    # bytes for an otherwise legitimately-published release.
    from tessera import cas as cas_mod
    from tessera import originstore

    # Find the manifest that `current` points to, then one of its chunks.
    current = originstore.read_current_pointer(origin, fingerprint, "bert-tiny", "1.2.0")
    envelope = originstore.read_manifest_envelope(origin, current["digest"])
    import base64

    manifest = json.loads(base64.b64decode(envelope["payload"]))
    chunk_digest = manifest["files"][0]["chunks"][0]
    obj_path = cas_mod.object_path(origin, chunk_digest)
    corrupted = bytearray(obj_path.read_bytes())
    corrupted[0] ^= 0xFF
    obj_path.write_bytes(bytes(corrupted))

    server = TestServer(build_app(origin))
    await server.start_server()
    try:
        base_url = str(server.make_url(""))
        result = await invoke(runner, ["trust", "add", "acme-lab", fingerprint, "--mirror", base_url])
        assert result.exit_code == 0, result.output

        result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-tiny@1.2.0"])
        assert result.exit_code == 40, result.output
        payload = json.loads(result.output)
        assert payload["ok"] is False

        fail_check = next(c for c in payload["checks"] if not c["ok"])
        assert fail_check["id"] == "V8"
        assert "evidence" in fail_check

        evidence_dir = Path(fail_check["evidence"])
        assert evidence_dir.is_dir()
        assert (evidence_dir / "report.json").exists()
        assert (evidence_dir / "bytes.bin").exists()

        # Nothing materialized.
        home = workspace["home"]
        assert not (home / "verified" / "acme-lab").exists()
    finally:
        await server.close()
