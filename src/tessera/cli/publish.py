"""`publish`, per 04_FRONTEND_SPEC.md section 4.

Deliberately does not accept `--base`/`--dataset`/`--code` provenance
flags in M1: `provenance` is always null on the manifest until M3 builds
attestations, and silently accepting flags that imply lineage recording
while doing nothing with them would violate the "loud, specific" UX
principle -- an unrecognized flag is a clean usage error (exit 2) until
provenance actually exists.
"""

from __future__ import annotations

from pathlib import Path

import click

from .. import keys, manifest as manifest_mod, originstore
from ..store import ensure_layout
from ._common import find_sole_publisher


@click.command("publish")
@click.argument("source_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--name", required=True)
@click.option("--version", required=True)
@click.option("--type", "artifact_type", type=click.Choice(["model", "dataset"]), required=True)
@click.option("--release-key", "release_key_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--store", type=click.Path(path_type=Path), required=True, help="Origin store directory")
@click.option("--passphrase-fd", type=int, default=None)
def publish_command(
    source_dir: Path,
    name: str,
    version: str,
    artifact_type: str,
    release_key_path: Path,
    store: Path,
    passphrase_fd: int | None,
) -> None:
    """Chunk, hash, and sign everything under SOURCE_DIR as a new release."""
    passphrase = keys.read_passphrase(passphrase_fd)
    release_loaded = keys.load_encrypted_key(release_key_path, passphrase)
    if release_loaded.role != "release":
        raise click.ClickException(f"{release_key_path} is a {release_loaded.role} key, not a release key")

    ensure_layout(store)
    fingerprint = find_sole_publisher(store)
    seq = originstore.next_seq(store, fingerprint, name)

    click.echo(f"hashing files under {source_dir} ...")
    built = manifest_mod.build_manifest(
        source_dir,
        store,
        publisher=fingerprint,
        name=name,
        version=version,
        seq=seq,
        artifact_type=artifact_type,
    )
    total_chunks = sum(len(f["chunks"]) for f in built["files"])
    click.echo(f"done: {len(built['files'])} file(s), {built['total_size']} bytes, {total_chunks} chunks")

    digest = manifest_mod.manifest_digest(built)
    envelope = manifest_mod.sign_manifest(built, release_loaded.private_key, release_loaded.key_id)
    originstore.write_manifest_envelope(store, digest, envelope)
    originstore.write_current_pointer(store, fingerprint, name, version, digest)

    click.echo(f"manifest {digest} signed (release key {release_loaded.key_id})")
    click.echo(f"published {name}@{version} (seq {seq})")
