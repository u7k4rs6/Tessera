"""`publisher init` / `publisher delegate`, per 04_FRONTEND_SPEC.md section 4.

M1 deviates deliberately from the frontend spec's abbreviated transcript: it
takes `--root-key` (the encrypted private key) directly on both commands
rather than splitting into an export/sign/import ceremony. That ceremony
exists to support an air-gapped root across a multi-step *rotation* flow
(M3); M1 has no rotation or chain-walking and a 1-of-1 threshold, so the
ceremony would be complexity with nothing yet to justify it.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import click

from .. import keys, originstore, root
from ..store import ensure_layout


@click.group("publisher")
def publisher_group() -> None:
    """Publisher-side commands: initialize an origin, delegate role keys."""


@publisher_group.command("init")
@click.argument("name")
@click.option("--root-key", "root_key_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--store", type=click.Path(path_type=Path), required=True, help="Origin store directory")
@click.option("--passphrase-fd", type=int, default=None)
def publisher_init(name: str, root_key_path: Path, store: Path, passphrase_fd: int | None) -> None:
    """Initialize a new publisher identity at STORE, named NAME locally."""
    passphrase = keys.read_passphrase(passphrase_fd)
    loaded = keys.load_encrypted_key(root_key_path, passphrase)
    if loaded.role != "root":
        raise click.ClickException(f"{root_key_path} is a {loaded.role} key, not a root key")

    pub = keys.public_bytes(loaded.public_key)
    doc = root.build_root_doc(root_key_id=loaded.key_id, root_pub=pub)
    envelope = root.sign_root_doc(doc, loaded.private_key, loaded.key_id)

    ensure_layout(store)
    originstore.write_root_doc(store, loaded.key_id, 1, envelope)

    click.echo(f"initialized publisher {name} -> {loaded.key_id}")
    click.echo(f"store: {store}")


@publisher_group.command("delegate")
@click.option("--role", type=click.Choice(["release", "timestamp"]), required=True)
@click.option("--key", "pub_key_path", type=click.Path(exists=True, path_type=Path), required=True, help="Public key file (.pub) to delegate")
@click.option("--root-key", "root_key_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--store", type=click.Path(path_type=Path), required=True)
@click.option("--passphrase-fd", type=int, default=None)
def publisher_delegate(role: str, pub_key_path: Path, root_key_path: Path, store: Path, passphrase_fd: int | None) -> None:
    """Add a release or timestamp key to the root document."""
    passphrase = keys.read_passphrase(passphrase_fd)
    root_loaded = keys.load_encrypted_key(root_key_path, passphrase)
    if root_loaded.role != "root":
        raise click.ClickException(f"{root_key_path} is a {root_loaded.role} key, not a root key")

    pubfile_role, delegated_kid, delegated_pub = keys.load_public_key_file(pub_key_path)
    if pubfile_role != role:
        raise click.ClickException(f"{pub_key_path} is a {pubfile_role} key, not {role!r}")

    existing_envelope = originstore.read_root_doc(store, root_loaded.key_id, 1)
    if existing_envelope is None:
        raise click.ClickException(f"no root document for {root_loaded.key_id} at {store}; run `publisher init` first")

    doc = json.loads(base64.b64decode(existing_envelope["payload"], validate=True))
    doc["keys"][role] = [{"id": delegated_kid, "pub": base64.b64encode(delegated_pub).decode("ascii")}]

    new_envelope = root.sign_root_doc(doc, root_loaded.private_key, root_loaded.key_id)
    originstore.write_root_doc(store, root_loaded.key_id, 1, new_envelope)

    click.echo(f"delegated {role} key {delegated_kid}")
