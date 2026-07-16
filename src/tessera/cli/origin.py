from __future__ import annotations

from pathlib import Path

import click
from aiohttp import web

from .. import httpserver
from ..store import ensure_layout


@click.group("origin")
def origin_group() -> None:
    """Origin-server commands."""


@origin_group.command("serve")
@click.option("--store", type=click.Path(path_type=Path), required=True, help="Origin store directory")
@click.option("--bind", default="127.0.0.1:7433", help="host:port to listen on")
def origin_serve(store: Path, bind: str) -> None:
    """Serve STORE over HTTP. No keys are loaded; this process only reads
    what `publish` already wrote."""
    ensure_layout(store)
    host, _, port_s = bind.rpartition(":")
    if not host:
        raise click.ClickException(f"--bind must be host:port, got {bind!r}")
    port = int(port_s)

    app = httpserver.build_app(store)
    click.echo(f"serving {store} on {host}:{port}")
    web.run_app(app, host=host, port=port, print=None)
