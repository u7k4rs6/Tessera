from __future__ import annotations

import asyncio
import sys

import click

from .. import fetch_flow, trust_store
from ..errors import TesseraError
from ..httpclient import OriginClient
from ..store import default_home, ensure_layout
from ._output import emit


@click.command("fetch")
@click.argument("ref")
@click.option("--mirror", default=None, help="Mirror base URL, overriding the pinned mirror list")
@click.pass_context
def fetch_command(ctx: click.Context, ref: str, mirror: str | None) -> None:
    """Fetch and verify REF (NAME/ARTIFACT@VERSION), materializing it on success."""
    home = default_home()
    ensure_layout(home)

    publisher_name = ref.split("/", 1)[0]
    base_url = mirror
    if base_url is None:
        try:
            pin = trust_store.load_pin(home, publisher_name)
            base_url = pin["mirrors"][0] if pin["mirrors"] else None
        except TesseraError:
            base_url = None
    if base_url is None:
        # No mirror configured (or no pin at all): still run the flow so V1
        # produces the canonical missing-pin result, or (if a pin exists
        # with no mirrors) so V2's network attempt against a clearly
        # unreachable placeholder produces a clean exit-20 result rather
        # than a crash.
        base_url = "http://127.0.0.1:1"

    async def run() -> dict:
        async with OriginClient(base_url) as client:
            return await fetch_flow.fetch(home, client, ref)

    result = asyncio.run(run())
    emit(ctx, result)
    sys.exit(result["exit_code"])
