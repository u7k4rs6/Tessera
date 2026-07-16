"""The `tessera` CLI entry point, per 04_FRONTEND_SPEC.md section 3.

Verified by default, and only: no flag, environment variable, or config
key anywhere in this codebase disables a verification check or yields an
artifact that skipped one.
"""

from __future__ import annotations

import click

from .fetch import fetch_command
from .keygen import keygen_command
from .origin import origin_group
from .publish import publish_command
from .publisher import publisher_group
from .trust import trust_group
from .verify import verify_command


@click.group()
@click.option("--json", "json_output", is_flag=True, help="Emit a machine-readable result/v1 JSON object")
@click.option("--quiet", is_flag=True, help="Suppress progress output")
@click.pass_context
def main(ctx: click.Context, json_output: bool, quiet: bool) -> None:
    """Tessera: verified-by-default distribution for ML models and datasets."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = json_output
    ctx.obj["quiet"] = quiet


main.add_command(keygen_command)
main.add_command(publisher_group)
main.add_command(publish_command)
main.add_command(origin_group)
main.add_command(trust_group)
main.add_command(fetch_command)
main.add_command(verify_command)


if __name__ == "__main__":
    main()
