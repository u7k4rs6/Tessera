"""Small helpers shared across CLI commands."""

from __future__ import annotations

from pathlib import Path

import click


def find_sole_publisher(store: Path) -> str:
    """M1/M2 support exactly one publisher per origin store; return its
    fingerprint (the name of the sole subdirectory under `publisher/`).
    """
    publisher_dir = store / "publisher"
    if not publisher_dir.is_dir():
        raise click.ClickException(f"{store}: no publisher initialized here; run `publisher init` first")
    candidates = [p.name for p in publisher_dir.iterdir() if p.is_dir()]
    if len(candidates) == 0:
        raise click.ClickException(f"{store}: no publisher initialized here; run `publisher init` first")
    if len(candidates) > 1:
        raise click.ClickException(
            f"{store}: multiple publishers present ({', '.join(candidates)}); one publisher per store is supported"
        )
    return candidates[0]
