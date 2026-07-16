"""Local storage layout, per 02_TECHNICAL_ARCHITECTURE.md section 8.

    <home>/
      config.toml
      trust/<publisher>/
      objects/<aa>/<digest>
      verified/<publisher>/<artifact>/<version>/
      quarantine/<timestamp>-<reason>/
      peers.json

No database; state is small JSON/TOML files written with atomic rename.
`<home>` is either the consumer's `~/.tessera` or an origin's `--store`
directory -- both share this same CAS-centric layout.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

DEFAULT_HOME_ENV = "TESSERA_HOME"


def default_home() -> Path:
    override = os.environ.get(DEFAULT_HOME_ENV)
    if override:
        return Path(override)
    return Path.home() / ".tessera"


def objects_dir(home: Path) -> Path:
    return home / "objects"


def trust_dir(home: Path) -> Path:
    return home / "trust"


def verified_dir(home: Path) -> Path:
    return home / "verified"


def quarantine_dir(home: Path) -> Path:
    return home / "quarantine"


def peers_path(home: Path) -> Path:
    return home / "peers.json"


def ensure_layout(home: Path) -> None:
    for d in (objects_dir(home), trust_dir(home), verified_dir(home), quarantine_dir(home)):
        d.mkdir(parents=True, exist_ok=True)
    (objects_dir(home) / ".tmp").mkdir(parents=True, exist_ok=True)


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    """Write `data` to `path` via a temp file + atomic rename in the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def atomic_write_json(path: Path, obj, *, mode: int = 0o644) -> None:
    atomic_write_bytes(path, json.dumps(obj, indent=2, sort_keys=True).encode() + b"\n", mode=mode)


def read_json(path: Path):
    with open(path, "rb") as f:
        return json.loads(f.read())
