"""Local trust pins, per 02_TECHNICAL_ARCHITECTURE.md section 2 and section 8.

A human-friendly publisher name is a purely local alias for a pinned root
key fingerprint, created by `trust add` -- exactly like an SSH
`known_hosts` entry. There is no global naming authority; the pin is the
trust bootstrap and this module is where it lives on disk.
"""

from __future__ import annotations

from pathlib import Path

from .errors import PinMismatchError
from .store import atomic_write_json, read_json, trust_dir


def pin_dir(home: Path, name: str) -> Path:
    return trust_dir(home) / name


def pin_path(home: Path, name: str) -> Path:
    return pin_dir(home, name) / "pin.json"


def root_cache_path(home: Path, name: str) -> Path:
    return pin_dir(home, name) / "root.json"


def add_pin(home: Path, name: str, fingerprint: str, mirrors: list[str] | None = None) -> dict:
    doc = {
        "tessera": "pin/v1",
        "name": name,
        "fingerprint": fingerprint,
        "mirrors": list(mirrors or []),
    }
    atomic_write_json(pin_path(home, name), doc)
    return doc


def load_pin(home: Path, name: str) -> dict:
    path = pin_path(home, name)
    if not path.exists():
        raise PinMismatchError(f'no pin for "{name}"', name=name)
    return read_json(path)


def has_pin(home: Path, name: str) -> bool:
    return pin_path(home, name).exists()


def cache_root_envelope(home: Path, name: str, envelope: dict) -> None:
    atomic_write_json(root_cache_path(home, name), envelope)


def load_cached_root_envelope(home: Path, name: str) -> dict | None:
    path = root_cache_path(home, name)
    if not path.exists():
        return None
    return read_json(path)
