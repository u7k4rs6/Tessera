"""Quarantine: evidence capture on verification failure.

Per 03_SECURITY_AND_ACCESS.md section 7: on any verification failure that
involved received bytes, the offending material moves to
`quarantine/<utc-timestamp>-<code>/` containing the bytes, the expected and
actual digests, the peer identity/URL, and a machine-readable `report.json`.
Quarantine is evidence, never input: nothing in this codebase ever reads
bytes back out of quarantine into a verification path.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .store import atomic_write_bytes, atomic_write_json, quarantine_dir


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")[:-3] + "Z"


def quarantine(
    home: Path,
    *,
    code: int,
    data: bytes,
    expected: str | None,
    actual: str | None,
    peer: str | None = None,
    reason: str = "",
    extra: dict | None = None,
) -> Path:
    """Move failing bytes + evidence into a fresh quarantine directory. Returns the directory."""
    ts = _utc_timestamp()
    qdir = quarantine_dir(home) / f"{ts}-{code}"
    qdir.mkdir(parents=True, exist_ok=False)

    atomic_write_bytes(qdir / "bytes.bin", data)

    report = {
        "tessera": "quarantine-report/v1",
        "timestamp": ts,
        "exit_code": code,
        "reason": reason,
        "expected_digest": expected,
        "actual_digest": actual,
        "peer": peer,
        "size": len(data),
    }
    if extra:
        report["extra"] = extra
    atomic_write_json(qdir / "report.json", report)
    return qdir
