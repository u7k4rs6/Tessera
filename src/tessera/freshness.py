"""V4 and V5 orchestration, shared by `fetch_flow.py` and `verify_flow.py`.

`fetch_verified_timestamp` is V4 end to end: fetch the timestamp envelope,
verify its signature/expiry (`timestamp.verify_timestamp_envelope`), then
check it against the consumer's persisted rollback/equivocation state
(`trust_store.check_and_advance_timestamp_seq`). `fetch_verified_snapshot`
is V5: fetch the snapshot's raw bytes by digest and confirm they hash to
it (`snapshot.verify_snapshot`).
"""

from __future__ import annotations

from pathlib import Path

from . import trust_store
from .errors import NetworkError, StaleError
from .httpclient import OriginClient
from .snapshot import verify_snapshot
from .timestamp import verify_timestamp_envelope


async def fetch_verified_timestamp(
    home: Path,
    client: OriginClient,
    publisher_name: str,
    fingerprint: str,
    authorized_timestamp_keys: dict[str, bytes],
) -> dict:
    """Implements V4. Returns the verified timestamp statement."""
    envelope = await client.get_timestamp(fingerprint)
    if envelope is None:
        raise StaleError(f"no timestamp obtainable for {fingerprint}", peer=client.base_url)

    statement = verify_timestamp_envelope(envelope, authorized_keys=authorized_timestamp_keys, publisher=fingerprint)
    trust_store.check_and_advance_timestamp_seq(home, publisher_name, statement["seq"], envelope)
    return statement


async def fetch_verified_snapshot(client: OriginClient, fingerprint: str, snapshot_digest: str) -> dict:
    """Implements V5. Returns the verified snapshot document."""
    data = await client.get_snapshot(fingerprint, snapshot_digest)
    if data is None:
        raise NetworkError(f"snapshot {snapshot_digest} not found at origin", peer=client.base_url)
    return verify_snapshot(data, expected_digest=snapshot_digest)
