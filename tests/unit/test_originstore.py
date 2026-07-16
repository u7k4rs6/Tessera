import concurrent.futures

import pytest

from tessera import originstore, store as store_mod


@pytest.fixture
def store(tmp_path):
    store_mod.ensure_layout(tmp_path)
    return tmp_path


FP = "b3:" + "1" * 64


def test_timestamp_round_trip(store):
    assert originstore.read_timestamp(store, FP) is None
    envelope = {"payloadType": "t", "payload": "cGF5bG9hZA==", "signatures": [{"keyid": "k", "sig": "s"}]}
    originstore.write_timestamp(store, FP, envelope)
    assert originstore.read_timestamp(store, FP) == envelope


def test_next_timestamp_seq_monotonic(store):
    assert originstore.next_timestamp_seq(store, FP) == 1
    assert originstore.next_timestamp_seq(store, FP) == 2
    assert originstore.next_timestamp_seq(store, FP) == 3


def test_next_seq_is_lock_protected_against_concurrent_publish(store):
    # Without the lock in originstore.next_seq, concurrent callers could
    # both read the same "current" value and allocate the same seq twice --
    # silently breaking the uniqueness the rollback high-water marks
    # depend on. Real OS threads (not asyncio tasks) are needed here since
    # fcntl locks are contended at the OS level, and file I/O/flock releases
    # the GIL, so this genuinely exercises the race the lock prevents.
    n = 40
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(lambda _: originstore.next_seq(store, FP, "bert-tiny"), range(n)))

    assert sorted(results) == list(range(1, n + 1)), "every seq must be allocated exactly once, with no gaps"


def test_next_timestamp_seq_is_lock_protected_against_concurrent_reissue(store):
    n = 40
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(lambda _: originstore.next_timestamp_seq(store, FP), range(n)))

    assert sorted(results) == list(range(1, n + 1))


def test_snapshot_raw_bytes_round_trip_not_rebuilt_json(store):
    # The whole point: snapshot storage must not touch json.dumps/loads at
    # all on the write/read path, only raw bytes in, raw bytes out.
    from tessera.hashing import b3_hex

    canonical_bytes = b'{"artifacts":{},"publisher":"b3:1111","tessera":"snapshot/v1"}'
    digest = b3_hex(canonical_bytes)

    assert originstore.read_snapshot_bytes(store, FP, digest) is None
    originstore.write_snapshot(store, FP, digest, canonical_bytes)
    round_tripped = originstore.read_snapshot_bytes(store, FP, digest)
    assert round_tripped == canonical_bytes
    assert b3_hex(round_tripped) == digest


def test_snapshot_path_rejects_invalid_digest(store):
    from tessera.errors import InternalError

    with pytest.raises(InternalError):
        originstore.snapshot_path(store, FP, "not-a-digest")


def test_list_artifacts_and_versions_from_current_pointers(store):
    assert originstore.list_artifacts(store, FP) == []

    originstore.write_current_pointer(store, FP, "bert-tiny", "1.0.0", "b3:" + "a" * 64)
    originstore.write_current_pointer(store, FP, "bert-tiny", "1.2.0", "b3:" + "b" * 64)
    originstore.write_current_pointer(store, FP, "sst5", "0.1.0", "b3:" + "c" * 64)

    assert originstore.list_artifacts(store, FP) == ["bert-tiny", "sst5"]
    assert originstore.list_versions(store, FP, "bert-tiny") == ["1.0.0", "1.2.0"]
    assert originstore.list_versions(store, FP, "sst5") == ["0.1.0"]
    assert originstore.list_versions(store, FP, "nonexistent") == []
