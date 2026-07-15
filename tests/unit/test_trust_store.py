import pytest

from tessera import store, trust_store
from tessera.errors import PinMismatchError


@pytest.fixture
def home(tmp_path):
    store.ensure_layout(tmp_path)
    return tmp_path


def test_add_and_load_pin(home):
    trust_store.add_pin(home, "acme-lab", "b3:" + "a" * 64, mirrors=["https://mirror.example.org"])
    assert trust_store.has_pin(home, "acme-lab")
    pin = trust_store.load_pin(home, "acme-lab")
    assert pin["name"] == "acme-lab"
    assert pin["fingerprint"] == "b3:" + "a" * 64
    assert pin["mirrors"] == ["https://mirror.example.org"]


def test_load_pin_missing_raises(home):
    assert not trust_store.has_pin(home, "nobody")
    with pytest.raises(PinMismatchError):
        trust_store.load_pin(home, "nobody")


def test_root_envelope_cache_round_trip(home):
    assert trust_store.load_cached_root_envelope(home, "acme-lab") is None
    envelope = {"payloadType": "t", "payload": "cGF5bG9hZA==", "signatures": []}
    trust_store.cache_root_envelope(home, "acme-lab", envelope)
    assert trust_store.load_cached_root_envelope(home, "acme-lab") == envelope
