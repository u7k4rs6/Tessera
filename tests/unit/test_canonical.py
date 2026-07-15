from tessera.canonical import canonicalize


def test_key_ordering_is_deterministic():
    a = canonicalize({"b": 1, "a": 2, "c": 3})
    b = canonicalize({"c": 3, "b": 1, "a": 2})
    assert a == b
    assert a == b'{"a":2,"b":1,"c":3}'


def test_nested_structures_canonicalize_consistently():
    obj1 = {"outer": {"z": 1, "y": [3, 2, 1]}, "list": [{"b": 1, "a": 2}]}
    obj2 = {"list": [{"a": 2, "b": 1}], "outer": {"y": [3, 2, 1], "z": 1}}
    assert canonicalize(obj1) == canonicalize(obj2)


def test_mutation_changes_canonical_bytes():
    base = {"name": "bert-tiny", "version": "1.2.0", "seq": 14}
    mutated = {"name": "bert-tiny", "version": "1.2.0", "seq": 15}
    assert canonicalize(base) != canonicalize(mutated)


def test_no_insignificant_whitespace():
    out = canonicalize({"a": 1, "b": [1, 2, 3]})
    assert b" " not in out
    assert b"\n" not in out
