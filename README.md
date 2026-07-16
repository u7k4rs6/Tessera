# Tessera

Verified-by-default distribution for ML models and datasets. A publisher
signs once, any number of untrusted mirrors carry bytes, and every
consumer verifies locally that what it received is exactly what the
publisher signed. A mirror can withhold content but is structurally unable
to poison it; there is no unverified fetch path, anywhere.

This repository implements **all four milestones (M1-M4)**: content-
addressed storage, chunking, the signed manifest, DSSE/JCS sign-and-verify,
an origin HTTP server, materialize/quarantine, the core exit-code table
(M1); the timestamp+snapshot freshness layer, consumer-persisted rollback
high-water marks, a multi-peer fetch scheduler with persistent peer
scoring/blacklisting, and mirror sync/serve (M2); root key rotation with
TUF-style cross-signing, fail-closed retroactive key revocation, a
transparency log with inclusion/consistency proofs and cross-source
equivocation detection, provenance attestations with a lineage walk, and
dataset record-index diffing (M3); and eclipse/freeze hardening,
cross-source timestamp equivocation checking, a combined-attack chaos
scenario, parser fuzzing, and scripted compromise-playbook drills (M4).
The full V1-V10 verification pipeline runs on every `fetch`. A standalone
mirror daemon is the one deliberately-deferred, post-M4 item -- see
`DECISIONS.md` (D10) for why. `THREAT_COVERAGE.md` maps every threat in
`03_SECURITY_AND_ACCESS.md`'s table to its proving test.

## Install (development)

```
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Run the tests

```
.venv/bin/pytest
```

This runs the unit suite; the T1, T2A, T2B, T4A, T4B, T4C, T5B, T6A, T6B
adversarial tests plus the M4 combined chaos scenario (T1+T2b+T6a against
one fetch) -- in-process tampering mirror / lookalike-key / stale-mirror /
root-rotation / key-revocation / split-view / eclipse / Sybil-flood
fixtures, all built from real Tessera code, not mocks; the
PBT-MANIFEST-MUTATE, PBT-CHUNK-MUTATE, PBT-HISTORY-MONOTONE, and
transparency-log Merkle-proof property tests, plus M4's parser fuzzing
(structurally-arbitrary, not single-byte-mutated, input across every
envelope/manifest/root/timestamp/checkpoint/provenance/snapshot/proof
parser -- `--hypothesis-profile=thorough` for a deeper, opt-in 1000-
example pass); and end-to-end scripted scenarios driven through the real
`tessera` CLI, including a multi-mirror resilience run, a mirror sync/
serve round trip, a full M3 ceremony walkthrough (provenance-carrying
publish, dataset record diff, rotate, revoke, `--resign-all` recovery,
and `status`), and the M4 timestamp-key/root-key compromise-playbook
drills.

## Quickstart

One-time publisher setup:

```
tessera keygen --role root --out root.key
tessera keygen --role release --out release.key
tessera keygen --role timestamp --out ts.key
tessera publisher init acme-lab --root-key root.key --store ./origin-store
tessera publisher delegate --role release --key release.key.pub --root-key root.key --store ./origin-store
tessera publisher delegate --role timestamp --key ts.key.pub --root-key root.key --store ./origin-store
```

Publish a release, reissue freshness, and serve it:

```
tessera publish ./my-model-dir --name bert-tiny --version 1.2.0 --type model \
    --release-key release.key --store ./origin-store
tessera origin reissue-timestamp --store ./origin-store --timestamp-key ts.key
tessera origin serve --store ./origin-store --bind 127.0.0.1:7433
```

`origin reissue-timestamp` is independent of `publish` -- the timestamp
key is meant to live on a different, more frequently-online host than the
release key, and it needs to run on its own cadence (well inside the 24h
TTL) even when nothing new has been published.

Pin the publisher and fetch, from a consumer. `--mirror` is repeatable;
`fetch` will retry a chunk against another configured mirror if one serves
a bad one, and score that mirror down for future sessions:

```
tessera trust add acme-lab <fingerprint printed by publisher init> \
    --mirror http://127.0.0.1:7433 --mirror http://backup-mirror:7433
tessera fetch acme-lab/bert-tiny@1.2.0
```

Running a mirror requires no keys or accounts. `mirror sync` replicates
every root version and the transparency log alongside chunks/manifests:

```
tessera mirror sync <fingerprint> --from http://127.0.0.1:7433 --store ./mirror-store
tessera mirror serve --store ./mirror-store --bind 0.0.0.0:7433
```

Publish with provenance (materials resolved from the local trust cache --
`fetch` them first) and a dataset record index:

```
tessera publish ./finetuned-model --name bert-finetuned --version 1.0.0 --type model \
    --base acme-lab/base-model@1.0.0 --dataset acme-lab/my-dataset@1.0.0 \
    --code git+https://example.com/train@abc123 \
    --release-key release.key --store ./origin-store

tessera publish ./my-dataset-dir --name my-dataset --version 2.0.0 --type dataset \
    --records line --release-key release.key --store ./origin-store
```

Inspect lineage, diff two dataset versions, and check the transparency log:

```
tessera provenance acme-lab/bert-finetuned@1.0.0
tessera diff acme-lab/my-dataset@1.0.0 acme-lab/my-dataset@2.0.0
tessera log show acme-lab
```

Rotate the root key (run wherever the current AND new root private keys
are both available -- D5 keeps root keys offline) and apply it on the
publish host:

```
tessera keygen --role root --out root2.key
tessera rotate --store ./origin-store --root-key root.key --new-root-key root2.key --out rotated.json
tessera publisher import-root rotated.json --store ./origin-store --release-key release.key
```

Revoke a compromised key (D13: fail closed, retroactive) and recover:

```
tessera revoke <release-key-fingerprint> --reason compromised \
    --store ./origin-store --root-key root2.key --out revoked.json
tessera publisher import-root revoked.json --store ./origin-store --release-key release.key

tessera keygen --role release --out release2.key
tessera publisher delegate --role release --key release2.key.pub --root-key root2.key --store ./origin-store
tessera publish --resign-all --release-key release2.key --store ./origin-store
```

Check for materialized artifacts whose signer has since been revoked:

```
tessera status acme-lab
```

Every command accepts `--json` for a machine-readable object (`result/v1`
for `fetch`/`verify`; `lineage/v1`, `diff/v1`, `status/v1`, `log/v1` for
the M3 report commands); human output is a rendering of the same object.
See `04_FRONTEND_SPEC.md` for the full command surface and exit-code
table.
