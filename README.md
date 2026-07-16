# Tessera

Verified-by-default distribution for ML models and datasets. A publisher
signs once, any number of untrusted mirrors carry bytes, and every
consumer verifies locally that what it received is exactly what the
publisher signed. A mirror can withhold content but is structurally unable
to poison it; there is no unverified fetch path, anywhere.

This repository currently implements **Milestones 1 and 2**: content-
addressed storage, chunking, the signed manifest, DSSE/JCS sign-and-verify,
an origin HTTP server, materialize/quarantine, the core exit-code table
(M1) -- plus the timestamp+snapshot freshness layer, consumer-persisted
rollback high-water marks, a multi-peer fetch scheduler with persistent
peer scoring/blacklisting, and mirror sync/serve (M2). The transparency
log, provenance attestations, dataset diff, and key rotation/revocation
are out of scope until M3-M4 -- see `DECISIONS.md` for what's deliberately
deferred and why.

## Install (development)

```
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Run the tests

```
.venv/bin/pytest
```

This runs the unit suite; the T1, T2A, T4A adversarial tests (in-process
tampering mirror / lookalike-key / stale-mirror fixtures); the
PBT-MANIFEST-MUTATE, PBT-CHUNK-MUTATE, and PBT-HISTORY-MONOTONE property
tests; and end-to-end scripted scenarios driven through the real `tessera`
CLI, including a multi-mirror resilience run and a mirror sync/serve round
trip.

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

Running a mirror requires no keys or accounts:

```
tessera mirror sync <fingerprint> --from http://127.0.0.1:7433 --store ./mirror-store
tessera mirror serve --store ./mirror-store --bind 0.0.0.0:7433
```

Every command accepts `--json` for a machine-readable `result/v1` object;
human output is a rendering of the same object. See `04_FRONTEND_SPEC.md`
for the full command surface and exit-code table.
