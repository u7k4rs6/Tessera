# Tessera

Verified-by-default distribution for ML models and datasets. A publisher
signs once, any number of untrusted mirrors carry bytes, and every
consumer verifies locally that what it received is exactly what the
publisher signed. A mirror can withhold content but is structurally unable
to poison it; there is no unverified fetch path, anywhere.

This repository currently implements **Milestone 1**: content-addressed
storage, chunking, the signed manifest, DSSE/JCS sign-and-verify, an
origin HTTP server, single-peer fetch and local verify, materialize/
quarantine, and the core exit-code table. Rollback protection, the
transparency log, multi-mirror scheduling with peer scoring, provenance
attestations, and key rotation/revocation are out of scope until M2-M4 --
see `DECISIONS.md` for what's deliberately deferred and why.

## Install (development)

```
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Run the tests

```
.venv/bin/pytest
```

This runs the unit suite, the T2A/T4A adversarial tests (in-process
tampering mirror / lookalike-key fixtures), the PBT-MANIFEST-MUTATE and
PBT-CHUNK-MUTATE property tests, and an end-to-end scripted scenario
driven through the real `tessera` CLI.

## Quickstart

One-time publisher setup:

```
tessera keygen --role root --out root.key
tessera keygen --role release --out release.key
tessera publisher init acme-lab --root-key root.key --store ./origin-store
tessera publisher delegate --role release --key release.key.pub --root-key root.key --store ./origin-store
```

Publish a release and serve it:

```
tessera publish ./my-model-dir --name bert-tiny --version 1.2.0 --type model \
    --release-key release.key --store ./origin-store
tessera origin serve --store ./origin-store --bind 127.0.0.1:7433
```

Pin the publisher and fetch, from a consumer:

```
tessera trust add acme-lab <fingerprint printed by publisher init> --mirror http://127.0.0.1:7433
tessera fetch acme-lab/bert-tiny@1.2.0
```

Every command accepts `--json` for a machine-readable `result/v1` object;
human output is a rendering of the same object. See `04_FRONTEND_SPEC.md`
for the full command surface and exit-code table.
