# Tessera: Decision Log

Seeded from the architecture doc's decision log (section 12), renamed
Custody -> Tessera, plus the M1-specific decisions made while implementing
this milestone. New decisions get appended here as the project grows.

## Carried over from the design docs

- **D1** BLAKE3 over SHA-256. Verification is the hot path; BLAKE3 is
  SIMD-optimized and parallelizes across cores. The `b3:` prefix keeps a
  future algorithm migration (or a secondary digest for interop) from
  breaking the format.
- **D2** Fixed 4 MiB chunks over content-defined chunking. Simplicity and a
  simple fetch scheduler now; cross-version dataset dedup is deferred until
  there's real traffic to tune against.
- **D3** A flat, ordered chunk-digest list per file rather than a Merkle
  tree with per-chunk proofs. Manifests are small enough to fetch whole; a
  flat list is harder to get wrong.
- **D4** RFC 8785 (JCS) canonical JSON inside DSSE envelopes. Kills an
  entire class of canonicalization-bypass bugs; DSSE is small, reviewed,
  and already used by in-toto/sigstore.
- **D5** Three key roles (offline root, online release, online timestamp).
  The minimum role set the threat model needs.
- **D6** The snapshot is digest-bound to the timestamp rather than
  separately signed. One fewer online key; freshness comes from the
  timestamp's TTL, integrity from the digest.
- **D7** A single publisher-operated transparency log with client-side
  inclusion/consistency proofs and cross-source checkpoint comparison,
  rather than third-party witnesses or a ledger.
- **D8** A thin custom HTTP layer over libtorrent/IPFS/libp2p. The trust
  layer is custom regardless of transport choice; a custom layer keeps
  every verification decision in auditable project code.
- **D9** JSON/TOML state files with atomic rename; no database. Every state
  file stays human-inspectable during adversarial debugging.
- **D10** Python 3.11+ for M1-M4 (native-speed hashing via the `blake3`
  binding, Hypothesis for property-based adversarial tests, rapid
  iteration). Rust is noted as a post-M4 option for a standalone mirror
  daemon only.
- **D11** No unverified fetch path exists anywhere in the design. Tested,
  not just documented (see `tests/unit/test_no_bypass.py`).
- **D12** Publisher naming is local pinning; no global registry. A registry
  would reintroduce the central trust root the system exists to remove.

## M1-specific decisions

- **D13** `keygen --role timestamp` is implemented generically for all
  three roles in M1, even though nothing consumes a timestamp document
  yet. Same Ed25519+scrypt code path per role; costs nothing now and saves
  a rework when M2 adds the timestamp signer.
- **D14** `publisher init`/`publisher delegate` take `--root-key` directly
  and sign inline, rather than the export/sign/import ceremony shown for
  `rotate`/`revoke` in the frontend spec. That ceremony exists to support
  an air-gapped root across a multi-step *rotation* flow (M3); M1 has no
  rotation or chain-walking and a 1-of-1 threshold, so splitting the
  ceremony now would be complexity with nothing yet to justify it.
- **D15** `publish` does not accept `--base`/`--dataset`/`--code`
  provenance flags in M1. `provenance` is always `null` on the M1
  manifest; silently accepting flags that imply lineage recording while
  doing nothing with them would violate the "loud, specific" failure/UX
  principle. An unrecognized flag is a clean usage error (exit 2) until M3
  actually builds attestations.
- **D16** The `GET /v1/{publisher}/current/{name}/{version}` endpoint
  (`resolve.py`) is an M1-only bridge from a version reference to a
  manifest digest, standing in for the signed snapshot/timestamp
  resolution flow M2 introduces. It carries no trust weight: the manifest
  it points to is independently verified (V6) regardless of what this
  bridge returns, so a wrong or malicious value here can only cause a
  failed fetch, never an accepted bad artifact.
