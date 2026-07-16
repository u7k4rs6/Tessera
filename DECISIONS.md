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

## M2-specific decisions

- **D17** The snapshot keeps every published version (`versions: {version:
  {...}}` plus a `current_version` pointer), not just the current one.
  V6's own spec text says the snapshot "maps name@version to a manifest
  digest" -- not "name to its current version" -- and M1 already supported
  fetching any historical version by exact ref; dropping that would be a
  silent regression. `originstore`'s existing `current/<artifact>/<version>`
  bookkeeping already holds exactly this data, so `origin
  reissue-timestamp` just enumerates it.
- **D18** The M1 `/current` bridge is removed outright (route, `resolve.py`,
  `OriginClient.get_current`), not kept as a fallback. It carried zero
  trust weight even in M1 (D16), there are no external consumers pre-1.0
  to stay compatible with, and a dead trust-adjacent HTTP endpoint is a
  liability (attack surface, a foot-gun if something is ever miswired back
  to it) rather than a convenience.
- **D19** Peer scores (`peers.py`) are clamped to `[-50, +20]`. Unbounded
  scores make weighted-random selection degenerate at both ends -- an old,
  very-good peer would be picked almost deterministically forever, and a
  once-bad peer would need an implausibly long good streak to matter
  again, defeating the "small exploration share so a formerly bad mirror
  can rehabilitate" requirement (architecture doc section 6.2).
- **D20** `verify` never enforces the rollback high-water marks `fetch`
  does, and never advances the per-artifact manifest-seq hwm. `verify`
  checks a specific, named reference against what the publisher signed for
  it -- a legitimate thing to ask about an old version long after a newer
  one exists (e.g. auditing an old backup). hwm enforcement is about
  "give me the current, freshest artifact," which is `fetch`'s job. (The
  timestamp hwm does still advance as a side effect of `verify`'s network-
  fallback path, since that's about detecting a stale/equivocating
  overall snapshot pointer, not about which artifact version is being
  checked -- a different, orthogonal concern.)
- **D21** Metadata resolution (V2 root, V4 timestamp, V5 snapshot, V6
  manifest) falls back across every configured peer in score order
  (`_try_each_peer` in `fetch_flow.py`) rather than pinning to one peer or
  requiring all configured peers to agree. Each document is independently
  verified regardless of which peer served it, so a bad, down, or
  malicious-but-unsuccessful peer there only costs availability/score,
  never correctness -- this is also what makes a T4A-shaped lookalike-root
  attempt or a T2B-shaped stale-mirror attempt fail over to an honest peer
  automatically when one is configured, rather than failing the whole
  operation.
- **D22** Timestamp reissue is a fully separate command
  (`origin reissue-timestamp`), never folded into `publish`. Matches D5's
  role-separation philosophy (release and timestamp keys are meant to live
  on different hosts in a real deployment) and gives the TTL-driven
  reissue cadence -- needed even with zero new publishes -- an obviously
  correct home instead of being bolted onto an unrelated command.
- **D23** `mirror sync`'s ingest checks are real where they can be
  (chunk-by-digest via `cas.write_verified`, snapshot-bytes-by-digest) but
  only shape/self-consistency checks for root/timestamp/manifest, since a
  mirror holds no pin and therefore has no trusted key to verify a
  signature against. This is by design, not a shortcut: per the PRD, a
  mirror's ingest verification exists only to avoid caching obviously
  corrupt garbage and is never trust-relevant to a downstream consumer,
  who verifies everything itself, from a mirror or an origin, identically.

## M3-specific decisions

- **D24** Revocation is retroactive and fail-closed with no time-based
  carve-out (security doc section 5.5): a cryptographically valid
  signature from a key in the accumulated `revoked_keys` set is rejected
  everywhere -- manifest, timestamp, checkpoint, provenance -- even on a
  document that would otherwise verify cleanly, and even if the signature
  predates the revocation. `root.py`'s `revoked` field is cumulative
  (each new root version copies forward every prior revocation and
  appends any new one), so a single verified root document's own
  `revoked` list is always the FULL revocation history up to that
  version -- no need to re-walk the whole chain to know what's revoked,
  only to know the chain itself is legitimate.
- **D25** Revocation propagation is exactly one hop later than the
  cross-signature that authorized it: `verify_root_link` for hop N->N+1
  is checked against the `revoked_keys` accumulated BEFORE that hop;
  N+1's own new revocations are unioned in only after the hop succeeds.
  Otherwise a root could never revoke the very key it just used to sign
  its own rotation into existence.
- **D26** Three explicitly-scoped root verification entry points
  (`verify_root_genesis`, `verify_root_link`, `verify_root_chain`, plus
  the pre-M3 `verify_root_doc`), not one function with a mode flag. Which
  one is safe to call depends entirely on the trust boundary of the input
  (a fresh, fully-untrusted network response vs. a document already
  chain-verified once and now only being re-checked against local cache
  tampering) -- collapsing them into one function with a boolean would
  make it easy to accidentally call the unsafe one on untrusted input.
  Doing exactly that in `verify_flow.py`'s network-fallback path was a
  real, latent T4A gap this milestone's flag day closed: that path
  previously called `verify_root_doc` (self-consistency only, no check
  that the served document is really signed by the PINNED fingerprint's
  own key) directly against a fresh network response, instead of the
  safe genesis+chain-walk.
- **D27** The transparency log is stored as one atomic JSON array
  (`log/leaves.json`) plus a checkpoint (`log/checkpoint.json` +
  per-tree-size history), lock-protected exactly like `next_seq`, rather
  than the architecture doc's literal framing of individually
  content-addressed leaves that mirrors replicate "for free." A single
  JSON array is simpler and matches D9's "inspectable JSON over
  cleverness" philosophy; the cost is that `mirror sync` needs one
  explicit added step (fetch+replicate `checkpoint.json` and
  `log/leaves.json` via a new `GET .../log/leaves` route, added
  specifically because no existing route exposed raw leaves) instead of
  picking the log up automatically the way it walks chunks and
  manifests. O(n) rewrite per publish is a known, documented scaling
  limit, not a blocker at CLI scale.
- **D28** Consistency proofs are the full ordered leaf-hash list up to
  the new size (O(n)), not RFC 6962's O(log n) SUBPROOF construction.
  Same security property (any inconsistency between an old and a
  claimed-newer checkpoint is detected), much simpler and more obviously
  correct code, and the asymptotic gap isn't meaningful at the leaf
  counts a single publisher accumulates. Inclusion proofs ARE the real
  RFC 6962 O(log n) audit path -- that one is cheap and correct to do
  properly, and every fetch needs it, so the simplification is scoped
  specifically to the operation (consistency checks) that's rare and
  small in practice.
- **D29** Checkpoints are signed with the release key, no new role (D5's
  three-role model stays fixed). A provenance attestation's `subject`
  binds to `manifest.content_digest()` -- the manifest's canonical bytes
  with `provenance` forced to `null` -- rather than the manifest's own
  final digest (with `provenance` populated). Binding to the final digest
  is circular: the manifest's digest depends on what's inside it,
  including the provenance pointer, which itself depends on the subject
  digest it's being computed for. Binding to the pre-provenance content
  digest breaks the cycle while still tying the attestation to the exact
  file/chunk content being attested to.
- **D30** `publish`'s `--base`/`--dataset`/`--code` provenance flags
  resolve materials ONLY from the local trust cache
  (`trust_store.load_cached_manifest`), never the network -- continuing
  D22's role-separation principle that a publish host shouldn't need live
  network access to sign a release. An uncached reference is a clean
  usage error naming `tessera fetch` as the remedy, not a silent network
  fetch mid-publish.
- **D31** `record_index` is keyed per-file (`{relative_path:
  [record_digest, ...]}`) at the manifest's top level, built only for
  `.jsonl` files when `--records` is non-`none` and the artifact type is
  `dataset` -- other extensions stay opaque even with `--records` set,
  since v1 only knows how to delimit JSONL. `tessera diff` reports
  per-file status (`added`/`removed`/positional diff) rather than
  refusing when the two versions' file sets don't match exactly.
- **D32** `tessera status`'s materialized-but-revoked marking is a pure
  reconciliation, never a re-verification or a deletion: `fetch_flow`
  writes a `.tessera-status.json` breadcrumb (manifest digest + signer
  key id) into each materialized artifact directory at fetch time;
  `status` cross-references breadcrumbs against a FRESHLY fetched
  current root's revoked-key set (never a cached one, since the whole
  point is to catch a revocation the consumer hasn't fetched anything
  new since) and reports, but never touches, the artifact on disk --
  matching the security doc's framing that refusing a flagged artifact
  is a caller policy decision, not something this layer enforces.
- **D33** `tessera provenance`'s lineage walk defaults to metadata-only
  (root, manifest, and attestation verified; no chunk bytes pulled)
  unless `--deep` is given, which pulls each unmaterialized node via the
  real `fetch` pipeline. A `max_depth` (default 5) plus a visited-ref set
  guard against cyclic materials graphs -- a valid signature on a
  `materials` entry proves who asserted the edge, not that the graph it
  describes is acyclic. A node that fails to resolve is a leaf carrying
  an `error`, not a reason to abort the whole walk: lineage is a report
  for a human, not a pass/fail gate.
- **D34** `publish --resign-all` also re-signs the CURRENT transparency-
  log checkpoint (same tree_size/root_hash, fresh signature only) with
  the new release key, not just the manifests. This was a real gap found
  during end-to-end testing: without it, if the stored checkpoint
  happened to be signed by the very release key being revoked, V7 (log
  freshness) would stay broken for every consumer until some unrelated
  future publish/rotate/revoke happened to refresh the checkpoint --
  defeating `--resign-all`'s entire purpose as the recovery path after a
  release-key compromise.
- **D35** `publisher delegate` resolves the publisher's permanent
  identity via the stored `publisher/` directory layout and bumps
  whatever the current root version is, rather than assuming (as the
  pre-M3 implementation did) that the CURRENT root key's own id is the
  same value as the publisher's permanent fingerprint. That assumption
  only holds before any rotation has ever happened; found and fixed
  during end-to-end testing of a delegate-after-rotate ceremony.
