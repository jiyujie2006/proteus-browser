# M1A — Deterministic Signed-Config Core

M1A is the non-UI, infrastructure-independent slice of roadmap M1. It is
complete when this command is green:

```bash
npm run m1a
```

## Completed

- Strict Rust Profile Config model aligned with the normative JSON Schema.
- Transparent, versioned seed dataset shared with the Node verification lab.
- Generator `0.2.0`, semantic rules `1.1.0`, and reference dataset `0.3.0`
  are bound independently in provenance.
- HMAC-SHA256 domain-separated deterministic sampling from a 32-byte seed.
- Explicit required engine-major input, including a multi-major dataset
  regression proving the same target constraint is preserved during replay.
- Joint engine/GPU/screen/hardware/font/media selection for the first supported
  target: Chrome 150 on Windows 11 desktop/laptop. GPU selection is conditioned
  on both OS and device class.
- A reduced `Chrome/<major>.0.0.0` UA plus the pinned Chrome target's exact,
  ordered UA-CH brand/full-version lists (including its deterministic GREASE
  entry), rather than a hand-written generic brand list.
- Derived locale, media IDs, fixed noise policy, network hints, performance
  policy, provenance, and a clearly labeled seed rarity heuristic.
- Generation-strict semantic rules with stable rule IDs and structured reasons.
- Exact validation of screen mode/available dimensions, WebGL extensions,
  WebGPU adapter records, UA-CH records, and GPU device-class eligibility.
- Dataset semantic uniqueness checks for engine, GPU, screen/weight, hardware,
  font, and media sampling records.
- Chrome 150 non-Android Device Memory buckets through 32 GiB, with explicit
  plausible 16/32-GiB joint hardware pairs.
- Deterministic canonical JSON for the strict Profile Config value domain and an
  explicit signature domain. The envelope's `RFC8785` label is contract metadata
  locked by the supported-domain vectors, not a claim of a general-purpose
  arbitrary-JSON RFC 8785 implementation.
- Ed25519 signature envelope with a signed-input-bound key ID and a strict
  in-memory/JSON trust-store abstraction intended for later protected,
  installation-scoped provisioning.
- Exact dataset SHA-256 provenance plus deterministic ingest replay: every
  derived value must reproduce byte-for-value from the declared inputs.
- Parsed datasets are immutable outside the crate. Complete read-only accessors
  preserve transparency without allowing a caller to mutate a sampling table
  while retaining the SHA-256 of different source bytes.
- Fail-closed ingest for duplicate JSON keys, oversized input, unknown fields,
  unsupported schema versions, unknown keys, malformed signatures, tampering,
  and semantic incoherence.
- Versioned cross-language signing vectors and golden signed configs: v2 is the
  current generator vector, while v1 remains byte-for-byte preserved and its
  legacy signature is still tested.
- Independent Node verification of canonical hashes, Ed25519 signature,
  tamper rejection, and V1/V2 zero-inconsistency output. For a complete current
  Profile Config, the Node rules fail closed on an unknown exact engine target
  and independently mirror Rust's non-structural `validate()` constraints for
  persona, UA/UA-CH, GPU, screen, hardware, locale, media, performance, noise,
  rarity, and provenance. Runtime observations retain their broader tolerances.
- Multi-seed property loop checking deterministic validity plus UUID/media-ID
  uniqueness across 128 seeds. This is a smoke/property check, not a
  population-scale statistical de-correlation proof.

The validation layers have deliberately different jobs. Draft 2020-12 JSON
Schema validation owns the full required/unknown-field, type, enum, null-shape,
UUID/base64/digest-format, and numeric-range contract. The dependency-free Node
score CLI additionally duplicates minimum root-envelope completeness so a
malformed config cannot be mislabeled `blends-in`; this is not a replacement for
the full schema gate. Ed25519 owns authorization and tamper detection. Rust plus
the independent Node rule catalog own semantic coherence. Finally, Rust
`verify_reproducible()` is authoritative for exact deterministic replay: it
rebuilds the whole body from the declared seed, profile ID, persona, engine
request, timezone-derived region, and exact dataset bytes.

The Node rules intentionally do not duplicate the HMAC sampler. For example, a
different but semantically valid dataset hardware pair, font subset, same-region
timezone, media ID, rarity value/reason list, or network/noise mode may pass the
schema and semantic layer; it still fails deterministic replay unless it is the
exact seed-selected output. This boundary is covered by Rust replay tests, while
the cross-language mutation tests cover semantic drift.

## Explicitly not completed

M1A does not satisfy roadmap M1 by itself. Still required:

- real Chromium config ingest before first script;
- protected trust-anchor provisioning and launch nonce/replay handling in the
  browser process;
- native navigator/screen/canvas/WebGL/WebGPU/audio/font/locale/media surfaces;
- main frame, iframe, Shared Worker, Dedicated Worker, and Service Worker parity;
- a real Chromium build and artifact-driven runtime gate;
- external tester correlation;
- deterministic validation/rarity resampling with an attempt counter; M1A makes
  one deterministic draw and fails closed when it has no valid candidate;
- calibrated coherent-imperfection sampling and per-profile noise-shape
  variation; the current config emits one fixed `hw-natural`/`subpixel` policy;
- the M4 fleet red-team classifier and population-scale de-correlation gate.

The current seed weights are transparent heuristics, not population telemetry.
Calibrated distribution-backed rarity remains an M4 deliverable.
