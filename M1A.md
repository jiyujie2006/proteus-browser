# M1A — Deterministic Signed-Config Core

M1A is the non-UI, infrastructure-independent slice of roadmap M1. It is
complete when this command is green:

```bash
npm run m1a
```

## Completed

- Strict Rust Profile Config model aligned with the normative JSON Schema.
- Transparent, versioned seed dataset shared with the Node verification lab.
- HMAC-SHA256 domain-separated deterministic sampling from a 32-byte seed.
- Explicit required engine-major input, including a multi-major dataset
  regression proving the same target constraint is preserved during replay.
- Joint engine/GPU/screen/hardware/font/media selection for the first supported
  target: Chrome 150 on Windows 11 desktop/laptop.
- Derived UA, Client Hints, locale, media IDs, noise policy, network hints,
  performance policy, provenance, and a clearly labeled seed rarity heuristic.
- Generation-strict semantic rules with stable rule IDs and structured reasons.
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
- Fixed cross-language signing vector and golden signed config.
- Independent Node verification of canonical hashes, Ed25519 signature,
  tamper rejection, and V1/V2 zero-inconsistency output.
- Multi-seed property loop checking deterministic validity plus UUID/media-ID
  uniqueness across 128 seeds. This is a smoke/property check, not a
  population-scale statistical de-correlation proof.

## Explicitly not completed

M1A does not satisfy roadmap M1 by itself. Still required:

- real Chromium config ingest before first script;
- protected trust-anchor provisioning and launch nonce/replay handling in the
  browser process;
- native navigator/screen/canvas/WebGL/WebGPU/audio/font/locale/media surfaces;
- main frame, iframe, Shared Worker, Dedicated Worker, and Service Worker parity;
- a real Chromium build and artifact-driven runtime gate;
- external tester correlation.

The current seed weights are transparent heuristics, not population telemetry.
Calibrated distribution-backed rarity remains an M4 deliverable.
