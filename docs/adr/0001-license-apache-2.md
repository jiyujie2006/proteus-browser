# ADR 0001 — Apache-2.0 for our code (over MIT)

**Status:** Accepted · **Date:** 2026 · **Deciders:** project owner

## Context

The project owner asked for MIT *or* Apache-2.0. Both are permissive, business-
friendly, and compatible with the engine upstreams (Chromium BSD-3 + others,
Firefox/Camoufox MPL-2.0). We must pick one for our own first-party code.

A relevant, unusual factor: Proteus is **circumvention-adjacent**. It implements
techniques for resisting fingerprinting and automation detection. Such projects
have a higher-than-average chance of touching patented methods (fingerprinting,
anti-fraud, and TLS/network techniques are actively patented areas), and of
attracting patent-based legal pressure.

## Options

1. **MIT** — shortest, most familiar, maximally permissive. **No explicit patent
   grant.**
2. **Apache-2.0** — permissive, but adds: an **explicit patent license** from
   contributors for patent claims necessarily infringed by their contributions,
   a **patent-retaliation** clause, explicit trademark boundaries, and
   redistribution requirements for changed files and applicable NOTICE content.

## Decision

**Apache-2.0** for all first-party Proteus code.

## Rationale

- **Explicit, bounded patent grant.** Contributors grant a patent license for
  claims necessarily infringed by their contributions. This is stronger than
  MIT's silence, but it is not patent clearance, a third-party patent license,
  or indemnity.
- **Patent-retaliation clause** deters patent aggression against the project.
- **Trademark boundary clarity** matters because we nominatively refer to
  upstream products. Apache-2.0 §6 does not grant trademark rights and does not
  establish or clear a Proteus mark; trademark review remains separate.
- **NOTICE mechanism** preserves attribution notices that actually apply to the
  distributed work. Planned dependencies and release instructions belong in
  [the third-party licensing plan](../10-third-party-licensing.md), not in the
  current [NOTICE](../../NOTICE).
- **Ecosystem precedent.** Brave, ungoogled-chromium, and many browser-adjacent
  projects operate comfortably under permissive licensing alongside Chromium's
  BSD; Apache-2.0 is well-understood by enterprises (an audience for our
  open-core services, [08](../08-sustainability.md)).

The cost over MIT — slightly more ceremony (NOTICE, change notices) — is trivial
relative to the patent-grant benefit.

## Consequences

- The repository-level [LICENSE](../../LICENSE), package metadata, and
  documentation identify first-party Proteus work as Apache-2.0. New source
  files should also use `SPDX-License-Identifier: Apache-2.0` when their syntax
  permits; generated data and strict fixtures may rely on repository- or
  directory-level metadata.
- Inbound first-party contributions are Apache-2.0 via DCO sign-off
  ([CONTRIBUTING.md](../../CONTRIBUTING.md)).
- Engine subtree files derived from MPL-2.0 code **remain MPL-2.0**; Chromium
  files and patch payloads retain the applicable upstream terms. Apache-2.0
  applies to separate first-party code that contains no upstream covered code.
- Each future binary distribution must carry an artifact-derived component
  inventory, the exact required license texts and notices, and any corresponding
  source-availability material. This is a release gate to be implemented, not a
  capability the current scaffold claims to provide
  ([tdd/05](../tdd/05-build-and-tracking.md) §5).

## Notes

MPL-2.0 is file-level copyleft: when Proteus eventually distributes modified
MPL-covered files, their source and notices must be made available as required.
No Firefox/Camoufox source or binary is present in the current repository.
