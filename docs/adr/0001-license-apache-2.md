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
   contributors, a **patent-retaliation** clause (your patent license terminates
   if you sue the project for patent infringement over it), explicit
   **trademark** handling, and a requirement to state changes / keep NOTICE.

## Decision

**Apache-2.0** for all first-party Proteus code.

## Rationale

- **Explicit patent grant.** Contributors grant a patent license to their
  contributions. For a project in a patent-dense, circumvention-adjacent space,
  this materially reduces downstream legal risk for users and integrators vs.
  MIT's silence on patents.
- **Patent-retaliation clause** deters patent aggression against the project.
- **Trademark clarity** matters because we nominatively use "Chromium,"
  "Firefox," etc., and will have our own mark; Apache-2.0's §6 is explicit.
- **NOTICE mechanism** fits our need to carry forward Chromium/Firefox/Camoufox
  attributions cleanly ([NOTICE](../../NOTICE)).
- **Ecosystem precedent.** Brave, ungoogled-chromium, and many browser-adjacent
  projects operate comfortably under permissive licensing alongside Chromium's
  BSD; Apache-2.0 is well-understood by enterprises (an audience for our
  open-core services, [08](../08-sustainability.md)).

The cost over MIT — slightly more ceremony (NOTICE, change notices) — is trivial
relative to the patent-grant benefit.

## Consequences

- First-party files carry an Apache-2.0 header; the repo has [LICENSE](../../LICENSE)
  and [NOTICE](../../NOTICE).
- Inbound contributions are Apache-2.0 via DCO sign-off
  ([CONTRIBUTING.md](../../CONTRIBUTING.md)).
- Engine subtree files that are Derivative Works of MPL-2.0 (Camoufox/Firefox)
  **remain MPL-2.0**; BSD-3 Chromium files remain under their terms. Apache-2.0
  applies to *our* new code. This mixed-licensing is normal and compatible; the
  NOTICE and per-file headers make it explicit.
- Downstream redistributors must reproduce LICENSE + NOTICE and mark changes —
  handled by our release tooling ([tdd/05](../tdd/05-build-and-tracking.md) §5).

## Notes

MPL-2.0 (Firefox/Camoufox) is file-level copyleft: modifications to MPL files
must be shared, which we do (and contribute upstream). Apache-2.0 for our own
code and MPL-2.0 for modified engine files coexist without conflict.
