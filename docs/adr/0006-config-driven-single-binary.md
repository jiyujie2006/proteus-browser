# ADR 0006 — One engine binary, N identities via signed config

**Status:** Accepted · **Date:** 2026 · **Serves:** Principles VI, VIII

## Context

Each profile must present a *different* native fingerprint, but all values are
produced by the native engine ([ADR 0005](0005-native-over-injection.md)). Naively,
"native per-profile values" could suggest compiling a different engine per profile
or per identity. How do we get per-identity native behavior from a single,
maintainable engine?

## Decision

**Exactly one engine binary per family**, whose fingerprint behavior is entirely
driven by a **signed, versioned per-profile configuration** parsed at launch. No
fingerprint value is a compile-time constant; all come from the config. The engine
**verifies the config's signature** and **fails closed** if it's missing/invalid.

## Rationale

- **Per-profile builds would make the treadmill impossible.** Chromium builds are
  enormous and slow; compiling per profile (or per identity) is a non-starter for
  distribution *and* for rebasing on every Chromium release
  ([Principle VIII](../02-design-principles.md)). One binary + N configs is the
  only shape that scales and stays trackable.
- **Data, not code, holds the variation.** GPU strings, font sets, and
  distributions live in **datasets** (also out-of-band, signed), so refreshing the
  population model doesn't even require an engine rebuild
  ([tdd/02](../tdd/02-fingerprint-engine.md) §7, [tdd/05](../tdd/05-build-and-tracking.md) §6).
- **Signing prevents forged reconfiguration.** Because the engine can read every
  cookie, a malicious local process or page must not be able to hand it a config
  that changes its identity or behavior. The Manager signs configs with a local
  key; the engine verifies (relates to [Principle VI](../02-design-principles.md)).
- **Pre-script application is required** so values are correct before any page
  code runs, in every process — the config-ingest mechanism delivers this
  ([tdd/01](../tdd/01-chromium-engine.md) §3).
- **Reproducibility & audit.** A profile is fully described by `{persona params,
  seed, engine version, dataset version}`, so it's reconstructible and auditable
  ([tdd/02](../tdd/02-fingerprint-engine.md), [tdd/07](../tdd/07-manager-and-storage.md) §10).

## Consequences

- The **profile config schema** becomes the most important interface in the
  system, versioned independently
  ([schemas/profile-config.schema.json](../schemas/profile-config.schema.json),
  [04-architecture.md](../04-architecture.md) §6).
- The engine gains a config-ingest + signature-verify path and per-renderer/worker
  propagation ([tdd/01](../tdd/01-chromium-engine.md) §3).
- **Fail-closed** on invalid config is a security property, not just an error case.
- A debug affordance can dump the effective config for support/audit
  ([tdd/01](../tdd/01-chromium-engine.md) §7).
- Secrets (proxy creds) are deliberately **not** in the fingerprint config — they
  come from the encrypted proxy library — so the config can be signed/shared/
  audited without leaking credentials
  ([04-architecture.md](../04-architecture.md) §6).

## Notes

This ADR ties ADR 0005 (native) to Principle VIII (treadmill): native values that
are nonetheless configurable-not-compiled is what makes native quality
*maintainable* at scale. It's the hinge between "high quality" and "survivable."
