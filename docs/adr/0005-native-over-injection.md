# ADR 0005 — Native engine production over JavaScript injection

**Status:** Accepted · **Date:** 2026 · **Serves:** Principle III · **Threat
vectors:** V3

## Context

There are two ways to change what a fingerprint surface reports:

1. **JavaScript injection** — run script (via an extension, a CDP hook, or a
   content-script) that overrides `navigator.*`, patches `HTMLCanvasElement`
   prototype methods, etc., *after* the page context exists.
2. **Native modification** — change the C++ engine so the surface *natively*
   returns the configured value.

Injection is far cheaper to build and doesn't require forking/building Chromium.
Many high-volume tools rely on it heavily. This ADR records why Proteus does not.

## Decision

**Native production is the default and strongly-preferred path.** JavaScript
injection is allowed *only* with a documented reason that no native path exists,
and only if the override passes the full anti-trace test battery.

## Rationale

Injection leaves **deterministic V3 spoofing traces** that native production
avoids by construction:

- **`Function.prototype.toString`** on a JS-overridden getter reveals JS source
  (or a telltale `native code` forgery that itself can be caught), whereas a
  native getter genuinely returns `[native code]`.
- **Property descriptors** (accessor vs. data property, `enumerable`,
  `configurable`, `writable`) are easy to get subtly wrong when overriding in JS;
  native code has the correct shape automatically.
- **Prototype chain** anomalies (override on instance vs. prototype) are a common
  injection tell; native has the value in the right place.
- **Cross-context consistency is the killer.** An injected script must be
  installed in *every* context — main frame, every same/cross-origin iframe,
  every dedicated/shared Web Worker, and Service Workers — *before* any page code
  runs there. Missing or racing on *any* context yields a value mismatch across
  contexts, a strong V3 signal. Native values are present in **all** contexts by
  construction ([tdd/01](../tdd/01-chromium-engine.md) §3).
- **Timing.** Injection races the page's first script; native values are set
  before any script runs.
- **Proxy/Reflect detection.** Sites can detect JS `Proxy`/getter traps used to
  fake values; native has nothing to trap.

The maintenance cost of native (a Chromium fork on the treadmill) is real, but it
is precisely the cost that buys the elimination of an *entire class* of detection —
and we de-risk that cost with heavy build/tracking automation
([tdd/05](../tdd/05-build-and-tracking.md)). This is [Bet 1](../00-vision.md).

## Consequences

- We maintain a Chromium fork and patch set
  ([tdd/01](../tdd/01-chromium-engine.md)), and accept the treadmill
  ([Principle VIII](../02-design-principles.md), [ADR context]).
- Every modified surface must pass anti-trace acceptance tests (toString,
  descriptors, prototype, cross-context) in CI
  ([tdd/01](../tdd/01-chromium-engine.md) §6, [tdd/06](../tdd/06-verification-lab.md)).
- The Firefox family gets the same benefit via Camoufox's native patching (also
  native, not injection).
- Where a rare surface genuinely has no native path, an injection must pass the
  same battery or it doesn't ship; such exceptions are documented per-surface.
- This is why the project is design-heavy and build-heavy rather than a
  quick-to-ship extension: the quality bar *requires* it.

## Notes

This ADR is the justification for the entire existence of the Chromium-engine TDD
and the build/tracking TDD. If we were willing to accept V3 traces, Proteus could
be a browser extension — and would be as detectable as the tools we're
differentiating from.
