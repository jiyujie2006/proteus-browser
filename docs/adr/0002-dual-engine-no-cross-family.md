# ADR 0002 — Dual native engine; never impersonate across engine families

**Status:** Accepted · **Date:** 2026 · **Serves:** Principle II · **Threat
vectors:** V4

## Context

An anti-detect browser must decide *which* browsers a given engine will present
as. A tempting feature is "present as anything" — let one engine claim to be
Chrome, Edge, *and* Safari — because users want to cover all popular browsers,
and Safari coverage is frequently requested (macOS/iOS audiences).

But the browser a page sees is not just a User-Agent string. It's the JS engine's
observable behaviors, the TLS ClientHello (JA3/JA4), the HTTP/2 settings, and
subtle DOM/CSS quirks — all produced by the *real* underlying engine.

## Options

1. **Universal impersonation** — one engine (say Chromium) presents as Chrome,
   Edge, Firefox, *and* Safari via configuration.
2. **Same-family only** — Chromium presents only as Chromium-family browsers
   (Chrome/Edge/Brave/Opera); Firefox presents only as Firefox. Safari requires a
   real WebKit engine (deferred).

## Decision

**Same-family only.** We maintain a **dual native engine** — a modified Chromium
and a Firefox (via Camoufox) — and **never** make one impersonate a browser from
another engine family. No Chromium-as-Safari, no Firefox-as-Chrome.

## Rationale

- **Cross-family impersonation is an unwinnable V4 mismatch.** If Chromium claims
  to be Safari, its TLS handshake is BoringSSL's (Chrome's JA3/JA4), its HTTP/2
  settings are Chrome's, and its JS-engine quirks are V8's — none of which match
  Safari's WebKit/Network.framework stack. A site cross-checking any lower layer
  catches it instantly. The UA string is the *easiest* thing to fake and the
  *least* trusted signal.
- **Same-family gives correct lower layers for free.** Because a Chromium engine
  presenting as Chrome/Edge/Brave *is* Chromium, its TLS/H2/JS behaviors are
  genuinely those of a Chromium browser. Staying in-family means the hardest-to-
  fake layers are simply *true*. This is the elegant synergy that makes
  [ADR 0003 (tunnel-not-MITM)](0003-tunnel-not-mitm.md) work.
- **Honesty over false coverage.** Offering "Safari mode" that dies on TLS
  inspection would violate Principle IV and get users flagged while feeling safe.
  Better to cover Chromium+Firefox *excellently* than four families *badly*.
- **Edge/Brave/Opera are real, coherent targets** because they *are* Chromium —
  presenting as them from our Chromium engine is legitimate same-family behavior,
  not cross-family costume.

## Consequences

- **Safari/WebKit is deferred** to long-term research as a *true third engine*,
  not faked. Documented in [00-vision.md](../00-vision.md) and
  [06-roadmap.md](../06-roadmap.md) (M5+).
- Users needing Safari today are told, honestly, that we don't fake it and why
  (Principle IV) rather than sold a detectable costume.
- The profile config's `engine.family` and `engine.brand` are constrained so a
  brand is only selectable within its real family
  ([schemas/profile-config.schema.json](../schemas/profile-config.schema.json)).
- The network layer can rely on the real handshake being correct
  ([tdd/03](../tdd/03-network-layer.md)).
- We carry the maintenance cost of *two* engines, accepted as the price of
  coverage without cross-family lies.

## Notes

This decision is the single most important coherence guarantee in the project.
Every "can't we just also present as X?" request is answered here: only if we run
X's real engine.
