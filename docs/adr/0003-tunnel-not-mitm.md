# ADR 0003 — Preserve the network fingerprint by tunneling, not MITM

**Status:** Accepted · **Date:** 2026 · **Serves:** Principles II, IV · **Threat
vectors:** V4

## Context

Every profile's traffic must egress through the user's chosen proxy. We control
this via a per-profile network sidecar. A central question: does the sidecar
**terminate TLS** (man-in-the-middle) or **tunnel** it?

Terminating TLS is common in proxy tooling because it lets the intermediary
inspect and modify traffic. Many anti-detect and scraping stacks do it, often
without realizing the fingerprinting cost.

## Options

1. **MITM** — the sidecar terminates the browser's TLS, then opens its own TLS to
   the origin. Enables inspection/modification.
2. **Tunnel** — the sidecar moves TLS records at the TCP/CONNECT level without
   decrypting; the origin completes the handshake directly with the browser's TLS
   stack.
3. **Active forgery (uTLS)** — the sidecar itself presents a chosen real browser's
   ClientHello using uTLS.

## Decision

**Tunnel by default** (option 2). **Never MITM** (reject option 1). Keep **active
forgery (option 3) as an opt-in, narrow fallback** for exact-version pinning only,
never for cross-family impersonation.

## Rationale

- **MITM creates the exact V4 mismatch we exist to prevent.** If the sidecar
  terminates TLS, the origin sees the *sidecar's* TLS fingerprint (a Go/OpenSSL
  JA3/JA4), while the page's JavaScript claims Chrome. That is a self-inflicted,
  glaring cross-layer contradiction. A tool trying to look like Chrome that MITMs
  its own traffic defeats itself.
- **Tunneling makes the network fingerprint correct for free.** The browser's real
  BoringSSL completes the handshake with the origin, so JA3/JA4/JARM and the H2
  fingerprint are *genuinely* the claimed Chromium browser's — because
  [ADR 0002](0002-dual-engine-no-cross-family.md) guarantees we didn't lie about
  the engine family. No shaping, no drift, no maintenance.
- **Less code, less risk.** A passthrough tunnel is simpler and safer than a TLS-
  terminating proxy that must be kept byte-current with a real browser's
  handshake.
- **uTLS is a second treadmill**, so it's reserved for the minority case where the
  engine's own handshake needs pinning to an exact version, and even then only to
  emit a handshake matching the *real* claimed browser (Principle IV).

## Consequences

- The sidecar does **not** inspect or modify TLS traffic by default. Features that
  would require reading plaintext traffic are out of scope for the default path.
- The verification lab includes a **JA3/JA4 parity probe** asserting the origin
  sees the real engine's handshake ([tdd/06](../tdd/06-verification-lab.md)).
- An architectural prohibition + test guards against anyone "helpfully" adding
  MITM for traffic inspection later ([tdd/03](../tdd/03-network-layer.md) §14).
- HTTP/3 (QUIC over UDP) needs explicit handling since it doesn't CONNECT-tunnel
  like TCP — resolved via the QUIC policy ([tdd/03](../tdd/03-network-layer.md)
  §7).
- Honest boundary: the sidecar can't fix the **TCP/IP stack** fingerprint of the
  proxy exit host — that's the proxy's, not the browser's, and we say so
  (Principle IV, [tdd/03](../tdd/03-network-layer.md) §9).

## Notes

The counter-intuitive headline — *we protect the network fingerprint by not
touching it* — is a direct consequence of ADR 0002. Together they turn "don't lie
about the engine" into "the hardest-to-fake layers are simply true."
