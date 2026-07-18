# TDD 03 — Network Layer (Sidecar, Proxy, TLS/H2 Fidelity, Leak Guards)

**Status:** Design · **Serves principles:** II, IV, V · **Threat vectors:** V4
(cross-layer mismatch), including TLS-in-TLS tunnel detection and ECH shape, plus
DNS/WebRTC leaks feeding V1/V7

This is Proteus's biggest differentiator. A flawless JavaScript fingerprint is
undone by a single mismatched layer beneath it. Most high-volume tools ignore
this entirely. The core insight is counter-intuitive and gets stated up front:

> **We preserve the network fingerprint by *not* touching it.** The sidecar
> tunnels; it never terminates TLS. The origin therefore sees the *real* engine's
> ClientHello and HTTP/2 behavior, which — because we never impersonate across
> engine families (Principle II) — genuinely match the claimed browser.

## 1. Goals & non-goals

**Goals**
- Egress all profile traffic through the user's chosen upstream proxy chain.
- **Preserve** the engine's real TLS (JA3/JA4/JARM) and HTTP/2 (Akamai-style)
  fingerprints end-to-end to the origin.
- Eliminate DNS leaks (resolve via DoH through the proxy).
- Eliminate WebRTC IP leaks (defense in depth with the engine).
- Apply a coherent QUIC/HTTP-3 policy per persona.
- Per-profile network isolation.
- Be honest about what the *proxy* controls that we cannot (TCP/IP fingerprint,
  IP reputation).

**Non-goals**
- Being a proxy *provider* (we consume the user's proxies; providers integrate via
  plugins).
- MITM/TLS interception (explicitly rejected — see §3).
- Anonymity-network behavior (Tor-style) — different threat model.

## 2. Why the sidecar exists at all

The engine can point at a proxy directly, so why a sidecar per profile? Because
several things must happen *together and consistently*, and the engine's built-in
proxy support doesn't cover them:

- Chained/multi-hop upstreams and protocols the engine doesn't speak natively
  (SSH tunnel, WireGuard).
- Forced DoH so DNS never leaks outside the tunnel.
- A single enforcement point that **fails closed** (no accidental direct egress
  revealing the real IP).
- Per-profile policy (QUIC on/off, WebRTC egress rules) applied uniformly.
- A place to *optionally* do active TLS shaping (§6) when — and only when —
  needed, without ever becoming a MITM.

## 3. The tunnel-not-MITM principle (the crux)

**A MITM proxy terminates TLS**: the client TLS-handshakes with the proxy, the
proxy handshakes separately with the origin. The origin then sees the *proxy's*
TLS stack — a Go/OpenSSL fingerprint — **not** the browser's. That is a
self-inflicted V4 mismatch: your JS says Chrome, your TLS says Go. Many tools do
this (often to inspect/modify traffic) and thereby *create* the very signal
they're trying to avoid.

**Proteus tunnels instead.** The sidecar moves bytes at the TCP/CONNECT level:
the browser's TLS records pass through opaque. The origin completes the handshake
with the *browser's* BoringSSL. JA3/JA4/JARM are therefore genuinely Chrome's,
for free, with zero shaping. This is the elegant payoff of Principle II: because
we didn't lie about the engine family, the real handshake *is* the right answer.

```
        ┌─────────┐   TLS records (opaque)   ┌─────────┐   TLS records   ┌────────┐
Browser │ Boring  │ ───────────────────────▶ │ SIDECAR │ ──────────────▶ │ ORIGIN │
BoringSSL│ SSL    │   (CONNECT tunnel;        │ (no TLS │  via upstream   │        │
         └─────────┘    never decrypted here) │  termi- │  proxy chain    └────────┘
                                              │ nation) │
                                              └─────────┘
   Origin's JA3/JA4 == real Chrome's, because Chrome did the handshake.
```

## 4. Proxy chain

**Supported upstream protocols:**
- HTTP/HTTPS `CONNECT` proxies.
- SOCKS5 (with auth, remote DNS).
- SSH tunnels (local dynamic forwarding).
- WireGuard (as an interface-level upstream).
- Chaining (e.g., SSH → SOCKS5 → origin) where the user wants multi-hop.

**Behavior:**
- The engine is launched with the sidecar's loopback listener as its sole proxy;
  no bypass list that could leak.
- The sidecar dials the upstream chain and CONNECT-tunnels the engine's streams.
- **Fail closed:** if the upstream is down, connections error; the sidecar never
  falls back to direct egress. A dead proxy means no traffic, not leaked traffic.
- **Per-profile isolation:** one sidecar instance per profile, its own upstream
  credentials (pulled from the proxy library, never stored in the fingerprint
  config), its own listener.

## 5. DNS: no leaks

- All name resolution goes **DoH** (DNS-over-HTTPS) through the tunnel to a
  configurable resolver, so the local network/ISP never sees profile DNS and
  resolution reflects the exit location.
- The engine is configured to use the sidecar/secure DNS path; the sidecar
  refuses plaintext DNS egress.
- **Consistency angle:** resolving at the exit (remote DNS for SOCKS5, DoH via
  tunnel) keeps DNS geolocation aligned with the exit IP (feeds V1 coherence and
  avoids a classic leak).

## 6. Optional active TLS/H2 alignment (used rarely, carefully)

Tunneling gives correct fingerprints *for free* in the normal case. There is one
advanced case where we may want *active* shaping: pinning the ClientHello to a
*specific* Chrome build when the engine's own handshake drifts from the exact
version we're claiming, or when interoperating with a component we don't control.

- **Preferred:** achieve alignment by making the *engine* emit the right
  handshake (it's real Chromium; the claimed version and the actual build are
  kept close by the tracking system), so no shaping is needed.
- **Fallback (opt-in, per-profile):** a Go path using **uTLS** (and **uquic** for
  QUIC) to actively present a chosen, real browser ClientHello. **This is only
  ever used to emit a handshake that matches the claimed real browser** — never
  to cross families, never to fabricate an impossible client. When enabled, the
  sidecar does participate in TLS, so it is used *only* where the benefit
  outweighs becoming a handshake origin, and the verification lab confirms the
  resulting JA3/JA4 matches the target real browser.
- **Default: off.** Most profiles never need it; the honest, real handshake is
  best.

Rationale for keeping this narrow: every time we synthesize a handshake we take
on responsibility for keeping it byte-current with a real browser — a second
treadmill. We prefer to let the real engine be the source of truth (Principle
II/III) and reserve uTLS for the minority case.

## 6a. TLS-in-TLS tunnel detection (an honest boundary, V4)

Tunneling gives *correct* JA3/JA4 for free — but there is a distinct V4 signal a
proxy-centric design must confront head-on: **TLS-in-TLS detection.** When the
browser's TLS session is carried inside a CONNECT tunnel that is *itself* TLS
(HTTPS proxy, or an inner browser TLS over an outer proxy TLS), the nesting has an
observable timing and record-size signature. A sophisticated origin or on-path
anti-bot can infer "this connection is tunneled through another TLS layer" from
the *shape* of the traffic — record sizes, the handshake-within-payload timing,
the burst pattern of the inner handshake — **without decrypting anything and
regardless of whether JA3 matches.** Recent research and production anti-bot
systems have demonstrated this against proxied clients specifically.

**What we can honestly do:**
- **Prefer tunnel topologies with less nesting.** A SOCKS5 or plain-CONNECT
  upstream (no outer TLS to the proxy) does not create the TLS-in-TLS pattern that
  an HTTPS-proxy hop does. Where the user's chain allows, the sidecar prefers the
  topology with the smallest nesting signature and tells the user when their chain
  forces an extra TLS layer.
- **Reduce, not erase, the shape signal.** Where an outer TLS hop is unavoidable,
  padding and record-size policies can blunt some of the size signal; we do not
  claim they remove the timing signature.
- **Measure it.** The verification lab's parity harness (tdd/06 §3, §3a) records
  whether a controlled origin can distinguish a Proteus session as tunneled, so
  this is a tracked signal, not a blind spot.

**What we will not pretend:** we cannot make a proxied connection provably
indistinguishable from a direct one against a determined on-path detector. Using a
proxy is legitimate and common, but "invisibly proxied" is not a promise we make
(threat model §4). This honesty *is* the Principle IV posture — we surface the
residual risk rather than bury it.

## 6b. ECH (Encrypted ClientHello) coherence (V4)

ECH encrypts the true SNI (and increasingly other ClientHello contents) under a
public key fetched via DNS (HTTPS/SVCB records), sending a benign outer name in
the clear. Its deployment is growing, and it changes the network-fingerprint story
in two ways that matter to us:

- **ECH strengthens tunnel-not-MITM.** With more of the ClientHello encrypted,
  there is even *less* for a MITM proxy to preserve correctly — a MITM that
  terminates TLS cannot reproduce the real browser's ECH behavior, so the case for
  tunneling (letting the real BoringSSL speak) gets stronger, not weaker.
- **ECH presence/shape is itself a fingerprint (a fresh V4 tell).** Whether a
  client attempts ECH, how it does GREASE-ECH (Chrome sends a GREASE ECH extension
  even when it has no real config), the outer-SNI behavior, and the DNS lookups
  that precede it are all observable. A claimed current Chrome that does **not**
  do ECH+GREASE the way the real current Chrome of that version does is now
  incoherent.

**Design consequences for the sidecar:**
- **Don't strip or rewrite ECH/GREASE.** Because we tunnel, the engine's real ECH
  and GREASE-ECH pass through untouched — the correct default. The sidecar must
  not helpfully "normalize" them.
- **Keep the DNS path ECH-aware.** ECH configs arrive via HTTPS/SVCB DNS records;
  our forced-DoH resolver (§5) must fetch and honor them through the tunnel so the
  ECH the engine attempts matches what a real browser on that network would have
  learned — and so the pre-handshake DNS pattern stays coherent with the exit.
- **Coherence with the claimed version.** ECH behavior tracks Chromium version;
  the tracking system (tdd/05) keeps build≈claim so ECH behavior matches by
  construction. The uTLS fallback (§6), when used at all, must reproduce the
  claimed version's ECH/GREASE, not a stale handshake.
- **Measure it.** The parity harness (tdd/06) records ECH-attempt and GREASE shape
  alongside JA3/JA4 so "ECH looks like the claimed Chrome" is a tracked probe.

## 7. QUIC / HTTP-3 policy

- HTTP/3 presence and transport parameters are themselves a fingerprint. The
  policy is **match the claimed brand/version**: if the real Chrome of that
  version would attempt H3 in this context, allow it; otherwise disable coherently.
- Because H3 is UDP and doesn't CONNECT-tunnel like TCP, the sidecar's H3 handling
  is explicit: either tunnel UDP through an upstream that supports it, or (per
  policy) disable H3 for that profile so it falls back to H2 — *consistently*, so
  there's no "sometimes H3, sometimes not" anomaly.
- The QUIC policy is one of the `network` hints in the profile config so engine
  and sidecar agree.

## 8. WebRTC leak guard (defense in depth)

WebRTC can reveal the real local/public IP via ICE candidates, bypassing the
proxy. We defend in two places:
- **Engine (tdd/01 §4.10):** constrain candidate gathering to the proxy path,
  suppress host/local candidate leakage, keep the object surface looking normal.
- **Sidecar:** enforce that STUN/TURN and media egress only traverse the tunnel;
  block direct UDP that would expose the real IP.
- **Verification lab** has a dedicated WebRTC-leak probe (real IP must never
  appear).
- **Balance:** we avoid *over*-stripping WebRTC (a totally dead WebRTC is itself a
  tell); the goal is "behaves like a normal browser behind a NAT/proxy."

## 9. What the proxy controls and we cannot (honesty, Principle IV)

Stated plainly and surfaced in the Manager:
- **TCP/IP stack fingerprint (p0f-style):** TTL, window size, MSS reflect the
  *proxy exit host's* OS, not the browser. A residential proxy on a real Windows
  box is coherent; a Linux datacenter proxy claiming to front a "macOS" persona
  is a latent V4 signal we cannot fix from the browser. The Manager's proxy
  quality check flags likely mismatches.
- **IP reputation (V7):** datacenter vs residential, ASN, blocklist history. We
  detect and warn; we cannot launder a bad IP.
- **Latency/geo realism:** an exit whose latency/geo contradicts the persona is a
  soft signal; the proxy library surfaces geo and RTT.

The product's job here is *informing the user's choice*, not pretending the
browser can override the network's ground truth.

## 10. Proxy library integration (with tdd/07)

- The Manager's proxy library stores proxies (encrypted), runs health checks, and
  does IP geolocation + reputation heuristics.
- **Auto-coherence:** on attaching a proxy to a profile, the Manager sets the
  persona's timezone/locale from the proxy geo by default (R-TZ-GEO in tdd/02),
  and warns on any contradiction it can't auto-fix (e.g., a TCP/IP OS mismatch).
- Proxy provider plugins (residential/mobile providers) can populate the library
  via an SDK (tdd/07), but the sidecar treats all upstreams uniformly.

## 11. Component design (Go)

```
net-sidecar (one process per launched profile)
├─ listener        loopback SOCKS5+HTTP for the engine
├─ dialer          upstream chain: http/socks5/ssh/wireguard, with fail-closed
├─ dns             DoH client, remote-resolve, no plaintext egress
├─ tunnel          CONNECT/stream passthrough (no TLS termination) [default]
├─ tls-active      optional uTLS/uquic handshake shaping (opt-in, §6)
├─ quic            H3 policy + UDP handling
├─ webrtc-guard    egress rules for STUN/TURN/media
└─ control         local RPC from Manager (config, health, teardown)
```

- **Why Go:** the uTLS/uquic ecosystem is the most mature available, and Go
  cross-compiles cleanly to Win/mac/Linux for a per-profile helper.
- **Lifetime:** spawned by the Manager alongside the engine, torn down with it;
  crashes fail the engine's network closed (no leak), and the Manager restarts or
  surfaces the error.
- **Security:** binds loopback only; authenticated local control channel; no
  inbound from anywhere but its paired engine.

## 12. Interaction summary

| With | Contract |
|---|---|
| Engine (tdd/01) | Engine egresses only via sidecar; shares QUIC/WebRTC policy from config; never bypasses |
| Fingerprint engine (tdd/02) | Consumes timezone/geo coherence (R-TZ-GEO); QUIC policy hint |
| Manager (tdd/07) | Spawns/tears down sidecar; supplies upstream creds from proxy library; shows proxy quality/geo |
| Verification lab (tdd/06) | JA3/JA4/JARM parity, H2 fingerprint, ECH/GREASE parity, TLS-in-TLS exposure, DNS-leak, WebRTC-leak probes |

## 13. Testing strategy

- **TLS parity:** capture the JA3/JA4 the origin sees for a Proteus profile vs. a
  real browser of the claimed identity; assert equality (default tunnel mode).
- **ECH/GREASE parity:** assert the profile attempts ECH and emits GREASE-ECH the
  same way the real claimed-version Chrome does; assert the outer-SNI/DNS pattern
  is coherent with the exit (§6b).
- **TLS-in-TLS exposure:** from a controlled origin, measure whether the session
  is distinguishable as tunneled; track the residual signal per upstream topology
  and assert the sidecar picks the least-nesting option available (§6a).
- **H2 fingerprint:** compare SETTINGS/window/priority/pseudo-header order to the
  real browser's.
- **DNS-leak:** assert no plaintext DNS escapes; resolution geolocates to exit.
- **WebRTC-leak:** assert the real public/local IP never appears in candidates.
- **Fail-closed:** kill the upstream mid-session; assert no direct egress.
- **uTLS mode (when used):** assert the synthesized handshake (including ECH/
  GREASE) matches the target real browser's JA3/JA4 and doesn't drift.

## 14. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Someone "helpfully" adds MITM to inspect traffic | Architectural prohibition + tests asserting real-engine JA3 reaches origin |
| TLS-in-TLS reveals the connection is tunneled | Prefer least-nesting topology; blunt size signal; measure and disclose honestly (§6a) — not claimed solved |
| ECH/GREASE drifts from the claimed Chrome version | Tunnel passes real ECH through; tracking keeps build≈claim; parity probe (§6b) |
| Sidecar "normalizes" ECH and breaks coherence | Explicit no-strip/no-rewrite rule; ECH passes through opaque like all TLS |
| Engine build drifts from claimed version → TLS slightly off | Tracking keeps build≈claim; uTLS fallback for exact pin (§6) |
| H3/UDP leaks around the tunnel | Explicit QUIC policy; disable-coherently option; UDP egress rules |
| WebRTC over-stripping becomes a tell | "Look normal behind NAT" rule; probe both leak and normality |
| Proxy exit OS contradicts persona (TCP/IP) | Honest warning; can't fix from browser; guide proxy choice |
| uTLS handshake goes stale | Only-when-needed; verification-lab drift check; prefer real engine |

## 15. Open questions

- WireGuard-as-upstream packaging per OS (kernel vs userspace) — userspace
  (wireguard-go) for portability in M2, revisit.
- Whether to offer UDP/H3 tunneling in M2 or ship "H3-disabled-coherently" first
  and add H3 tunneling in M4.
- How far TLS-in-TLS shape mitigation (§6a) is worth taking vs. simply disclosing
  the residual signal and steering users to lower-nesting topologies — measure
  the real distinguishability per upstream type first, then decide.
- ECH rollout pace (§6b): how aggressively to track ECH behavior changes across
  Chromium versions, and whether the parity harness needs its own ECH-config
  fixture server.
- Default DoH resolver choice and per-profile override UX.
- How much proxy-reputation heuristics we bundle vs. leave to provider plugins.
