# Proteus — The Plan

This is the executive overview of the whole project, skimmable in a few minutes,
with links into the detailed corpus. If you read only one file, read this — then
follow the links that matter to you. The detailed reading order lives in
[`docs/README.md`](docs/README.md).

---

## The idea in one paragraph

Proteus is an **open-source anti-detect (fingerprint) browser project** that aims to be
the *集大成者* — the synthesis of the best of every existing tool, done in the
open and done honestly. It is designed to combine the **native-engine quality**
of the expensive closed tools, the **auditability** of open source, the **good
UX** of the high-volume tools, and three things almost nobody does well:
**network-layer consistency**, **realistic-distribution sampling with rarity
scoring**, and a **public, continuously-verified effectiveness dashboard**. The target is
**local-first** operation (your cookies stay on your machine, encrypted),
**reproducible builds** (so you can verify the eventual binary), and
**Apache-2.0** licensing. It is currently pre-alpha; no engine binary is shipped.

## The four hard truths it's built on

Winning is not a UI problem. In priority order, it is:

1. **Consistency.** The #1 way these tools get caught is *incoherence* — a macOS
   claim with Windows fonts, an Apple GPU under `Win32`, a timezone that fights the
   proxy's IP. Fix coherence and you beat most detection. Read it at the *fleet*
   level too: the population of profiles you emit must blend into the real world,
   not cluster into a recognizable "made by this tool" cohort
   ([`docs/adr/0007`](docs/adr/0007-fleet-de-correlation.md)).
2. **Native production.** Fingerprint values must come from the C++ engine, not
   JavaScript overrides, or they leave detectable traces (wrong `toString`,
   descriptors, Worker/iframe mismatches).
3. **Cross-layer alignment.** The JS fingerprint, the TLS handshake (JA3/JA4,
   ECH shape, and whether the connection looks tunneled), the HTTP/2 settings, and
   behavior must all tell the *same* story. Perfect JS with a Go TLS fingerprint
   still dies.
4. **The treadmill.** Chromium ships every few weeks; a fingerprint that lags the
   real population is anomalous by definition. Staying current is survival.

Everything in the design is downstream of these. Full reasoning:
[`docs/00-vision.md`](docs/00-vision.md), [`docs/01-threat-model.md`](docs/01-threat-model.md).

## The nine design principles (the rules that never bend)

I. Consistency > hiding uniqueness > erasing traces · II. Never impersonate across
engine families · III. Native over injection · IV. Honesty in every claim · V.
Local-first, data belongs to the user · VI. Trust the binary, verifiably · VII.
Effectiveness must be measurable and non-degrading · VIII. Design for the treadmill
· IX. Never weaken the sandbox.

Detail: [`docs/02-design-principles.md`](docs/02-design-principles.md).

## How it is designed to be built (target architecture)

```
Manager (Tauri/Rust + Web UI) ── profiles · proxies · team · verify-lab · RPA
      │  embeds the fingerprint engine (persona → coherence → rarity → config)
      │  signs the per-profile config
      ▼
Modified engine (Chromium OR Firefox) ── ONE binary, N identities via signed config
      │  native fingerprint surfaces · anti-CDP · stealth automation endpoint
      │  tunnel (NEVER MITM) → the origin sees the REAL engine's TLS/H2
      ▼
Network sidecar (Go, per profile) ── proxy chain · DoH · WebRTC guard · QUIC policy
```

The counter-intuitive crux: **we protect the network fingerprint by *not* touching
it.** Because we never lie about the engine family (Principle II), the real
handshake *is* the correct one — so the sidecar just tunnels. Detail:
[`docs/04-architecture.md`](docs/04-architecture.md).

## What the completed system is intended to add

- **Four-layer consistency** with tunnel-not-MITM fidelity — even most premium
  tools don't do all of it.
- **Real-distribution sampling + rarity scoring** — actively avoid being
  *over-unique* (and *over-clean*); show a "blend-in" score. Attacks the second-biggest detection
  vector that nearly everyone ignores.
- **Fleet de-correlation, measured** — the whole population of profiles must blend
  into the real world, not just each profile individually. An adversarial red-team
  classifier that tries to detect "made by Proteus" is a tracked release gate.
  This is the vector that historically kills popular stealth tools, and almost
  nobody measures it ([`docs/adr/0007`](docs/adr/0007-fleet-de-correlation.md)).
- **Public regression dashboard** — verifiable, non-degrading effectiveness.
- **Reproducible builds + provenance** — trust the binary, don't just hope.
- **Local-first + zero-knowledge sync** — your data, your keys.
- **Persona model** — coherence by construction, not random field-mixing.
- **Fingerprint aging & warm-up** — identities that update and mature like real
  ones.
- **Deterministic rebuild from seed** — portable, auditable, team-reproducible.
- **Plugin SDK + open fingerprint schema** — a community that keeps pace with
  detection.

Full comparison vs. every tool class:
[`docs/03-competitive-analysis.md`](docs/03-competitive-analysis.md).

## What it honestly does NOT do

No tool can make you undetectable. Proteus does not control **behavior** (mouse/
keystroke biometrics), **reputation** (IP/proxy quality, account-history graphs),
or the **proxy exit host's** TCP/IP fingerprint. The completed system aims to
make the browser and network-layer identity as indistinguishable as the state of
the art permits, give users tools for the remaining risks, and state the
boundary in context. The current pre-alpha has no modified browser or network
sidecar yet. This honesty is a principle (IV) and a competitive weapon closed
tools can't match.
Detail: [`docs/01-threat-model.md`](docs/01-threat-model.md) §4.

## The subsystems (where the engineering lives)

| TDD | Subsystem | The hard part |
|---|---|---|
| [01](docs/tdd/01-chromium-engine.md) | Chromium engine | Native surfaces set pre-script, consistent across all contexts, one binary via config |
| [02](docs/tdd/02-fingerprint-engine.md) | Fingerprint engine | Persona coherence + rule validation + rarity scoring, deterministic |
| [03](docs/tdd/03-network-layer.md) | Network layer | Tunnel-not-MITM TLS/H2 fidelity + leak guards + proxy chains |
| [04](docs/tdd/04-anti-automation.md) | Anti-automation | No `Runtime.enable` leak; stealth CDP; genuine `isTrusted` |
| [05](docs/tdd/05-build-and-tracking.md) | Build & tracking | Auto-rebase bot + reproducible builds + provenance (survival) |
| [06](docs/tdd/06-verification-lab.md) | Verification lab | Measure coherence, gate releases, public dashboard |
| [07](docs/tdd/07-manager-and-storage.md) | Manager & storage | Encrypted, persona-first UX that makes coherence effortless |
| [08](docs/tdd/08-sync-and-collaboration.md) | Sync & teams | Zero-knowledge E2E sync (needs crypto-review ADR first) |

Load-bearing decisions are recorded as ADRs: [`docs/adr/`](docs/adr/). The central
data contract is [`docs/schemas/profile-config.schema.json`](docs/schemas/profile-config.schema.json).

## The plan of attack (sequencing)

**Prove "coherent + verifiable" before building anything pretty.**

- **M0 — Foundations & the ruler:** reproducible Chromium build + verification lab.
  *You can't improve what you can't measure.*
- **M1 — Single-profile proof:** native surfaces + config channel + coherence
  rules → one profile passes every suite green with zero inconsistencies.
- **M2 — Network layer:** sidecar, tunnel-not-MITM → JA3/JA4/H2 match the claimed
  browser; no DNS/WebRTC leaks.
- **M3 — Productization (v1.0):** Manager, encrypted storage, stealth CDP,
  importers → a non-expert can do it all in minutes. Ship the free local v1.0.
- **M4 — Scale & dual-engine:** Camoufox, real datasets + rarity, the
  version-tracking bot, public dashboard, RPA.
- **M5 — Collaboration & innovation:** zero-knowledge sync, aging, warm-up, plugin
  SDK; WebKit/Safari research.

A single strong engineer can reach the M0–M2 technical proof; staying on the
treadmill from M4 needs a team or funded community. Detail:
[`docs/06-roadmap.md`](docs/06-roadmap.md).

## Why it won't die (the part most open anti-detect browsers get wrong)

The moat isn't the code — it's **staying maintained**. Chromium builds cost real
money and skilled labor. Proteus funds the treadmill with **open-core**:
everything that makes it *effective* is free, open, and local forever; only
*conveniences* (hosted zero-knowledge sync, enterprise support, managed proxies)
are paid, and that revenue buys the engineer-hours and build compute that keep the
free core current. The paid boundary never touches effectiveness, we say so
publicly, and reproducible builds prove we mean it. Detail:
[`docs/08-sustainability.md`](docs/08-sustainability.md).

## Legal & license

Apache-2.0 for our code (patent grant matters for a circumvention-adjacent
project — [`docs/adr/0001`](docs/adr/0001-license-apache-2.md)). The current
repository ships no engine binary; future artifacts must carry an
artifact-derived license/notice bundle
([`docs/10-third-party-licensing.md`](docs/10-third-party-licensing.md)).
[`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) states project intent but is not part of
the license and adds no use restriction.

## Status & next step

**Pre-alpha / non-UI core work in progress.** Two tracks must be kept separate:

- The M0 ruler, hard contracts, and GitHub-hosted reference workflow are
  runnable/testable, but the production build path is not complete: the current
  runner class lacks Chromium-scale macOS storage, and a trusted
  external-ephemeral controller/finalizer has not been implemented. The hard
  exit therefore cannot yet produce its six A/B builds. The sole active layer0
  patch defaults Google-backed Network Time querying off; this is not complete
  de-Googling. The 16 M1/M3 specifications are a separate backlog and do not
  gate or hash into M0. See [`M0.md`](M0.md).
- The bounded **M1A signed-config core** is complete: deterministic Rust
  generation, strict structural and semantic validation, Ed25519 signing and
  fail-closed verification, fixed vectors, and independent Node conformance
  checks. See [`M1A.md`](M1A.md).

M1A is not roadmap M1. The critical path remains a real Chromium checkout and
build pipeline, followed by pre-script config ingest, protected trust-anchor and
replay handling, native surfaces, and cross-context runtime tests. Manager/UI
work remains a later M3 deliverable and is not part of the current slice. The
milestone definitions in [`docs/06-roadmap.md`](docs/06-roadmap.md) remain
unchanged.
