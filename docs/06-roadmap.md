# 06 — Roadmap

The sequencing rationale in one line: **prove "coherent + verifiable" before
building anything pretty.** A beautiful UI over a detectable engine is the red
ocean the high-volume tools already own; it is not where we win. So we build the
moat (engine, fingerprint, network, measurement) first and the product on top.

Durations are relative and indicative, not commitments — the treadmill and
funding (see [08-sustainability.md](08-sustainability.md)) set the real pace.

## Current implementation snapshot

This roadmap defines hard exits; a runnable scaffold is not the same as a
completed milestone.

- **M0 contracts and reference workflow ready:** the ruler, exact source/
  dependency/toolchain contracts, runtime packaging, artifact licenses/SBOM,
  GitHub-hosted six-run workflow definitions, OIDC/Sigstore predicates,
  aggregation, identity cross-checks, and hard gate are regression-tested.
- **M0 production path and hard exit remain open:** the current hosted runner
  class cannot provide Chromium-scale macOS build storage, while the
  external-ephemeral controller, pinned key, post-destruction receipt channel,
  and independent finalizer are not implemented. Consequently no signed,
  independently reproducible Win/macOS/Linux A/B bundle set has passed the hard
  gate. The sole active patch defaults Google-backed Network Time querying off;
  it is not a complete de-Google claim. The 15 M1 and one M3 specifications
  remain separate non-M0 backlogs. See [M0.md](../M0.md).
- **M1A config core complete:** the first non-UI, infrastructure-independent M1
  slice provides deterministic Rust config generation, strict validation,
  Ed25519 signing/fail-closed verification, fixed vectors, and independent Node
  conformance. See [M1A.md](../M1A.md).
- **M1 remains open:** there is no native Chromium config ingest, native
  fingerprint surface implementation, or cross-context/runtime proof. Manager
  and UI work remains in M3 and is not part of the current slice.

## Milestone map

```
M0  Foundations & the ruler        ── build pipeline + verification lab
M1  Single-profile proof           ── native fp surfaces + config channel + rules
M2  Network layer & sidecar        ── proxy chain, tunnel-not-MITM, leak guards
M3  Productization (v1.0)           ── Manager, storage, stealth CDP, importers
M4  Scale & dual-engine            ── Camoufox, real datasets+rarity, tracking bot, RPA
M5  Collaboration & innovation      ── ZK sync, aging, warm-up, plugin SDK; WebKit R&D
```

Each milestone has **exit criteria** — objective gates, mostly enforced by the
verification lab, not vibes.

---

## M0 — Foundations & the ruler

**Current status:** contracts and a GitHub-hosted reference path are
implemented; the production execution backend is incomplete. The hard gate
stays red until a viable trusted runner path produces six real, independent
three-platform A/B builds and authenticated live reports.

**Goal:** be able to build the engine reproducibly, and **measure** fingerprint
quality objectively. Without the ruler, all later fingerprint work is blind.

**Work**
- Chromium fork + the active layer0 Network Time default-off patch that
  **builds** on all three platforms via depot_tools/gn/ninja. The hard A/B
  evidence profile deliberately disables caller-supplied cache wrappers so a
  cache cannot become an undeclared shared input; a reviewed, version-pinned
  sccache/reclient contract can be added later for farm throughput. This bounded
  change blocks the default Google-backed time query, can be explicitly
  re-enabled, and is not complete de-Googling. Layer1/2 payloads remain empty;
  their specifications stay in milestone-labelled backlogs and are not M0 build
  inputs. Each platform build compiles `components_unittests`, directly asserts
  that the compiled Network Time feature default is disabled, and retains the
  upstream explicit disable/enable regression; the artifact-driven report also
  rejects a captured NetLog containing the default Google time endpoint.
- Reproducible-build pipeline + SLSA provenance skeleton (Principle VI from day
  one).
- **Verification lab v0**: the built-in, offline CreepJS-class suite with V1–V5
  probe scaffolding and scoring + inconsistency extraction (tdd/06).
- Threat-model→probe mapping stubbed so every later change has a test home.

**Exit criteria**
- A signed, reproducible stock-ish build is produced by CI on Win/mac/Linux.
- The verification lab runs headless in CI and scores a profile, listing
  inconsistencies.
- **The ruler exists**: we can put a number and an inconsistency list on any
  build. Everything after this is measurable.

*Rationale for going first:* [Principle VII](02-design-principles.md). You can't
improve or defend what you can't measure.

---

## M1 — Single-profile proof of force

**Current status:** not complete. M1A completes only the signed-config
generation/validation/signing contract; native Chromium consumption and runtime
surface proof are still absent.

**Goal:** one profile that is **coherent and passes the suites**, produced
natively via the config channel.

**Work**
- The **config-ingest linchpin** (tdd/01 §3): signed config parsed pre-script,
  propagated to all renderers/workers.
- Native fingerprint surfaces (tdd/01 §4): navigator, screen, canvas, WebGL,
  WebGPU, audio, fonts (with per-OS font bundling), timezone/locale, Client
  Hints, media devices, speech voices.
- Fingerprint engine v1 (tdd/02): persona model, constraint sampler, **rule
  validator** (coherence), deterministic emitter. Rarity scoring can be basic
  here; full datasets come in M4.
- Anti-trace acceptance tests (tdd/01 §6) green across all contexts.
- Basic native automation-trace removal: `navigator.webdriver` and observable
  automation switch/infobar behavior. The stealth CDP endpoint remains M3.

**Exit criteria**
- A single profile passes the built-in suite **and** bot.sannysoft, pixelscan,
  and CreepJS **green with zero consistency warnings**.
- Anti-trace probes (toString/descriptors/prototype/cross-context) all pass.
- The same value set is present in main frame, iframe, Worker, and Service Worker
  (V3 closed by construction).

*This milestone is the core technical proof.* If M1 lands, the central bet
(native + coherence) is validated.

---

## M2 — Network layer & sidecar

**Goal:** the identity is coherent **below** JavaScript too — TLS/H2 match, no
leaks.

**Work**
- Network sidecar (tdd/03): upstream proxy chain (HTTP/SOCKS5/SSH/WireGuard),
  fail-closed, per-profile isolation.
- Forced **DoH** (no DNS leak); **WebRTC-leak guard** (engine + sidecar defense in
  depth); QUIC/H3 coherent policy.
- **Tunnel-not-MITM** proven: the origin sees the real engine's JA3/JA4.
- Optional uTLS/uquic active-alignment path (off by default), for exact version
  pinning only.
- **ECH/GREASE coherence** and **TLS-in-TLS** honest handling (tdd/03 §6a–6b):
  pass real ECH through, prefer lower-nesting proxy topologies, measure residual
  tunnel exposure rather than claim it solved.
- Verification lab: JA3/JA4/JARM parity, H2 fingerprint, ECH-shape,
  TLS-in-TLS exposure, DNS-leak, WebRTC-leak probes.

**Exit criteria**
- A profile's **JA3/JA4 and HTTP/2 fingerprints match a real browser** of the
  claimed identity (parity harness green).
- No DNS leak; no WebRTC real-IP leak; fail-closed verified (kill proxy → no
  direct egress).
- Timezone/locale coherent with proxy geo end-to-end.

*After M2, the four-layer consistency thesis is demonstrated — the biggest
differentiator is real.*

---

## M3 — Productization → v1.0

**Goal:** a non-expert can create, proxy, launch, automate, and import profiles.
Ship the **local, fully-functional open v1.0**.

**Work**
- Manager (tdd/07): profile library, proxy library (health/geo/quality),
  persona-first create flow with blend-in feedback, tags/groups/batch.
- Encrypted storage (SQLCipher + OS keychain); per-profile isolation & lifecycle;
  fail-closed orchestration.
- **Stealth CDP endpoint** (layer2 patch 0003, including the
  `Runtime.enable`-leak-free path) + Playwright/Puppeteer adapters (tdd/04);
  Selenium if it fits.
- **Importers** (Multilogin/GoLogin/AdsPower/Dolphin + cookies) — session-
  preserving.
- One-click verification-lab integration in the UI.

**Exit criteria**
- End-to-end: create → coherent profile → attach proxy → launch → automate →
  verify, in minutes, by a non-expert.
- Import a competitor profile without losing sessions.
- Data-at-rest encryption verified (no plaintext cookies on disk).
- **v1.0 released**: local, free, open, reproducibly built.

---

## M4 — Scale & dual-engine

**Goal:** many coherent profiles at population scale, a second engine, and the
automation that keeps us on the treadmill.

**Work**
- **Camoufox integration** (tdd/01 §11): Firefox family via the shared config;
  one dashboard for both engines.
- **Real-distribution datasets + full rarity scoring** (tdd/02 §6–7), including
  the owned cold-start dataset workflow (tdd/02 §7a) and **coherence-as-a-
  distribution** realistic-imperfection sampling (tdd/02 §6a).
- **Fleet de-correlation + the red-team classifier** (tdd/02 §9, tdd/06 §5a,
  adr/0007): the adversarial cohort-detection metric goes live as a release gate.
- **Version-tracking bot** (tdd/05 §4): auto-rebase, verify, provenance, publish;
  beta look-ahead.
- **Public regression dashboard** live (tdd/06 §5), including the V2b fleet and
  V6 behavioral tracks.
- **No-code RPA runtime** (tdd/04 §6, tdd/07 §8).

**Exit criteria**
- New Chromium stable → bot rebases, verifies green, publishes a signed build with
  minimal human touch.
- Firefox-family profiles pass the suite on the same dashboard as Chromium.
- Public dashboard shows non-degrading scores across ≥2 releases.
- Generating N profiles yields a crowd-spread (rarity) with no shared artifact,
  **and the red-team cohort classifier cannot separate Proteus profiles from a
  real hold-out above a small margin** (V2b de-correlation gate green).

---

## M5 — Collaboration & innovation

**Goal:** teams, and the features that make identities durable and lived-in.

**Work**
- **Zero-knowledge E2E sync + team RBAC + session hand-off + audit** (tdd/08) —
  gated behind a **crypto-review ADR** before implementation.
- **Fingerprint aging** and **profile warm-up** (tdd/07 §10).
- **Plugin SDK** (tdd/07 §9): probes, data sources/rules, proxy providers, RPA
  nodes, importers.
- **Open fingerprint schema standard** + opt-in DP dataset contribution loop
  (tdd/02 §8).
- **WebKit/Safari** true-third-engine **research** (not a ship commitment).

**Exit criteria**
- A team shares a profile and hands off a live session with no server-visible
  plaintext (zero-knowledge assertion test green).
- Aging/warm-up demonstrably make profiles update/mature realistically.
- At least one community plugin of each type works against the stable SDK.

---

## Cross-cutting, every milestone

- **Verification lab stays green** — no release lowers scores (Principle VII).
- **Reproducible + provenance** for every published build (Principle VI).
- **Honesty** in docs/UI — no undetectability claims (Principle IV).
- **Sustainability** progress — the treadmill needs funding before M4's tracking
  costs bite (see [08](08-sustainability.md)).

## Sequencing rationale (why this order)

1. **M0 before all** — measurement is the prerequisite for iteration.
2. **M1 before network** — prove native coherence in JS first; it's the core bet.
3. **M2 before product** — the network layer is the differentiator; prove it
   before polishing UX.
4. **M3 makes it usable** — only now does UX matter, and it's built on a proven
   core.
5. **M4 scales & automates** — dual-engine and the tracking bot are what make it
   *survivable*, added once the single-engine core is solid.
6. **M5 collaborates & innovates** — highest-level features last, and ZK sync
   waits for a crypto review so we don't ship a security mistake.

A single strong engineer can plausibly reach M0–M2 (the technical proof); staying
on the treadmill from M4 onward needs a team or funded community. That reality
shapes [08-sustainability.md](08-sustainability.md).
