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

- **Linux-first rollout adopted:** `M0-Linux` is the active, non-release
  development checkpoint. It will use an owner-controlled, manually dispatched
  self-hosted Actions runner to produce a Linux x64 bring-up build followed by
  clean-root A/B comparisons. It is planned but has not passed. Host support for
  macOS and Windows follows in a later platform-completion phase and does not
  block Linux native-engine work after this checkpoint
  ([ADR 0008](adr/0008-staged-platform-rollout.md)).
- **M0 contracts and reference workflow ready:** the ruler, exact source/
  dependency/toolchain contracts, runtime packaging, artifact licenses/SBOM,
  GitHub-hosted six-run workflow definitions, OIDC/Sigstore predicates,
  aggregation, identity cross-checks, and hard gate are regression-tested.
- **The three-platform hard M0 remains open:** planning prose calls the existing
  full exit `M0-Full`; its machine contracts and commands retain the name `M0`.
  The current hosted runner class cannot provide Chromium-scale macOS build
  storage, while the external-ephemeral controller, pinned key,
  post-destruction receipt channel, and independent finalizer are not
  implemented. Consequently no signed, independently reproducible
  Win/macOS/Linux A/B bundle set has passed the hard gate. M0-Linux evidence
  cannot substitute for it. The sole active patch defaults Google-backed
  Network Time querying off; it is not a complete de-Google claim. The 15 M1
  and one M3 specifications remain separate non-M0 backlogs. See
  [M0.md](../M0.md).
- **M1A config core complete:** the first non-UI, infrastructure-independent M1
  slice provides deterministic Rust config generation, strict validation,
  Ed25519 signing/fail-closed verification, fixed vectors, and independent Node
  conformance. See [M1A.md](../M1A.md).
- **M1 remains open:** there is no native Chromium config ingest, native
  fingerprint surface implementation, or cross-context/runtime proof. Manager
  and UI work remains in M3 and is not part of the current slice.

## Milestone map

```
M0  Foundations & the ruler
├─ M0-Linux Linux-only checkpoint   ─ active, non-release development gate
├─ platform completion              ─ deferred macOS + Windows host support
└─ M0-Full three-platform hard exit ─ six-build assurance
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

**Current status:** the `M0-Linux` development checkpoint is adopted but has no
runner workflow or real build evidence yet. The existing contracts and
GitHub-hosted reference path implement the `M0-Full` assurance boundary; its
production execution backend remains incomplete. The hard gate stays red until
a viable trusted runner path produces six real, independent three-platform A/B
builds and authenticated live reports.

**Goal:** be able to build the engine reproducibly, and **measure** fingerprint
quality objectively. Without the ruler, all later fingerprint work is blind.

**Work**
- Deliver in two explicitly different lanes:
  - **M0-Linux developer lane:** a separate, manually dispatched Actions
    workflow targets owner-controlled Linux x64 hardware. Manual shell builds
    are iteration-only. Each run pins the exact `main` commit and performs the
    complete fetch → patch → build → test → package → live-verify → records
    pipeline.
  - **M0-Full hard lane:** retain the existing three-platform, six-run contract,
    authenticated builder identities, and independent lifecycle assurance
    unchanged. M0-Linux records must use a different developer-attested
    assurance label and cannot be accepted by the hard verifier. macOS and
    Windows developer bring-up occurs after the Linux checkpoint and before
    this full gate can run.
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

**M0-Linux checkpoint exit (non-release)**

- One real integration build first succeeds on Linux x64 through the dedicated
  Actions developer lane.
- A and B then run from clean build roots for the same pinned `main` commit, and
  their complete bundle trees match byte-for-byte.
- Every run applies the exact source and active patch series, builds
  `chrome` plus `components_unittests`, runs the Network Time assertions,
  packages a runnable bundle, drives the artifact-derived ruler, and retains
  dependency/toolchain locks, licenses, SBOM, manifest, and build records.
- Evidence identifies the owner-controlled self-hosted lifecycle as
  **developer-attested**. It does not claim independent builder trust, release
  readiness, macOS/Windows host support, or
  `full-bundle-builder-attested/v2`.
- Passing this checkpoint unlocks Linux non-UI M1 implementation and runtime
  testing. It does not make `npm run m0:milestone` green.

**M0-Full hard exit criteria**

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
surface proof are still absent. The near-term host scope is Linux x64, beginning
after M0-Linux; macOS and Windows implementation/parity follow without being
removed from the eventual three-platform target.

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

1. **The ruler before engine iteration** — M0-Linux must pass before Linux
   native-engine runtime work is treated as enabled. macOS and Windows host work
   follows that checkpoint. M0-Full remains mandatory before any three-platform
   support, release, or supply-chain assurance claim.
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
