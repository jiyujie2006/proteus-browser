# Proteus — Documentation

This is the design corpus for Proteus, an open-source anti-detect (fingerprint)
browser. It is deliberately design-first: the documents here are the plan of
record. Read them in roughly this order.

## Core narrative

| # | Doc | What it answers |
|---|---|---|
| 00 | [vision.md](00-vision.md) | What we're building, the thesis, and the bets we're making |
| 01 | [threat-model.md](01-threat-model.md) | Who the adversary is, their detection vectors ranked, and what we honestly cannot do |
| 02 | [design-principles.md](02-design-principles.md) | The non-negotiable rules every decision serves |
| 03 | [competitive-analysis.md](03-competitive-analysis.md) | Where existing tools win and lose, and our wedge |
| 04 | [architecture.md](04-architecture.md) | System components, boundaries, data flow, and the config contract |
| 05 | [product-ux.md](05-product-ux.md) | The Manager app, profile/proxy/team UX, importers |
| 06 | [roadmap.md](06-roadmap.md) | Milestones M0–M5, sequencing rationale, exit criteria |
| 07 | [security-privacy.md](07-security-privacy.md) | Data-at-rest, key management, sandbox stance, telemetry stance |
| 08 | [sustainability.md](08-sustainability.md) | How the project stays alive: open-core, governance, funding the treadmill |
| 09 | [glossary.md](09-glossary.md) | Terms of art: JA3/JA4, Client Hints, persona, etc. |
| 10 | [third-party-licensing.md](10-third-party-licensing.md) | Current license scope and future artifact compliance gates |

## Technical Design Documents (`tdd/`)

Deep, buildable designs for each hard subsystem. These are where the real
engineering lives.

| # | TDD | Subsystem |
|---|---|---|
| 01 | [tdd/01-chromium-engine.md](tdd/01-chromium-engine.md) | Native Chromium fingerprint & anti-automation patches |
| 02 | [tdd/02-fingerprint-engine.md](tdd/02-fingerprint-engine.md) | Persona generation, consistency constraints, rarity scoring |
| 03 | [tdd/03-network-layer.md](tdd/03-network-layer.md) | Sidecar, proxy chains, tunnel-not-MITM, TLS/H2 fidelity, leak guards |
| 04 | [tdd/04-anti-automation.md](tdd/04-anti-automation.md) | Anti-CDP, stealth CDP endpoint, automation compatibility |
| 05 | [tdd/05-build-and-tracking.md](tdd/05-build-and-tracking.md) | Patch management, build farm, version-tracking bot, reproducible builds |
| 06 | [tdd/06-verification-lab.md](tdd/06-verification-lab.md) | Local detection suite, scoring, public regression dashboard |
| 07 | [tdd/07-manager-and-storage.md](tdd/07-manager-and-storage.md) | Desktop app, encrypted storage, profile lifecycle |
| 08 | [tdd/08-sync-and-collaboration.md](tdd/08-sync-and-collaboration.md) | Zero-knowledge E2E sync and team features |

## Architecture Decision Records (`adr/`)

The load-bearing decisions, each with context, options weighed, and
consequences. See [adr/README.md](adr/README.md) for the index.

## Schemas (`schemas/`)

Machine-readable contracts. The most important is the **profile config** — the
signed JSON the Manager hands the engine at launch. See
[schemas/README.md](schemas/README.md).
