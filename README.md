<div align="center">

# Proteus

**An open-source anti-detect (fingerprint) browser that is honest about how it works.**

Target: local-first · reproducible builds · native dual-engine · Apache-2.0

</div>

---

> **Status: Pre-alpha, non-UI core work in progress.** The local verification
> ruler/tooling scaffold is runnable, and the M1A deterministic signed-config
> core is implemented and tested. The hard M0 milestone is **not complete**:
> Chromium patches are still placeholders, and there are no signed,
> independently reproducible Win/macOS/Linux engine bundles or
> builder-attested live verification reports. No modified engine binary, native
> Chromium integration, Manager, or UI is shipped. See
> [`M0.md`](M0.md), [`M1A.md`](M1A.md), and the
> [roadmap](docs/06-roadmap.md).

Proteus aims to become a browser for running many isolated identities from one
machine — for privacy research, web QA and testing, ad verification,
price/market research, and legitimate multi-account operations — while reducing
the shared automation tells that make those identities look like the same robot
to modern anti-bot systems.

Most tools in this space are either expensive and closed (so you cannot verify
what they do, and your cookies live on their servers), or cheap and shallow (JS
injection that leaves obvious traces and falls apart under cross-layer
inspection). Proteus aims to be the "best of both": the native-engine quality of
the high-end commercial tools, the auditability of open source, and a set of
things almost nobody does well — **network-layer consistency**, **realistic
distribution sampling**, and **a public, continuous anti-detection regression
dashboard**.

## What makes it different

The capabilities below describe the intended system. Today, only the local
ruler/tooling scaffold and the bounded M1A config core described above are
implemented.

- **Native dual-engine, not JS injection.** Fingerprint values are produced by
  the C++ engine itself (Chromium-family and Firefox-family). That kills the
  entire class of "spoofing traces" — `toString` tells, wrong property
  descriptors, prototype-chain anomalies — and it stays consistent inside
  iframes, Web Workers, and Service Workers, where JS patches leak.
- **Consistency over everything.** A profile is a *persona*: one plausible real
  device whose OS, fonts, GPU/WebGL strings, screen, timezone, and Client Hints
  all agree with each other — and with the proxy's geolocation. Incoherence is
  the #1 way anti-bot systems catch these tools; we treat it as the primary
  enemy. See [`docs/01-threat-model.md`](docs/01-threat-model.md).
- **Four-layer alignment.** JS fingerprint, **TLS (JA3/JA4)**, **HTTP/2**, and
  behavior tell the *same* story. We achieve TLS/H2 fidelity by **tunneling, not
  MITM-ing** — the real Chromium network stack speaks to the origin, so its
  handshake is genuinely Chrome's. See [`docs/tdd/03-network-layer.md`](docs/tdd/03-network-layer.md).
- **Realistic distribution + rarity scoring.** We sample from real-world
  distributions and *reject fingerprints that are too unique* — because a
  flawless, one-of-a-kind fingerprint is itself a signal. You get a "blend-in"
  score. See [`docs/tdd/02-fingerprint-engine.md`](docs/tdd/02-fingerprint-engine.md).
- **Local-first, zero-knowledge sync.** Your profiles and cookies live on your
  machine, encrypted. Optional team sync is end-to-end encrypted; the
  (self-hostable) server never sees plaintext.
- **Reproducible builds + provenance (target).** The single biggest trust
  problem with a binary that can read all your cookies is "can I trust this
  binary?" We answer it with reproducible builds and SLSA provenance, not a
  promise.
- **Verifiable, not just claimed (target).** A public regression CI will run
  detection suites against every release so effectiveness is a measurable fact
  that cannot silently degrade. See
  [`docs/tdd/06-verification-lab.md`](docs/tdd/06-verification-lab.md).

## What it is honestly *not*

No tool can make you "undetectable," and any tool that claims otherwise is
lying. Anti-bot systems also use **behavior**, **account-history graphs**, and
**IP/proxy reputation** — none of which a browser alone can fix. The completed
Proteus system aims to make your *browser fingerprint and network layer* as
indistinguishable-from-real as the state of the art allows, give you tools to do
the rest right, and state where the boundary is. The current pre-alpha does not
yet provide that browser runtime. See
[`docs/01-threat-model.md`](docs/01-threat-model.md) §"What we cannot do."

Proteus is a **dual-use** tool intended for lawful use. Multi-accounting may
violate some sites' Terms of Service; that is your call and your risk. See
[`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md).

## Target architecture at a glance

```
Manager (Tauri/Rust + Web UI)  ── profiles · proxies · team · verify-lab · RPA
        │  signed per-profile config
        ▼
Modified engine (Chromium or Firefox)  ◀── one binary, N identities via config
        │  tunnel (no MITM → real TLS/H2 preserved)
        ▼
Network sidecar (Go)  ── proxy chain · DoH · WebRTC-leak guard · QUIC policy
```

Full detail: [`docs/04-architecture.md`](docs/04-architecture.md).

## Repository layout

```
docs/            Vision, threat model, architecture, roadmap, product, ops
docs/tdd/        Deep technical design docs, one per hard subsystem
docs/adr/        Architecture Decision Records — the load-bearing choices
docs/schemas/    JSON Schemas for the profile config contract
fingerprint/     Implemented M1A Rust config generator/validator/signer
verify-lab/      Runnable local verification ruler and Node conformance tests
engine-chromium/ Patch/build/tracking scaffold; patch bodies are placeholders
scripts/         Local milestone gates and supporting tooling
```

The remaining target code trees (`engine-firefox/`, `net-sidecar/`, `manager/`,
`sync/`) arrive with their roadmap milestones. Existing directories do not
imply that the corresponding milestone has passed: in particular,
`engine-chromium/` is currently a fail-closed scaffold, not a patched browser.

## Where to start reading

| If you want to… | Read |
|---|---|
| Understand the thesis and bets | [`docs/00-vision.md`](docs/00-vision.md) |
| Understand what we're up against | [`docs/01-threat-model.md`](docs/01-threat-model.md) |
| Understand the non-negotiable rules | [`docs/02-design-principles.md`](docs/02-design-principles.md) |
| See how it compares to existing tools | [`docs/03-competitive-analysis.md`](docs/03-competitive-analysis.md) |
| Understand the system shape | [`docs/04-architecture.md`](docs/04-architecture.md) |
| Go deep on a subsystem | [`docs/tdd/`](docs/tdd/) |
| See the plan and sequencing | [`docs/06-roadmap.md`](docs/06-roadmap.md) |
| Understand why decisions were made | [`docs/adr/`](docs/adr/) |

## License

Proteus's own code is licensed under **Apache-2.0** (chosen over MIT for its
explicit patent grant — see [`docs/adr/0001-license-apache-2.md`](docs/adr/0001-license-apache-2.md)).
The current repository does not contain or distribute Chromium, Firefox,
Camoufox, or modified engine binaries. Future engine distributions will remain
subject to every applicable upstream and bundled-component license; the
artifact-specific process is documented in
[`docs/10-third-party-licensing.md`](docs/10-third-party-licensing.md).
[`NOTICE`](NOTICE) contains only current attribution notices. Contributions are
accepted under the terms in [`CONTRIBUTING.md`](CONTRIBUTING.md).

[`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) is a non-binding statement of project
intent. It is not part of the Apache-2.0 license and does not narrow the rights
granted by that license.
