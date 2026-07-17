# 03 — Competitive Analysis

An honest map of the landscape: where each class of tool wins, where it loses,
and the specific wedge Proteus drives between them. The goal is not to disparage
prior art — Camoufox and fingerprint-chromium in particular are genuinely good
and we build on their ideas — but to be precise about the gap we fill.

## The landscape in four quadrants

```
                    Native engine quality
                            ▲
              Multilogin    │    ┌─ PROTEUS (target) ─┐
              Kameleo       │    │  native + open +   │
              Octo          │    │  network-layer +   │
   Closed ◀───────────────┼──────────────────────────▶ Open
              AdsPower      │    Camoufox
              GoLogin       │    fingerprint-chromium
              Dolphin{anty} │
                            ▼
                     JS-injection / shallow
```

Proteus targets the empty upper-right: native-engine quality **and** open, plus
the network layer that even most of the upper-left ignores.

## Class A — High-end closed (Multilogin, Kameleo, Octo Browser)

**Where they win**
- Native engine modification (Kameleo and Octo especially) — good fingerprint
  quality, coherent across contexts.
- Large curated fingerprint pools.
- Polished team features and support.
- Fast upstream tracking (they have paid engineers).

**Where they lose**
- **Closed source**: you cannot verify what the binary does with your live
  sessions. For a tool that reads every cookie, this is the central trust
  problem, and it is unfixable in their model.
- **Cloud-hosted profiles**: your cookies/sessions live on their infrastructure.
- **Expensive**: subscription costs that put them out of reach for many.
- **Network layer**: partially addressed at best, and opaque.

**Proteus's wedge:** match native quality, but be open, local-first, reproducibly
built (trust the binary), and free at the core.

## Class B — High-volume closed (AdsPower, GoLogin, Dolphin{anty})

**Where they win**
- Accessible pricing and big feature surface (profile management, proxy
  integration, RPA, team seats).
- Good onboarding UX; large user bases and templates.

**Where they lose**
- **Frequent reliance on JS injection** for many fingerprint surfaces, which
  leaves V3 spoofing traces (toString tells, descriptor anomalies, Worker/iframe
  leaks).
- **Randomly-combined fingerprints** that are either incoherent (V1) or
  improbably unique (V2) — they optimize "randomize everything" rather than
  "blend in."
- **Network layer largely unaddressed** (V4).
- Closed source; cloud-hosted profiles common.

**Proteus's wedge:** native production kills the injection traces; the
consistency + rarity engine kills the incoherence and over-uniqueness; and we
actually do the network layer. Match their UX, beat their core.

## Class C — Open-source engine work (Camoufox, fingerprint-chromium, ungoogled-chromium)

**Where they win**
- **Camoufox**: excellent *native* Firefox patching, strong anti-detection,
  Playwright-friendly, open (MPL-2.0). The gold standard for open native Firefox
  work.
- **fingerprint-chromium**: demonstrates native Chromium fingerprint patching in
  the open.
- **ungoogled-chromium**: the reference for de-Googling and a clean, rebase-able
  Chromium patch methodology.

**Where they lose (as complete *products*)**
- Single-engine, not a unified dual-engine product.
- Little or no *product* layer: no polished profile/proxy/team manager, no
  importers, no integrated verification lab, no zero-knowledge sync.
- Consistency is left largely to the user; no rarity scoring or persona model.
- Network-layer alignment is inherited (good) but not a managed, proxy-aware
  system with leak guards and provider integration.

**Proteus's stance:** *build on them, don't replace them.* We integrate and
upstream-contribute to Camoufox for the Firefox engine rather than reinventing
it, take the ungoogled-chromium patch methodology as prior art, and add the
consistency engine, network system, product, verification lab, and sustainability
model around them. This is collaboration, not competition. See
[third-party licensing](10-third-party-licensing.md) and
[CONTRIBUTING.md](../CONTRIBUTING.md). No upstream engine checkout, binary, or
copied upstream patch payload is present in the current pre-alpha repository.
The one active Proteus-authored patch contains the minimum BSD-3-Clause Chromium
diff context needed to change the Network Time feature default.

## Class D — Commercial fingerprinting (FingerprintJS Pro et al.)

Not a competitor — the *adversary*, and also a useful teacher. Their open-source
detector and CreepJS define much of what we must pass. We treat their public
techniques as the spec for the verification lab (V1–V3 especially).

## Target feature-by-feature comparison

The Proteus column describes the completed roadmap target, not the current
pre-alpha. Today only the bounded signed-config core and local verification
scaffold exist; there is no modified engine, sidecar, Manager, sync service,
dashboard, RPA runtime, or production build provenance.

| Capability | Class A (Multilogin/Kameleo/Octo) | Class B (AdsPower/GoLogin/Dolphin) | Class C (Camoufox etc.) | **Proteus** |
|---|---|---|---|---|
| Native engine modification | Strong | Mixed / weak | Strong (single-engine) | **Strong, dual-engine** |
| Open source | No | No | Yes | **Yes (Apache-2.0)** |
| Local-first data ownership | No (cloud) | Mostly no | Yes | **Yes + ZK sync** |
| Consistency/persona engine | Partial, opaque | Weak (random) | Manual | **Explicit, rule-checked** |
| Rarity / blend-in scoring | No | No | No | **Yes (novel)** |
| Network-layer (TLS/H2) alignment | Partial | Rare | Inherited | **Managed, tunnel-not-MITM** |
| Anti-CDP / stealth automation | Yes (paywalled) | Yes (limited) | Yes | **Yes, first-class** |
| Verification lab built-in | No | No | No | **Yes + public dashboard** |
| Reproducible build + provenance | No | No | Partial | **Yes (SLSA)** |
| No-code RPA | Some | Yes | No | **Yes (plugin nodes)** |
| Importers from competitors | Limited | Limited | No | **Yes** |
| Price | Expensive | Subscription | Free | **Free core (open-core)** |

## Future one-paragraph pitch against each

These are positioning statements for the completed target system, not claims
about the current repository state.

- **vs. Multilogin/Kameleo/Octo:** "Same native-engine quality, but you can read
  the source, your cookies never leave your machine, the binary is reproducibly
  built so you can trust it, and the core is free."
- **vs. AdsPower/GoLogin/Dolphin:** "No JavaScript-injection tells, fingerprints
  that are coherent *and* common instead of random, a real network layer, and a
  public scoreboard proving it works — open source, local-first."
- **vs. Camoufox/fingerprint-chromium:** "Everything you love about native
  open-source engine work, now dual-engine with a consistency engine, a managed
  network system, a real product around it, and a sustainability model — and we
  contribute back."

## The risk we must respect

The competitive advantage evaporates if we cannot keep up with Chromium releases.
Class A stays current with paid engineers; Class C sometimes lags. Our answer is
the version-tracking automation ([tdd/05](tdd/05-build-and-tracking.md)) and a
funding model for the treadmill ([08-sustainability.md](08-sustainability.md)).
Being better on day one is not enough; being *maintained* is the moat.
