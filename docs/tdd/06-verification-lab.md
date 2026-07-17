# TDD 06 — Verification Lab & Continuous Regression

**Status:** Design · **Serves principles:** IV, VII · **Threat vectors:** the
measurement layer for V1–V5

You cannot improve what you cannot measure, and an anti-detect browser that
silently regresses is worse than useless — it gives false confidence. The
verification lab is Proteus's immune system and its most important trust artifact:
it converts "it works" from a claim into a public, continuously-verified fact.

## 1. Goals & non-goals

**Goals**
- A **local** detection suite users can run against any profile in one click, with
  a clear score and, crucially, **highlighted inconsistencies** (not just a
  number).
- A **CI regression gate** that blocks any release that lowers scores (Principle
  VII) — the hard dependency from [tdd/05](05-build-and-tracking.md) §8.
- A **public dashboard** showing per-release scores over time, so effectiveness is
  transparent (Principle IV) and non-degrading is visible.
- Coverage mapped 1:1 to the threat model's vectors.

**Non-goals**
- Guaranteeing real-world site outcomes (we measure signals, not verdicts of
  specific anti-bot vendors we can't run).
- Replacing external testers — we integrate them where possible and add our own.

## 2. Structure: probes, suites, scoring

```
verify-lab/
├─ probes/            individual checks, each mapped to a threat vector
│   ├─ v1-coherence/  platform↔gpu, ua↔ch, tz↔geo, font↔os, screen-real, hw-pair…
│   ├─ v2-rarity/     blend-in estimate, over-uniqueness, cross-profile corr.
│   ├─ v3-traces/     toString, descriptors, prototype, cross-context (worker/iframe)
│   ├─ v4-network/    ja3/ja4/jarm parity, h2 fingerprint, dns-leak, webrtc-leak
│   └─ v5-automation/ webdriver, infobar, cdc_, runtime.enable-leak, isTrusted, headless
├─ suites/            curated bundles (quick / full / external)
├─ runner/            headless + headful execution; per-profile
├─ scoring/           per-vector + aggregate; inconsistency extraction
└─ dashboard/         public regression site
```

**Each probe** declares: the vector it covers, a pass/fail (or a measured value +
threshold), and — for coherence probes — the *specific fields that disagree* so
the UI can show "timezone (America/New_York) contradicts proxy geo (DE)" rather
than a bare fail.

## 3. Local detection suites

**(a) Built-in, offline, CreepJS-class suite.** We ship a bundled,
locally-served detection page modeled on the open techniques of CreepJS,
FingerprintJS (open), and the classic bot tests — so users can test **without
sending their fingerprint to any third party** (Principle V). The page covers
V1/V2/V3/V5 surfaces and produces a scored, inconsistency-highlighted report;
V4 requires the separate controlled-origin network harness below.

**(b) Optional external checks.** With explicit user action, the lab can open
known external testers and help interpret them:
- bot.sannysoft.com (automation tells)
- pixelscan.net (coherence/consistency)
- browserleaks.com (per-surface leaks: WebRTC, canvas, fonts, WebGL, DNS)
- iphey.com, amiunique.org, coveryourtracks.eff.org (uniqueness/coherence)
- creepjs (the hosted reference)

These are opt-in because they transmit the fingerprint off-device; the built-in
suite is the default.

**(c) TLS/H2 parity harness.** A controlled origin (local or project-hosted) that
records the JA3/JA4/JARM and H2 fingerprint it receives, so a profile's *network*
layer can be compared to a real browser of the claimed identity (the tdd/03
parity tests run here).

## 4. Scoring & the "inconsistency highlight"

The number matters less than *why*:
- **Per-vector scores** (V1–V5) plus an aggregate blend-in/coherence score.
- **Inconsistency list:** every failed coherence rule rendered as a human
  sentence with the exact contradicting fields — this is the actionable output.
  Its Node rules are independently implemented from the Rust fingerprint
  validator and locked to the same versioned dataset/rule contract with
  cross-language conformance tests, so drift becomes a test failure.
- **Rarity feedback:** the blend-in score with the specific rare attribute called
  out (from tdd/02 §6), so a user can pick a more common persona.
- **No green-washing:** a profile that passes every *automation* probe but has a
  timezone/geo mismatch is *not* shown as "good" — coherence (V1) dominates the
  aggregate, matching Principle I's ordering.

## 5. Continuous regression CI + public dashboard (the trust moat)

**CI gate (mandatory, tdd/05 §8):**
- On every engine/fingerprint change and every rebase, the full suite runs
  headless across platforms.
- **Any** probe regressing vs. the last release **blocks** the release. New
  surfaces must ship with new probes (Principle VII).

**Public dashboard:**
- Per-release, per-vector scores plotted over time, publicly.
- Diffs between releases ("what changed") linked from release notes.
- This is something **closed competitors structurally cannot offer** — a running,
  independent-checkable record that the tool actually resists detection and hasn't
  quietly rotted. It is simultaneously the QA system and the strongest marketing
  asset (Principle IV).

## 6. Keeping the lab honest (avoiding self-graded delusion)

A suite we write ourselves could flatter us. Guards:
- **External-tester correlation:** periodically confirm our built-in scores track
  the opt-in external testers; divergence is a bug in our probes.
- **Adversarial probe contributions:** the community is invited to submit *new*
  detection probes (each strengthens everyone); a probe that catches a real Proteus
  profile is a high-value contribution, not an embarrassment (Principle VII/VIII).
- **Real-world signal loop:** where users report a site distinguishing a profile,
  we reduce it to a new probe first, then fix — so the lab grows toward reality.
- **Coverage audit:** the "completeness" question — *what vector are we not
  probing?* — is a standing review item tied to the threat model.

## 7. Interaction summary

| With | Contract |
|---|---|
| Fingerprint engine (tdd/02) | Independent implementation, version/dataset locked by conformance tests |
| Engine (tdd/01) | Provides the anti-trace/cross-context acceptance tests |
| Network (tdd/03) | Hosts the JA3/JA4/H2/DNS/WebRTC parity + leak probes |
| Anti-automation (tdd/04) | Hosts the webdriver/runtime.enable/isTrusted probes |
| Build/tracking (tdd/05) | Is the mandatory CI gate; supplies pass/fail + diffs |
| Manager (tdd/07) | One-click "test this profile"; renders score + inconsistencies |

## 8. Testing strategy (the tester's own tests)

- **Probe self-tests:** each probe has known-good/known-bad fixtures so the probe
  itself is verified (a broken probe that always passes is dangerous).
- **Determinism:** given a fixed profile + engine build, scores are reproducible.
- **Platform matrix:** the suite runs on Win/mac/Linux (surfaces differ by host).

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| We grade ourselves too kindly | External-tester correlation; community adversarial probes |
| Probe rots as detection evolves | Real-world signal loop; standing coverage audit vs. threat model |
| A broken probe hides a regression | Probe self-tests with known-bad fixtures |
| Dashboard becomes a target to game | Score on coherence-first aggregate; publish methodology (Principle IV) |
| External testers change/break | Built-in suite is the default and stable; external is opt-in extra |

## 10. Open questions

- Whether to host the TLS/H2 parity origin ourselves (needs a stable public
  endpoint) or ship it for local self-hosting only — start local, add hosted later.
- How to publish the dashboard without it becoming a how-to for the adversary —
  publish scores/trends and methodology, not the exact evasions per surface.
- Governance for community probe contributions (bar to avoid noisy/incorrect
  probes skewing scores).
