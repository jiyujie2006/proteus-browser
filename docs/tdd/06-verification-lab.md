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
│   ├─ v2-rarity/     blend-in estimate, over-uniqueness, too-clean tail
│   ├─ v2b-fleet/     cross-profile correlation + adversarial cohort classifier
│   ├─ v3-traces/     toString, descriptors, prototype, cross-context (worker/iframe)
│   ├─ v4-network/    ja3/ja4/jarm parity, h2 fingerprint, ech shape, tls-in-tls, dns-leak, webrtc-leak
│   ├─ v5-automation/ webdriver, infobar, cdc_, runtime.enable-leak, isTrusted, headless
│   └─ v6-behavior/   humanized-input realism vs. real human interaction distributions
├─ suites/            curated bundles (quick / full / external)
├─ runner/            headless + headful execution; per-profile
├─ scoring/           per-vector + aggregate; inconsistency extraction
├─ red-team/          adversarial cohort classifier + probe-generation loop (§5a)
└─ dashboard/         public regression site
```

**Each probe** declares: the vector it covers, a pass/fail (or a measured value +
threshold), and — for coherence probes — the *specific fields that disagree* so
the UI can show "timezone (America/New_York) contradicts proxy geo (DE)" rather
than a bare fail. V2b and V6 are *population-* and *distribution-* level rather
than single-field, so they are scored differently (§3a, §5a) but report into the
same dashboard.

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
parity tests run here). The same harness records the ECH-shape and TLS-in-TLS
signals (tdd/03 §6a–6b) so the network-layer coherence and honest-boundary claims
are measured, not just asserted.

## 3a. Behavioral self-measurement (V6, measured not outsourced)

The threat model is explicit that V6 (behavior) is substantially the *user's*
operational responsibility, and we never claim to make automation behave like a
human *for* the user. But "we can't guarantee it" is not a reason to leave it
*unmeasured* — Principle VII says every protective claim is backed by a probe or
stated as a limitation, and "our input primitives are genuinely human-shaped" is a
claim we make (tdd/04 §5). So the lab measures our own primitives:

- **isTrusted / provenance:** assert engine-generated input events report
  `isTrusted === true` and originate from the real input pipeline (the baseline
  advantage over JS `dispatchEvent`).
- **Distributional realism:** compare the mouse-path (velocity, curvature,
  micro-jitter, Fitts's-law timing) and keystroke (dwell/flight) distributions
  our humanized primitives emit against reference distributions of *real* human
  interaction. A probe fails if our "humanized" output is distinguishable from
  human on a statistic a behavioral-biometrics vendor would plausibly use (e.g.,
  too-regular inter-key timing, straight-line cursor moves, constant velocity).
- **Honest scope:** this scores the *primitives we ship*, not the user's
  operational behavior (what they click, how fast, how repetitively). The report
  says so in-context, so a green here is never mis-read as "your automation is
  undetectable." Almost no tool measures its own behavioral realism at all;
  doing so — even while disclaiming the part we don't own — is a concrete
  differentiator squarely inside our "measure everything" philosophy.

These probes run in the suite but are labeled V6-scope so the dashboard shows
them as a distinct, honestly-bounded track.

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

## 5a. The adversarial red-team loop (co-evolution, the innovation)

Every probe described so far is a *fixed* check: it encodes a detection technique
we already know and asserts we pass it. That is necessary but structurally
backward-looking — it can only catch regressions against yesterday's adversary.
The red-team loop makes the lab *forward-looking* by giving it an adversary that
actively tries to detect Proteus and feeding what it finds back in as new probes.
It is the mechanism that operationalizes the V2b (fleet) defense and keeps the
whole suite honest against a moving target.

**The cohort classifier (attacks V2b directly).** We train a classifier whose job
is to separate "fingerprint generated by Proteus" from "real fingerprint," given
a large batch of generated profiles and a real reference corpus. Crucially it
sees the *population*, not one profile, so it can learn exactly the cohort
signatures single-profile tests are blind to (§2, threat-model V2b): a constant
noise shape, a too-flat joint distribution, an over-represented "safe" persona, a
tell-tale bundled-font set. Its accuracy is a **regression metric**:

- Classifier can't beat chance by more than a small margin → fleet
  de-correlation is holding.
- Classifier learns to separate us → that is a bug, and *what it keyed on* is a
  precise, actionable finding ("profiles cluster on canvas-noise spectral shape";
  "timezone is quantized to one value per region"). It becomes the next fix and
  then a permanent fixed probe.

**The probe-generation loop (attacks V1/V3/V5 staleness).** Beyond the cohort
classifier, the red-team component is where *adversarial* effort is invested on
purpose: fuzzing surfaces for cross-context inconsistencies, searching for any
residual injected-override trace, trying known and novel `Runtime.enable`-style
side channels. A red-team finding that catches a real Proteus profile is treated
as a high-value contribution, not an embarrassment (Principle VII/VIII) — the
community is explicitly invited to attack, and the strongest attacks become
probes everyone inherits.

**Why this is co-evolution, not just testing.** The generator and the red-team
adversary improve against each other: each fix the generator ships is a harder
target the classifier must learn, and each signature the classifier learns is a
constraint the generator must satisfy. This arms race — run *internally*, on our
schedule, before the real adversary runs it in production — is how an open project
can plausibly *out-iterate* closed tools on the one axis that matters. It is the
single most important thing that turns "we measure ourselves" from potential
self-flattery (§6) into a genuine, adversarial, non-degrading guarantee.

**Boundaries (Principle IV).** The classifier is only as good as its real
reference corpus, which we keep legal and fresh *without* collecting raw user
fingerprints (public reference data + opt-in DP aggregates; see tdd/02 §7a–8). A
green from the red-team loop means "our current adversary can't separate us,"
not "no adversary ever will" — the dashboard states this scope. Whether the
adversary is a fixed held-out model or an online co-trained one is an open
question (tdd/02 §14).

## 6. Keeping the lab honest (avoiding self-graded delusion)

A suite we write ourselves could flatter us. Guards:
- **The adversarial red-team loop (§5a):** the primary structural guard — an
  adversary trained to *detect* us, whose success is a tracked regression metric.
  Self-flattery is hard when a classifier is actively trying to separate your
  output from real fingerprints.
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
| Fingerprint engine (tdd/02) | Independent implementation, version/dataset locked by conformance tests; consumes fleet de-correlation (§9) as a gate |
| Engine (tdd/01) | Provides the anti-trace/cross-context acceptance tests |
| Network (tdd/03) | Hosts the JA3/JA4/H2/ECH/TLS-in-TLS/DNS/WebRTC parity + leak probes |
| Anti-automation (tdd/04) | Hosts the webdriver/runtime.enable/isTrusted probes + V6 behavioral realism (§3a) |
| Build/tracking (tdd/05) | Is the mandatory CI gate; supplies pass/fail + diffs; runs the red-team loop per release |
| Manager (tdd/07) | One-click "test this profile"; renders score + inconsistencies |

## 8. Testing strategy (the tester's own tests)

- **Probe self-tests:** each probe has known-good/known-bad fixtures so the probe
  itself is verified (a broken probe that always passes is dangerous).
- **Determinism:** given a fixed profile + engine build, scores are reproducible.
- **Platform matrix:** the suite runs on Win/mac/Linux (surfaces differ by host).

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| We grade ourselves too kindly | Adversarial red-team classifier (§5a); external-tester correlation; community adversarial probes |
| Fleet clusters invisibly to single-profile tests (V2b) | Population-level cohort classifier is a tracked regression metric (§5a) |
| Probe rots as detection evolves | Real-world signal loop; red-team probe generation; standing coverage audit vs. threat model |
| A broken probe hides a regression | Probe self-tests with known-bad fixtures |
| Red-team corpus goes stale or leaks user data | Public reference data + opt-in DP only; no raw fingerprints collected (tdd/02 §7a–8) |
| Dashboard becomes a target to game | Score on coherence-first aggregate; publish methodology (Principle IV) |
| External testers change/break | Built-in suite is the default and stable; external is opt-in extra |

## 10. Open questions

- Whether to host the TLS/H2 parity origin ourselves (needs a stable public
  endpoint) or ship it for local self-hosting only — start local, add hosted later.
- How to publish the dashboard without it becoming a how-to for the adversary —
  publish scores/trends and methodology, not the exact evasions per surface.
- Governance for community probe contributions (bar to avoid noisy/incorrect
  probes skewing scores).
