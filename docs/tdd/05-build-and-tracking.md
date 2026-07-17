# TDD 05 — Build, Version Tracking & Reproducibility

**Status:** Design · **Serves principles:** VI, VII, VIII · **Threat vectors:**
addresses the meta-risk (falling behind upstream → whole-project V1/V2 failure)

This is the subsystem that decides whether Proteus *lives*. The graveyard of
open-source anti-detect browsers is full of projects that worked once and could
not keep pace with Chromium. Tracking is treated as core engineering, heavily
automated, not an afterthought.

## 1. Goals & non-goals

**Goals**
- Build the modified Chromium (and package the Camoufox-based Firefox) for
  Windows, macOS, Linux, reproducibly.
- **Automatically** rebase the patch series onto new Chromium stable releases,
  run the verification lab, and publish a green build with minimal human touch.
- **Reproducible builds + SLSA provenance** so users can trust the binary
  (Principle VI).
- Refresh fingerprint datasets on their own cadence (decoupled from engine
  builds).
- Precisely localize breakage (which patch, which probe) when a rebase fails.

**Non-goals**
- Building every Chromium channel (we track **stable**; dev/beta only for
  look-ahead).
- Per-profile builds (architecturally forbidden — tdd/01 §7).

## 2. Build system

**Toolchain:** Chromium's native `depot_tools`, `gn` + `ninja`, with **`sccache`**
(or `reclient` where available) for aggressive compile caching. Cross-compilation
targets Win/mac/Linux; codesigning/notarization per platform on release.

**Infrastructure options (decided by budget, see sustainability):**
- Large CI runners (hosted) for occasional builds, or
- A self-hosted build farm for frequent rebases (Chromium is enormous; cache hit
  rate dominates wall-clock).

**Artifacts:** per-platform engine bundles (engine + bundled fonts + default
signed dataset), each with a manifest recording: Chromium base version, patch
series hash, dataset version, toolchain versions, and build flags.

## 3. Patch management

The patch series from [tdd/01](01-chromium-engine.md) is the input.

```
patches/
  series                 # ordered, layered (layer0/1/2)
  <layerN>/NNNN-*.patch   # each with Rationale/Surface/Upstream-risk/Tests header
```

- **Small, single-purpose patches** keyed to a surface, so a rebase conflict is
  localized to one surface, and the guarding probes are known.
- **`Upstream-risk` header** tells the bot which patches are likely to conflict on
  a given Chromium refactor, so it can pre-warn maintainers.
- A `quilt`/`git-rebase`-style flow (methodology from ungoogled-chromium/Camoufox)
  keeps the series maintainable.

## 4. The version-tracking bot (the automation that saves the project)

A scheduled pipeline:

```
1. WATCH     new Chromium stable tag detected
2. SYNC      fetch the new source at that tag (depot_tools)
3. REBASE    apply patch series in order
                ├─ all apply cleanly ─────────────▶ continue
                └─ conflict ─▶ localize to first failing patch,
                               open an issue tagged with the surface +
                               Upstream-risk note + the conflicting hunk,
                               ping the surface owner. STOP.
4. BUILD     gn+ninja+sccache, all platforms
5. VERIFY    run the full verification-lab suite (tdd/06) headless
                ├─ all green ─────────────────────▶ continue
                └─ any probe regressed ─▶ open an issue with the exact
                                          failing probes + diff vs last
                                          release. STOP.
6. PROVENANCE reproducible-build check + SLSA attestation + sign
7. PUBLISH   release candidate; humans approve promotion to stable
```

- **Human-in-the-loop only where judgment is needed** (approving a promotion,
  fixing a genuine conflict). Everything mechanical is automated.
- **Precise localization** (step 3/5) is what turns "the rebase broke, somewhere"
  into "patch 0005 (WebGL surface) conflicts with upstream's refactor of
  `webgl_rendering_context_base.cc`; probes webgl-vendor, webgl-ext at risk."
- **Look-ahead:** optionally run steps 1–5 against Chromium **beta/dev** so we see
  breakage *weeks* before it hits stable and can prepare patches in advance
  (turning the treadmill from reactive to proactive).

## 5. Reproducible builds & provenance (Principle VI)

The trust linchpin: a binary that can read every cookie must be tie-able to the
public source.

- **Reproducibility:** pin all toolchain and dependency versions; strip
  nondeterminism (build paths, timestamps, ordering); target **bit-for-bit**
  reproducible output so an independent rebuilder gets the same artifact hash.
- **Provenance:** generate **SLSA** provenance attestations describing exactly how
  the artifact was built (source, patch hash, toolchain, flags) and **sign**
  releases. Publish an **SBOM (CycloneDX)** enumerating every component + license.
- **Verification story for users:** documented steps for a third party to rebuild
  and confirm the hash, and to verify the provenance/signature. This is what makes
  "open source" mean something for a binary — it converts Principle VI from a
  slogan into a check anyone can run.

## 6. Dataset build & refresh (decoupled)

- Fingerprint datasets (tdd/02 §7) are **data**, versioned and signed
  independently of engine builds, so distributions refresh without an engine
  rebuild (Principle VIII).
- A separate pipeline validates a candidate dataset (schema, licensing of any
  bundled fonts, sanity of distributions), signs it, and publishes it; the Manager
  pulls signed dataset updates.
- Staleness is a tracked correctness issue (stale dataset → V2 rarity), with its
  own cadence and alerting.

## 7. Release & update delivery

- **Channels:** stable (default) and a beta/canary for look-ahead testers.
- **Signed updates**, provenance-attached; the Manager verifies signatures before
  applying.
- **Update honesty:** release notes state which surfaces changed and link the
  dashboard scores, so users see effectiveness didn't regress (Principle VII).
- **Fingerprint aging (innovation, tdd/07 ties in):** because a real browser
  updates over time, the Manager can *gradually* move profiles onto new engine
  versions along a realistic cadence rather than snapping everyone to the newest
  build at once (which would be its own anomaly).

## 8. CI gates (what must pass before anything ships)

1. Patch series applies on the target Chromium tag.
2. Builds succeed on all platforms.
3. **Verification-lab suite green** (V1–V5 probes) — no regressions vs. last
   release (Principle VII).
4. License/SBOM check passes (no non-redistributable artifact snuck in).
5. Reproducibility check passes (independent rebuild matches hash).
6. Provenance/signature generated.

A red on 3 blocks release even if everything compiles — effectiveness is the
product.

## 9. Interaction summary

| With | Contract |
|---|---|
| Engine (tdd/01) | Consumes the patch series; requires rationale/risk/test headers |
| Fingerprint engine (tdd/02) | Builds/signs dataset bundles; version stamping |
| Verification lab (tdd/06) | Runs as the mandatory CI gate; supplies pass/fail + diffs |
| Manager (tdd/07) | Receives signed engine + dataset updates; verifies provenance |
| Firefox/Camoufox | Packages the upstream-tracked Camoufox build alongside |

## 10. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Chromium refactor breaks many patches at once | Small patches + Upstream-risk headers + beta look-ahead to prepare early |
| Build cost/time (Chromium is huge) | sccache/reclient; self-hosted farm; incremental caching |
| A regression slips through | Verification-lab CI gate blocks release on any probe regression |
| Reproducibility drifts (nondeterminism creeps in) | Pinned toolchain; reproducibility check *in* CI, not manual |
| Maintainer bandwidth for conflicts | Precise localization minimizes human time; funded maintainership (08) |
| Dataset licensing regression | Automated license/SBOM gate; per-font checks |

## 11. Open questions

- Hosted runners vs. self-hosted farm for the expected rebase cadence — model
  cost in M0 once build times are measured.
- Exact SLSA level target (aim for a high, independently-verifiable level) and
  which attestation tooling.
- How far ahead to run beta/dev look-ahead (every beta vs. milestone betas).
- Degree of auto-resolution for trivial conflicts (whitespace/context) vs. always
  human — start conservative (always human on real conflicts).
