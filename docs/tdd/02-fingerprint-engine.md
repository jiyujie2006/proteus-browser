# TDD 02 — Fingerprint Engine (Consistency & Rarity)

**Status:** M1A core implemented; full M1/M4 scope pending · **Serves
principles:** I, IV, V, VIII · **Threat vectors:** V1 (incoherence), V2 (rarity),
V2b (fleet correlation)

This subsystem turns "we *can* set any value" (tdd/01) into "we set values that
look like a real, common device." It is a pure, local Rust library embedded in
the Manager. It is the difference between Proteus and tools that randomize fields
independently.

> **Current boundary:** M1A implements a strict Rust model, deterministic
> generation and semantic validation for Chrome 150 on Windows 11
> desktop/laptop, Ed25519 signing/fail-closed reload, fixed vectors, and
> independent Node conformance. Its transparent versioned seed weights are
> heuristics, not population telemetry. Calibrated distribution-backed rarity,
> deterministic rejection/resampling, coherent-imperfection sampling,
> per-profile noise-shape variation, the fleet classifier, signed dataset
> bundles, native browser consumption, and runtime/cross-context proof remain
> future work.

## 1. Goals & non-goals

**Goals**
- Generate a **coherent** identity: every field agrees with every other and with
  the proxy (defeat V1).
- Make the coherent whole **common**, not rare; score and expose blend-in
  (defeat V2).
- Make coherence itself **realistic, not maximal**: sample the small
  imperfections real devices carry so a profile does not sit in the thin tail of
  the "too clean" distribution (defeat V2's second face — see §6a).
- Make the *fleet* — every profile Proteus emits — reproduce real population
  spread and share **no learnable generator signature**, so membership in the
  Proteus cohort is not itself detectable (defeat V2b — see §9).
- Be **deterministic**: the same complete, versioned input set — persona request,
  seed, engine target, dataset, rules, schema, and generator — produces the same
  config (audit, team rebuild, portability).
- Run **fully offline**; datasets are local, updated via signed bundles.
- Encode known detection heuristics as **explicit, testable rules**.

**Non-goals**
- Producing the raw browser values themselves (that's the engine, tdd/01).
- Network egress (that's the sidecar, tdd/03).
- Guaranteeing any specific site — we optimize signals, not outcomes.

## 2. The four stages

```
persona params ─▶ (A) CONSTRAINT SAMPLER ─▶ candidate identity
                          │  joint distributions, not independent draws
                          ▼
                  (B) RULE VALIDATOR ─▶ pass / fail + reasons
                          │  encodes known detection heuristics
                          ▼
                  (C) RARITY SCORER ─▶ blend-in score; reject if too rare
                          │
                          ▼
                  (D) DETERMINISTIC EMITTER ─▶ signed profile config (schema)
```

If (B) fails or (C) rejects, resample within the same persona constraints (seed
advanced deterministically) until pass, or report why no coherent-common
identity is available for the requested persona (rare, but honest).

**M1A boundary:** that retry loop is target design, not current behavior. M1A
makes one deterministic draw and returns an honest error if no candidate exists
or strict validation fails. An attempt-indexed deterministic resampler remains
open work.

## 3. The persona model (the heart of coherence)

We do **not** sample fields independently. We sample a **persona = one plausible
real device**, then derive fields under it.

A persona is anchored by a small set of *primary* choices, each drawn from a real
distribution; everything else is *derived* or *constrained*:

```
Persona
├─ os            {name, version, arch}        ← from OS market-share distribution
├─ device class  {desktop|laptop}             ← conditioned on OS
├─ engine        {family, brand, version}     ← from browser-share dist, valid for OS
├─ gpu           {vendor, renderer family}    ← from GPU dist valid for OS+class
├─ screen        {resolution, dpr}            ← from real (OS, class)→screen dist
├─ region        {timezone, languages}        ← from proxy geo (or user choice)
└─ hardware      {cores, memory}              ← from (class)→hardware dist
```

**Derivation examples (all V1 defenses):**
- `navigator.platform`, `oscpu`, UA OS token ← `os`.
- WebGL vendor/renderer, WebGPU adapter ← `gpu` (and `gpu` was drawn *valid for
  the OS*, so no Apple GPU on Windows can occur).
- Font set ← `os` version (superset package).
- Client Hints ← `engine` + `os`.
- Timezone/Accept-Language ← `region` (defaulted from proxy geo).
- Concurrency/memory ← `device class` distribution (plausible pairs only).

The persona is the mechanism that makes independence-induced incoherence
*structurally impossible*, not merely checked-for.

## 4. Stage A — the constraint sampler

**Input:** persona parameters. Some may be user-pinned (e.g., "Windows 11, en-US,
proxy in Germany"); the rest are sampled.

**Method:** a **conditional joint model**. We model
`P(fields) = P(os)·P(engine|os)·P(gpu|os,class)·P(screen|os,class)·P(hw|class)·…`
using the real-distribution dataset (§7). Sampling walks the conditional chain
seeded by `seed`, so it is deterministic and coherent by construction.

**Pinning:** a user pin fixes a factor and we sample the rest *conditioned* on
it. If a pin makes the joint improbable (e.g., a GPU that never ships with the
pinned OS), the sampler refuses and explains (better an honest refusal than a
V1/V2 landmine).

**Target determinism:** every random draw uses a stream derived from
`HMAC(seed, "sampler/<factor>/<attempt>")`, so resampling is reproducible and
independent across factors and profiles. M1A currently implements the
domain-separated factor streams for one attempt; it does not yet advance the
`attempt` component.

## 5. Stage B — the rule validator

The sampler makes coherence *likely by construction*; the validator makes it
*guaranteed* and encodes specific, known detection heuristics as hard rules. This
is where we translate "what anti-bots check" into machine-checked invariants.

**Rule catalog (initial, extensible; each rule is a testable predicate):**

- **R-PLATFORM-GPU:** `navigator.platform` OS ⟺ GPU vendor family is possible on
  that OS. (No Apple renderer on Win32.)
- **R-UA-CH:** UA string tokens ⟺ Client Hints brands/platform/version/
  full-version-list, all mutually consistent and matching `engine`.
- **R-FONT-OS:** presented font set ⊇ OS core set ∧ ⊆ OS superset for `os.version`.
- **R-TZ-GEO:** `locale.timezone` consistent with `region`, and (when a proxy is
  attached) with the proxy's IP geolocation. Emits a *warning to the Manager* if
  the attached proxy contradicts, rather than silently shipping a mismatch.
- **R-LANG:** `navigator.languages[0]` head ⟺ `Accept-Language` head ⟺ region.
- **R-SCREEN-REAL:** (resolution, dpr, colorDepth) is a really-shipped tuple for
  (os, class); avail dims leave OS-appropriate chrome room.
- **R-HW-PAIR:** (hardwareConcurrency, deviceMemory) is a plausible pair for the
  device class (no 32-core/0.25GB).
- **R-WEBGL-WEBGPU:** WebGL GPU family ⟺ WebGPU adapter family (no RTX in WebGL,
  Intel in WebGPU).
- **R-MEDIA-OS:** enumerateDevices set and speech voices match `os`.
- **R-VERSION-LIVE:** `engine.version` is within the currently-plausible live
  window for that brand (not a version no longer in the wild → V2). Backed by the
  dataset's version-share table.
- **R-PERF-PRECISION:** claimed `performance.now` precision matches the claimed
  brand/version's real behavior.

**Output:** `Valid` or `Invalid{failed_rules, human_reasons}`. In the target
design, invalid triggers resampling (Stage A) or, if persistently infeasible, an
honest error to the user. M1A currently returns the validation error immediately.

**Extensibility:** rules are data-driven and pluginnable so the community can add
newly-discovered heuristics (Principle VII/VIII). Each rule ships with test
fixtures.

## 6. Stage C — the rarity scorer (blend-in, both directions)

**M1A status:** the current `rarity` result is a clearly labeled seed heuristic
derived from transparent candidate weights. It exercises the contract and
rejects invalid generation outcomes, but it is not an estimate of population
probability. The calibrated method below remains an M4 deliverable.

Coherent is necessary but not sufficient: a coherent one-in-ten-million device is
still a V2 signal *and* trackable. We score how well the candidate **blends in**
and reject the tail. Prior art exists for distribution-driven generation
(Apify's *browserforge* / *fingerprint-suite* sample from a Bayesian network over
real fingerprints); what we add is scoring blend-in on the *coarsened observable*,
exposing that score to the user, rejecting **both** tails (too-rare *and*
too-clean, §6a), and co-designing it with fleet de-correlation (§9). We treat the
combination, not distribution sampling alone, as the differentiator, and we say so
honestly rather than claiming to have invented sampling.

**Method:**
- For the *observable* fingerprint fields (the ones a site can actually read), we
  estimate the candidate's **population probability** from the same
  distributions, using the conditional model plus marginal frequencies of the
  most-probed surfaces (UA, platform, GPU string, resolution, timezone, font
  set, language).
- Combine into a **blend-in score** in [0,1] (roughly, how large a crowd shares
  a materially-indistinguishable configuration). We deliberately score on the
  *coarsened* observable (bucketed resolution, GPU family, etc.), because that is
  what the crowd shares — not the exact noised canvas value.
- **Reject** candidates below a configurable floor (default: prefer the modes;
  reject long-tail combinations). Prefer high-frequency values when sampling has
  a choice.

**What it deliberately does *not* do:** it does not chase a *single most common*
fingerprint for everyone — that would make all Proteus users identical, a
different V2/V2b problem and cross-user correlation risk (§9). It targets "in a
large, natural crowd," not "the mode singleton."

**Surfaced to the user:** the Manager shows the blend-in score and, if low, what's
making the profile rare ("this exact resolution+GPU pair is uncommon"), so the
user can choose a more common persona. Exposing this number to the user is itself
uncommon among tools; it directly attacks the second-biggest detection vector.

**Target interaction with noise:** native per-profile canvas/audio/WebGL noise
(tdd/01) will make the profile *stable-unique* for tracking-resistance at the
pixel level while the *coarse* observable stays common. The calibrated rarity
scorer will operate on the coarse observable and bound noise so it does not push
the coarse bucket into the tail. M1A carries only the fixed policy declaration,
not the native perturbation or its calibrated shape.

## 6a. Stage C′ — coherence as a distribution (defeating "too clean")

**M4 target; not implemented in M1A.** The current seed generator does not carry
an imperfection distribution and does not nudge a too-clean candidate. The
remainder of this section specifies the calibrated future behavior.

**The insight:** V2 has a second face (see
[threat model](../01-threat-model.md) §V2). Real populations are not perfectly
coherent. A meaningful fraction of real users run a browser a few point-releases
behind, keep a timezone they never corrected after moving, carry one unexpected
font a game or design tool installed, or use a slightly non-standard resolution
from a display-scaling setting. "How internally tidy is this device" is itself a
distribution, and a generator that always emits the *maximally* tidy, freshly
updated, imperfection-free persona lands in that distribution's thin tail — a
rarity signal that no single coherence rule flags, because nothing is
*contradictory*, only *implausibly perfect*.

**The response — sample imperfection, never incoherence.** We distinguish two
kinds of "flaw":

- **Incoherent flaws** (an Apple GPU under Win32, a timezone that fights the
  proxy) — a hard V1 kill. Never emitted; the rule validator (§5) forbids them.
- **Coherent imperfections** (a slightly-behind patch version still inside the
  live window, a plausible extra font that ships with common software on that OS,
  a real-but-less-common resolution for the device class) — *present in real
  populations*, coherent, and therefore realistic to include at their real rate.

The M4 generator will draw these from the dataset's **imperfection
distributions**, at
frequencies calibrated to the real world, seeded deterministically like every
other draw. A profile might get exactly the same tidiness a real device would:
usually clean, sometimes carrying one realistic quirk. The rule validator still
runs on the result, so an imperfection can never cross into incoherence.

**Bounds and honesty.** Every imperfection is itself a modeled, coherent value
with its own rule fixtures — we are widening the target from "the tidy mode" to
"the real coherence distribution," not injecting random noise. Imperfection rates
are dataset-versioned and auditable (Principle IV). This is co-designed with the
rarity scorer: §6 scores *which coarse bucket* you land in; §6a scores *how
plausibly tidy* the whole looks. A candidate that is too clean is nudged, not
mangled, back toward the realistic middle.

**Why almost nobody does this:** most tools treat coherence as a checkbox to
maximize. Modeling it as a distribution to *match* is harder, needs real data,
and only pays off against sophisticated detectors — which is exactly the frontier
we are trying to win. It is a concrete, testable differentiator.

## 7. The dataset

**M1A status:** the repository currently carries one versioned shared seed
dataset for the first Windows/Chrome target. Its weights are transparent
heuristics and the file is not yet a production signed distribution bundle. The
catalog and update system below describe the target M4 dataset.

**Contents (all versioned, signed bundles, local):**
- OS market-share by version; browser brand+version share (for R-VERSION-LIVE).
- GPU model distribution conditioned on OS/class, with the exact WebGL
  vendor/renderer strings and WebGPU adapter info each maps to.
- Real (OS, class) → screen resolution + DPR joint distribution.
- Per-OS-version font superset and core-set packages.
- Device concurrency/memory distributions by class.
- Media-device and speech-voice sets by OS.
- Locale/timezone reference (IANA) and geo→timezone mapping.

**Sources & ethics:**
- Public datasets and published telemetry where licensing permits.
- Vendor reference tables (GPU→string maps) built from public driver data.
- **Optional** opt-in aggregation from Proteus's own users under **differential
  privacy** (see §8 and [07-security-privacy.md](../07-security-privacy.md)) — no
  raw fingerprints ever collected; only DP-aggregated distribution updates.
- Every bundled artifact's license verified for redistribution (fonts
  especially; see
  [third-party licensing](../10-third-party-licensing.md)).

### 7a. The cold-start problem (the hardest non-engine problem)

**Stated plainly:** the DP telemetry loop (§8) only turns *after* we have a user
base, and the closed Class-A tools have a multi-year head start of real collected
fingerprints we deliberately will not replicate (we never collect raw
fingerprints). So the dataset's *initial* fidelity — before any network effect —
is a first-class, hard, **owned** problem, not a footnote. A stale or thin
starting distribution directly causes V2 rarity and V2b clustering, so this has a
named owner and a milestone, like any other correctness dependency.

**Concrete bootstrap sources (real, legal, refreshable):**
- **Chrome UX Report (CrUX)** and public web-analytics aggregates for
  OS/browser-version/device-class/viewport marginals and their joint structure.
- **Public UA-CH / User-Agent telemetry** (e.g., published browser-share and
  device datasets) for the version-live window (R-VERSION-LIVE) and brand share.
- **Vendor/driver reference data** for the exact WebGL/WebGPU vendor–renderer
  strings each real GPU emits, conditioned on OS — built from public driver
  packages, not scraped from users.
- **Public screen/DPI statistics** for real (OS, class)→resolution+DPR joints,
  including their tails (needed for §6a realistic imperfection).
- **Per-OS font manifests** derived from the OS's own shipped packages and the
  common-software fonts that realistically co-occur.
- **IANA/CLDR** for timezone/locale/geo reference (deterministic, licensed).
- **Opt-in DP telemetry (§8)** layered on top *once available*, to refine — never
  as the initial source.

**Bootstrap acceptance bar:** a candidate starting dataset must (a) reproduce the
published marginals of its sources within a documented tolerance, (b) preserve
the *joint* structure the rule validator depends on (no impossible pairs, real
pairs at real rates), and (c) pass the fleet de-correlation probe (§9) so the
starting distribution is not itself flat/quantized in a way that clusters. The
dataset ships versioned and signed with a provenance manifest naming every source
and its license.

**Sources & ethics (continued):**

**Freshness (Principle VIII):** distributions drift as new GPUs/OSes/browser
versions appear. Bundles are refreshed out-of-band and signed; the engine records
which dataset version produced a profile. Stale datasets are a correctness bug
(they cause V2 rarity), tracked like any other.

## 8. Optional DP telemetry for the dataset

Strictly opt-in, off by default (Principle V). If a user opts in:
- The client computes *local* contributions to coarse marginal counts (e.g., "one
  more Win11 + RTX3060 + 1920×1080 observation"), adds calibrated noise (local
  differential privacy), and submits only the noised aggregate delta.
- No raw fingerprint, no per-user identifier, no cross-field joins that could
  re-identify. Privacy budget accounted and documented.
- Result feeds the *next* signed dataset bundle, improving everyone's blend-in.
This is a virtuous loop that a closed tool can't credibly offer (Principle IV
transparency).

## 9. Fleet de-correlation (defeating V2b)

**M4 target; only a small M1A smoke check exists.** M1A checks deterministic
per-seed UUID/media-ID diversity across 128 seeds. It does not yet emit
per-profile noise-shape parameters, compare a generated fleet with a real
hold-out, or run the adversarial classifier. Its emitted noise policy is the same
fixed `hw-natural`/`subpixel` policy for every profile.

Two problems, one principle. **Local de-correlation:** two profiles on the same
machine must not be linkable through *our* artifacts. **Fleet de-correlation:**
the entire population of profiles Proteus emits — across *all* users — must not
carry a learnable generator signature that lets a detector flag "this was made by
Proteus" (V2b). The second is the harder, more strategic one, and it is the
vector that has historically killed stealth tools once they got popular enough to
profile. The target design addresses both by construction; the load-bearing
commitment is recorded in [adr/0007](../adr/0007-fleet-de-correlation.md).

**Target local (per-machine) de-correlation:**
- Native noise seeds will be per-profile and independent (`HMAC(seed_p, …)`), so
  canvas/audio/WebGL values do not share a hidden watermark.
- Sampler streams are per-profile independent.
- Native implementations must emit no constant "Proteus signature" or shared
  magic value across profiles.

**Fleet-level (cross-user) de-correlation — target V2b defenses:**
- **Independent noise *shape*, not just value.** It is not enough that two
  profiles get different canvas values; the *statistical shape* of the
  perturbation (its amplitude profile, spectral signature, quantization) must not
  be a constant across the fleet, or the shape itself becomes the cohort tell.
  Noise parameters will be drawn per-profile from a modeled range, not
  hard-coded.
- **Anti-clustering sampling.** The sampler must reproduce the real population's
  *spread*, including its tails (§6a), not collapse onto a handful of "safe"
  modal personas. If every Proteus user who asks for "most common US desktop"
  gets the *same* persona, that persona's over-representation is a fleet signal.
  The M4 sampler will sample proportional to real frequency (with the blend-in
  floor), so the fleet's joint distribution matches the world's rather than a
  flat or spiked synthetic one.
- **No bundled-artifact tell.** Identical font *byte-sets* presented across
  unrelated devices is a classic cohort signature. The font policy (tdd/01 §4.8)
  will present per-OS sets that match what that OS realistically ships; where we
  bundle, we will track whether the presented set is distinguishable from a real
  device's and keep it inside the realistic range rather than a single
  canonical Proteus bundle.
- **Distributional realism over convenience.** Any place we would otherwise take
  a shortcut that quantizes or flattens a distribution (rounding all DPRs,
  picking one canonical timezone per region) is a potential cohort tell and is
  called out in review.

**The future measurement that keeps it honest — the red-team classifier.** We
will not merely assert fleet de-correlation; we will *attack* it. The
verification lab will run an adversarial classifier
([tdd/06](06-verification-lab.md) §5a) trained to
distinguish "generated by Proteus" from real fingerprints across a large batch of
generated profiles. Its success is our regression metric: if it can learn the
cohort, we have a bug, and what it keys on becomes the next fix. This turns V2b
from an untestable worry into a measured, non-degrading gate (Principle VII).

## 10. API (embedded library)

```rust
// Illustrative, not final.
pub struct PersonaParams { /* pins + free factors */ }
pub struct Dataset { version: Version, /* … */ }

pub struct GeneratedProfile {
    pub config: ProfileConfig,   // serializes to the signed schema
    pub blend_in: f32,           // 0..1
    pub rarity_reasons: Vec<String>,
    pub provenance: Provenance,  // {seed, dataset_version, engine_version, rules_version}
}

pub fn generate(
    params: &PersonaParams,
    seed: &Seed,
    dataset: &Dataset,
    engine_target: &EngineTarget,   // family/brand/version window
) -> Result<GeneratedProfile, GenError>;

pub fn validate(config: &ProfileConfig, dataset: &Dataset) -> ValidationReport;
pub fn rescore(config: &ProfileConfig, dataset: &Dataset) -> RarityReport;
```

- `generate` = Stages A–D. `validate`/`rescore` let the Manager re-check an
  imported or edited profile (e.g., after a competitor import, or when a user
  attaches a proxy whose geo contradicts the timezone).
- Everything is deterministic given the complete versioned inputs;
  `provenance` records dataset, engine, rules, and generator versions alongside
  the config's seed/persona/schema fields for reproducibility and audit.

## 11. Interaction with the rest of the system

- **Manager (tdd/07):** calls `generate` on profile creation; shows blend-in;
  re-runs `validate` when a proxy is attached (R-TZ-GEO) and offers to fix the
  timezone from the proxy geo.
- **Engine (tdd/01):** consumes the emitted config; dev-build asserts re-check the
  same invariants as a second net.
- **Verification lab (tdd/06):** runs the rule set and correlation/rarity probes
  as CI gates.
- **Importers:** map competitor profile formats into `ProfileConfig`, then run
  `validate`+`rescore` and warn about any incoherence/rarity the import carries.

## 12. Testing strategy

**Implemented in M1A:** fixed golden config/signing vectors, independent Node
signature/tamper/conformance checks, semantic negative cases, and a 128-seed
determinism/validity plus UUID/media-ID uniqueness smoke loop. Native browser/runtime
tests, deterministic rejection/resampling, calibrated rarity/imperfection
evaluation, noise-shape variation, and population-scale correlation remain open.

The current cross-language gate separates four contracts instead of pretending
one checker proves all of them:

1. Draft 2020-12 JSON Schema owns the full structure, required/unknown fields,
   types, enums, nullable shape, UUID/base64/digest formats, and numeric bounds.
   The dependency-free score CLI also checks minimum root-envelope completeness
   so malformed configs fail closed before semantic scoring.
2. Ed25519 over the canonical, domain-separated input owns authorization and
   tamper detection.
3. Rust `validate()` and the independent Node config rules own semantic
   coherence. Complete current configs use generation-strict equality and must
   name an exact dataset engine target; runtime observations remain tolerant.
4. Rust `verify_reproducible()` owns exact HMAC-sampler replay. It rejects a
   semantically valid alternate candidate, font set, same-region timezone,
   derived media ID, rarity value/reasons, or policy field when that value was
   not the declared seed's exact output. Node intentionally does not clone the
   sampler.

- **Property tests:** for random personas, generated configs always pass all
  rules (coherence-by-construction invariant).
- **Golden tests:** fixed `{params, seed, dataset}` → fixed config (determinism).
- **Rule fixtures:** each rule has positive/negative fixtures; adding a rule adds
  fixtures.
- **Imperfection realism (§6a):** over many seeds, the *rate* of coherent
  imperfections (behind-window versions, extra fonts, non-standard resolutions)
  matches the dataset's declared distribution — never zero (too clean), never
  incoherent (a rule fires).
- **Rarity calibration:** verify blend-in scores correlate with actual population
  frequency on held-out distribution data.
- **Fleet de-correlation (§9, V2b):** generate a large batch of profiles and run
  the adversarial red-team classifier (tdd/06 §5a); assert it cannot separate
  Proteus profiles from a real hold-out above a small margin, and that the
  batch's joint (GPU, resolution, timezone, fonts) distribution matches the
  reference population's spread and tails rather than clustering.

## 13. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Dataset staleness → rarity | Signed refresh cadence; dataset version tracked; stale = bug |
| Cold-start dataset thin/biased → V2/V2b | Owned bootstrap workflow with named public sources + acceptance bar (§7a) |
| Over-optimizing to the mode → all users identical | Score "large crowd," not "singleton mode"; anti-clustering sampling; red-team classifier (§9) |
| Fleet carries a learnable generator signature (V2b) | Per-profile noise *shape*; distributional realism; adversarial classifier gate (§9, tdd/06 §5a) |
| "Too clean" profiles fall in the tail | Coherence-as-distribution: sample realistic imperfection (§6a) |
| Font-license limits distort OS realism | Coherent substitute sets; document gaps; per-font license check |
| Rules encode an *incorrect* heuristic → over-constrain | Rules are data + fixtures + community-reviewed; falsifiable |
| Proxy geo unavailable/wrong | R-TZ-GEO warns; Manager offers geo lookup; honest mismatch surfacing |
| DP telemetry privacy concerns | Off by default; local DP; documented budget; no raw data ever |

## 14. Open questions

- Exact form of the joint model (hierarchical conditional tables vs. a learned
  density) — start with transparent conditional tables (auditable, Principle IV)
  and revisit only if fidelity demands it.
- Blend-in floor default and whether to make it adaptive per target-site class.
- How aggressively to prefer modes vs. spread across the crowd (the
  de-correlation/blend-in balance) — tune with the red-team classifier and the
  correlation probe.
- Calibration of the §6a imperfection rates: how much realistic "mess" to inject
  before it starts *helping* correlation rather than hurting rarity — resolve
  empirically against the red-team classifier, not by taste.
- Architecture of the red-team classifier (§9): a fixed held-out reference corpus
  vs. an online adversary that co-evolves with the generator, and how to keep its
  training data legal and fresh without collecting raw user fingerprints.
- Governance of the community rule/dataset contributions (review bar to avoid a
  bad heuristic degrading everyone).
