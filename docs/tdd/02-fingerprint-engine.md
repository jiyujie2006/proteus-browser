# TDD 02 — Fingerprint Engine (Consistency & Rarity)

**Status:** M1A core implemented; full M1/M4 scope pending · **Serves
principles:** I, IV, V, VIII · **Threat vectors:** V1 (incoherence), V2 (rarity)

This subsystem turns "we *can* set any value" (tdd/01) into "we set values that
look like a real, common device." It is a pure, local Rust library embedded in
the Manager. It is the difference between Proteus and tools that randomize fields
independently.

> **Current boundary:** M1A implements a strict Rust model, deterministic
> generation and semantic validation for Chrome 150 on Windows 11
> desktop/laptop, Ed25519 signing/fail-closed reload, fixed vectors, and
> independent Node conformance. Its transparent versioned seed weights are
> heuristics, not population telemetry. Calibrated distribution-backed rarity,
> signed dataset bundles, native browser consumption, and runtime/cross-context
> proof remain future work.

## 1. Goals & non-goals

**Goals**
- Generate a **coherent** identity: every field agrees with every other and with
  the proxy (defeat V1).
- Make the coherent whole **common**, not rare; score and expose blend-in
  (defeat V2).
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

**Determinism:** every random draw uses a stream derived from
`HMAC(seed, "sampler/<factor>/<attempt>")`, so resampling is reproducible and
independent across factors and profiles.

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

**Output:** `Valid` or `Invalid{failed_rules, human_reasons}`. Invalid triggers
resample (Stage A) or, if persistently infeasible, an honest error to the user.

**Extensibility:** rules are data-driven and pluginnable so the community can add
newly-discovered heuristics (Principle VII/VIII). Each rule ships with test
fixtures.

## 6. Stage C — the rarity scorer (the novel part)

**M1A status:** the current `rarity` result is a clearly labeled seed heuristic
derived from transparent candidate weights. It exercises the contract and
rejects invalid generation outcomes, but it is not an estimate of population
probability. The calibrated method below remains an M4 deliverable.

Coherent is necessary but not sufficient: a coherent one-in-ten-million device is
still a V2 signal *and* trackable. We score how well the candidate **blends in**
and reject the tail.

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
different V2 problem and cross-user correlation risk (§9). It targets "in a large,
natural crowd," not "the mode singleton."

**Surfaced to the user:** the Manager shows the blend-in score and, if low, what's
making the profile rare ("this exact resolution+GPU pair is uncommon"), so the
user can choose a more common persona. Almost no other tool exposes this; it
directly attacks the second-biggest detection vector.

**Interaction with noise:** per-profile canvas/audio/WebGL noise (tdd/01) makes
the profile *stable-unique* for tracking-resistance at the pixel level, but the
*coarse* observable stays common. The rarity scorer operates on the coarse
observable; the noise amplitude is bounded (hw-natural) so it never pushes the
coarse bucket into the tail. These two are explicitly co-designed, not in
tension.

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
- Every bundled artifact's license verified for redistribution (fonts especially;
  see [NOTICE](../../NOTICE)).

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

## 9. Cross-profile de-correlation

Two profiles on the same machine must not be linkable through *our* artifacts:
- Noise seeds are per-profile and independent (`HMAC(seed_p, …)`), so canvas/
  audio/WebGL values don't share a hidden watermark.
- Sampler streams are per-profile independent.
- We avoid emitting a constant "Proteus signature" anywhere (no shared magic
  value across profiles — that would be a catastrophic cross-user V2/V3 tell).
- The verification lab includes a **correlation probe**: generate N profiles,
  confirm no shared distinguishing artifact and that their coarse observables
  spread across the crowd rather than clustering.

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
tests, calibrated rarity evaluation, and population-scale correlation remain
open.

- **Property tests:** for random personas, generated configs always pass all
  rules (coherence-by-construction invariant).
- **Golden tests:** fixed `{params, seed, dataset}` → fixed config (determinism).
- **Rule fixtures:** each rule has positive/negative fixtures; adding a rule adds
  fixtures.
- **Rarity calibration:** verify blend-in scores correlate with actual population
  frequency on held-out distribution data.
- **De-correlation:** N-profile correlation probe (as §9).

## 13. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Dataset staleness → rarity | Signed refresh cadence; dataset version tracked; stale = bug |
| Over-optimizing to the mode → all users identical | Score "large crowd," not "singleton mode"; de-correlation probe |
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
  de-correlation/blend-in balance) — tune with the correlation probe.
- Governance of the community rule/dataset contributions (review bar to avoid a
  bad heuristic degrading everyone).
