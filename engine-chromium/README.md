# engine-chromium — Proteus Chromium engine (M0 worktree)

> **M0 status: contracts and GitHub-hosted reference workflow implemented;
> production execution backend pending.** This directory contains the active
> patch, exact source/dependency/toolchain contracts, platform build scripts,
> runtime packaging, artifact SBOM/license generation, six-run evidence
> producer, and strict verifier—but **it has no currently viable macOS runner
> backend and does not commit a Chromium checkout or produced binary.**
>
> That is deliberate and honest: a Chromium build needs **~100 GB of disk, 16 GB+
> RAM, `depot_tools`, and hours of compute** (or a warm `sccache`). It runs on the
> dedicated build farm described in
> [`docs/tdd/05-build-and-tracking.md`](../docs/tdd/05-build-and-tracking.md) §2,
> not on a laptop. The current workflow accepts only GitHub-hosted builders, whose
> configured macOS class lacks Chromium-scale storage. External-ephemeral
> verification is only a schema today; a trusted controller, pinned key,
> post-destruction receipt, and independent finalizer remain to be built. The
> hard gate establishes M0 only after real A/B outputs from all three platforms
> pass byte-level, Sigstore, and GitHub-identity checks.

## What M0 delivers here

| Piece | File(s) | State |
|---|---|---|
| Active M0 series + future patch backlogs | `patches/series`, `patches/backlog/*.series`, `patches/**/*.patch` | 1 active real M0 layer0 patch; 15 M1 + 1 M3 placeholder specifications are excluded from M0 apply/hash |
| Deterministic patch-catalog validator | `scripts/check-series.mjs` | **Runs now** — validates disjoint ownership, ordering, milestone/status and rationale headers |
| Strict immutable baseline | `CHROMIUM_BASELINE`, `scripts/baseline.mjs` | **Runs now** — exact canonical origins and 40-hex Chromium/depot_tools commits; rejects shell/unknown/duplicate input |
| Fetch + sync (depot_tools) | `scripts/fetch-chromium.sh` | Requires fresh ephemeral roots, pins both repositories, disables depot auto-update, controls `.gclient`, and verifies tag/HEAD before and after sync; network-heavy integration not exercised here |
| Apply active series (rebase-friendly) | `scripts/apply-patches.mjs` (`.sh` compatibility wrapper) | Production mode requires the exact clean baseline, applies the real active patch, and verifies the resulting index tree; future backlogs are never read |
| Build (gn + ninja) | `scripts/build.sh` | Infrastructure-bound; rejects unlocked cache wrappers and verifies pinned depot/source + exact active-patch tree before building |
| Platform build/finalization | `scripts/build-{linux,macos,windows}.*`, `scripts/finalize-m0-build.*` | Fetches, patches, builds, captures effective args/toolchains/runtime closure, packages the complete bundle, drives the live ruler, and emits the artifact SBOM |
| Hard-M0 producer + verifier | `scripts/m0-build-record.mjs`, `../scripts/m0-evidence-v2.mjs` | Produces canonical predicates/records and independently recomputes all bundle/API/attestation facts at `full-bundle-builder-attested/v2` |
| Six-run reference workflow | `../.github/workflows/m0-{builder,aggregate,hard-gate}.yml` | Defines one fresh GitHub-hosted run per platform/slot and six-run verification; production runner/controller integration remains open |
| Reproducible-build flags + legacy provenance | `scripts/provenance.mjs`, `build/args.gn` | **Runs now**; the demo remains explicitly below the v2 hard gate |
| Version-tracking bot pipeline | `tracking-bot/pipeline.mjs` | **Runs now** in `--dry-run`; a state-machine scaffold, not proof that real stages integrate |
| Repository component metadata check | `scripts/sbom.mjs` | **Runs now** — declares current repository components, including Chromium source context, in a clearly marked CycloneDX-shaped stub; not a production SBOM or redistribution decision |
| Scaffold honesty regression test | `test/scaffold-honesty.mjs` (`.sh` compatibility wrapper) | **Runs now** — cross-platform checks cover baseline injection/ambiguity, catalog isolation, checkout/fetch pins, placeholder rejection, provenance, and SBOM markers |

"Runs now" means only that the command executes in this environment without a
Chromium checkout. It does not certify the unexercised infrastructure-bound
integration or a successful Chromium build.

## The honest boundary (Principle IV, VI)

- We do **not** claim a green Chromium build until the six real builder runs
  and hard gate succeed. The active layer0 patch is real and defaults
  Google-backed Network Time querying off, but an explicit feature override can
  re-enable it. It is deliberately bounded and is not complete de-Googling.
  Sixteen future specifications are catalogued but do not gate M0.
- Reproducibility and SLSA provenance are **designed in from the first build**
  (Principle VI), not bolted on — see `scripts/provenance.mjs` and `build/args.gn`.
- The VERIFY step calls the artifact-driven verification lab and binds its
  report to the packaged entrypoint. Each platform build also runs Chromium's
  exact default-disabled Network Time unit test; the live report gracefully
  closes Chromium, reads one stable bounded NetLog, and fails if the default
  Google time endpoint appears. That integration still has to be exercised by
  the first real six-build run.
- Machine live-drive reports require a caller-claimed external disposable
  runner and label local process cleanup as best-effort. The hard exit still
  needs builder-attested VM/container/job containment; a CLI flag is not proof.
- GitHub larger-runner labels used by the reference builder must begin with an
  API-verifiable OS family (`linux-`/`ubuntu-`, `windows-`, or
  `macos-`/`darwin-`). Linux and Windows builds require X64 hosts; macOS may use
  X64 or ARM64 while producing both universal slices.
- The legacy v1 evidence hashes one executable entrypoint. The v2 hard path
  instead requires the complete bundle tree, independent builder/workflow
  identities, raw Sigstore bundles, effective generated GN args, resolved
  dependencies, and fully captured platform toolchains.
- `scripts/sbom.mjs` inventories current repository declarations, including the
  BSD-3-Clause Chromium source context carried by the active patch, and
  deliberately excludes planned engines and external packages. A release still
  requires the artifact-derived SBOM, exact notices, and accompanying materials
  described in
  [`docs/10-third-party-licensing.md`](../docs/10-third-party-licensing.md).

## Layout

```
engine-chromium/
├─ patches/
│  ├─ series                       sole active build/hash input
│  ├─ backlog/
│  │  ├─ m1.series                 15 future M1 specifications
│  │  └─ m3.series                 1 future M3 specification
│  ├─ layer0-degoogle/              Proteus Network Time default-off patch
│  ├─ layer1-fingerprint/           our core IP: config ingest + native surfaces
│  └─ layer2-antiautomation/        anti-CDP, stealth endpoint
├─ scripts/
│  ├─ baseline.mjs                  strict source/tool pin parser (runs now)
│  ├─ patch-series.mjs              shared active/catalog contract (runs now)
│  ├─ chromium-checkout.mjs         exact source/tree preflight (runs now)
│  ├─ depot-tools-checkout.mjs      exact depot_tools preflight (runs now)
│  ├─ check-series.mjs              validate active + backlog catalog (runs now)
│  ├─ fetch-chromium.sh             exact-commit depot_tools/Chromium sync
│  ├─ apply-patches.mjs             apply active series, localize failures
│  ├─ apply-patches.sh              POSIX compatibility wrapper
│  ├─ build.sh                      pinned-checkout gn + ninja entrypoint
│  ├─ provenance.mjs                reproducible-build manifest + SLSA skeleton (runs now)
│  └─ sbom.mjs                      current-scope component stub (runs now)
├─ test/
│  ├─ scaffold-honesty.mjs          cross-platform fail-closed regression checks
│  └─ scaffold-honesty.sh           POSIX compatibility wrapper
├─ tracking-bot/
│  └─ pipeline.mjs                  the version-tracking state machine (runs now, --dry-run)
├─ build/
│  └─ args.gn                       reproducible-build gn args (documented)
└─ CHROMIUM_BASELINE                immutable repositories/commits/profile
```

## Try the parts that run now

```bash
cd engine-chromium

# Validate the active/backlog catalog (deterministic, no Chromium needed):
node scripts/check-series.mjs

# Validate only the M0 build input; future backlogs cannot affect this result:
node scripts/check-series.mjs --active

# Inspect the strict source/tool baseline:
node scripts/baseline.mjs --json

# Generate a reproducible-build provenance document for a (hypothetical) artifact:
node scripts/provenance.mjs --demo

# Bind a real packaged file to its exact source/build invocation:
node scripts/provenance.mjs \
  --artifact /path/to/packaged-engine \
  --effective-gn-args /path/to/out/Proteus/args.gn \
  --chromium-commit <full-commit> \
  --platform linux-x64 \
  --invocation-id <ci-run-id>

# Inspect the active catalog without modifying a checkout.
PROTEUS_CHROMIUM_SRC=/path/to/chromium \
  node scripts/apply-patches.mjs --allow-placeholders

# Apply the real active patch to the exact clean pinned checkout.
PROTEUS_CHROMIUM_SRC=/path/to/chromium \
  node scripts/apply-patches.mjs

# Emit the current-repository component stub (not a production SBOM):
node scripts/sbom.mjs

# Run the cross-platform scaffold honesty regression checks:
node test/scaffold-honesty.mjs

# Dry-run the whole version-tracking pipeline (no network, no build):
node tracking-bot/pipeline.mjs --dry-run
```

See [`docs/tdd/05-build-and-tracking.md`](../docs/tdd/05-build-and-tracking.md) and
[`docs/tdd/01-chromium-engine.md`](../docs/tdd/01-chromium-engine.md) for the full
design these scaffolds implement.
