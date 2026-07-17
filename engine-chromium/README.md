# engine-chromium — Proteus Chromium engine (M0 scaffold)

> **M0 status: scaffold, not a build.** This directory contains interfaces and
> early tooling for a future modified Chromium engine — the layered patch-series
> specification, build-script scaffolds, a version-tracking state-machine
> scaffold, and provenance/SBOM document scaffolds — but **it does not contain a
> Chromium checkout, real patch hunks, or a produced binary.**
>
> That is deliberate and honest: a Chromium build needs **~100 GB of disk, 16 GB+
> RAM, `depot_tools`, and hours of compute** (or a warm `sccache`). It runs on the
> dedicated build farm described in
> [`docs/tdd/05-build-and-tracking.md`](../docs/tdd/05-build-and-tracking.md) §2,
> not on a laptop inside a planning session. These files make the planned stages
> inspectable and test their fail-closed boundaries. They do not establish that a
> real fetch, patch, build, verification, or release pipeline is correct.

## What M0 delivers here

| Piece | File(s) | State |
|---|---|---|
| Layered patch series (layer0/1/2) with rationale headers | `patches/series`, `patches/**/*.patch` | Ordered specification only; every current series entry is a documented placeholder with no diff hunks |
| Deterministic patch-series validator | `scripts/check-series.mjs` | **Runs now** — validates every patch has the required headers and the series file is consistent |
| Fetch + sync (depot_tools) | `scripts/fetch-chromium.sh` | Infrastructure-bound script scaffold; not exercised here |
| Apply patch series (rebase-friendly) | `scripts/apply-patches.mjs` (`.sh` compatibility wrapper) | Production mode rejects any placeholder before touching the checkout; `--allow-placeholders` is scaffold inspection only |
| Build (gn + ninja + sccache) | `scripts/build.sh` | Infrastructure-bound script scaffold; not exercised here |
| Reproducible-build flags + provenance | `scripts/provenance.mjs`, `build/args.gn` | **Runs now**; real mode requires an ordinary artifact file, while explicit `--demo` hashes a documented sentinel |
| Signed entrypoint-evidence layer | `scripts/assemble-m0-evidence.mjs`, `../scripts/m0-evidence.mjs` | Implementation and fixture regressions run; real assembly awaits governed pinned-public-key provisioning and genuine build outputs, and remains below the full-bundle, builder-attested hard-M0 assurance level |
| Version-tracking bot pipeline | `tracking-bot/pipeline.mjs` | **Runs now** in `--dry-run`; a state-machine scaffold, not proof that real stages integrate |
| Repository component metadata check | `scripts/sbom.mjs` | **Runs now** — names only current first-party components in a clearly marked CycloneDX-shaped stub; not a production SBOM or redistribution decision |
| Scaffold honesty regression test | `test/scaffold-honesty.mjs` (`.sh` compatibility wrapper) | **Runs now** — eight cross-platform checks cover placeholder rejection, provenance input validation, digest shape, and SBOM UUID/stub markers |

"Runs now" means only that the command executes in this environment without a
Chromium checkout. It does not certify the unexercised infrastructure-bound
integration or a successful Chromium build.

## The honest boundary (Principle IV, VI)

- We do **not** claim a green Chromium build, applied patch series, correct
  end-to-end pipeline, or production-ready artifact in M0. The current patch
  files are placeholders, and production patch application therefore fails.
- Reproducibility and SLSA provenance are **designed in from the first build**
  (Principle VI), not bolted on — see `scripts/provenance.mjs` and `build/args.gn`.
- The planned VERIFY step is intended to call the verification lab on real
  infrastructure; that integration still has to be exercised and proven.
- Machine live-drive reports require a caller-claimed external disposable
  runner and label local process cleanup as best-effort. The hard exit still
  needs builder-attested VM/container/job containment; a CLI flag is not proof.
- Current evidence hashes one executable entrypoint. The hard exit additionally
  requires a canonical manifest for the complete engine bundle, independent
  builder/workflow attestations, effective generated GN args, and the fully
  pinned compiler/gn/ninja/depot_tools/cache toolchain.
- The formal M0 release public key has not been provisioned in the repository.
  Tests create isolated fixture keys; they do not stand in for release-key
  governance.
- `scripts/sbom.mjs` inventories current first-party repository components only
  and deliberately excludes planned engines and external packages. A release
  still requires the artifact-derived SBOM, exact notices, and accompanying
  materials described in
  [`docs/10-third-party-licensing.md`](../docs/10-third-party-licensing.md).

## Layout

```
engine-chromium/
├─ patches/
│  ├─ series                       ordered, layered list (applied top-to-bottom)
│  ├─ layer0-degoogle/              upstream-ish de-Google (ungoogled-derived)
│  ├─ layer1-fingerprint/           our core IP: config ingest + native surfaces
│  └─ layer2-antiautomation/        anti-CDP, stealth endpoint
├─ scripts/
│  ├─ check-series.mjs              validate patch headers + series (runs now)
│  ├─ fetch-chromium.sh             depot_tools fetch/sync to a pinned tag
│  ├─ apply-patches.mjs             apply the series, localize failures
│  ├─ apply-patches.sh              POSIX compatibility wrapper
│  ├─ build.sh                      gn + ninja + sccache
│  ├─ provenance.mjs                reproducible-build manifest + SLSA skeleton (runs now)
│  └─ sbom.mjs                      current-scope component stub (runs now)
├─ test/
│  ├─ scaffold-honesty.mjs          cross-platform fail-closed regression checks
│  └─ scaffold-honesty.sh           POSIX compatibility wrapper
├─ tracking-bot/
│  └─ pipeline.mjs                  the version-tracking state machine (runs now, --dry-run)
├─ build/
│  └─ args.gn                       reproducible-build gn args (documented)
└─ CHROMIUM_BASELINE                the pinned upstream version we track
```

## Try the parts that run now

```bash
cd engine-chromium

# Validate the patch series structure + headers (deterministic, no Chromium needed):
node scripts/check-series.mjs

# Generate a reproducible-build provenance document for a (hypothetical) artifact:
node scripts/provenance.mjs --demo

# Bind a real packaged file to its exact source/build invocation:
node scripts/provenance.mjs \
  --artifact /path/to/packaged-engine \
  --chromium-commit <full-commit> \
  --platform linux-x64 \
  --invocation-id <ci-run-id>

# Inspect patch placeholders without claiming they were applied.
# Production use omits this flag and currently fails closed.
PROTEUS_CHROMIUM_SRC=/path/to/chromium \
  node scripts/apply-patches.mjs --allow-placeholders

# Emit the current-repository component stub (not a production SBOM):
node scripts/sbom.mjs

# Run the eight cross-platform scaffold honesty regression checks:
node test/scaffold-honesty.mjs

# Dry-run the whole version-tracking pipeline (no network, no build):
node tracking-bot/pipeline.mjs --dry-run
```

See [`docs/tdd/05-build-and-tracking.md`](../docs/tdd/05-build-and-tracking.md) and
[`docs/tdd/01-chromium-engine.md`](../docs/tdd/01-chromium-engine.md) for the full
design these scaffolds implement.
