# Proteus Verification Lab — the ruler

> M0 deliverable. This is the measurement layer described in
> [`docs/tdd/06-verification-lab.md`](../docs/tdd/06-verification-lab.md). It exists
> so that every later engine change is **measurable** (Principle VII): you cannot
> improve what you cannot measure, and an anti-detect browser that silently
> regresses is worse than useless.

It scores a browser fingerprint (or a Proteus profile config) against the
threat-model vectors **V1–V5** and — the actionable part — extracts the **exact
inconsistencies**, e.g. *"timezone (America/New_York) contradicts proxy geo (DE)"*
rather than a bare number.

The scoring CLI and local server have **zero runtime dependencies**: they use
Node ESM and built-ins only. The integration test suite additionally uses the
root-locked Ajv packages for full Draft 2020-12 schema validation; run
`npm ci` once from the repository root before `npm run verify:tests`.

## Quick start

```bash
cd verify-lab

# Run the lab's own tests (fixtures + determinism). This is the CI gate.
node bin/verify-lab.mjs selftest

# Score a fingerprint or profile config, human-readable:
node bin/verify-lab.mjs score fixtures/good-windows-chrome.json
node bin/verify-lab.mjs score fixtures/bad-v1-apple-gpu-on-windows.json --json

# The local M0 ruler-subset gate (the hard milestone gate is run from repo root):
node bin/verify-lab.mjs m0-gate

# Serve the local, offline probe page — open it in any browser and click
# "Test this browser". Nothing leaves your machine (Principle V).
node bin/verify-lab.mjs serve --port 8791

# Drive a REAL headless Chrome against the probe page and score its live
# fingerprint (needs Node 22+, Chrome/Chromium, and `serve` running):
node tools/drive-chrome.mjs

# Emit a signed-evidence input report. Machine mode does NOT use `serve`: it
# starts a private IPv4-loopback server for the fixed, hashed headless probe,
# rejects --url, talks through CDP pipe fds 3/4, and captures a bounded Chromium
# NetLog which must show no default Google Network Time query during collection.
# It must run inside an externally enforced disposable runner.
node tools/drive-chrome.mjs --json --external-containment \
  --chrome /path/to/engine-executable \
  --platform linux-x64 \
  --linux-sandbox /root-owned/mode-4755/chrome_sandbox \
  > /path/to/verification-report.json
```

## What it measures

| Vector | Meaning | Example rule |
|---|---|---|
| **V1** coherence | fields agree with each other + proxy | `R-PLATFORM-GPU` (no Apple GPU on Win32) |
| **V2** rarity | how common (blend-in) vs. a matter of degree | `R-VERSION-LIVE` (version in the live window) |
| **V3** traces | no injection tells | `R-NATIVE-TOSTRING`, `R-CROSS-CONTEXT` |
| **V4** network | TLS/H2 parity, no leaks | `R-TLS-PARITY`, `R-NO-WEBRTC-LEAK` |
| **V5** automation | no CDP/webdriver tells | `R-NO-WEBDRIVER`, `R-NO-RUNTIME-LEAK` |

## The scoring model (why a single tell caps the score)

Two rules from the threat model, made concrete in
[`src/score.mjs`](src/score.mjs):

1. **Deterministic tells gate the verdict ("no green-washing").** A rule marked
   `fatal` (webdriver true, Apple GPU on Windows, TLS mismatch, cross-context
   leak) is something a real detector acts on *by itself* — so it caps the
   aggregate into "detectable" no matter how clean everything else is. Clean
   vectors cannot average a real tell away, because detectors don't average.
2. **Coherence dominates (Principle I).** A V1 failure yields the most severe
   verdict, `detectable-incoherent`.

`soft` failures (V2 rarity) are matters of degree: they pull the score down a
gradient and can land a profile on `borderline`, but do not by themselves mean
"caught."

Verdicts: `blends-in` ≥ 90% and no tells · `borderline` ≥ 70% soft-only ·
`detectable` (a tell fired) · `detectable-incoherent` (a V1 tell fired).

## Structure

```
bin/verify-lab.mjs     CLI: score · selftest · serve · m0-gate
src/
  rules.mjs            Node rule catalog (V1–V5), version-locked to Rust (tdd/06 §4)
  score.mjs            per-vector + gated aggregate + inconsistency extraction
  normalize.mjs        maps a profile-config OR a probe collection → one observation
  report.mjs           human-readable report (inconsistency list is the hero)
  selftest.mjs         runs every fixture against its declared _expect block
  reference.mjs        Node loader for the reference dataset
  reference-util.mjs   pure helpers (browser-safe, no node:fs)
  browser-close.mjs    bounded Browser.close write/normal-exit protocol
  cdp-pipe.mjs         bounded NUL-framed CDP client over child fds 3/4
  controlled-probe.mjs fixed two-file probe server + byte-level binding
  network-time-audit.mjs stable NetLog reader + default-query audit
  artifact-report.mjs  recomputed machine baseline report builder
data/reference.json    coherence reference data (OS↔platform, GPU-per-OS, fonts, tz…)
probe-page/            the offline, in-browser detection page (index.html + collect.js)
fixtures/              known-good / known-bad profiles; the lab tests itself on these
tools/drive-chrome.mjs drive real headless Chrome and score its live fingerprint
test/run-tests.mjs     integration: full Draft 2020-12 schema + reference/conformance checks
```

## Shared source of truth

The Node lab and Rust fingerprint engine have independent rule
implementations, intentionally version-locked through `RULES_VERSION`, the
exact shared dataset digest, fixed vectors, and cross-language conformance
tests. This catches drift without pretending two language implementations are a
single source file. `data/reference.json` is the seed dataset; the full
distribution-backed dataset arrives in M4 (tdd/02 §7).

## A note the M0 live-drive already taught us

Running `tools/drive-chrome.mjs` against the actually-installed Chrome 150
immediately caught that the seed `liveVersionWindow` was stale (it lowballed the
window and false-flagged current Chrome). That is exactly the "stale dataset → V2
false signal" risk from tdd/02 §7 — and it demonstrates why the ruler drives real
browsers, not just fixtures. The window was corrected; staleness stays a tracked
data-refresh concern.

## Limits (honest, per Principle IV)

- The page-side V3 probes run real checks, but **V4 (network)** cannot be judged
  by page JS — it needs the sidecar/controlled-origin harness (tdd/03, tdd/06
  §3c). Those fields score `na` here, never a fabricated pass.
- The reference data is a curated **seed**; some rules are conservative to avoid
  false positives. Breadth grows with the M4 dataset and community probe
  contributions (tdd/06 §6).
- A machine report binds the launched entrypoint digest, executable header,
  controlled probe bytes, raw observation, and recomputed score. It is not an
  independent build or execution attestation: the hard M0 release gate still
  requires a complete engine-bundle manifest and builder-authenticated live run.
- `--external-containment` is a caller acknowledgement, not an attestation.
  Process-group/`taskkill` teardown is best-effort and cannot contain a hostile
  process that deliberately escapes its group or job. Machine mode therefore
  refuses to run without an externally enforced disposable VM/container/job;
  hard M0 additionally requires the builder/orchestrator to attest that boundary.
- Linux machine mode also requires `--linux-sandbox` to name a canonical,
  root-owned ordinary file with exact mode `4755`. The builder installs its
  freshly built `chrome_sandbox` into a root-controlled directory and the
  harness passes it through `CHROME_DEVEL_SANDBOX`; `--no-sandbox` is never used.
