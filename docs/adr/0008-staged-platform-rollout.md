# ADR 0008 — Stage host support: Linux first

**Status:** Accepted · **Date:** 2026-07-18 · **Serves:** Principles IV, VI,
VII, VIII

## Context

The project is maintained by an individual developer and a full Chromium build
needs substantially more disk, memory, and wall time than a standard hosted CI
runner provides. Linux and Windows can be developed on owner-controlled
hardware, while macOS requires separate Apple hardware or rented capacity.
Supporting every host at once also multiplies toolchain and runtime-debugging
work before the first engine exists. The current hard-M0 assurance model adds a
second unresolved problem: it needs independently authenticated, disposable
builders rather than a long-lived personal machine.

Waiting for equal three-platform infrastructure would stop useful engine work.
Silently removing macOS or Windows from the existing M0 contract would instead
weaken a published reproducibility and supply-chain claim. The plan needs a
checkpoint that unblocks development while keeping those statements
distinguishable.

## Options

1. **Block all engine development on the existing three-platform hard M0.**
   This preserves one gate but makes macOS and Windows capacity a prerequisite
   for Linux engine work.
2. **Redefine M0 as Linux-only.** This is cheaper, but would make the current
   schemas, workflows, commands, and documentation overstate what one
   developer-owned machine proves.
3. **Add a non-release Linux checkpoint and preserve hard M0.** Use a separate
   Actions lane and evidence namespace for Linux development; add macOS and
   Windows later; keep the existing three-platform gate unchanged.

## Decision

**Adopt option 3.**

The near-term platform checkpoint is named **M0-Linux — Linux development
checkpoint**:

- Scope is Linux x64 engine build/runtime work. It contains no Manager or UI
  work.
- GitHub Actions remains the orchestrator. The workflow is manually dispatched
  from the pinned `main` commit onto an owner-controlled self-hosted Linux
  runner.
- A manual shell build may shorten iteration, but it does not count toward the
  checkpoint.
- Linux first completes one integration build, then A and B builds from clean
  roots for the same commit. Their complete bundle trees must match
  byte-for-byte.
- The build must retain the exact source/active-series inputs,
  `components_unittests`, the Network Time assertions, runnable packaging,
  artifact-driven verification report, dependency/toolchain records, licenses,
  SBOM, manifest, and build records.
- Its assurance is explicitly **developer-attested**. Reusing developer-owned
  hardware can provide useful determinism evidence, but not independent builder
  identity or destruction proof.

The existing **M0 — Foundations & the ruler** remains the hard milestone.
Planning prose may call its complete three-platform exit **M0-Full** to avoid
ambiguity, but machine-facing contract, schema, workflow, patch metadata, and
command names remain `M0`. It still requires independent A/B builds for Windows
x64, macOS universal, and Linux x64 and the existing
`full-bundle-builder-attested/v2` assurance.

macOS host support, universal packaging, runtime verification, signing, and
parity are deferred together with Windows x64 host build/runtime support. They
form the next platform-completion phase after M0-Linux; this decision does not
set an order between macOS and Windows. Lightweight macOS and Windows contract
tests may continue to protect portable shared code. They are not host-support
claims.

Passing M0-Linux unlocks non-UI M1 native-engine implementation and runtime
testing on Linux. It does not:

- satisfy `npm run m0:milestone`;
- claim macOS, Windows, or three-platform host support;
- authorize a release;
- satisfy the existing hard-M0 provenance or supply-chain assurance boundary;
- complete roadmap M1 by itself.

This ADR sequences build/runtime **host platforms**. It does not change the
profile persona schema or M1A's current Windows 11 persona dataset.

## Runner security boundary

The self-hosted Linux development lane is deliberately separate from workflows
that process untrusted contributions:

- it is `workflow_dispatch`-only and accepts the exact default-branch commit;
- pull-request and fork events cannot target it;
- permissions are least-privilege and no unrelated repository secrets are
  exposed;
- runner registration is single-job/ephemeral where practical, and build roots
  are recreated for every run;
- records must identify the self-hosted, developer-attested lifecycle honestly.

These controls reduce risk to a personal workstation. They do not turn it into
the independently provisioned and destroyed environment required by hard M0.

## Consequences

- Linux engine work can advance before macOS and Windows host capacity exists.
- Two clean Linux development builds are needed for the M0-Linux exit after the
  initial bring-up run, so the checkpoint still measures reproducibility rather
  than only compilation.
- A new workflow, fixed single-platform Linux development contract, evidence
  namespace, and downgrade tests must be implemented. The current hard builder
  must not gain a permissive self-hosted mode.
- macOS and Windows remain visible technical debt and prerequisites for any
  three-platform release/support statement.
- The eventual hard runner choice—larger hosted runners or a trusted
  external-ephemeral controller/finalizer—remains open and can use timing data
  gathered from M0-Linux.
