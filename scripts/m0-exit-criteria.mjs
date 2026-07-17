#!/usr/bin/env node
// m0-exit-criteria.mjs — local M0 scaffold gate + honest milestone audit.
//
// Default mode verifies only what can run without a Chromium checkout. Passing
// means "the local ruler/tooling scaffold is ready", not "M0 is complete".
// `--milestone` additionally enforces the hard roadmap criteria and therefore
// remains red until the real active patch applies to the exact clean checkout
// and full-bundle, builder-attested evidence exists at the required assurance.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runTrackingPipeline } from '../engine-chromium/tracking-bot/pipeline.mjs';
import { loadReference } from '../verify-lab/src/reference.mjs';
import { RULES_VERSION, runRules } from '../verify-lab/src/rules.mjs';
import {
  patchSeriesSha256,
} from './m0-evidence.mjs';
import {
  M0_EVIDENCE_V2_ASSURANCE_LEVEL,
  verifyM0EvidenceV2,
} from './m0-evidence-v2.mjs';
import {
  readChromiumBaseline,
} from '../engine-chromium/scripts/baseline.mjs';
import {
  auditActivePatchSeries,
  patchHasPayload,
} from '../engine-chromium/scripts/patch-series.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, '..');

let pass = 0, fail = 0;
const results = [];
const milestoneResults = [];
const requireMilestone = process.argv.includes('--milestone');

function check(label, fn, { scaffold = false } = {}) {
  let ok = false, detail = '';
  try { const r = fn(); ok = r.ok; detail = r.detail || ''; }
  catch (e) { ok = false; detail = e.message.split('\n')[0]; }
  results.push({ label, ok, detail, scaffold });
  if (ok) pass++; else fail++;
}

function milestoneCheck(label, fn) {
  let ok = false, detail = '';
  try { const r = fn(); ok = r.ok; detail = r.detail || ''; }
  catch (e) { ok = false; detail = e.message.split('\n')[0]; }
  milestoneResults.push({ label, ok, detail });
}

function runNode(cwd, args, env = {}) {
  try {
    const out = execFileSync('node', args, {
      cwd: join(REPO, cwd),
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    }).toString();
    return { ok: true, out };
  } catch (e) {
    return { ok: false, out: (e.stdout || '').toString() + (e.stderr || '').toString() };
  }
}

let trackingDryRun;
function fullTrackingDryRun() {
  if (!trackingDryRun) {
    trackingDryRun = runTrackingPipeline({
      dry: true,
      simulatedVersion: '151.0.7900.50',
      write: () => {},
    });
  }
  return trackingDryRun;
}

let buildEvidenceAudit;
function fullBuildEvidenceAudit() {
  const sourceDigest = process.env.PROTEUS_EXPECTED_SOURCE_DIGEST;
  buildEvidenceAudit ??= verifyM0EvidenceV2(REPO, {
    expectedSourceDigest: sourceDigest,
    expectedSignerDigest:
      process.env.PROTEUS_EXPECTED_SIGNER_DIGEST ?? sourceDigest,
    expectedRunnerControllerKeySha256:
      process.env.PROTEUS_EXPECTED_RUNNER_KEY_SHA256,
    expectedGhSha256: process.env.PROTEUS_EXPECTED_GH_SHA256,
    ghPath: process.env.PROTEUS_GH_PATH,
  });
  return buildEvidenceAudit;
}

function hardBuildEvidenceAudit() {
  const audit = fullBuildEvidenceAudit();
  if (!audit.ok
      || audit.assuranceLevel === M0_EVIDENCE_V2_ASSURANCE_LEVEL) {
    return audit;
  }
  return {
    ...audit,
    ok: false,
    failures: [
      `evidence assurance ${audit.assuranceLevel} is below required ${M0_EVIDENCE_V2_ASSURANCE_LEVEL}`,
      'hard M0 requires complete bundles from six independently authenticated builder runs',
    ],
  };
}

// ---- Deliverable 1: the ruler ----------------------------------------------

check('verify-lab self-test passes (fixtures + determinism)', () => {
  const r = runNode('verify-lab', ['bin/verify-lab.mjs', 'selftest', '--json']);
  if (!r.ok) return { ok: false, detail: 'selftest failed' };
  const j = JSON.parse(r.out);
  return { ok: j.failed === 0 && j.deterministic, detail: `${j.passed}/${j.total} fixtures, deterministic=${j.deterministic}` };
});

check('verify-lab integration tests pass (schema + reference data)', () => {
  const r = runNode('verify-lab', ['test/run-tests.mjs']);
  return { ok: r.ok, detail: r.ok ? 'schema agreement + reference consistency' : 'integration tests failed' };
});

check('ruler puts a score + inconsistency list on a profile', () => {
  const r = runNode('verify-lab', ['bin/verify-lab.mjs', 'score', 'fixtures/bad-v1-apple-gpu-on-windows.json', '--json']);
  // score exits 1 for a detectable profile; parse stdout regardless.
  const j = JSON.parse(r.out);
  const hasList = Array.isArray(j.inconsistencies) && j.inconsistencies.length >= 1 && j.inconsistencies[0].reason;
  return { ok: typeof j.aggregate === 'number' && hasList, detail: `aggregate=${j.aggregate}, ${j.inconsistencies.length} inconsistencies with reasons` };
});

check('coherence gate works (no green-washing)', () => {
  const r = runNode('verify-lab', ['bin/verify-lab.mjs', 'score', 'fixtures/bad-v1-apple-gpu-on-windows.json', '--json']);
  const j = JSON.parse(r.out);
  return { ok: j.verdict === 'detectable-incoherent' && j.gated === true, detail: `verdict=${j.verdict}, gated=${j.gated}` };
});

check('all five threat vectors V1–V5 are covered by rules', () => {
  const ref = loadReference();
  const rules = runRules({}, ref);
  const vectors = ['V1', 'V2', 'V3', 'V4', 'V5'];
  const covered = new Set(rules.map((rule) => rule.vector));
  const missing = vectors.filter((vector) => !covered.has(vector));
  const versionMatches = ref._rulesVersion === RULES_VERSION;
  return {
    ok: missing.length === 0 && versionMatches,
    detail: missing.length
      ? `missing ${missing.join(',')}`
      : versionMatches
        ? `V1,V2,V3,V4,V5 all present; rules ${RULES_VERSION}`
        : `dataset rules ${ref._rulesVersion} != catalog ${RULES_VERSION}`,
  };
});

check('probe page + live-drive harness exist (runtime path)', () => {
  const page = existsSync(join(REPO, 'verify-lab', 'probe-page', 'index.html'));
  const collect = existsSync(join(REPO, 'verify-lab', 'probe-page', 'collect.js'));
  const drive = existsSync(join(REPO, 'verify-lab', 'tools', 'drive-chrome.mjs'));
  return { ok: page && collect && drive, detail: 'index.html + collect.js + drive-chrome.mjs' };
});

// ---- Deliverable 2: reproducible-build / tracking pipeline ------------------

check('active M0 patch profile is valid independently of future backlogs', () => {
  const r = runNode('engine-chromium', ['scripts/check-series.mjs', '--active']);
  return {
    ok: r.ok,
    detail: r.ok
      ? '1 active layer0 input; M1/M3 backlog files are not read by this gate'
      : 'active M0 series invalid',
  };
});

check('Chromium and depot_tools baseline is strict and commit-pinned', () => {
  const r = runNode('engine-chromium', ['scripts/baseline.mjs', '--json']);
  if (!r.ok) return { ok: false, detail: 'strict baseline validation failed' };
  const baseline = JSON.parse(r.out);
  return {
    ok: /^[0-9a-f]{40}$/.test(baseline.CHROMIUM_COMMIT)
      && /^[0-9a-f]{40}$/.test(baseline.DEPOT_TOOLS_COMMIT),
    detail: `Chromium ${baseline.CHROMIUM_STABLE} @ ${baseline.CHROMIUM_COMMIT.slice(0, 12)}…; depot_tools ${baseline.DEPOT_TOOLS_COMMIT.slice(0, 12)}…`,
  };
});

check('hard-M0 build and trust contracts are internally consistent', () => {
  const r = runNode('engine-chromium', ['scripts/build-contract.mjs', '--check']);
  return {
    ok: r.ok,
    detail: r.ok
      ? `six-build ${M0_EVIDENCE_V2_ASSURANCE_LEVEL} contract`
      : 'hard-M0 build/trust contract validation failed',
  };
});

check('engine scaffold fails closed across supported Node platforms', () => {
  const r = runNode('.', ['engine-chromium/test/scaffold-honesty.mjs', '--m0']);
  return {
    ok: r.ok,
    detail: r.ok
      ? 'real-patch preflight, isolated-placeholder, provenance, and manifest honesty regressions'
      : 'scaffold honesty regression tests failed',
  };
});

check('repository license policy + component metadata pass', () => {
  const r = runNode('.', ['scripts/license-policy.mjs']);
  return {
    ok: r.ok,
    detail: r.ok
      ? 'canonical license + current-scope manifest checks pass (not release compliance)'
      : 'repository license-policy check failed',
  };
});

check('demo provenance document has an in-toto/SLSA shape', () => {
  const r = runNode('engine-chromium', ['scripts/provenance.mjs', '--demo']);
  if (!r.ok) return { ok: false, detail: 'provenance failed' };
  const j = JSON.parse(r.out);
  const okShape = j.predicateType === 'https://slsa.dev/provenance/v1'
    && j.predicate.buildDefinition.internalParameters.patchSeriesHash?.startsWith('sha256:')
    && j._proteusNotes?.m0Status?.startsWith('DEMO ONLY');
  return { ok: okShape, detail: 'shape + patch hash checked; subject is explicitly a demo sentinel' };
});

check('shared GN release contract is cross-platform and sandbox stays enabled', () => {
  const args = readFileSync(join(REPO, 'engine-chromium', 'build', 'args.gn'), 'utf8');
  const release = args.includes('is_debug = false')
    && args.includes('is_official_build = true')
    && args.includes('use_thin_lto = true');
  const noPlatformOnlyArgs =
    !/^\s*(?:strip_absolute_paths_from_debug_symbols|enable_stripping)\s*=/mu
      .test(args);
  const noSandboxDisable = !/disable_sandbox\s*=\s*true/.test(args);
  return {
    ok: release && noPlatformOnlyArgs && noSandboxDisable,
    detail: 'shared args avoid M150 platform-only overrides; build records validate effective args and A/B trees',
  };
});

check('tracking state-machine scaffold traverses every dry-run state', () => {
  const r = fullTrackingDryRun();
  const steps = ['WATCH', 'SYNC', 'REBASE', 'BUILD', 'VERIFY', 'PROVENANCE', 'PUBLISH'];
  const seen = new Set(r.events.map((event) => event.step));
  const missing = steps.filter((step) => !seen.has(step));
  return {
    ok: r.code === 0 && missing.length === 0,
    detail: missing.length ? `missing steps: ${missing.join(', ')}` : 'WATCH→…→PUBLISH control flow traversed without real stages',
  };
});

check('dry-run VERIFY state invokes the local ruler gate', () => {
  const r = fullTrackingDryRun();
  const verified = r.events.some((event) =>
    event.step === 'VERIFY' && event.message.includes('verification lab green'));
  return { ok: r.code === 0 && verified, detail: 'rebase pipeline gates on verify-lab (tdd/05 §8)' };
});

// ---- Build-infra criteria: scaffolded, run on the farm ---------------------

check('Chromium fetch/apply/build scaffold scripts exist', () => {
  const need = ['fetch-chromium.sh', 'apply-patches.sh', 'build.sh'].map((s) => join(REPO, 'engine-chromium', 'scripts', s));
  const ok = need.every(existsSync);
  return {
    ok,
    detail: 'presence only; production apply requires the exact clean checkout and hard M0 still requires builder-attested evidence',
  };
}, { scaffold: true });

check('cryptographic M0 evidence verifiers reject forged manifests', () => {
  const legacy = runNode('.', ['engine-chromium/test/m0-evidence.mjs']);
  const complete = runNode('.', ['engine-chromium/test/m0-evidence-v2.mjs']);
  return {
    ok: legacy.ok && complete.ok,
    detail: legacy.ok && complete.ok
      ? 'entrypoint and full-bundle v2 digest/run/path/identity/attestation/report tamper cases'
      : 'evidence verifier regression tests failed',
  };
});

// ---- Hard roadmap milestone criteria ---------------------------------------

milestoneCheck('active M0 patch profile applies to the exact pinned Chromium commit', () => {
  const engineRoot = join(REPO, 'engine-chromium');
  let baseline;
  let activeAudit;
  try {
    baseline = readChromiumBaseline(join(engineRoot, 'CHROMIUM_BASELINE'));
    activeAudit = auditActivePatchSeries(
      join(engineRoot, 'patches'),
      baseline.PATCH_PROFILE,
    );
  } catch (error) {
    return { ok: false, detail: `invalid active patch contract: ${error.message}` };
  }
  if (activeAudit.errors.length > 0) {
    return {
      ok: false,
      detail: `invalid active patch contract: ${activeAudit.errors[0]}`,
    };
  }
  const series = activeAudit.active;
  const patchPaths = series.map((entry) => join(engineRoot, 'patches', entry));
  const invalid = [];
  for (let index = 0; index < patchPaths.length; index += 1) {
    if (!patchHasPayload(patchPaths[index])) invalid.push(series[index]);
  }
  if (invalid.length) {
    return {
      ok: false,
      detail: `${invalid.length}/${series.length} active M0 patch has no git-parseable payload; 16 future specifications do not gate M0`,
    };
  }

  const audit = hardBuildEvidenceAudit();
  if (!audit.ok) {
    return {
      ok: false,
      detail: `active patch payload exists, but builder evidence is invalid: ${audit.failures[0]}`,
    };
  }
  if (audit.chromiumCommit !== baseline.CHROMIUM_COMMIT) {
    return {
      ok: false,
      detail: 'builder evidence does not bind the pinned Chromium commit',
    };
  }
  const localSeriesHash = patchSeriesSha256(REPO);
  if (audit.patchSeriesSha256 !== localSeriesHash) {
    return {
      ok: false,
      detail: 'builder evidence does not bind the active M0 patch series',
    };
  }
  return {
    ok: true,
    detail: `${series.length} active patch built successfully in six trusted runs at ${baseline.CHROMIUM_COMMIT.slice(0, 12)}…; series sha256:${localSeriesHash.slice(0, 12)}…`,
  };
});

milestoneCheck('dedicated three-platform Chromium build workflow exists', () => {
  const workflowSpecs = [
    ['m0-builder.yml', [
      'windows-x64',
      'macos-universal',
      'linux-x64',
      'actions/attest@',
      'actions/upload-artifact@',
      'm0-build-record.mjs prepare',
    ]],
    ['m0-aggregate.yml', [
      'windows_a_run_id',
      'linux_b_run_id',
      'm0-evidence-v2.mjs',
      'm0-index-',
    ]],
    ['m0-hard-gate.yml', [
      'workflow_run:',
      'M0 aggregate',
      'validate-artifact-staging.mjs',
      'npm run m0:milestone',
    ]],
  ];
  const missing = [];
  for (const [name, markers] of workflowSpecs) {
    const path = join(REPO, '.github', 'workflows', name);
    if (!existsSync(path)) {
      missing.push(name);
      continue;
    }
    const source = readFileSync(path, 'utf8');
    for (const marker of markers) {
      if (!source.includes(marker)) missing.push(`${name}:${marker}`);
    }
  }
  const attested = hardBuildEvidenceAudit().ok;
  return {
    ok: missing.length === 0 && attested,
    detail: missing.length
      ? `workflow chain is missing: ${missing.join(', ')}`
      : attested
        ? 'builder → aggregate → hard-gate chain authenticated all six runs'
        : 'workflow chain exists, but no independently authenticated six-run evidence is present',
  };
});

milestoneCheck('signed reproducible Win/macOS/Linux build evidence exists', () => {
  const audit = hardBuildEvidenceAudit();
  return {
    ok: audit.ok,
    detail: audit.ok
      ? `${audit.verifiedBuilds} complete builds: A/B tree digests, provenance, SBOM, toolchains, dependencies, and Sigstore bundles verified`
      : audit.failures.slice(0, 2).join('; '),
  };
});

milestoneCheck('built bundles have builder-attested live verification reports', () => {
  const audit = hardBuildEvidenceAudit();
  return {
    ok: audit.ok,
    detail: audit.ok
      ? 'six artifact-driven drive-chrome v1.1 reports were recomputed for V1–V5 and bound to their complete bundles'
      : audit.failures.slice(0, 2).join('; '),
  };
});

// ---- Report ----------------------------------------------------------------

console.log('\n  ══════════════════════════════════════════════════════════════');
console.log('   Proteus — M0 local scaffold gate + milestone audit');
console.log('  ══════════════════════════════════════════════════════════════\n');
console.log('   Local ruler checks:\n');
for (const r of results.filter((r) => !r.scaffold).slice(0, 6)) line(r);
console.log('\n   Local build/tracking scaffold checks:\n');
for (const r of results.filter((r) => !r.scaffold).slice(6)) line(r);
for (const r of results.filter((r) => r.scaffold)) line(r);
console.log('\n   Roadmap M0 hard exit criteria (real infrastructure):\n');
for (const r of milestoneResults) line(r, true);

function line(r, milestone = false) {
  const mark = r.ok ? '✅' : '❌';
  const tag = milestone ? ' \x1b[2m(milestone)\x1b[0m' : r.scaffold ? ' \x1b[2m(scaffold)\x1b[0m' : '';
  console.log(`   ${mark} ${r.label}${tag}`);
  if (r.detail) console.log(`        ${r.detail}`);
}

console.log('\n  ' + '─'.repeat(62));
const localOk = fail === 0;
const milestonePassed = milestoneResults.filter((result) => result.ok).length;
const milestoneOk = milestonePassed === milestoneResults.length;
console.log(`   Local scaffold: ${pass}/${pass + fail} checks met`);
console.log(`   Roadmap milestone: ${milestonePassed}/${milestoneResults.length} hard criteria verified`);
if (localOk) {
  console.log('   ✅ LOCAL SCAFFOLD READY — ruler and fail-closed tooling checks pass.');
} else {
  console.log('   ❌ LOCAL SCAFFOLD REGRESSED — see failures above.');
}
console.log(milestoneOk
  ? '   ✅ ROADMAP M0 EXIT VERIFIED with real build evidence.'
  : '   ⚠️  ROADMAP M0 NOT YET COMPLETE — no green build is being claimed.');
console.log('  ' + '─'.repeat(62) + '\n');
process.exit(localOk && (!requireMilestone || milestoneOk) ? 0 : 1);
