#!/usr/bin/env node
// m0-exit-criteria.mjs — local M0 scaffold gate + honest milestone audit.
//
// Default mode verifies only what can run without a Chromium checkout. Passing
// means "the local ruler/tooling scaffold is ready", not "M0 is complete".
// `--milestone` additionally enforces the hard roadmap criteria and therefore
// remains red until real patches and full-bundle, builder-attested evidence
// exist at the explicitly required assurance level.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runTrackingPipeline } from '../engine-chromium/tracking-bot/pipeline.mjs';
import { loadReference } from '../verify-lab/src/reference.mjs';
import { RULES_VERSION, runRules } from '../verify-lab/src/rules.mjs';
import {
  M0_HARD_ASSURANCE_LEVEL,
  patchSeriesSha256,
  verifyM0BuildEvidence,
} from './m0-evidence.mjs';

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
  buildEvidenceAudit ??= verifyM0BuildEvidence(REPO);
  return buildEvidenceAudit;
}

function hardBuildEvidenceAudit() {
  const audit = fullBuildEvidenceAudit();
  if (!audit.ok || audit.assuranceLevel === M0_HARD_ASSURANCE_LEVEL) {
    return audit;
  }
  return {
    ...audit,
    ok: false,
    failures: [
      `evidence assurance ${audit.assuranceLevel} is below required ${M0_HARD_ASSURANCE_LEVEL}`,
      'hard M0 requires a complete engine-bundle manifest, independently authenticated builders, an attested live-harness run, and effective build args/toolchains',
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

check('patch series is valid (layered + rationale headers)', () => {
  const r = runNode('engine-chromium', ['scripts/check-series.mjs']);
  return { ok: r.ok, detail: r.ok ? 'series structure + headers valid' : 'series invalid' };
});

check('engine scaffold fails closed across supported Node platforms', () => {
  const r = runNode('.', ['engine-chromium/test/scaffold-honesty.mjs']);
  return {
    ok: r.ok,
    detail: r.ok
      ? 'placeholder apply, provenance, and manifest honesty regressions'
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

check('initial GN reproducibility knobs exist and sandbox stays enabled', () => {
  const args = readFileSync(join(REPO, 'engine-chromium', 'build', 'args.gn'), 'utf8');
  const repro = args.includes('strip_absolute_paths_from_debug_symbols = true');
  const noSandboxDisable = !/disable_sandbox\s*=\s*true/.test(args);
  return { ok: repro && noSandboxDisable, detail: 'local config check only; bit-for-bit reproducibility still needs two real builds' };
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
  return { ok, detail: 'presence only; production apply currently rejects placeholder patches' };
}, { scaffold: true });

check('cryptographic M0 evidence verifier rejects forged manifests', () => {
  const r = runNode('.', ['engine-chromium/test/m0-evidence.mjs']);
  return {
    ok: r.ok,
    detail: r.ok
      ? 'bounded entrypoint evidence + digest/run/path/identity/signature/report tamper cases'
      : 'evidence verifier regression tests failed',
  };
});

// ---- Hard roadmap milestone criteria ---------------------------------------

milestoneCheck('patch series contains real applicable diff hunks', () => {
  const series = readFileSync(join(REPO, 'engine-chromium', 'patches', 'series'), 'utf8')
    .split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
  const patchPaths = series.map((entry) =>
    join(REPO, 'engine-chromium', 'patches', entry));
  const invalid = [];
  for (let index = 0; index < patchPaths.length; index += 1) {
    try {
      execFileSync('git', ['apply', '--numstat', patchPaths[index]], {
        cwd: REPO,
        stdio: 'ignore',
      });
    } catch {
      invalid.push(series[index]);
    }
  }
  if (invalid.length) {
    return {
      ok: false,
      detail: `${invalid.length}/${series.length} patches have no git-parseable payload`,
    };
  }

  const checkout = process.env.PROTEUS_CHROMIUM_CHECKOUT
    || join(REPO, 'engine-chromium', 'src', 'src');
  if (!existsSync(checkout)) {
    return {
      ok: false,
      detail: 'real hunks exist, but no clean Chromium checkout is available for git apply --check',
    };
  }
  let dirty;
  try {
    dirty = execFileSync(
      'git',
      ['-C', checkout, 'status', '--porcelain'],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    ).toString().trim();
  } catch {
    return {
      ok: false,
      detail: 'Chromium checkout is not a readable Git work tree',
    };
  }
  if (dirty) {
    return {
      ok: false,
      detail: 'Chromium checkout has modifications or untracked files; apply-check requires a clean source tree',
    };
  }
  try {
    execFileSync(
      'git',
      ['-C', checkout, 'apply', '--check', '--index', '--whitespace=nowarn', ...patchPaths],
      { stdio: 'ignore' },
    );
  } catch {
    return {
      ok: false,
      detail: 'git apply --check rejected the complete series against the clean checkout',
    };
  }
  const audit = fullBuildEvidenceAudit();
  if (!audit.chromiumCommit) {
    return {
      ok: false,
      detail: 'patches apply, but no build evidence commit is available to bind the checkout',
    };
  }
  let checkoutCommit;
  try {
    checkoutCommit = execFileSync(
      'git',
      ['-C', checkout, 'rev-parse', 'HEAD'],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    ).toString().trim();
  } catch {
    return {
      ok: false,
      detail: 'cannot resolve the clean Chromium checkout HEAD',
    };
  }
  if (checkoutCommit !== audit.chromiumCommit) {
    return {
      ok: false,
      detail: `checkout HEAD ${checkoutCommit.slice(0, 12)}… != evidence ${audit.chromiumCommit.slice(0, 12)}…`,
    };
  }
  const baseline = readFileSync(
    join(REPO, 'engine-chromium', 'CHROMIUM_BASELINE'),
    'utf8',
  ).match(/^CHROMIUM_STABLE=(.+)$/m)?.[1];
  let baselineCommit;
  try {
    baselineCommit = execFileSync(
      'git',
      ['-C', checkout, 'rev-parse', '--verify', `refs/tags/${baseline}^{commit}`],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    ).toString().trim();
  } catch {
    return {
      ok: false,
      detail: `cannot resolve pinned Chromium tag ${baseline ?? '(missing)'}`,
    };
  }
  if (baselineCommit !== checkoutCommit) {
    return {
      ok: false,
      detail: `checkout HEAD is not the pinned Chromium tag ${baseline}`,
    };
  }
  return {
    ok: true,
    detail: `${series.length} real patches apply cleanly; series sha256:${patchSeriesSha256(REPO).slice(0, 12)}…`,
  };
});

milestoneCheck('dedicated three-platform Chromium build workflow exists', () => {
  const workflow = join(REPO, '.github', 'workflows', 'chromium-build.yml');
  if (!existsSync(workflow)) {
    return {
      ok: false,
      detail: 'missing .github/workflows/chromium-build.yml',
    };
  }
  const source = readFileSync(workflow, 'utf8');
  const required = [
    'windows-latest',
    'macos-latest',
    'ubuntu-latest',
    'engine-chromium/scripts/build.sh',
    'actions/upload-artifact',
    'm0-build-evidence',
  ];
  const missing = required.filter((marker) => !source.includes(marker));
  const attested = hardBuildEvidenceAudit().ok;
  return {
    ok: missing.length === 0 && attested,
    detail: missing.length
      ? `workflow missing required build/evidence markers: ${missing.join(', ')}`
      : attested
        ? 'three OS runs are declared and independently attested by hard evidence'
        : 'workflow markers exist, but no independently authenticated workflow-run evidence is present',
  };
});

milestoneCheck('signed reproducible Win/macOS/Linux build evidence exists', () => {
  const audit = hardBuildEvidenceAudit();
  return {
    ok: audit.ok,
    detail: audit.ok
      ? 'actual files, two-build digests, provenance bindings, and pinned-key signatures verified'
      : audit.failures.slice(0, 2).join('; '),
  };
});

milestoneCheck('built bundles have builder-attested live verification reports', () => {
  const audit = hardBuildEvidenceAudit();
  return {
    ok: audit.ok,
    detail: audit.ok
      ? 'three attested live runs bind recomputed baselines to complete engine bundles'
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
