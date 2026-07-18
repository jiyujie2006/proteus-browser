#!/usr/bin/env node
// pipeline.mjs — the version-tracking bot (docs/tdd/05 §4). The automation that
// keeps Proteus alive on the Chromium treadmill. This is the state machine:
//
//   WATCH → SYNC → REBASE → BUILD → VERIFY → PROVENANCE → PUBLISH
//
// Human-in-the-loop only where judgment is needed (approve a promotion, fix a
// genuine conflict). Everything mechanical is automated. Precise localization
// turns "the rebase broke somewhere" into "patch NNNN (surface) conflicts; probes
// X,Y at risk."
//
// --dry-run runs the state machine end-to-end WITHOUT network/build/depot_tools,
// using the local scaffold, so the control flow is verifiable in M0. The real run
// (on the farm) swaps the stubbed steps for fetch-chromium.sh / build.sh /
// verify-lab, gated at each step.

import { writeSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readChromiumBaseline } from '../scripts/baseline.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const REPO = join(ROOT, '..');

const DRY = process.argv.includes('--dry-run');
const defaultWrite = (line = '') => writeSync(process.stdout.fd, line + '\n');

// In a real run this queries the Chromium release API. In --dry-run we simulate
// "no newer stable" (the common case) unless PROTEUS_SIMULATE_NEW is set.
function latestUpstreamStable(current, simulatedVersion) {
  if (simulatedVersion) return simulatedVersion;
  return current; // dry-run default: up to date
}

/**
 * Run the tracking state machine.
 *
 * Kept callable as a module so the top-level exit-criteria script can exercise
 * the state machine without creating a nested Node process that then needs to
 * spawn its own checks. `events` is the authoritative machine-readable trace;
 * human log text is presentation only.
 */
export function runTrackingPipeline({
  dry = DRY,
  simulatedVersion = process.env.PROTEUS_SIMULATE_NEW,
  write = defaultWrite,
} = {}) {
  const events = [];
  const out = (line = '') => write(line);
  const log = (step, msg) => {
    events.push({ step, message: msg });
    out(`  [${step}] ${msg}`);
  };
  const finish = (code) => ({ code, events });
  const stopIssue = (title, body) => {
    out('\n  ⛔ PIPELINE STOP — human action needed');
    out(`     issue: ${title}`);
    for (const l of body) out(`       ${l}`);
    out();
  };

  const base = readChromiumBaseline(join(ROOT, 'CHROMIUM_BASELINE'));
  out('\n  Proteus version-tracking bot' + (dry ? '  (DRY RUN — no network/build)' : ''));
  out('  ' + '─'.repeat(58));

  // 1. WATCH
  const current = base.CHROMIUM_STABLE;
  const latest = latestUpstreamStable(current, simulatedVersion);
  log('WATCH', `pinned=${current}  latest-stable=${latest}`);
  if (latest === current) {
    log('WATCH', 'up to date — nothing to do.');
    out('  ' + '─'.repeat(58));
    out('  ✅ no action needed (set PROTEUS_SIMULATE_NEW=<ver> to exercise a rebase)\n');
    return finish(0);
  }
  log('WATCH', `new stable ${latest} detected → starting rebase pipeline`);

  // 2. SYNC
  if (dry) {
    log(
      'SYNC',
      `would require a reviewed candidate baseline for ${latest} and run scripts/fetch-chromium.sh --baseline <candidate> (skipped in dry-run)`,
    );
  } else {
    stopIssue('reviewed candidate baseline required', [
      `detected ${latest}, but the immutable baseline still pins ${base.CHROMIUM_STABLE}.`,
      'Resolve the official tag to an exact commit, pin depot_tools, and submit the candidate baseline for review before any fetch/build.',
      'The tracker refuses to fetch a new tag while silently using the old baseline.',
    ]);
    return finish(2);
  }

  // 3. REBASE — validate series first (this part is real even in dry-run).
  log('REBASE', 'validating the active patch series independently of future backlogs…');
  try {
    execFileSync('node', ['scripts/check-series.mjs', '--active'], {
      cwd: ROOT,
      stdio: 'ignore',
    });
    log('REBASE', 'active series valid.');
  } catch (e) {
    const detail = [e.code, e.status != null ? `status=${e.status}` : null, e.signal]
      .filter(Boolean)
      .join(', ');
    stopIssue('patch series invalid', [
      `check-series.mjs failed${detail ? ` (${detail})` : ''} — fix the series before rebasing.`,
    ]);
    return finish(2);
  }
  if (dry) {
    log('REBASE', 'would run node scripts/apply-patches.mjs (skipped). On conflict, the bot opens an issue');
    log('REBASE', 'tagged with the failing patch surface + Upstream-risk note + failing hunk, and STOPS.');
  } else {
    try {
      execFileSync(process.execPath, ['scripts/apply-patches.mjs'], {
        cwd: ROOT,
        stdio: 'inherit',
      });
    }
    catch (e) {
      stopIssue(`rebase conflict on ${latest}`, ['apply-patches.mjs localized the first failing patch (see output above).']);
      return finish(2);
    }
  }

  // 4. BUILD
  if (dry) log('BUILD', 'would run scripts/build.sh (gn+ninja+sccache, multi-hour) (skipped)');
  else execFileSync('bash', ['scripts/build.sh'], { cwd: ROOT, stdio: 'inherit' });

  // 5. VERIFY — the mandatory gate (tdd/06). Real even in dry-run: runs the ruler.
  log('VERIFY', 'running the verification-lab gate…');
  try {
    execFileSync('node', ['bin/verify-lab.mjs', 'm0-gate'], {
      cwd: join(REPO, 'verify-lab'),
      stdio: 'ignore',
    });
    log('VERIFY', 'verification lab green (M0 ruler gate).');
  } catch (e) {
    stopIssue('verification regressed', ['verify-lab reported a regression — release blocked (tdd/05 §8 gate 3).']);
    return finish(3);
  }

  // 6. PROVENANCE
  log('PROVENANCE', 'generating reproducible-build provenance + SBOM…');
  if (dry) {
    execFileSync('node', ['scripts/sbom.mjs'], { cwd: ROOT, stdio: 'ignore' }); // license gate
    log('PROVENANCE', 'SBOM license gate passed; provenance doc would be generated for the real artifact.');
  } else {
    const provenanceInputs = {
      artifact: process.env.PROTEUS_ARTIFACT || '',
      chromiumCommit: process.env.PROTEUS_CHROMIUM_COMMIT || '',
      effectiveGnArgs: process.env.PROTEUS_EFFECTIVE_GN_ARGS || '',
      platform: process.env.PROTEUS_PLATFORM || '',
      invocationId: process.env.PROTEUS_INVOCATION_ID || '',
    };
    execFileSync(
      'node',
      [
        'scripts/provenance.mjs',
        '--artifact',
        provenanceInputs.artifact,
        '--chromium-commit',
        provenanceInputs.chromiumCommit,
        '--effective-gn-args',
        provenanceInputs.effectiveGnArgs,
        '--platform',
        provenanceInputs.platform,
        '--invocation-id',
        provenanceInputs.invocationId,
      ],
      { cwd: ROOT, stdio: 'inherit' },
    );
  }

  // 7. PUBLISH — always human-approved for promotion to stable.
  log('PUBLISH', 'release candidate prepared. Promotion to stable requires human approval.');
  out('  ' + '─'.repeat(58));
  out(`  ✅ pipeline reached PUBLISH for ${latest} (awaiting human promotion)\n`);
  return finish(0);
}

const isDirect = process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isDirect) process.exit(runTrackingPipeline().code);
