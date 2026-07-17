#!/usr/bin/env node
// Cross-platform regression checks for the engine scaffold's fail-closed
// claims. These tests require no Chromium checkout, network access, or UI.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  BASELINE_KEYS,
  parseChromiumBaseline,
  readChromiumBaseline,
} from '../scripts/baseline.mjs';
import {
  activePatchSeriesSha256,
  auditActivePatchSeries,
  auditPatchCatalog,
  parseSeriesText,
  patchHasPayload,
} from '../scripts/patch-series.mjs';
import {
  auditPinnedChromiumCheckout,
} from '../scripts/chromium-checkout.mjs';
import {
  auditPinnedDepotTools,
} from '../scripts/depot-tools-checkout.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const APPLY = join(ROOT, 'scripts', 'apply-patches.mjs');
const PROVENANCE = join(ROOT, 'scripts', 'provenance.mjs');
const SBOM = join(ROOT, 'scripts', 'sbom.mjs');
const BASELINE_SCRIPT = join(ROOT, 'scripts', 'baseline.mjs');
const BASELINE_PATH = join(ROOT, 'CHROMIUM_BASELINE');
const FETCH = join(ROOT, 'scripts', 'fetch-chromium.sh');
const BUILD = join(ROOT, 'scripts', 'build.sh');
const BASELINE = readChromiumBaseline(join(ROOT, 'CHROMIUM_BASELINE'));
const BASELINE_RAW = readFileSync(BASELINE_PATH, 'utf8');
const cliArgs = process.argv.slice(2);
const m0Only = cliArgs.length === 1 && cliArgs[0] === '--m0';
if (cliArgs.length > (m0Only ? 1 : 0)) {
  console.error('usage: scaffold-honesty.mjs [--m0]');
  process.exit(64);
}

const TEMP = mkdtempSync(join(tmpdir(), 'proteus-scaffold-honesty-'));
const CHROMIUM_PARENT = join(TEMP, 'chromium');
mkdirSync(join(CHROMIUM_PARENT, 'src'), { recursive: true });

let passed = 0;
let runNumber = 0;

function check(name, body) {
  try {
    body();
  } catch (error) {
    throw new Error(`${name}: ${error.message}`, { cause: error });
  }
  passed += 1;
  console.log(`ok ${passed} - ${name}`);
}

function runNode(script, args = [], options = {}) {
  runNumber += 1;
  const stdoutPath = join(TEMP, `run-${runNumber}.stdout`);
  const stderrPath = join(TEMP, `run-${runNumber}.stderr`);
  const stdoutFd = openSync(stdoutPath, 'w');
  const stderrFd = openSync(stderrPath, 'w');

  let result;
  try {
    result = spawnSync(process.execPath, [script, ...args], {
      cwd: options.cwd ?? ROOT,
      env: { ...process.env, ...options.env },
      stdio: ['ignore', stdoutFd, stderrFd],
      windowsHide: true,
    });
  } finally {
    closeSync(stdoutFd);
    closeSync(stderrFd);
  }

  return {
    error: result.error,
    signal: result.signal,
    status: result.status,
    stdout: readFileSync(stdoutPath, 'utf8'),
    stderr: readFileSync(stderrPath, 'utf8'),
  };
}

function expectStatus(expected, script, args = [], options = {}) {
  const result = runNode(script, args, options);
  if (result.error || result.status !== expected) {
    const actual = result.error
      ? result.error.message
      : result.signal
        ? `signal ${result.signal}`
        : `exit ${result.status}`;
    throw new Error(
      `expected exit ${expected}, got ${actual}\n`
      + `--- stdout ---\n${result.stdout}`
      + `--- stderr ---\n${result.stderr}`,
    );
  }
  return result;
}

const applyEnvironment = { PROTEUS_CHROMIUM_SRC: CHROMIUM_PARENT };

try {
  check('production patch apply rejects an unpinned checkout without a success claim', () => {
    const result = expectStatus(1, APPLY, [], { env: applyEnvironment });
    assert.match(
      result.stderr,
      /Chromium preflight failed: Chromium checkout is not a usable Git worktree/,
      'production rejection should identify the invalid checkout',
    );
    assert.doesNotMatch(
      `${result.stdout}\n${result.stderr}`,
      /all [0-9]+ active patches applied/,
      'production rejection must not claim all patches applied',
    );
    assert.doesNotMatch(
      `${result.stdout}\n${result.stderr}`,
      /layer1-fingerprint|layer2-antiautomation/,
      'M1/M3 backlog paths must not enter production apply',
    );
  });

  check('explicit inspection mode reports the real active payload without applying it', () => {
    const result = expectStatus(0, APPLY, ['--allow-placeholders'], {
      env: applyEnvironment,
    });
    assert.match(result.stdout, /scaffold inspection complete/, 'scaffold mode should label its result');
    assert.match(result.stdout, /1 real, 0 placeholder\(s\)/);
    assert.match(
      result.stdout,
      /0001-disable-google-network-time\.patch  \(real payload\)/,
    );
    assert.match(
      result.stdout,
      /NOT a complete patch application/,
      'scaffold mode should deny complete application',
    );
    assert.doesNotMatch(
      `${result.stdout}\n${result.stderr}`,
      /all [0-9]+ active patches applied/,
      'scaffold mode must not claim all patches applied',
    );
    assert.match(result.stdout, /future M1\/M3 backlog files are excluded and were not read/);
    assert.doesNotMatch(
      `${result.stdout}\n${result.stderr}`,
      /layer1-fingerprint|layer2-antiautomation/,
      'scaffold apply must not process future backlog paths',
    );
  });

  check('isolated active placeholder fixture remains fail-closed in production apply', () => {
    const engine = join(TEMP, 'placeholder-apply-engine');
    const scripts = join(engine, 'scripts');
    const layer0 = join(engine, 'patches', 'layer0-fixture');
    const sourceParent = join(engine, 'src');
    cpSync(join(ROOT, 'scripts'), scripts, { recursive: true });
    cpSync(BASELINE_PATH, join(engine, 'CHROMIUM_BASELINE'));
    mkdirSync(layer0, { recursive: true });
    mkdirSync(join(sourceParent, 'src'), { recursive: true });
    writeFileSync(
      join(engine, 'patches', 'series'),
      'layer0-fixture/0001-placeholder.patch\n',
    );
    const placeholder = join(layer0, '0001-placeholder.patch');
    writeFileSync(
      placeholder,
      [
        '# Rationale: isolated fail-closed fixture',
        '# Surface: fixture',
        '# Upstream-risk: LOW',
        '# Tests: scaffold-honesty',
        '# Target-milestone: M0',
        '# Status: ACTIVE PLACEHOLDER',
        '',
      ].join('\n'),
    );
    const audit = auditActivePatchSeries(
      join(engine, 'patches'),
      BASELINE.PATCH_PROFILE,
    );
    assert.deepEqual(audit.errors, []);
    assert.equal(patchHasPayload(placeholder), false);

    const result = expectStatus(
      3,
      join(scripts, 'apply-patches.mjs'),
      [],
      { env: { PROTEUS_CHROMIUM_SRC: sourceParent } },
    );
    assert.match(
      result.stderr,
      /1 placeholder\(s\) with no diff hunks or valid patch payload/,
    );
    assert.doesNotMatch(
      `${result.stdout}\n${result.stderr}`,
      /all [0-9]+ active patches applied/,
      'placeholder rejection must not claim application success',
    );

    writeFileSync(
      placeholder,
      readFileSync(placeholder, 'utf8').replace(
        '# Status: ACTIVE PLACEHOLDER',
        '# Status: ACTIVE',
      ),
    );
    assert.ok(
      auditActivePatchSeries(
        join(engine, 'patches'),
        BASELINE.PATCH_PROFILE,
      ).errors.some((error) => error.includes('# Status: ACTIVE PLACEHOLDER')),
      'metadata must identify a payload-free active entry as a placeholder',
    );
  });

  if (!m0Only) {
    check('patch catalog separates one M0 input from 15 M1 and one M3 specifications', () => {
      const audit = auditPatchCatalog(join(ROOT, 'patches'), BASELINE.PATCH_PROFILE);
      assert.deepEqual(audit.errors, []);
      assert.deepEqual(audit.active, [
        'layer0-degoogle/0001-disable-google-network-time.patch',
      ]);
      assert.equal(
        audit.series.find(({ id }) => id === 'm1-backlog').entries.length,
        15,
      );
      assert.equal(
        audit.series.find(({ id }) => id === 'm3-backlog').entries.length,
        1,
      );
      assert.equal(audit.onDisk.length, 17);
    });
  }

  check('active-series hash excludes future backlog bytes but binds active bytes', () => {
    const engine = join(TEMP, 'patch-hash-engine');
    const patches = join(engine, 'patches');
    const layer0 = join(patches, 'layer0-degoogle');
    mkdirSync(layer0, { recursive: true });
    cpSync(join(ROOT, 'patches', 'series'), join(patches, 'series'));
    cpSync(
      join(ROOT, 'patches', 'layer0-degoogle', '0001-disable-google-network-time.patch'),
      join(layer0, '0001-disable-google-network-time.patch'),
    );
    const before = activePatchSeriesSha256(engine, BASELINE.PATCH_PROFILE);
    const future = join(patches, 'unreferenced-future-specification');
    writeFileSync(future, '# future-only bytes\n');
    assert.equal(
      activePatchSeriesSha256(engine, BASELINE.PATCH_PROFILE),
      before,
      'future specification bytes must not alter an M0 artifact hash',
    );
    const active = join(
      engine,
      'patches',
      'layer0-degoogle',
      '0001-disable-google-network-time.patch',
    );
    writeFileSync(active, `${readFileSync(active, 'utf8')}\n# active change\n`);
    assert.notEqual(
      activePatchSeriesSha256(engine, BASELINE.PATCH_PROFILE),
      before,
      'active patch bytes must alter the M0 artifact hash',
    );
  });

  if (!m0Only) {
    check('patch catalog rejects duplicates, orphans, wrong milestones, and unsafe paths', () => {
      const duplicateRoot = patchFixture('duplicate');
      const m1Series = join(duplicateRoot, 'backlog', 'm1.series');
      writeFileSync(
        m1Series,
        `${readFileSync(m1Series, 'utf8')}layer0-degoogle/0001-disable-google-network-time.patch\n`,
      );
      assert.ok(
        auditPatchCatalog(duplicateRoot, BASELINE.PATCH_PROFILE)
          .errors.some((error) => error.includes('listed in both')),
      );
      assert.deepEqual(
        auditActivePatchSeries(duplicateRoot, BASELINE.PATCH_PROFILE).errors,
        [],
        'future catalog errors must not enter the active M0 contract',
      );

      const orphanRoot = patchFixture('orphan');
      writeFileSync(
        join(orphanRoot, 'layer1-fingerprint', '9999-orphan.patch'),
        '# orphan\n',
      );
      assert.ok(
        auditPatchCatalog(orphanRoot, BASELINE.PATCH_PROFILE)
          .errors.some((error) => error.includes('is not catalogued')),
      );

      const milestoneRoot = patchFixture('milestone');
      const patch = join(
        milestoneRoot,
        'layer2-antiautomation',
        '0003-stealth-cdp.patch',
      );
      writeFileSync(
        patch,
        readFileSync(patch, 'utf8').replace(
          '# Target-milestone: M3',
          '# Target-milestone: M1',
        ),
      );
      assert.ok(
        auditPatchCatalog(milestoneRoot, BASELINE.PATCH_PROFILE)
          .errors.some((error) => error.includes('does not match M3')),
      );

      assert.throws(
        () => parseSeriesText('../escape.patch\n', 'fixture.series'),
        /invalid patch path/,
      );
    });
  }

  check('active-series hash rejects a layer1 entry under the M0 layer0 profile', () => {
    const engine = join(TEMP, 'profile-engine');
    const patches = join(engine, 'patches');
    const layer0 = join(patches, 'layer0-fixture');
    const layer1 = join(patches, 'layer1-fixture');
    mkdirSync(layer0, { recursive: true });
    mkdirSync(layer1, { recursive: true });
    const metadata = (milestone, status) => [
      '# Rationale: fixture',
      '# Surface: fixture',
      '# Upstream-risk: LOW',
      '# Tests: fixture',
      `# Target-milestone: ${milestone}`,
      `# Status: ${status}`,
      '',
    ].join('\n');
    writeFileSync(
      join(patches, 'series'),
      'layer0-fixture/0001-active.patch\nlayer1-fixture/0001-forbidden.patch\n',
    );
    writeFileSync(
      join(layer0, '0001-active.patch'),
      metadata('M0', 'ACTIVE PLACEHOLDER'),
    );
    writeFileSync(
      join(layer1, '0001-forbidden.patch'),
      metadata('M0', 'ACTIVE PLACEHOLDER'),
    );
    assert.throws(
      () => activePatchSeriesSha256(engine, BASELINE.PATCH_PROFILE),
      /not allowed in the M0 layer0 profile/,
    );
  });

  check('strict baseline parser accepts the pinned file and CRLF only', () => {
    assert.deepEqual(Object.keys(BASELINE), BASELINE_KEYS);
    assert.deepEqual(
      parseChromiumBaseline(BASELINE_RAW.replaceAll('\n', '\r\n'), 'CRLF fixture'),
      BASELINE,
    );
  });

  check('strict baseline parser rejects missing, ambiguous, malformed, and executable text', () => {
    const replace = (key, value) => BASELINE_RAW.replace(
      new RegExp(`^${key}=.*$`, 'm'),
      `${key}=${value}`,
    );
    const remove = (key) => BASELINE_RAW
      .split('\n')
      .filter((line) => !line.startsWith(`${key}=`))
      .join('\n');
    const invalid = [
      remove('CHROMIUM_COMMIT'),
      `${BASELINE_RAW}\nCHANNEL=stable\n`,
      `${BASELINE_RAW}\nUNKNOWN_KEY=value\n`,
      `${BASELINE_RAW}\ntouch /tmp/proteus-must-not-run\n`,
      BASELINE_RAW.replace('CHANNEL=stable', 'export CHANNEL=stable'),
      BASELINE_RAW.replace('CHANNEL=stable', ' CHANNEL=stable'),
      replace('CHROMIUM_STABLE', '150.0.7871'),
      replace('MILESTONE', '149'),
      replace('CHANNEL', 'beta'),
      replace('CHROMIUM_COMMIT', BASELINE.CHROMIUM_COMMIT.toUpperCase()),
      replace('DEPOT_TOOLS_COMMIT', '0'.repeat(40)),
      replace('PINNED_AT', '2026-02-30'),
      `${BASELINE_RAW}\nEVIL=$(touch /tmp/proteus-must-not-run)\n`,
      `\uFEFF${BASELINE_RAW}`,
      `${BASELINE_RAW}\u0000`,
      `# unsafe\u0000comment\n${BASELINE_RAW}`,
    ];
    for (const [index, raw] of invalid.entries()) {
      assert.throws(
        () => parseChromiumBaseline(raw, `invalid fixture ${index}`),
        undefined,
        `invalid baseline fixture ${index} unexpectedly passed`,
      );
    }
  });

  check('baseline file reader rejects invalid UTF-8', () => {
    const path = join(TEMP, 'invalid-utf8.baseline');
    writeFileSync(path, Buffer.from([0x23, 0x20, 0xff, 0x0a]));
    assert.throws(() => readChromiumBaseline(path));
  });

  check('baseline CLI is machine-clean and never executes injected assignments', () => {
    const get = expectStatus(0, BASELINE_SCRIPT, [
      '--file',
      BASELINE_PATH,
      '--get',
      'CHROMIUM_COMMIT',
    ]);
    assert.equal(get.stdout, `${BASELINE.CHROMIUM_COMMIT}\n`);
    assert.equal(get.stderr, '');

    const json = expectStatus(0, BASELINE_SCRIPT, [
      '--file',
      BASELINE_PATH,
      '--json',
    ]);
    assert.deepEqual(JSON.parse(json.stdout), BASELINE);

    const conflict = expectStatus(2, BASELINE_SCRIPT, ['--json', '--get', 'CHANNEL']);
    assert.equal(conflict.stdout, '');

    const marker = join(TEMP, 'injection-marker');
    const malicious = join(TEMP, 'malicious.baseline');
    writeFileSync(malicious, `${BASELINE_RAW}\nEVIL=$(touch ${marker})\n`);
    const rejected = expectStatus(2, BASELINE_SCRIPT, [
      '--file',
      malicious,
      '--check',
    ]);
    assert.equal(rejected.stdout, '');
    assert.equal(existsSync(marker), false);
  });

  check('fetch preflight pins tools, source, config, and post-sync HEAD without shell sourcing', () => {
    const source = readFileSync(FETCH, 'utf8');
    assert.doesNotMatch(source, /^\s*(?:source|\.)\s+.*CHROMIUM_BASELINE/m);
    assert.doesNotMatch(source, /\beval\b/);
    const disableUpdate = source.indexOf('export DEPOT_TOOLS_UPDATE=0');
    const depotCheck = source.indexOf('\nassert_depot_tools\n');
    const pathPrepend = source.indexOf('PATH="$DEPOT_TOOLS_DIR:$PATH"');
    const firstGclient = source.indexOf('"$DEPOT_TOOLS_DIR/gclient" config');
    assert.ok(
      disableUpdate >= 0
        && depotCheck > disableUpdate
        && pathPrepend > depotCheck
        && firstGclient > pathPrepend,
      'depot_tools must be frozen and verified before it can execute',
    );
    for (const marker of [
      'remote get-url origin',
      'refs/tags/$CHROMIUM_STABLE^{commit}',
      'checkout --detach "$CHROMIUM_COMMIT"',
      '--revision "src@$CHROMIUM_COMMIT"',
      'gclient moved Chromium HEAD',
      'fetch requires fresh, non-existent source and depot_tools roots',
      'cp "$GCLIENT_FIXTURE_DIR/.gclient" "$SRC_DIR/.gclient"',
      'scripts/depot-tools-checkout.mjs',
      'scripts/chromium-checkout.mjs',
    ]) {
      assert.ok(source.includes(marker), `fetch contract missing ${marker}`);
    }
    const syntax = spawnSync('bash', ['-n', FETCH], {
      cwd: ROOT,
      stdio: 'pipe',
      windowsHide: true,
    });
    assert.equal(syntax.status, 0, syntax.stderr?.toString());
  });

  check('fetch refuses relative, overlapping, or reusable roots before network access', () => {
    const existingSource = join(TEMP, 'existing-source');
    const existingDepot = join(TEMP, 'existing-depot');
    mkdirSync(existingSource);
    mkdirSync(existingDepot);
    const reused = runBash(FETCH, {
      PROTEUS_CHROMIUM_SRC: existingSource,
      PROTEUS_DEPOT_TOOLS_DIR: existingDepot,
    });
    assert.equal(reused.status, 1);
    assert.match(reused.stderr, /requires fresh, non-existent/);

    const relative = runBash(FETCH, {
      PROTEUS_CHROMIUM_SRC: 'relative-source',
      PROTEUS_DEPOT_TOOLS_DIR: existingDepot,
    });
    assert.equal(relative.status, 1);
    assert.match(relative.stderr, /must be an absolute path/);

    const overlap = runBash(FETCH, {
      PROTEUS_CHROMIUM_SRC: TEMP,
      PROTEUS_DEPOT_TOOLS_DIR: join(TEMP, 'nested-depot'),
    });
    assert.equal(overlap.status, 1);
    assert.match(overlap.stderr, /inside source root/);
  });

  check('checkout policy detects wrong origins, tracked changes, and hidden index flags', () => {
    const chromium = createGitFixture('chromium-checkout');
    runGit(chromium.root, ['tag', '1.2.3.4']);
    runGit(chromium.root, [
      'remote',
      'add',
      'origin',
      BASELINE.CHROMIUM_REPOSITORY,
    ]);
    const chromiumBaseline = {
      ...BASELINE,
      CHROMIUM_STABLE: '1.2.3.4',
      CHROMIUM_COMMIT: chromium.commit,
      MILESTONE: '1',
    };
    assert.deepEqual(
      auditPinnedChromiumCheckout(chromium.root, chromiumBaseline).errors,
      [],
    );

    writeFileSync(chromium.file, 'tampered\n');
    assert.ok(
      auditPinnedChromiumCheckout(chromium.root, chromiumBaseline)
        .errors.some((error) => error.includes('worktree bytes')),
    );
    writeFileSync(chromium.file, 'pinned\n');

    runGit(chromium.root, ['update-index', '--assume-unchanged', 'tracked.txt']);
    assert.ok(
      auditPinnedChromiumCheckout(chromium.root, chromiumBaseline)
        .errors.some((error) => error.includes('tracked-file flags')),
    );
    runGit(chromium.root, ['update-index', '--no-assume-unchanged', 'tracked.txt']);
    runGit(chromium.root, ['update-index', '--skip-worktree', 'tracked.txt']);
    assert.ok(
      auditPinnedChromiumCheckout(chromium.root, chromiumBaseline)
        .errors.some((error) => error.includes('tracked-file flags')),
    );
    runGit(chromium.root, ['update-index', '--no-skip-worktree', 'tracked.txt']);

    const redirected = createGitFixture('redirected-chromium');
    runGit(redirected.root, ['tag', '1.2.3.4']);
    runGit(redirected.root, [
      'remote',
      'add',
      'origin',
      BASELINE.CHROMIUM_REPOSITORY,
    ]);
    const fakeSource = join(TEMP, 'fake-source');
    mkdirSync(fakeSource);
    writeFileSync(join(fakeSource, 'evil.cc'), 'not chromium\n');
    assert.ok(
      auditPinnedChromiumCheckout(fakeSource, chromiumBaseline, {
        environment: {
          ...process.env,
          GIT_DIR: join(redirected.root, '.git'),
          GIT_WORK_TREE: redirected.root,
        },
      }).errors.length > 0,
      'ambient GIT_DIR/GIT_WORK_TREE must not redirect the audited source path',
    );

    runGit(chromium.root, ['remote', 'set-url', 'origin', 'https://example.invalid/src']);
    assert.ok(
      auditPinnedChromiumCheckout(chromium.root, chromiumBaseline)
        .errors.some((error) => error.includes('origin')),
    );

    const depot = createGitFixture('depot-checkout');
    runGit(depot.root, [
      'remote',
      'add',
      'origin',
      BASELINE.DEPOT_TOOLS_REPOSITORY,
    ]);
    const depotBaseline = { ...BASELINE, DEPOT_TOOLS_COMMIT: depot.commit };
    assert.deepEqual(auditPinnedDepotTools(depot.root, depotBaseline).errors, []);
    writeFileSync(depot.file, 'tampered\n');
    assert.ok(
      auditPinnedDepotTools(depot.root, depotBaseline)
        .errors.some((error) => error.includes('worktree bytes')),
    );
    writeFileSync(depot.file, 'pinned\n');
    runGit(depot.root, ['update-index', '--skip-worktree', 'tracked.txt']);
    assert.ok(
      auditPinnedDepotTools(depot.root, depotBaseline)
        .errors.some((error) => error.includes('tracked-file flags')),
    );
    const fakeDepot = join(TEMP, 'fake-depot');
    mkdirSync(fakeDepot);
    writeFileSync(join(fakeDepot, 'evil'), 'not depot_tools\n');
    assert.ok(
      auditPinnedDepotTools(fakeDepot, depotBaseline, {
        environment: {
          ...process.env,
          GIT_DIR: join(depot.root, '.git'),
          GIT_WORK_TREE: depot.root,
        },
      }).errors.length > 0,
      'ambient Git repository overrides must not redirect depot_tools audit',
    );
  });

  check('patch metadata must precede a git-format diff payload', () => {
    const patchesRoot = join(TEMP, 'traditional-patch-catalog');
    const layer = join(patchesRoot, 'layer0-fixture');
    mkdirSync(layer, { recursive: true });
    writeFileSync(
      join(patchesRoot, 'series'),
      'layer0-fixture/0001-traditional.patch\n',
    );
    writeFileSync(
      join(layer, '0001-traditional.patch'),
      [
        '--- a/tracked.txt',
        '+++ b/tracked.txt',
        '@@ -1 +1 @@',
        '-before',
        '+after',
        '# Rationale: too late',
        '# Surface: fixture',
        '# Upstream-risk: LOW',
        '# Tests: fixture',
        '# Target-milestone: M0',
        '# Status: ACTIVE',
        '',
      ].join('\n'),
    );
    const audit = auditActivePatchSeries(patchesRoot, 'm0-layer0-v1');
    assert.ok(
      audit.errors.some((error) => error.includes('git-format patch')),
      'traditional payload must not bypass the pre-diff metadata boundary',
    );
  });

  check('patched checkout policy derives and verifies the exact active patch tree', () => {
    const chromium = createGitFixture('patched-checkout');
    runGit(chromium.root, ['tag', '1.2.3.4']);
    runGit(chromium.root, [
      'remote',
      'add',
      'origin',
      BASELINE.CHROMIUM_REPOSITORY,
    ]);
    const engine = join(TEMP, 'patched-engine');
    const patchDirectory = join(engine, 'patches', 'layer0-fixture');
    mkdirSync(patchDirectory, { recursive: true });
    writeFileSync(
      join(engine, 'patches', 'series'),
      'layer0-fixture/0001-change.patch\n',
    );
    const patch = join(patchDirectory, '0001-change.patch');
    writeFileSync(
      patch,
      [
        '# Rationale: fixture',
        '# Surface: fixture',
        '# Upstream-risk: LOW',
        '# Tests: fixture',
        '# Target-milestone: M0',
        '# Status: ACTIVE',
        'diff --git a/tracked.txt b/tracked.txt',
        '--- a/tracked.txt',
        '+++ b/tracked.txt',
        '@@ -1 +1 @@',
        '-pinned',
        '+patched',
        '',
      ].join('\n'),
    );
    runGit(chromium.root, ['apply', '--index', patch]);
    const fixtureBaseline = {
      ...BASELINE,
      CHROMIUM_STABLE: '1.2.3.4',
      CHROMIUM_COMMIT: chromium.commit,
      MILESTONE: '1',
    };
    const audit = auditPinnedChromiumCheckout(
      chromium.root,
      fixtureBaseline,
      { engineRoot: engine, state: 'patched' },
    );
    assert.deepEqual(audit.errors, []);
    assert.equal(audit.actualTree, audit.expectedTree);

    writeFileSync(chromium.file, 'not-the-index-bytes\n');
    assert.ok(
      auditPinnedChromiumCheckout(
        chromium.root,
        fixtureBaseline,
        { engineRoot: engine, state: 'patched' },
      ).errors.some((error) => error.includes('worktree bytes')),
    );
  });

  check('build entrypoint rejects unlocked wrappers and verifies exact patched inputs', () => {
    const source = readFileSync(BUILD, 'utf8');
    for (const marker of [
      'PROTEUS_CC_WRAPPER is not part of the locked M0 build contract',
      'scripts/depot-tools-checkout.mjs',
      'scripts/chromium-checkout.mjs',
      '--state patched',
      '"$DEPOT_TOOLS_DIR/gn" gen',
      '"$DEPOT_TOOLS_DIR/autoninja" -C',
    ]) {
      assert.ok(source.includes(marker), `build contract missing ${marker}`);
    }
    assert.doesNotMatch(source, />>\s*"\$OUT_DIR\/args\.gn"/);
    const syntax = spawnSync('bash', ['-n', BUILD], {
      cwd: ROOT,
      stdio: 'pipe',
      windowsHide: true,
    });
    assert.equal(syntax.status, 0, syntax.stderr?.toString());
  });

  check('provenance requires an explicit artifact or demo mode', () => {
    const result = expectStatus(2, PROVENANCE);
    assert.match(result.stderr, /no artifact supplied/, 'provenance should explain the missing artifact');
  });

  check('provenance rejects missing and non-ordinary artifacts', () => {
    const commonArgs = [
      '--chromium-commit',
      BASELINE.CHROMIUM_COMMIT,
      '--effective-gn-args',
      join(ROOT, 'build', 'args.gn'),
      '--platform',
      'linux-x64',
    ];
    const missing = expectStatus(2, PROVENANCE, [
      '--artifact',
      join(TEMP, 'missing.bin'),
      ...commonArgs,
      '--invocation-id',
      'missing-fixture',
    ]);
    assert.match(missing.stderr, /artifact does not exist/, 'missing artifact should be identified');

    const directory = expectStatus(2, PROVENANCE, [
      '--artifact',
      CHROMIUM_PARENT,
      ...commonArgs,
      '--invocation-id',
      'directory-fixture',
    ]);
    assert.match(
      directory.stderr,
      /not an ordinary/,
      'non-ordinary artifact should be identified',
    );
  });

  check('demo provenance has a sha256-only sentinel subject', () => {
    const result = expectStatus(0, PROVENANCE, ['--demo']);
    const document = JSON.parse(result.stdout);
    assert.deepEqual(Object.keys(document.subject[0].digest), ['sha256']);
    assert.match(document.subject[0].digest.sha256, /^[a-f0-9]{64}$/);
    assert.equal(
      document.subject[0].annotations['https://proteus.example/artifact-kind'],
      'demo-placeholder',
    );
    assert.match(document._proteusNotes.m0Status, /DEMO ONLY/);
  });

  check('real provenance hashes file bytes and keeps size in annotations', () => {
    const artifactPath = join(TEMP, 'engine.tar.zst');
    const bytes = Buffer.from('packaged-engine-fixture\n', 'utf8');
    writeFileSync(artifactPath, bytes);
    const result = expectStatus(0, PROVENANCE, [
      '--artifact',
      artifactPath,
      '--chromium-commit',
      BASELINE.CHROMIUM_COMMIT,
      '--effective-gn-args',
      join(ROOT, 'build', 'args.gn'),
      '--platform',
      'linux-x64',
      '--invocation-id',
      'fixture-run',
    ]);
    const document = JSON.parse(result.stdout);
    assert.deepEqual(Object.keys(document.subject[0].digest), ['sha256']);
    assert.equal(
      document.subject[0].digest.sha256,
      createHash('sha256').update(bytes).digest('hex'),
    );
    assert.equal(
      document.subject[0].annotations['https://proteus.example/size-bytes'],
      String(bytes.length),
    );
    assert.equal(
      document.subject[0].annotations['https://proteus.example/artifact-kind'],
      'file',
    );
    assert.equal(
      document.predicate.buildDefinition.externalParameters.effectiveGnArgsSha256,
      document.predicate.buildDefinition.externalParameters.gnArgsTemplateSha256,
    );
  });

  check('manifest stub serial is a stable RFC 4122 version-5 UUID', () => {
    const first = JSON.parse(expectStatus(0, SBOM, ['--json']).stdout);
    const second = JSON.parse(expectStatus(0, SBOM, ['--json']).stdout);
    assert.equal(first.serialNumber, second.serialNumber);
    assert.match(
      first.serialNumber,
      /^urn:uuid:[a-f0-9]{8}-[a-f0-9]{4}-5[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,
    );
  });

  check('manifest output identifies itself as a non-build-derived stub', () => {
    const document = JSON.parse(expectStatus(0, SBOM, ['--json']).stdout);
    const human = expectStatus(0, SBOM).stdout;
    const properties = Object.fromEntries(
      document.metadata.properties.map(({ name, value }) => [name, value]),
    );
    assert.equal(properties['proteus:document-kind'], 'repository-component-manifest-stub');
    assert.equal(properties['proteus:build-derived'], 'false');
    assert.match(
      properties['proteus:scope-note'],
      /Current repository components only, including the pinned Chromium diff context/,
    );
    assert.match(human, /NOT a production SBOM/);
    assert.match(human, /pinned Chromium diff context/);
    const componentNames = document.components.map(({ name }) => name);
    assert.deepEqual(componentNames, [
      'proteus-fingerprint',
      'proteus-verify-lab',
      'proteus-chromium-scaffold',
      'proteus-repository-tooling',
      'chromium-network-time-source-context',
    ]);
    const firstParty = document.components.filter(({ group }) => group === 'proteus');
    assert.ok(
      firstParty.every(({ licenses }) => (
        licenses.length === 1 && licenses[0].license.id === 'Apache-2.0'
      )),
      'first-party components must declare Apache-2.0 only',
    );
    const chromium = document.components.find(
      ({ name }) => name === 'chromium-network-time-source-context',
    );
    assert.equal(chromium.group, 'chromium');
    assert.equal(chromium.version, BASELINE.CHROMIUM_STABLE);
    assert.deepEqual(chromium.licenses, [
      { license: { id: 'BSD-3-Clause' } },
    ]);
    assert.deepEqual(chromium.hashes, [{
      alg: 'SHA-256',
      content: '704ad013d6af61138961ebe95b621c41be93738251ac6e8f5d997fe48881095d',
    }]);
  });

  console.log(`\n${passed} scaffold honesty checks passed.`);
} catch (error) {
  console.error(`not ok - ${error.message}`);
  process.exitCode = 1;
} finally {
  rmSync(TEMP, { force: true, recursive: true });
}

function patchFixture(name) {
  const root = join(TEMP, `patch-catalog-${name}`);
  cpSync(join(ROOT, 'patches'), root, { recursive: true });
  return root;
}

function createGitFixture(name) {
  const root = join(TEMP, name);
  mkdirSync(root);
  runGit(root, ['init', '--quiet']);
  runGit(root, ['config', 'user.name', 'Proteus Test']);
  runGit(root, ['config', 'user.email', 'test@invalid.example']);
  runGit(root, ['config', 'commit.gpgSign', 'false']);
  const file = join(root, 'tracked.txt');
  writeFileSync(file, 'pinned\n');
  runGit(root, ['add', 'tracked.txt']);
  runGit(root, ['commit', '--quiet', '-m', 'fixture']);
  return {
    commit: runGit(root, ['rev-parse', 'HEAD']),
    file,
    root,
  };
}

function runGit(root, args) {
  const result = spawnSync('git', ['-C', root, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`);
  }
  return result.stdout.trim();
}

function runBash(script, env) {
  const result = spawnSync('bash', [script], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  if (result.error) throw result.error;
  return result;
}
