#!/usr/bin/env node
// Cross-platform regression checks for the engine scaffold's fail-closed
// claims. These tests require no Chromium checkout, network access, or UI.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
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

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const APPLY = join(ROOT, 'scripts', 'apply-patches.mjs');
const PROVENANCE = join(ROOT, 'scripts', 'provenance.mjs');
const SBOM = join(ROOT, 'scripts', 'sbom.mjs');

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
  check('production patch apply rejects placeholders without a success claim', () => {
    const result = expectStatus(3, APPLY, [], { env: applyEnvironment });
    assert.match(
      result.stderr,
      /placeholder\(s\) with no diff hunks or valid patch payload/,
      'production rejection should identify placeholders',
    );
    assert.doesNotMatch(
      `${result.stdout}\n${result.stderr}`,
      /all [0-9]+ patches applied cleanly/,
      'production rejection must not claim all patches applied',
    );
  });

  check('explicit scaffold patch mode reports skips, not complete application', () => {
    const result = expectStatus(0, APPLY, ['--allow-placeholders'], {
      env: applyEnvironment,
    });
    assert.match(result.stdout, /scaffold inspection complete/, 'scaffold mode should label its result');
    assert.match(
      result.stdout,
      /NOT a complete patch application/,
      'scaffold mode should deny complete application',
    );
    assert.doesNotMatch(
      `${result.stdout}\n${result.stderr}`,
      /all [0-9]+ patches applied cleanly/,
      'scaffold mode must not claim all patches applied',
    );
  });

  check('provenance requires an explicit artifact or demo mode', () => {
    const result = expectStatus(2, PROVENANCE);
    assert.match(result.stderr, /no artifact supplied/, 'provenance should explain the missing artifact');
  });

  check('provenance rejects missing and non-ordinary artifacts', () => {
    const commonArgs = [
      '--chromium-commit',
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
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
      /not an ordinary file/,
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
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
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
    assert.equal(properties['proteus:document-kind'], 'component-manifest-stub');
    assert.equal(properties['proteus:build-derived'], 'false');
    assert.match(human, /NOT a production SBOM/);
  });

  console.log(`\n${passed} scaffold honesty checks passed.`);
} catch (error) {
  console.error(`not ok - ${error.message}`);
  process.exitCode = 1;
} finally {
  rmSync(TEMP, { force: true, recursive: true });
}
