#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  aggregateM0BuildRecords,
  completeM0BuildRecord,
  prepareM0BuildRecord,
} from '../scripts/m0-build-record.mjs';
import {
  M0_PLATFORM_IDS,
} from '../scripts/build-contract.mjs';

const TEMP = realpathSync(mkdtempSync(
  join(realpathSync(tmpdir()), 'proteus-m0-build-record-'),
));
const ARTIFACTS = join(TEMP, 'artifacts');
const SOURCE = '1'.repeat(40);
let passed = 0;

function check(label, body) {
  try {
    body();
    passed += 1;
    process.stdout.write(`ok - ${label}\n`);
  } catch (error) {
    process.stderr.write(`not ok - ${label}: ${error.stack || error}\n`);
    process.exitCode = 1;
  }
}

function json(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function createBuild(platform, slot, ordinal) {
  const root = join(ARTIFACTS, 'builds', platform, slot);
  const records = join(root, 'records');
  const bundle = join(root, 'bundle');
  const attestations = join(records, 'attestations');
  mkdirSync(join(bundle, 'LICENSES'), { recursive: true });
  mkdirSync(attestations, { recursive: true });
  json(join(records, 'bundle-manifest.json'), {
    treeSha256: String(ordinal).padStart(64, '0'),
  });
  for (const name of [
    'resolved-dependency-lock.json',
    'complete-toolchain-lock.json',
    'effective-gn-args.json',
    'build-sbom.cdx.json',
    'live-report.json',
  ]) {
    json(join(records, name), { name, platform, slot });
  }
  json(join(bundle, 'LICENSES', 'artifact-license-manifest.json'), {
    platform,
    slot,
  });
  for (const name of ['provenance', 'sbom', 'build']) {
    json(join(attestations, `${name}.sigstore.json`), {
      name,
      platform,
      slot,
    });
  }
  const materials = prepareM0BuildRecord({
    artifactRoot: ARTIFACTS,
    platform,
    slot,
    runId: String(1000 + ordinal),
    runAttempt: 1,
    checkRunId: String(2000 + ordinal),
    artifactId: String(3000 + ordinal),
    artifactName: `m0-payload-${platform}-${slot}-attempt-1`,
    artifactDigest: String(4000 + ordinal).padStart(64, '0'),
    artifactSize: 8192 + ordinal,
    artifactInnerSha256: String(5000 + ordinal).padStart(64, '0'),
    artifactInnerSize: 4096 + ordinal,
    runnerKind: 'github-hosted',
    sourceDigest: SOURCE,
  });
  const record = completeM0BuildRecord({
    artifactRoot: ARTIFACTS,
    platform,
    slot,
    recordCore: materials.recordCore,
  });
  json(join(records, 'build-record.json'), record);
  return { materials, record };
}

mkdirSync(ARTIFACTS, { recursive: true });
const builds = new Map();
let ordinal = 1;
for (const platform of M0_PLATFORM_IDS) {
  for (const slot of ['A', 'B']) {
    builds.set(`${platform}/${slot}`, createBuild(platform, slot, ordinal));
    ordinal += 1;
  }
}

check('builder emits canonical build and SLSA predicates from one fact set', () => {
  const { materials } = builds.get('linux-x64/A');
  assert.equal(materials.buildPredicate.schemaVersion, '2.0.0');
  assert.equal(
    materials.buildPredicate.outputs.bundleTreeSha256,
    materials.buildFacts.outputs.bundleTreeSha256,
  );
  assert.deepEqual(
    materials.provenancePredicate.buildDefinition.externalParameters,
    materials.buildPredicate,
  );
  assert.equal(
    materials.provenancePredicate.runDetails.metadata.invocationId,
    `${materials.buildFacts.runId}/1`,
  );
  assert.equal(
    materials.buildPredicate.github.artifactDigest,
    materials.buildFacts.artifactDigest,
  );
});

check('completed record binds three distinct raw Sigstore bundles', () => {
  const { record } = builds.get('windows-x64/B');
  assert.deepEqual(Object.keys(record.attestations), [
    'provenance',
    'sbom',
    'build',
  ]);
  assert.equal(
    new Set(Object.values(record.attestations).map(({ sha256 }) => sha256)).size,
    3,
  );
  assert.match(record.bundleManifest.treeSha256, /^[0-9a-f]{64}$/u);
});

check('aggregate indexes exactly six independently identified build records', () => {
  const evidence = aggregateM0BuildRecords({
    artifactRoot: ARTIFACTS,
    sourceDigest: SOURCE,
  });
  assert.equal(evidence.schemaVersion, '2.0.0');
  assert.deepEqual(Object.keys(evidence.platforms), M0_PLATFORM_IDS);
  const runIds = [];
  for (const platform of M0_PLATFORM_IDS) {
    assert.deepEqual(Object.keys(evidence.platforms[platform]), ['A', 'B']);
    runIds.push(
      evidence.platforms[platform].A.runId,
      evidence.platforms[platform].B.runId,
    );
  }
  assert.equal(new Set(runIds).size, 6);
});

check('descriptor bytes are recomputed instead of accepted from a draft', () => {
  const path = join(
    ARTIFACTS,
    'builds',
    'linux-x64',
    'A',
    'records',
    'resolved-dependency-lock.json',
  );
  writeFileSync(path, '{"tampered":true}\n');
  const rebuilt = prepareM0BuildRecord({
    artifactRoot: ARTIFACTS,
    platform: 'linux-x64',
    slot: 'A',
    runId: '9001',
    runAttempt: 1,
    checkRunId: '9002',
    artifactId: '9003',
    artifactName: 'm0-payload-linux-x64-A-attempt-1',
    artifactDigest: 'a'.repeat(64),
    artifactSize: 8192,
    artifactInnerSha256: 'b'.repeat(64),
    artifactInnerSize: 4096,
    runnerKind: 'github-hosted',
    sourceDigest: SOURCE,
  });
  assert.notEqual(
    rebuilt.recordCore.dependencyLock.sha256,
    builds.get('linux-x64/A').record.dependencyLock.sha256,
  );
  assert.equal(
    rebuilt.recordCore.dependencyLock.sha256,
    createHash('sha256')
      .update(readFileSync(path))
      .digest('hex'),
  );
});

rmSync(TEMP, { force: true, recursive: true });
if (!process.exitCode) {
  process.stdout.write(`${passed} M0 build-record tests passed\n`);
}
