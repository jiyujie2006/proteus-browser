#!/usr/bin/env node

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  assertPackageRecordDigests,
  createPackageRecord,
  validatePackageRecord,
} from '../scripts/package-record.mjs';

const dependencyLockBytes = Buffer.from('{"schemaVersion":1}\n');
const effectiveGnArgsBytes = Buffer.from('{"schemaVersion":"1.0.0"}\n');
const toolchainLockBytes = Buffer.from('{"schemaVersion":"1.0.0"}\n');
const licenseManifestBytes = Buffer.from(JSON.stringify({
  schemaVersion: '1.0.0',
  documentKind: 'artifact-license-bundle',
  platform: 'linux-x64',
}) + '\n');
const inputs = {
  platform: 'linux-x64',
  outDirRelative: 'out/Proteus',
  runtimeDependencies: ['chrome', 'locales', 'resources.pak'],
  dependencyLockBytes,
  effectiveGnArgsBytes,
  toolchainLockBytes,
  licenseManifestBytes,
};
let passed = 0;

function test(label, fn) {
  try {
    fn();
    passed += 1;
    process.stdout.write(`ok - ${label}\n`);
  } catch (error) {
    process.stderr.write(`not ok - ${label}: ${error.stack || error}\n`);
    process.exitCode = 1;
  }
}

let record;
test('package record binds the GN runtime closure and all build records', () => {
  record = createPackageRecord(inputs);
  assert.equal(record.documentKind, 'gn-runtime-dependency-package');
  assert.equal(record.runtimeDependencies.count, 3);
  assert.match(record.runtimeDependencies.sha256, /^[0-9a-f]{64}$/u);
  assert.deepEqual(
    record.runtimeDependencies.entries,
    ['chrome', 'locales', 'resources.pak'],
  );
  assert.equal(validatePackageRecord(record, inputs).ok, true);
});

test('package record is deterministic and contains no invocation or slot', () => {
  assert.deepEqual(createPackageRecord(inputs), record);
  const serialized = JSON.stringify(record);
  assert.equal(serialized.includes('runId'), false);
  assert.equal(serialized.includes('buildSlot'), false);
  assert.equal(serialized.includes('invocation'), false);
});

test('runtime-dependency substitution is rejected', () => {
  const changed = structuredClone(record);
  changed.runtimeDependencies.entries = ['chrome'];
  assert.throws(
    () => assertPackageRecordDigests(changed),
    /binding is invalid/u,
  );
});

test('build-record digest substitution is rejected against recomputed inputs', () => {
  const changed = structuredClone(record);
  changed.records.toolchainLock.sha256 = '0'.repeat(64);
  assert.throws(
    () => validatePackageRecord(changed, inputs),
    /differs from recomputed/u,
  );
});

test('producer digest substitution is rejected against repository bytes', () => {
  const changed = structuredClone(record);
  changed.producers[0].sha256 = '0'.repeat(64);
  assert.throws(
    () => validatePackageRecord(changed, inputs),
    /differs from recomputed/u,
  );
});

test('unsafe or absolute output directories are rejected', () => {
  for (const outDirRelative of [
    '/out/Proteus',
    'out/../Proteus',
    'build/Proteus',
    'out\\Proteus',
  ]) {
    assert.throws(
      () => createPackageRecord({ ...inputs, outDirRelative }),
      /source-relative under out/u,
    );
  }
});

test('producer list pins the current package implementation bytes', () => {
  const producer = record.producers.find(({ path }) =>
    path.endsWith('/package-record.mjs'));
  assert.ok(producer);
  assert.equal(
    producer.size,
    readFileSync(new URL('../scripts/package-record.mjs', import.meta.url)).length,
  );
});

if (!process.exitCode) {
  process.stdout.write(`${passed} package-record tests passed\n`);
}
