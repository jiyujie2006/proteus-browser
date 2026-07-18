#!/usr/bin/env node

import assert from 'node:assert/strict';

import {
  createBuildDerivedSbom,
  validateBuildDerivedSbom,
} from '../scripts/build-sbom.mjs';
import {
  readAndValidateM0BuildContract,
} from '../scripts/build-contract.mjs';

const {
  audit,
  buildContract,
  buildContractSha256,
  trustContractSha256,
} = readAndValidateM0BuildContract();
const digest = (character) => character.repeat(64);
const bindings = {
  bundleTreeSha256: digest('1'),
  bundleManifestSha256: digest('2'),
  dependencyLockSha256: digest('3'),
  toolchainLockSha256: digest('4'),
  effectiveGnArgsSha256: digest('5'),
  licenseBundleSha256: digest('6'),
  buildContractSha256,
  trustContractSha256,
  patchSeriesSha256: audit.patchSeriesSha256,
};
const bundleManifest = {
  schemaVersion: '1.0.0',
  platform: 'linux-x64',
  entrypoint: 'chrome',
  entries: [
    {
      path: 'LICENSES',
      type: 'directory',
      mode: '755',
    },
    {
      path: 'chrome',
      type: 'file',
      mode: '755',
      size: 7,
      sha256: digest('7'),
    },
    {
      path: 'resources.pak',
      type: 'file',
      mode: '644',
      size: 8,
      sha256: digest('8'),
    },
  ],
  treeSha256: bindings.bundleTreeSha256,
  totalFileBytes: 15,
};
const dependencyLock = {
  architecture: 'x64',
  chromium: {
    commit: buildContract.source.chromiumCommit,
    repository: buildContract.source.chromiumRepository,
    stable: buildContract.source.chromiumVersion,
  },
  dependencies: [
    {
      commit: buildContract.source.chromiumCommit,
      path: 'src',
      type: 'git',
      url: buildContract.source.chromiumRepository,
    },
    {
      declaredPackage: 'infra/tool/${platform}',
      instanceId: 'a'.repeat(40),
      package: 'infra/tool/linux-amd64',
      path: 'src/third_party/tool',
      serviceUrl: 'https://chrome-infra-packages.appspot.com',
      type: 'cipd',
    },
    {
      bucket: 'chromium-example',
      generation: 1742338539536352,
      object: 'objects/archive.tar.gz',
      output: '.objects_archive.tar.gz',
      path: 'src/third_party/archive',
      sha256: digest('f'),
      size: 1048576,
      type: 'gcs',
      url: 'gs://chromium-example/objects/archive.tar.gz',
    },
  ],
  depotTools: {
    cipdBootstrap: {
      manifestSha256: digest('9'),
      resolvedVersionsSha256: digest('a'),
    },
    cipdClient: {
      platform: 'linux-amd64',
      sha256: digest('b'),
      version: 'git_revision:example',
    },
    commit: buildContract.source.depotToolsCommit,
    repository: buildContract.source.depotToolsRepository,
    vpython3: {
      platform: 'linux-amd64',
      sha256: digest('c'),
    },
  },
  gclientConfigSha256: digest('d'),
  gclientRevinfoSha256: digest('e'),
  platform: 'linux',
  schemaVersion: 1,
};
const createdAt = '2026-07-17T08:00:00.000Z';
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

let sbom;
test('build-derived SBOM inventories packaged files and resolved inputs', () => {
  sbom = createBuildDerivedSbom({
    platform: 'linux-x64',
    slot: 'A',
    createdAt,
    bundleManifest,
    dependencyLock,
    bindings,
    buildContract,
  });
  assert.equal(sbom.bomFormat, 'CycloneDX');
  assert.equal(sbom.specVersion, '1.7');
  assert.equal(sbom.components.length, 5);
  assert.deepEqual(
    sbom.components.map(({ name }) => name),
    [
      'chrome',
      'resources.pak',
      'src',
      'infra/tool/linux-amd64',
      'objects/archive.tar.gz',
    ],
  );
  const gcs = sbom.components.find(({ group }) =>
    group === 'chromium.gclient.gcs');
  assert.equal(gcs.type, 'file');
  assert.equal(gcs.version, '1742338539536352');
  assert.deepEqual(gcs.hashes, [{
    alg: 'SHA-256',
    content: digest('f'),
  }]);
  assert.equal(
    gcs.externalReferences[0].url,
    'https://storage.googleapis.com/chromium-example/objects/archive.tar.gz'
    + '?generation=1742338539536352',
  );
  assert.equal(
    validateBuildDerivedSbom(sbom, {
      platform: 'linux-x64',
      slot: 'A',
      bundleManifest,
      dependencyLock,
      bindings,
      buildContract,
    }).ok,
    true,
  );
});

test('SBOM generation is deterministic for identical build records', () => {
  assert.deepEqual(
    createBuildDerivedSbom({
      platform: 'linux-x64',
      slot: 'A',
      createdAt,
      bundleManifest,
      dependencyLock,
      bindings,
      buildContract,
    }),
    sbom,
  );
});

test('bundle hash substitution is rejected', () => {
  const changed = structuredClone(sbom);
  changed.components[0].hashes[0].content = digest('f');
  assert.throws(
    () => validateBuildDerivedSbom(changed, {
      platform: 'linux-x64',
      slot: 'A',
      bundleManifest,
      dependencyLock,
      bindings,
      buildContract,
    }),
    /differs from recomputed/u,
  );
});

test('dependency omission is rejected', () => {
  const changed = structuredClone(sbom);
  changed.components.pop();
  assert.throws(
    () => validateBuildDerivedSbom(changed, {
      platform: 'linux-x64',
      slot: 'A',
      bundleManifest,
      dependencyLock,
      bindings,
      buildContract,
    }),
    /differs from recomputed/u,
  );
});

test('toolchain-lock binding tampering is rejected', () => {
  const changed = structuredClone(sbom);
  changed.metadata.properties.find(({ name }) =>
    name === 'proteus:toolchain-lock-sha256').value = digest('0');
  assert.throws(
    () => validateBuildDerivedSbom(changed, {
      platform: 'linux-x64',
      slot: 'A',
      bundleManifest,
      dependencyLock,
      bindings,
      buildContract,
    }),
    /differs from recomputed/u,
  );
});

test('non-canonical timestamps are rejected', () => {
  assert.throws(
    () => createBuildDerivedSbom({
      platform: 'linux-x64',
      slot: 'A',
      createdAt: '2026-07-17T08:00:00Z',
      bundleManifest,
      dependencyLock,
      bindings,
      buildContract,
    }),
    /canonical RFC 3339/u,
  );
});

test('unlocked dependency types are rejected', () => {
  const changed = structuredClone(dependencyLock);
  changed.dependencies[2] = {
    path: 'src/archive',
    type: 'http',
    url: 'https://example.test/archive.zip',
  };
  assert.throws(
    () => createBuildDerivedSbom({
      platform: 'linux-x64',
      slot: 'A',
      createdAt,
      bundleManifest,
      dependencyLock: changed,
      bindings,
      buildContract,
    }),
    /unsupported type/u,
  );
});

test('partial or internally inconsistent GCS locks are rejected', () => {
  for (const mutation of [
    (entry) => {
      delete entry.generation;
    },
    (entry) => {
      entry.sha256 = 'not-a-sha256';
    },
    (entry) => {
      entry.url = 'gs://other-bucket/objects/archive.tar.gz';
    },
    (entry) => {
      entry.output = '../archive.tar.gz';
    },
    (entry) => {
      entry.size = -1;
    },
  ]) {
    const changed = structuredClone(dependencyLock);
    mutation(changed.dependencies[2]);
    assert.throws(
      () => createBuildDerivedSbom({
        platform: 'linux-x64',
        slot: 'A',
        createdAt,
        bundleManifest,
        dependencyLock: changed,
        bindings,
        buildContract,
      }),
      /resolved GCS dependency/u,
    );
  }
});

if (!process.exitCode) {
  process.stdout.write(`${passed} build-SBOM tests passed\n`);
}
