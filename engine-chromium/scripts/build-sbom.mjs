#!/usr/bin/env node
// Create the artifact-specific CycloneDX inventory for an M0 engine build.
// The complete bundle manifest remains the byte-for-byte authority; this SBOM
// turns every packaged file and every resolved source/CIPD input into a
// component and binds the other build records by digest.

import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  writeSync,
} from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { parseStrictJson } from '../../scripts/strict-json.mjs';
import {
  M0_PLATFORM_IDS,
  readAndValidateM0BuildContract,
} from './build-contract.mjs';
import { verifyBundleManifest } from './bundle-manifest.mjs';
import {
  validateEffectiveGnArgsRecord,
} from './effective-gn-args.mjs';
import {
  verifyArtifactLicenseBundle,
} from './artifact-licenses.mjs';

const MAX_RECORD_BYTES = 128 * 1024 * 1024;
const SHA256_RE = /^[0-9a-f]{64}$/u;
const GIT_COMMIT_RE = /^[0-9a-f]{40}$/u;
const GCS_BUCKET_RE = /^[a-z0-9][a-z0-9._-]*[a-z0-9]$/u;
const UUID_NAMESPACE_URL = Buffer.from(
  '6ba7b8119dad11d180b400c04fd430c8',
  'hex',
);
const LICENSE_REFERENCE = 'LicenseRef-Proteus-Artifact-Notices';

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected, label) {
  if (!isPlainObject(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
      || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError(`${label} has missing or unknown fields`);
  }
}

function sameFileState(left, right) {
  return left.isFile()
    && right.isFile()
    && left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function readStableBytes(path, label) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  if (before.size > BigInt(MAX_RECORD_BYTES)) {
    throw new TypeError(`${label} exceeds ${MAX_RECORD_BYTES} bytes`);
  }
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameFileState(before, opened)) {
      throw new TypeError(`${label} changed while it was opened`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const rebound = lstatSync(path, { bigint: true });
    if (!sameFileState(opened, after) || !sameFileState(after, rebound)) {
      throw new TypeError(`${label} changed or was rebound while it was read`);
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function assertSha256(value, label) {
  if (!SHA256_RE.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 digest`);
  }
}

function assertPosixRelativePath(value, label) {
  if (typeof value !== 'string'
      || value === ''
      || value.length > 4096
      || value.startsWith('/')
      || value.endsWith('/')
      || value.includes('\\')
      || value.includes(':')
      || /[\u0000-\u001f\u007f]/u.test(value)
      || value.split('/').some((part) =>
        part === '' || part === '.' || part === '..')) {
    throw new TypeError(`${label} must be a canonical POSIX-relative path`);
  }
}

function assertGcsObjectName(value, label) {
  if (typeof value !== 'string'
      || value === ''
      || value.length > 4096
      || value.startsWith('/')
      || value.includes('\\')
      || value.includes(':')
      || value.includes('?')
      || value.includes('#')
      || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
}

function uuidV5(name) {
  const bytes = createHash('sha1')
    .update(UUID_NAMESPACE_URL)
    .update(name, 'utf8')
    .digest()
    .subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join('-');
}

function canonicalTimestamp(value, label = 'SBOM createdAt') {
  if (typeof value !== 'string'
      || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u.test(value)) {
    throw new TypeError(`${label} must be a canonical RFC 3339 UTC timestamp`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)
      || new Date(milliseconds).toISOString() !== value) {
    throw new TypeError(`${label} is not a real canonical UTC timestamp`);
  }
  return value;
}

function validateDependencyLock(document, buildContract, platform) {
  exactKeys(document, [
    'architecture',
    'chromium',
    'dependencies',
    'depotTools',
    'gclientConfigSha256',
    'gclientRevinfoSha256',
    'platform',
    'schemaVersion',
  ], 'resolved dependency lock');
  if (document.schemaVersion !== 1
      || document.platform !== buildContract.platforms[platform].hostPlatform
      || typeof document.architecture !== 'string'
      || document.architecture.length === 0) {
    throw new TypeError('resolved dependency lock platform is wrong');
  }
  exactKeys(
    document.chromium,
    ['commit', 'repository', 'stable'],
    'resolved dependency Chromium identity',
  );
  if (document.chromium.commit !== buildContract.source.chromiumCommit
      || document.chromium.repository !== buildContract.source.chromiumRepository
      || document.chromium.stable !== buildContract.source.chromiumVersion) {
    throw new TypeError('resolved dependency lock does not bind pinned Chromium');
  }
  if (!isPlainObject(document.depotTools)
      || document.depotTools.commit !== buildContract.source.depotToolsCommit
      || document.depotTools.repository
        !== buildContract.source.depotToolsRepository) {
    throw new TypeError('resolved dependency lock does not bind pinned depot_tools');
  }
  assertSha256(document.gclientConfigSha256, 'gclient config digest');
  assertSha256(document.gclientRevinfoSha256, 'gclient revinfo digest');
  if (!Array.isArray(document.dependencies)
      || document.dependencies.length === 0) {
    throw new TypeError('resolved dependency lock contains no dependencies');
  }
  const identities = new Set();
  const gcsOutputs = new Set();
  for (const [index, dependency] of document.dependencies.entries()) {
    if (!isPlainObject(dependency)
        || !['git', 'cipd', 'gcs'].includes(dependency.type)) {
      throw new TypeError(`resolved dependency ${index} has unsupported type`);
    }
    let identity;
    if (dependency.type === 'git') {
      identity = `git\0${dependency.path}\0${dependency.url}\0${dependency.commit}`;
    } else if (dependency.type === 'cipd') {
      identity =
        `cipd\0${dependency.path}\0${dependency.package}\0${dependency.instanceId}`;
    } else {
      identity = `gcs\0${dependency.path}\0${dependency.object}`;
    }
    if (identities.has(identity)) {
      throw new TypeError(`resolved dependency ${index} is duplicated`);
    }
    identities.add(identity);
    if (dependency.type === 'git') {
      exactKeys(
        dependency,
        ['commit', 'path', 'type', 'url'],
        `resolved Git dependency ${index}`,
      );
      if (!GIT_COMMIT_RE.test(dependency.commit)
          || typeof dependency.url !== 'string'
          || !dependency.url.startsWith('https://')) {
        throw new TypeError(`resolved Git dependency ${index} is not pinned`);
      }
    } else if (dependency.type === 'cipd') {
      exactKeys(
        dependency,
        [
          'declaredPackage',
          'instanceId',
          'package',
          'path',
          'serviceUrl',
          'type',
        ],
        `resolved CIPD dependency ${index}`,
      );
      if (typeof dependency.instanceId !== 'string'
          || !/^(?:[0-9a-f]{40}|[A-Za-z0-9_-]{44})$/u.test(
            dependency.instanceId,
          )
          || dependency.serviceUrl
            !== 'https://chrome-infra-packages.appspot.com') {
        throw new TypeError(`resolved CIPD dependency ${index} is not pinned`);
      }
    } else {
      exactKeys(
        dependency,
        [
          'bucket',
          'generation',
          'object',
          'output',
          'path',
          'sha256',
          'size',
          'type',
          'url',
        ],
        `resolved GCS dependency ${index}`,
      );
      assertPosixRelativePath(
        dependency.path,
        `resolved GCS dependency ${index} path`,
      );
      assertPosixRelativePath(
        dependency.output,
        `resolved GCS dependency ${index} output`,
      );
      assertGcsObjectName(
        dependency.object,
        `resolved GCS dependency ${index} object`,
      );
      assertSha256(
        dependency.sha256,
        `resolved GCS dependency ${index} digest`,
      );
      if (!GCS_BUCKET_RE.test(dependency.bucket)
          || dependency.url
            !== `gs://${dependency.bucket}/${dependency.object}`
          || !Number.isSafeInteger(dependency.generation)
          || dependency.generation <= 0
          || !Number.isSafeInteger(dependency.size)
          || dependency.size < 0) {
        throw new TypeError(`resolved GCS dependency ${index} is not pinned`);
      }
      const outputIdentity = `${dependency.path}\0${dependency.output}`;
      if (gcsOutputs.has(outputIdentity)) {
        throw new TypeError(`resolved GCS dependency ${index} reuses an output`);
      }
      gcsOutputs.add(outputIdentity);
    }
  }
}

function license() {
  return [{ expression: LICENSE_REFERENCE }];
}

function componentRef(domain, value) {
  return `urn:proteus:${domain}:sha256:${sha256(Buffer.from(value, 'utf8'))}`;
}

function bundleFileComponent(entry) {
  return {
    type: 'file',
    'bom-ref': componentRef('bundle-file', entry.path),
    group: 'org.proteus.bundle',
    name: entry.path,
    hashes: [{
      alg: 'SHA-256',
      content: entry.sha256,
    }],
    licenses: license(),
    properties: [
      { name: 'proteus:bundle-path', value: entry.path },
      { name: 'proteus:inventory-scope', value: 'packaged-file' },
      { name: 'proteus:file-mode', value: entry.mode },
      { name: 'proteus:file-size', value: String(entry.size) },
    ],
  };
}

function dependencyComponent(dependency, buildContract) {
  const serialized = JSON.stringify(dependency);
  if (dependency.type === 'git') {
    const isChromium = dependency.path === 'src'
      && dependency.commit === buildContract.source.chromiumCommit;
    return {
      type: 'library',
      'bom-ref': componentRef('git-dependency', serialized),
      group: 'chromium.gclient.git',
      name: dependency.path,
      version: dependency.commit,
      hashes: [{
        alg: 'SHA-1',
        content: dependency.commit,
      }],
      licenses: isChromium
        ? [{ license: { id: 'BSD-3-Clause' } }]
        : license(),
      externalReferences: [{
        type: 'vcs',
        url: `${dependency.url}@${dependency.commit}`,
      }],
      properties: [
        { name: 'proteus:inventory-scope', value: 'resolved-build-input' },
        { name: 'proteus:dependency-type', value: 'git' },
        { name: 'proteus:checkout-path', value: dependency.path },
      ],
    };
  }
  if (dependency.type === 'gcs') {
    const objectUrl = dependency.object
      .split('/')
      .map((part) => encodeURIComponent(part))
      .join('/');
    return {
      type: 'file',
      'bom-ref': componentRef('gcs-dependency', serialized),
      group: 'chromium.gclient.gcs',
      name: dependency.object,
      version: String(dependency.generation),
      hashes: [{
        alg: 'SHA-256',
        content: dependency.sha256,
      }],
      licenses: license(),
      externalReferences: [{
        type: 'distribution',
        url:
          `https://storage.googleapis.com/${dependency.bucket}/${objectUrl}`
          + `?generation=${dependency.generation}`,
      }],
      properties: [
        { name: 'proteus:inventory-scope', value: 'resolved-build-input' },
        { name: 'proteus:dependency-type', value: 'gcs' },
        { name: 'proteus:checkout-path', value: dependency.path },
        { name: 'proteus:gcs-bucket', value: dependency.bucket },
        { name: 'proteus:gcs-object', value: dependency.object },
        { name: 'proteus:gcs-output', value: dependency.output },
        { name: 'proteus:gcs-size', value: String(dependency.size) },
        {
          name: 'proteus:gcs-generation',
          value: String(dependency.generation),
        },
      ],
    };
  }
  return {
    type: 'library',
    'bom-ref': componentRef('cipd-dependency', serialized),
    group: 'chromium.gclient.cipd',
    name: dependency.package,
    version: dependency.instanceId,
    licenses: license(),
    externalReferences: [{
      type: 'distribution',
      url: `${dependency.serviceUrl}/p/${dependency.package}/+/${dependency.instanceId}`,
    }],
    properties: [
      { name: 'proteus:inventory-scope', value: 'resolved-build-input' },
      { name: 'proteus:dependency-type', value: 'cipd' },
      { name: 'proteus:checkout-path', value: dependency.path },
      { name: 'proteus:declared-package', value: dependency.declaredPackage },
    ],
  };
}

function bindingProperties(bindings, platform, slot) {
  const mapping = [
    ['proteus:build-derived', 'true'],
    ['proteus:platform', platform],
    ['proteus:build-slot', slot],
    ['proteus:bundle-tree-sha256', bindings.bundleTreeSha256],
    ['proteus:bundle-manifest-sha256', bindings.bundleManifestSha256],
    ['proteus:dependency-lock-sha256', bindings.dependencyLockSha256],
    ['proteus:toolchain-lock-sha256', bindings.toolchainLockSha256],
    ['proteus:effective-gn-args-sha256', bindings.effectiveGnArgsSha256],
    [
      'proteus:license-bundle-manifest-sha256',
      bindings.licenseBundleSha256,
    ],
    ['proteus:build-contract-sha256', bindings.buildContractSha256],
    ['proteus:trust-contract-sha256', bindings.trustContractSha256],
    ['proteus:active-patch-series-sha256', bindings.patchSeriesSha256],
  ];
  return mapping.map(([name, value]) => ({ name, value }));
}

function validateBindings(bindings) {
  exactKeys(bindings, [
    'bundleTreeSha256',
    'bundleManifestSha256',
    'dependencyLockSha256',
    'toolchainLockSha256',
    'effectiveGnArgsSha256',
    'licenseBundleSha256',
    'buildContractSha256',
    'trustContractSha256',
    'patchSeriesSha256',
  ], 'SBOM bindings');
  for (const [name, value] of Object.entries(bindings)) {
    assertSha256(value, `SBOM binding ${name}`);
  }
}

export function createBuildDerivedSbom({
  platform,
  slot,
  createdAt,
  bundleManifest,
  dependencyLock,
  bindings,
  buildContract,
}) {
  if (!M0_PLATFORM_IDS.includes(platform) || !['A', 'B'].includes(slot)) {
    throw new TypeError('SBOM platform or build slot is unsupported');
  }
  canonicalTimestamp(createdAt);
  validateBindings(bindings);
  validateDependencyLock(dependencyLock, buildContract, platform);
  if (bundleManifest.platform !== platform
      || bundleManifest.treeSha256 !== bindings.bundleTreeSha256
      || !Array.isArray(bundleManifest.entries)) {
    throw new TypeError('SBOM bundle manifest binding is wrong');
  }
  const files = bundleManifest.entries
    .filter(({ type }) => type === 'file')
    .map(bundleFileComponent);
  if (files.length === 0) {
    throw new TypeError('SBOM cannot be built from an empty file inventory');
  }
  const inputs = dependencyLock.dependencies.map((dependency) =>
    dependencyComponent(dependency, buildContract));
  const components = [...files, ...inputs];
  const references = components.map((component) => component['bom-ref']);
  if (new Set(references).size !== references.length) {
    throw new TypeError('SBOM component references are not unique');
  }
  const rootRef =
    `pkg:generic/proteus-chromium-engine@${buildContract.source.chromiumVersion}`
    + `?platform=${encodeURIComponent(platform)}`;
  const serialName = JSON.stringify({
    platform,
    slot,
    createdAt,
    bindings,
    components: references,
  });
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    serialNumber: `urn:uuid:${uuidV5(serialName)}`,
    version: 1,
    metadata: {
      timestamp: createdAt,
      component: {
        type: 'application',
        'bom-ref': rootRef,
        group: 'org.proteus',
        name: 'proteus-chromium-engine',
        version: buildContract.source.chromiumVersion,
        licenses: license(),
      },
      tools: {
        components: [{
          type: 'application',
          group: 'org.proteus',
          name: 'm0-build-sbom',
          version: '1.0.0',
          licenses: [{ license: { id: 'Apache-2.0' } }],
        }],
      },
      properties: bindingProperties(bindings, platform, slot),
    },
    components,
    dependencies: [
      { ref: rootRef, dependsOn: references },
      ...references.map((ref) => ({ ref, dependsOn: [] })),
    ],
  };
}

export function validateBuildDerivedSbom(document, {
  platform,
  slot,
  bundleManifest,
  dependencyLock,
  bindings,
  buildContract,
}) {
  if (!isPlainObject(document)
      || document.bomFormat !== 'CycloneDX'
      || document.specVersion !== '1.7'
      || typeof document.serialNumber !== 'string'
      || !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        document.serialNumber,
      )
      || !isPlainObject(document.metadata)) {
    throw new TypeError('document is not a canonical build-derived CycloneDX 1.7 SBOM');
  }
  const expected = createBuildDerivedSbom({
    platform,
    slot,
    createdAt: canonicalTimestamp(document.metadata.timestamp),
    bundleManifest,
    dependencyLock,
    bindings,
    buildContract,
  });
  if (!isDeepStrictEqual(document, expected)) {
    throw new TypeError('CycloneDX SBOM differs from recomputed build inputs');
  }
  return Object.freeze({
    ok: true,
    platform,
    slot,
    components: document.components.length,
    serialNumber: document.serialNumber,
  });
}

function parseArgs(args) {
  const values = {
    bundleDir: null,
    bundleManifest: null,
    createdAt: null,
    dependencyLock: null,
    effectiveGnArgs: null,
    platform: null,
    slot: null,
    toolchainLock: null,
  };
  const options = new Map([
    ['--bundle-dir', 'bundleDir'],
    ['--bundle-manifest', 'bundleManifest'],
    ['--created-at', 'createdAt'],
    ['--dependency-lock', 'dependencyLock'],
    ['--effective-gn-args', 'effectiveGnArgs'],
    ['--platform', 'platform'],
    ['--slot', 'slot'],
    ['--toolchain-lock', 'toolchainLock'],
  ]);
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    const key = options.get(option);
    if (!key) throw new TypeError(`unknown argument ${option}`);
    if (values[key] !== null) throw new TypeError(`${option} supplied twice`);
    const value = args[index + 1];
    if (!value || value.startsWith('--')) {
      throw new TypeError(`${option} requires a value`);
    }
    values[key] = value;
    index += 1;
  }
  if (Object.values(values).some((value) => value === null)) {
    throw new TypeError(
      'usage: build-sbom.mjs --bundle-dir <dir> --bundle-manifest <file> '
      + '--dependency-lock <file> --toolchain-lock <file> '
      + '--effective-gn-args <file> --platform <id> --slot <A|B> '
      + '--created-at <RFC3339>',
    );
  }
  return values;
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    const bundleManifestBytes = readStableBytes(
      resolve(args.bundleManifest),
      'complete bundle manifest',
    );
    const bundleManifest = parseStrictJson(
      bundleManifestBytes,
      'complete bundle manifest',
    );
    verifyBundleManifest(resolve(args.bundleDir), bundleManifest);
    const dependencyLockBytes = readStableBytes(
      resolve(args.dependencyLock),
      'resolved dependency lock',
    );
    const dependencyLock = parseStrictJson(
      dependencyLockBytes,
      'resolved dependency lock',
    );
    const toolchainLockBytes = readStableBytes(
      resolve(args.toolchainLock),
      'complete toolchain lock',
    );
    parseStrictJson(toolchainLockBytes, 'complete toolchain lock');
    const effectiveArgsBytes = readStableBytes(
      resolve(args.effectiveGnArgs),
      'effective GN args record',
    );
    const effectiveArgs = parseStrictJson(
      effectiveArgsBytes,
      'effective GN args record',
    );
    validateEffectiveGnArgsRecord(effectiveArgs, {
      platform: args.platform,
    });
    const licenseManifestPath = resolve(
      args.bundleDir,
      'LICENSES',
      'artifact-license-manifest.json',
    );
    const licenseManifestBytes = readStableBytes(
      licenseManifestPath,
      'artifact license manifest',
    );
    verifyArtifactLicenseBundle({
      bundleDir: resolve(args.bundleDir),
      manifest: licenseManifestBytes,
      platform: args.platform,
    });
    const {
      audit,
      buildContract,
      buildContractSha256,
      trustContractSha256,
    } = readAndValidateM0BuildContract();
    const bindings = {
      bundleTreeSha256: bundleManifest.treeSha256,
      bundleManifestSha256: sha256(bundleManifestBytes),
      dependencyLockSha256: sha256(dependencyLockBytes),
      toolchainLockSha256: sha256(toolchainLockBytes),
      effectiveGnArgsSha256: sha256(effectiveArgsBytes),
      licenseBundleSha256: sha256(licenseManifestBytes),
      buildContractSha256,
      trustContractSha256,
      patchSeriesSha256: audit.patchSeriesSha256,
    };
    const sbom = createBuildDerivedSbom({
      platform: args.platform,
      slot: args.slot,
      createdAt: args.createdAt,
      bundleManifest,
      dependencyLock,
      bindings,
      buildContract,
    });
    writeSync(process.stdout.fd, `${JSON.stringify(sbom, null, 2)}\n`);
  } catch (error) {
    writeSync(process.stderr.fd, `ERROR: ${error.message}\n`);
    process.exitCode = 2;
  }
}

const isDirect = import.meta.main ?? (
  process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
);
if (isDirect) main();
