#!/usr/bin/env node
// Canonical record for the GN runtime-dependency closure copied into an M0
// engine bundle. The record is itself covered by the complete tree manifest.

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
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  M0_PLATFORM_IDS,
  readAndValidateM0BuildContract,
} from './build-contract.mjs';
import { parseStrictJson } from '../../scripts/strict-json.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = resolve(HERE, '..');
const REPO_ROOT = resolve(ENGINE_ROOT, '..');
const MAX_RECORD_BYTES = 128 * 1024 * 1024;
const SHA256_RE = /^[0-9a-f]{64}$/u;
const PRODUCER_PATHS = Object.freeze([
  'engine-chromium/scripts/package-engine.mjs',
  'engine-chromium/scripts/package-record.mjs',
  'engine-chromium/scripts/artifact-licenses.mjs',
  'engine-chromium/scripts/bundle-manifest.mjs',
]);
const RECORD_NAMES = Object.freeze({
  dependencyLock: 'resolved-dependency-lock.json',
  effectiveGnArgs: 'effective-gn-args.json',
  toolchainLock: 'complete-toolchain-lock.json',
});

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

export function readStablePackageInput(path, label) {
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

function canonicalOutDir(value) {
  if (typeof value !== 'string'
      || !value.startsWith('out/')
      || value.includes('\\')
      || value.split('/').some((part) =>
        part === '' || part === '.' || part === '..')
      || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError('package output directory must be source-relative under out/');
  }
  return value;
}

function canonicalRuntimeDependencies(values) {
  if (!Array.isArray(values)
      || values.length === 0
      || values.some((value) =>
        typeof value !== 'string'
        || value.length === 0
        || value.startsWith('/')
        || value.includes('\\')
        || value.split('/').some((part) =>
          part === '' || part === '.' || part === '..')
        || /[\u0000-\u001f\u007f]/u.test(value))
      || new Set(values).size !== values.length) {
    throw new TypeError('runtime dependencies must be unique canonical relative paths');
  }
  return `${values.join('\n')}\n`;
}

function producerRecords(repoRoot) {
  return PRODUCER_PATHS.map((path) => {
    const bytes = readStablePackageInput(
      join(repoRoot, ...path.split('/')),
      `package producer ${path}`,
    );
    return {
      path,
      sha256: sha256(bytes),
      size: bytes.length,
    };
  });
}

function inputRecord(name, bytes) {
  if ((!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array))
      || bytes.length === 0
      || bytes.length > MAX_RECORD_BYTES) {
    throw new TypeError(`${name} has invalid bytes`);
  }
  return {
    name: RECORD_NAMES[name],
    sha256: sha256(bytes),
    size: bytes.length,
  };
}

export function createPackageRecord({
  platform,
  outDirRelative,
  runtimeDependencies,
  dependencyLockBytes,
  effectiveGnArgsBytes,
  toolchainLockBytes,
  licenseManifestBytes,
  repoRoot = REPO_ROOT,
}) {
  if (!M0_PLATFORM_IDS.includes(platform)) {
    throw new TypeError(`unsupported M0 platform ${String(platform)}`);
  }
  const runtimeText = canonicalRuntimeDependencies(runtimeDependencies);
  const {
    buildContract,
    buildContractSha256,
  } = readAndValidateM0BuildContract();
  const licenseManifest = parseStrictJson(
    licenseManifestBytes,
    'artifact license manifest',
  );
  if (licenseManifest.documentKind !== 'artifact-license-bundle'
      || licenseManifest.platform !== platform) {
    throw new TypeError('artifact license manifest does not match package platform');
  }
  return {
    schemaVersion: '1.0.0',
    documentKind: 'gn-runtime-dependency-package',
    platform,
    chromium: {
      repository: buildContract.source.chromiumRepository,
      version: buildContract.source.chromiumVersion,
      commit: buildContract.source.chromiumCommit,
    },
    buildContract: {
      path: 'BUILD-CONTRACT.json',
      sha256: buildContractSha256,
    },
    outputDirectory: canonicalOutDir(outDirRelative),
    runtimeDependencies: {
      command: buildContract.bundle.runtimeDependencyCommand,
      encoding: 'utf-8-lf',
      sha256: sha256(Buffer.from(runtimeText, 'utf8')),
      count: runtimeDependencies.length,
      entries: [...runtimeDependencies],
    },
    records: {
      dependencyLock: inputRecord('dependencyLock', dependencyLockBytes),
      effectiveGnArgs: inputRecord('effectiveGnArgs', effectiveGnArgsBytes),
      toolchainLock: inputRecord('toolchainLock', toolchainLockBytes),
      artifactLicenses: {
        name: 'LICENSES/artifact-license-manifest.json',
        sha256: sha256(licenseManifestBytes),
        size: licenseManifestBytes.length,
      },
    },
    producers: producerRecords(repoRoot),
  };
}

export function validatePackageRecord(document, inputs) {
  const expected = createPackageRecord(inputs);
  if (!isDeepStrictEqual(document, expected)) {
    throw new TypeError('package record differs from recomputed runtime closure');
  }
  return Object.freeze({
    ok: true,
    platform: expected.platform,
    runtimeDependencies: expected.runtimeDependencies.count,
    sha256: sha256(Buffer.from(
      `${JSON.stringify(expected, null, 2)}\n`,
      'utf8',
    )),
  });
}

export function writePackageRecord(path, record) {
  assertPackageRecordDigests(record);
  const bytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, 'utf8');
  const fd = openSync(
    path,
    constants.O_WRONLY
      | constants.O_CREAT
      | constants.O_EXCL
      | (constants.O_NOFOLLOW ?? 0),
    0o644,
  );
  try {
    let offset = 0;
    while (offset < bytes.length) {
      const written = writeSync(fd, bytes, offset, bytes.length - offset);
      if (written <= 0) {
        throw new TypeError('package record write made no progress');
      }
      offset += written;
    }
  } finally {
    closeSync(fd);
  }
  return Object.freeze({ bytes, sha256: sha256(bytes) });
}

export function assertPackageRecordDigests(document) {
  exactKeys(document, [
    'schemaVersion',
    'documentKind',
    'platform',
    'chromium',
    'buildContract',
    'outputDirectory',
    'runtimeDependencies',
    'records',
    'producers',
  ], 'package record');
  if (document.schemaVersion !== '1.0.0'
      || document.documentKind !== 'gn-runtime-dependency-package'
      || !M0_PLATFORM_IDS.includes(document.platform)) {
    throw new TypeError('unsupported package record');
  }
  exactKeys(
    document.runtimeDependencies,
    ['command', 'encoding', 'sha256', 'count', 'entries'],
    'package runtime dependencies',
  );
  const text = canonicalRuntimeDependencies(document.runtimeDependencies.entries);
  if (document.runtimeDependencies.encoding !== 'utf-8-lf'
      || document.runtimeDependencies.sha256
        !== sha256(Buffer.from(text, 'utf8'))
      || document.runtimeDependencies.count
        !== document.runtimeDependencies.entries.length) {
    throw new TypeError('package runtime dependency binding is invalid');
  }
  exactKeys(
    document.records,
    [
      'dependencyLock',
      'effectiveGnArgs',
      'toolchainLock',
      'artifactLicenses',
    ],
    'package input records',
  );
  for (const [name, item] of Object.entries(document.records)) {
    exactKeys(item, ['name', 'sha256', 'size'], `package record ${name}`);
    if (!SHA256_RE.test(item.sha256)
        || !Number.isSafeInteger(item.size)
        || item.size <= 0) {
      throw new TypeError(`package record ${name} has an invalid digest or size`);
    }
  }
  if (!Array.isArray(document.producers)
      || document.producers.length !== PRODUCER_PATHS.length) {
    throw new TypeError('package record producer set is incomplete');
  }
  for (const [index, item] of document.producers.entries()) {
    exactKeys(
      item,
      ['path', 'sha256', 'size'],
      `package producer ${index}`,
    );
    if (item.path !== PRODUCER_PATHS[index]
        || !SHA256_RE.test(item.sha256)
        || !Number.isSafeInteger(item.size)
        || item.size <= 0) {
      throw new TypeError(`package producer ${index} is invalid`);
    }
  }
  return document;
}
