#!/usr/bin/env node
// Build and verify the license/notice bundle that accompanies an M0 engine
// bundle. Chromium's official build generates about_credits.html from the
// shipped third-party metadata; accepting the checked-in sample would turn a
// redistribution record into a false claim, so this module fails closed.

import { createHash, timingSafeEqual } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  writeSync,
} from 'node:fs';
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { TextDecoder } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  M0_PLATFORM_IDS,
  readAndValidateM0BuildContract,
} from './build-contract.mjs';
import { parseStrictJson } from '../../scripts/strict-json.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = resolve(HERE, '..');
const REPO_ROOT = resolve(ENGINE_ROOT, '..');
const MAX_LEGAL_FILE_BYTES = 128 * 1024 * 1024;
const MIN_GENERATED_CREDITS_BYTES = 64 * 1024;
const MIN_GENERATED_CREDITS_ENTRIES = 25;
const MANIFEST_PATH = 'LICENSES/artifact-license-manifest.json';
const EXPECTED_FILES = Object.freeze([
  Object.freeze({
    path: 'LICENSES/Proteus-Apache-2.0.txt',
    role: 'first-party-license',
  }),
  Object.freeze({
    path: 'LICENSES/Chromium-BSD-3-Clause.txt',
    role: 'engine-license',
  }),
  Object.freeze({
    path: 'LICENSES/Chromium-Third-Party-Credits.html',
    role: 'build-derived-third-party-notices',
  }),
  Object.freeze({
    path: 'NOTICE',
    role: 'project-attribution',
  }),
]);

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

function readStableOrdinaryFile(path, label, maxBytes = MAX_LEGAL_FILE_BYTES) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  if (before.size > BigInt(maxBytes)) {
    throw new TypeError(`${label} exceeds ${maxBytes} bytes`);
  }
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameFileState(before, opened)) {
      throw new TypeError(`${label} changed while it was opened`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    if (!sameFileState(opened, after) || !sameFileState(after, pathAfter)) {
      throw new TypeError(`${label} changed or was rebound while it was read`);
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function writeExclusiveOrdinaryFile(path, bytes, label) {
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
      offset += writeSync(fd, bytes, offset, bytes.length - offset);
    }
    const written = fstatSync(fd, { bigint: true });
    if (!written.isFile()
        || written.isSymbolicLink()
        || written.size !== BigInt(bytes.length)) {
      throw new TypeError(`${label} was not written as an ordinary file`);
    }
  } finally {
    closeSync(fd);
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalExistingDirectory(path, label) {
  const absolute = resolve(path);
  const stat = lstatSync(absolute);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink directory`);
  }
  if (realpathSync(absolute) !== absolute) {
    throw new TypeError(`${label} path must already be canonical`);
  }
  return absolute;
}

function isContained(root, candidate) {
  const rel = relative(root, candidate);
  return rel === '' || (
    rel !== '..'
    && !rel.startsWith(`..${sep}`)
    && !isAbsolute(rel)
  );
}

function decodeUtf8(bytes, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new TypeError(`${label} is not valid UTF-8`);
  }
}

export function validateGeneratedChromiumCredits(bytes) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    throw new TypeError('Chromium credits must be bytes');
  }
  if (bytes.length < MIN_GENERATED_CREDITS_BYTES) {
    throw new TypeError(
      `Chromium credits are too small to be build-derived (${bytes.length} bytes)`,
    );
  }
  const text = decodeUtf8(bytes, 'Chromium credits');
  if (text.includes('\0')) {
    throw new TypeError('Chromium credits contain a NUL byte');
  }
  if (/This is sample credits page|set [`"']?generate_about_credits=true/i.test(text)) {
    throw new TypeError('Chromium sample credits are not release notices');
  }
  if (!/^<!-- Generated by licenses\.py; do not edit\. -->\r?\n<!doctype html>\s*<html>/iu.test(text)
      || !/<title>Credits<\/title>/u.test(text)
      || !/<!-- Chromium <3s the following projects -->/u.test(text)) {
    throw new TypeError(
      'Chromium credits do not match the pinned generated credits template',
    );
  }
  const products = text.match(/<div class="product">/gu) ?? [];
  const licenses = text.match(/<div class="license">/gu) ?? [];
  if (products.length < MIN_GENERATED_CREDITS_ENTRIES
      || products.length !== licenses.length) {
    throw new TypeError(
      'Chromium credits lack the expected generated third-party entries',
    );
  }
  if (/\{\{(?:entries|name|url|license|reciprocal-license-statement)\}\}/u.test(text)) {
    throw new TypeError('Chromium credits still contain template placeholders');
  }
  return Object.freeze({
    entries: products.length,
    sha256: sha256(bytes),
    size: bytes.length,
  });
}

function sourceFiles(repoRoot) {
  return Object.freeze([
    Object.freeze({
      source: join(repoRoot, 'LICENSE'),
      ...EXPECTED_FILES[0],
    }),
    Object.freeze({
      source: join(repoRoot, 'LICENSES', 'Chromium-BSD-3-Clause.txt'),
      ...EXPECTED_FILES[1],
    }),
    Object.freeze({
      source: join(repoRoot, 'NOTICE'),
      ...EXPECTED_FILES[3],
    }),
  ]);
}

export function createArtifactLicenseBundle({
  bundleDir,
  outDir,
  creditsOutDirs = [outDir],
  platform,
  repoRoot = REPO_ROOT,
}) {
  if (!M0_PLATFORM_IDS.includes(platform)) {
    throw new TypeError(`unsupported M0 platform ${String(platform)}`);
  }
  const destinationRoot = canonicalExistingDirectory(
    bundleDir,
    'engine bundle directory',
  );
  const outputRoot = canonicalExistingDirectory(outDir, 'GN output directory');
  const repositoryRoot = canonicalExistingDirectory(repoRoot, 'repository root');
  if (isContained(outputRoot, destinationRoot)
      || isContained(destinationRoot, outputRoot)) {
    throw new TypeError('GN output and engine bundle directories must be disjoint');
  }

  const {
    buildContract,
    buildContractSha256,
  } = readAndValidateM0BuildContract();
  const architectures = buildContract.platforms[platform].architectures;
  if (!Array.isArray(creditsOutDirs)
      || creditsOutDirs.length !== architectures.length) {
    throw new TypeError(
      `${platform} requires ${architectures.length} generated credits outputs`,
    );
  }
  const creditsSnapshots = [];
  for (const [index, architecture] of architectures.entries()) {
    const creditsOutput = canonicalExistingDirectory(
      creditsOutDirs[index],
      `${architecture} GN credits output directory`,
    );
    if (isContained(creditsOutput, destinationRoot)
        || isContained(destinationRoot, creditsOutput)) {
      throw new TypeError(
        `${architecture} GN credits output and bundle directories must be disjoint`,
      );
    }
    const bytes = readStableOrdinaryFile(
      join(
        creditsOutput,
        'gen',
        'components',
        'resources',
        'about_credits.html',
      ),
      `${architecture} build-derived Chromium credits`,
    );
    creditsSnapshots.push({
      architecture,
      bytes,
      audit: validateGeneratedChromiumCredits(bytes),
    });
  }
  const firstCredits = creditsSnapshots[0];
  for (const item of creditsSnapshots.slice(1)) {
    if (item.bytes.length !== firstCredits.bytes.length
        || !timingSafeEqual(item.bytes, firstCredits.bytes)) {
      throw new TypeError(
        `generated Chromium credits differ between ${firstCredits.architecture} and ${item.architecture}`,
      );
    }
  }
  const licensesDirectory = join(destinationRoot, 'LICENSES');
  mkdirSync(licensesDirectory, { recursive: false, mode: 0o755 });

  const files = [];
  for (const record of sourceFiles(repositoryRoot)) {
    const bytes = readStableOrdinaryFile(record.source, record.role);
    const destination = join(
      destinationRoot,
      ...record.path.split('/'),
    );
    if (!isContained(destinationRoot, destination)) {
      throw new TypeError(`license destination escapes bundle: ${record.path}`);
    }
    writeExclusiveOrdinaryFile(destination, bytes, record.role);
    files.push(Object.freeze({
      path: record.path,
      role: record.role,
      sha256: sha256(bytes),
      size: bytes.length,
    }));
  }
  const creditsRecord = EXPECTED_FILES[2];
  const creditsDestination = join(
    destinationRoot,
    ...creditsRecord.path.split('/'),
  );
  writeExclusiveOrdinaryFile(
    creditsDestination,
    firstCredits.bytes,
    creditsRecord.role,
  );
  files.splice(2, 0, Object.freeze({
    path: creditsRecord.path,
    role: creditsRecord.role,
    sha256: firstCredits.audit.sha256,
    size: firstCredits.audit.size,
  }));

  const manifest = Object.freeze({
    schemaVersion: '1.0.0',
    documentKind: 'artifact-license-bundle',
    platform,
    chromium: Object.freeze({
      repository: buildContract.source.chromiumRepository,
      version: buildContract.source.chromiumVersion,
      commit: buildContract.source.chromiumCommit,
    }),
    buildContract: Object.freeze({
      path: 'BUILD-CONTRACT.json',
      sha256: buildContractSha256,
    }),
    credits: Object.freeze({
      buildTarget: '//components/resources:about_credits',
      generator: '//tools/licenses/licenses.py credits',
      generatedPath: 'gen/components/resources/about_credits.html',
      architectures: Object.freeze([...architectures]),
      entries: firstCredits.audit.entries,
    }),
    files: Object.freeze(files),
  });
  const manifestBytes = Buffer.from(
    `${JSON.stringify(manifest, null, 2)}\n`,
    'utf8',
  );
  writeExclusiveOrdinaryFile(
    join(destinationRoot, ...MANIFEST_PATH.split('/')),
    manifestBytes,
    'artifact license manifest',
  );
  return manifest;
}

function assertSha256(value, label) {
  if (!/^[0-9a-f]{64}$/u.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 digest`);
  }
}

function assertSafeInteger(value, label, { positive = false } = {}) {
  if (!Number.isSafeInteger(value)
      || value < (positive ? 1 : 0)) {
    throw new TypeError(`${label} must be a ${positive ? 'positive' : 'non-negative'} safe integer`);
  }
}

export function verifyArtifactLicenseBundle({
  bundleDir,
  manifest,
  platform,
}) {
  const destinationRoot = canonicalExistingDirectory(
    bundleDir,
    'engine bundle directory',
  );
  const parsed = typeof manifest === 'string' || Buffer.isBuffer(manifest)
    ? parseStrictJson(manifest, 'artifact license manifest')
    : manifest;
  exactKeys(
    parsed,
    [
      'schemaVersion',
      'documentKind',
      'platform',
      'chromium',
      'buildContract',
      'credits',
      'files',
    ],
    'artifact license manifest',
  );
  if (parsed.schemaVersion !== '1.0.0'
      || parsed.documentKind !== 'artifact-license-bundle') {
    throw new TypeError('unsupported artifact license manifest');
  }
  if (parsed.platform !== platform || !M0_PLATFORM_IDS.includes(platform)) {
    throw new TypeError('artifact license manifest platform mismatch');
  }
  const {
    buildContract,
    buildContractSha256,
  } = readAndValidateM0BuildContract();
  exactKeys(
    parsed.chromium,
    ['repository', 'version', 'commit'],
    'artifact license Chromium identity',
  );
  for (const [key, expected] of Object.entries({
    repository: buildContract.source.chromiumRepository,
    version: buildContract.source.chromiumVersion,
    commit: buildContract.source.chromiumCommit,
  })) {
    if (parsed.chromium[key] !== expected) {
      throw new TypeError(`artifact license Chromium ${key} mismatch`);
    }
  }
  exactKeys(
    parsed.buildContract,
    ['path', 'sha256'],
    'artifact license build contract',
  );
  if (parsed.buildContract.path !== 'BUILD-CONTRACT.json'
      || parsed.buildContract.sha256 !== buildContractSha256) {
    throw new TypeError('artifact license build contract mismatch');
  }
  exactKeys(
    parsed.credits,
    [
      'buildTarget',
      'generator',
      'generatedPath',
      'architectures',
      'entries',
    ],
    'artifact license credits identity',
  );
  if (parsed.credits.buildTarget !== '//components/resources:about_credits'
      || parsed.credits.generator !== '//tools/licenses/licenses.py credits'
      || parsed.credits.generatedPath
        !== 'gen/components/resources/about_credits.html') {
    throw new TypeError('artifact license credits generator mismatch');
  }
  if (!Array.isArray(parsed.credits.architectures)
      || JSON.stringify(parsed.credits.architectures)
        !== JSON.stringify(buildContract.platforms[platform].architectures)) {
    throw new TypeError('artifact license credits architectures mismatch');
  }
  assertSafeInteger(parsed.credits.entries, 'artifact license credits entries', {
    positive: true,
  });
  if (!Array.isArray(parsed.files)
      || parsed.files.length !== EXPECTED_FILES.length) {
    throw new TypeError('artifact license manifest has an incomplete file set');
  }

  for (const [index, expected] of EXPECTED_FILES.entries()) {
    const record = parsed.files[index];
    exactKeys(
      record,
      ['path', 'role', 'sha256', 'size'],
      `artifact license file ${index}`,
    );
    if (record.path !== expected.path || record.role !== expected.role) {
      throw new TypeError(`artifact license file ${index} identity mismatch`);
    }
    assertSha256(record.sha256, `artifact license file ${index} sha256`);
    assertSafeInteger(record.size, `artifact license file ${index} size`);
    const bytes = readStableOrdinaryFile(
      join(destinationRoot, ...record.path.split('/')),
      `artifact license file ${record.path}`,
    );
    if (bytes.length !== record.size || sha256(bytes) !== record.sha256) {
      throw new TypeError(`artifact license file ${record.path} digest mismatch`);
    }
    if (record.role === 'build-derived-third-party-notices') {
      const credits = validateGeneratedChromiumCredits(bytes);
      if (credits.entries !== parsed.credits.entries) {
        throw new TypeError('artifact license credits entry count mismatch');
      }
    }
  }
  return Object.freeze({
    ok: true,
    platform,
    manifestSha256: sha256(Buffer.from(
      `${JSON.stringify(parsed, null, 2)}\n`,
      'utf8',
    )),
    files: parsed.files.length,
    creditsEntries: parsed.credits.entries,
  });
}

function parseArgs(args) {
  const values = {
    bundleDir: null,
    creditsOutDirs: [],
    manifest: null,
    outDir: null,
    platform: null,
  };
  let command = null;
  if (args[0] === 'create' || args[0] === 'verify') {
    [command] = args;
    args = args.slice(1);
  }
  const options = new Map([
    ['--bundle-dir', 'bundleDir'],
    ['--manifest', 'manifest'],
    ['--out-dir', 'outDir'],
    ['--platform', 'platform'],
  ]);
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (option === '--credits-out-dir') {
      const value = args[index + 1];
      if (!value || value.startsWith('--')) {
        throw new TypeError('--credits-out-dir requires a value');
      }
      values.creditsOutDirs.push(value);
      index += 1;
      continue;
    }
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
  if (!command || !values.bundleDir || !values.platform) {
    throw new TypeError(
      'usage: artifact-licenses.mjs <create|verify> --bundle-dir <dir> '
      + '--platform <id> [--out-dir <dir> | --manifest <file>]',
    );
  }
  if (command === 'create' && (!values.outDir || values.manifest)
      || command === 'verify' && (!values.manifest || values.outDir)) {
    throw new TypeError('create requires --out-dir; verify requires --manifest');
  }
  if (values.creditsOutDirs.length === 0 && values.outDir) {
    values.creditsOutDirs.push(values.outDir);
  }
  return { command, ...values };
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.command === 'create') {
      const manifest = createArtifactLicenseBundle(args);
      writeSync(process.stdout.fd, `${JSON.stringify(manifest, null, 2)}\n`);
    } else {
      const bytes = readStableOrdinaryFile(
        resolve(args.manifest),
        'artifact license manifest',
        8 * 1024 * 1024,
      );
      const audit = verifyArtifactLicenseBundle({
        bundleDir: args.bundleDir,
        manifest: bytes,
        platform: args.platform,
      });
      writeSync(process.stdout.fd, `${JSON.stringify(audit, null, 2)}\n`);
    }
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
