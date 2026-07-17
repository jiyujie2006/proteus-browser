#!/usr/bin/env node
// Collect GN-declared runtime dependencies into a fresh, relocatable bundle.

import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
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
import { createBundleManifest } from './bundle-manifest.mjs';
import {
  M0_PLATFORM_IDS,
  readAndValidateM0BuildContract,
} from './build-contract.mjs';
import { createArtifactLicenseBundle } from './artifact-licenses.mjs';
import {
  createPackageRecord,
  readStablePackageInput,
  writePackageRecord,
} from './package-record.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = resolve(HERE, '..');
const REPO_ROOT = resolve(ENGINE_ROOT, '..');
const MAX_RUNTIME_DEPS_BYTES = 16 * 1024 * 1024;
const MAX_RUNTIME_DEPS = 200_000;
const HASH_BUFFER_BYTES = 1024 * 1024;

function ordinaryDirectory(path, label) {
  const stat = lstatSync(path, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink directory`);
  }
  return stat;
}

function sameDirectoryState(left, right) {
  return left.isDirectory()
    && right.isDirectory()
    && left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
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

function isContained(root, candidate) {
  const rel = relative(root, candidate);
  return rel === '' || (
    rel !== '..'
    && !rel.startsWith(`..${sep}`)
    && !isAbsolute(rel)
  );
}

function canonicalExistingDirectory(path, label) {
  const value = resolve(path);
  ordinaryDirectory(value, label);
  if (realpathSync(value) !== value) {
    throw new TypeError(`${label} path must already be canonical`);
  }
  return value;
}

function canonicalFreshDirectory(path, label) {
  const value = resolve(path);
  const parent = dirname(value);
  ordinaryDirectory(parent, `${label} parent`);
  if (realpathSync(parent) !== parent) {
    throw new TypeError(`${label} parent path must already be canonical`);
  }
  try {
    lstatSync(value);
  } catch (error) {
    if (error.code === 'ENOENT') return value;
    throw error;
  }
  throw new TypeError(`${label} must not already exist`);
}

function readStableOrdinaryFile(path, label, maxBytes) {
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

export function parseRuntimeDependencies(raw) {
  if (typeof raw !== 'string') {
    throw new TypeError('runtime dependencies must be UTF-8 text');
  }
  const entries = [];
  const seen = new Set();
  for (const [index, original] of raw.split(/\r?\n/u).entries()) {
    if (original === '') continue;
    if (original.trim() !== original
        || original.includes('\\')
        || /[\u0000-\u001f\u007f]/u.test(original)) {
      throw new TypeError(`runtime_deps:${index + 1}: unsafe path`);
    }
    // GN spells outputs rooted directly in root_out_dir as "./chrome" while
    // nested runtime data is already build-relative. Normalize exactly that
    // single leading marker; all other dot segments remain invalid.
    const buildRelative = original.startsWith('./')
      ? original.slice(2)
      : original;
    const value = buildRelative.endsWith('/')
      ? buildRelative.slice(0, -1)
      : buildRelative;
    if (value === ''
        || value.startsWith('/')
        || /^[A-Za-z]:/u.test(value)
        || value.split('/').some((part) =>
          part === '' || part === '.' || part === '..')) {
      throw new TypeError(
        `runtime_deps:${index + 1}: path must be canonical and build-relative`,
      );
    }
    if (seen.has(value)) {
      throw new TypeError(`runtime_deps:${index + 1}: duplicate path ${value}`);
    }
    seen.add(value);
    entries.push(value);
    if (entries.length > MAX_RUNTIME_DEPS) {
      throw new TypeError(
        `runtime dependencies exceed ${MAX_RUNTIME_DEPS} entries`,
      );
    }
  }
  if (entries.length === 0) {
    throw new TypeError('runtime dependency list is empty');
  }
  return entries;
}

function hashFile(path, expected, label) {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameFileState(expected, opened)) {
      throw new TypeError(`${label} changed while it was opened`);
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(HASH_BUFFER_BYTES);
    for (;;) {
      const count = readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
    }
    const after = fstatSync(fd, { bigint: true });
    if (!sameFileState(opened, after)) {
      throw new TypeError(`${label} changed while it was hashed`);
    }
    return hash.digest('hex');
  } finally {
    closeSync(fd);
  }
}

function copyStableFile(source, destination, before, label) {
  const sourceHash = hashFile(source, before, label);
  copyFileSync(source, destination, constants.COPYFILE_EXCL);
  chmodSync(destination, Number(before.mode & 0o777n));
  const sourceAfter = lstatSync(source, { bigint: true });
  if (!sameFileState(before, sourceAfter)) {
    throw new TypeError(`${label} changed while it was copied`);
  }
  const destinationState = lstatSync(destination, { bigint: true });
  if (!destinationState.isFile() || destinationState.isSymbolicLink()) {
    throw new TypeError(`${label} destination is not an ordinary file`);
  }
  const destinationHash = hashFile(
    destination,
    destinationState,
    `${label} destination`,
  );
  if (sourceHash !== destinationHash) {
    throw new TypeError(`${label} destination bytes differ from source`);
  }
}

function copyTreeEntry(sourceRoot, destinationRoot, relativePath, copied) {
  const source = join(sourceRoot, ...relativePath.split('/'));
  const destination = join(destinationRoot, ...relativePath.split('/'));
  if (!isContained(sourceRoot, source)
      || !isContained(destinationRoot, destination)) {
    throw new TypeError(`runtime dependency escapes its root: ${relativePath}`);
  }
  const caseKey = process.platform === 'win32'
    ? relativePath.toLowerCase()
    : relativePath;
  const existing = copied.get(caseKey);
  if (existing) {
    if (existing !== relativePath) {
      throw new TypeError(
        `case-colliding runtime dependencies: ${existing} and ${relativePath}`,
      );
    }
    return;
  }

  const stat = lstatSync(source, { bigint: true });
  mkdirSync(dirname(destination), { recursive: true });
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    if (!copied.has(caseKey)) {
      mkdirSync(destination, { recursive: true });
      copied.set(caseKey, relativePath);
    }
    const before = stat;
    const names = readdirSync(source).sort(compareUtf8);
    for (const name of names) {
      if (name === '' || name === '.' || name === '..'
          || name.includes('/') || name.includes('\\')
          || /[\u0000-\u001f\u007f]/u.test(name)) {
        throw new TypeError(`runtime directory ${relativePath} has unsafe entries`);
      }
      copyTreeEntry(
        sourceRoot,
        destinationRoot,
        `${relativePath}/${name}`,
        copied,
      );
    }
    const afterNames = readdirSync(source).sort(compareUtf8);
    const after = lstatSync(source, { bigint: true });
    if (!sameDirectoryState(before, after)
        || JSON.stringify(names) !== JSON.stringify(afterNames)) {
      throw new TypeError(`runtime directory ${relativePath} changed while copied`);
    }
    chmodSync(destination, Number(before.mode & 0o777n));
  } else if (stat.isFile() && !stat.isSymbolicLink()) {
    copyStableFile(source, destination, stat, `runtime file ${relativePath}`);
    copied.set(caseKey, relativePath);
  } else if (stat.isSymbolicLink()) {
    const target = readlinkSync(source, 'utf8');
    if (target === ''
        || isAbsolute(target)
        || target.includes('\0')
        || /[\u0001-\u001f\u007f]/u.test(target)) {
      throw new TypeError(`runtime symlink ${relativePath} has an unsafe target`);
    }
    const lexicalTarget = resolve(dirname(source), target);
    if (!isContained(sourceRoot, lexicalTarget)) {
      throw new TypeError(`runtime symlink ${relativePath} escapes the output tree`);
    }
    const resolvedTarget = realpathSync(lexicalTarget);
    if (!isContained(sourceRoot, resolvedTarget)) {
      throw new TypeError(`runtime symlink ${relativePath} resolves outside output`);
    }
    symlinkSync(target, destination);
    const after = lstatSync(source, { bigint: true });
    if (!after.isSymbolicLink()
        || stat.dev !== after.dev
        || stat.ino !== after.ino
        || stat.mode !== after.mode
        || stat.mtimeNs !== after.mtimeNs
        || readlinkSync(source, 'utf8') !== target) {
      throw new TypeError(`runtime symlink ${relativePath} changed while copied`);
    }
    copied.set(caseKey, relativePath);
  } else {
    throw new TypeError(
      `runtime dependency ${relativePath} is a special file`,
    );
  }
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function copyLegalFile(source, destination, label) {
  const before = lstatSync(source, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary file`);
  }
  mkdirSync(dirname(destination), { recursive: true });
  copyStableFile(source, destination, before, label);
}

export function packageEngine({
  outDir,
  bundleDir,
  creditsOutDirs = [outDir],
  dependencyLock,
  effectiveGnArgs,
  outDirRelative,
  platform,
  runtimeDependencies,
  toolchainLock,
  repoRoot = REPO_ROOT,
}) {
  if (!M0_PLATFORM_IDS.includes(platform)) {
    throw new TypeError(`unsupported M0 platform ${String(platform)}`);
  }
  const { buildContract } = readAndValidateM0BuildContract();
  const expectedHost = buildContract.platforms[platform].hostPlatform;
  if (process.platform !== expectedHost) {
    throw new TypeError(
      `${platform} bundle packaging requires ${expectedHost}, got ${process.platform}`,
    );
  }
  const output = canonicalExistingDirectory(outDir, 'GN output directory');
  const destination = canonicalFreshDirectory(bundleDir, 'bundle directory');
  const dependencies = parseRuntimeDependencies(
    Array.isArray(runtimeDependencies)
      ? `${runtimeDependencies.join('\n')}\n`
      : runtimeDependencies,
  );

  mkdirSync(destination);
  try {
    const copied = new Map();
    for (const dependency of dependencies) {
      copyTreeEntry(output, destination, dependency, copied);
    }
    copyLegalFile(
      join(repoRoot, 'engine-chromium', 'build', 'm0-build-contract.json'),
      join(destination, 'BUILD-CONTRACT.json'),
      'M0 build contract',
    );
    createArtifactLicenseBundle({
      bundleDir: destination,
      outDir: output,
      creditsOutDirs,
      platform,
      repoRoot,
    });
    const dependencyLockBytes = readStablePackageInput(
      resolve(dependencyLock),
      'resolved dependency lock',
    );
    const effectiveGnArgsBytes = readStablePackageInput(
      resolve(effectiveGnArgs),
      'effective GN args record',
    );
    const toolchainLockBytes = readStablePackageInput(
      resolve(toolchainLock),
      'complete toolchain lock',
    );
    const licenseManifestBytes = readStablePackageInput(
      join(destination, 'LICENSES', 'artifact-license-manifest.json'),
      'artifact license manifest',
    );
    const packageRecord = createPackageRecord({
      platform,
      outDirRelative,
      runtimeDependencies: dependencies,
      dependencyLockBytes,
      effectiveGnArgsBytes,
      toolchainLockBytes,
      licenseManifestBytes,
      repoRoot,
    });
    writePackageRecord(
      join(destination, 'PACKAGE-RECORD.json'),
      packageRecord,
    );

    return createBundleManifest(destination, {
      platform,
      entrypoint: buildContract.platforms[platform].entrypoint,
    });
  } catch (error) {
    rmSync(destination, { force: true, recursive: true });
    throw error;
  }
}

function parseArgs(args) {
  const parsed = {
    outDir: null,
    bundleDir: null,
    creditsOutDirs: [],
    dependencyLock: null,
    effectiveGnArgs: null,
    outDirRelative: null,
    platform: null,
    runtimeDeps: null,
    toolchainLock: null,
  };
  const options = new Map([
    ['--out-dir', 'outDir'],
    ['--out-dir-relative', 'outDirRelative'],
    ['--bundle-dir', 'bundleDir'],
    ['--dependency-lock', 'dependencyLock'],
    ['--effective-gn-args', 'effectiveGnArgs'],
    ['--platform', 'platform'],
    ['--runtime-deps', 'runtimeDeps'],
    ['--toolchain-lock', 'toolchainLock'],
  ]);
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (option === '--credits-out-dir') {
      const value = args[index + 1];
      if (!value || value.startsWith('--')) {
        throw new TypeError('--credits-out-dir requires a value');
      }
      parsed.creditsOutDirs.push(value);
      index += 1;
      continue;
    }
    const key = options.get(option);
    if (!key) throw new TypeError(`unknown argument ${option}`);
    if (parsed[key] !== null) throw new TypeError(`${option} supplied twice`);
    const value = args[index + 1];
    if (!value || value.startsWith('--')) {
      throw new TypeError(`${option} requires a value`);
    }
    parsed[key] = value;
    index += 1;
  }
  if (Object.entries(parsed).some(([key, value]) =>
    key !== 'creditsOutDirs' && value === null)) {
    throw new TypeError(
      'usage: package-engine.mjs --out-dir <dir> --bundle-dir <fresh-dir> '
      + '--out-dir-relative <out/...> --platform <id> --runtime-deps <file> '
      + '--dependency-lock <file> --effective-gn-args <file> '
      + '--toolchain-lock <file>',
    );
  }
  if (parsed.creditsOutDirs.length === 0) {
    parsed.creditsOutDirs.push(parsed.outDir);
  }
  return parsed;
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    const runtimeBytes = readStableOrdinaryFile(
      resolve(args.runtimeDeps),
      'runtime dependency list',
      MAX_RUNTIME_DEPS_BYTES,
    );
    const runtimeDependencies = parseRuntimeDependencies(
      new TextDecoder('utf-8', { fatal: true }).decode(runtimeBytes),
    );
    const manifest = packageEngine({
      outDir: args.outDir,
      bundleDir: args.bundleDir,
      creditsOutDirs: args.creditsOutDirs,
      dependencyLock: args.dependencyLock,
      effectiveGnArgs: args.effectiveGnArgs,
      outDirRelative: args.outDirRelative,
      platform: args.platform,
      runtimeDependencies,
      toolchainLock: args.toolchainLock,
    });
    writeSync(process.stdout.fd, `${JSON.stringify(manifest, null, 2)}\n`);
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
