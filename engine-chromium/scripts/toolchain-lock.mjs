#!/usr/bin/env node
// Capture and verify the complete, build-derived M0 toolchain identity.
//
// A version string is never treated as a toolchain identity. Every executable
// that selects or performs the build is hashed as a stable ordinary file, and
// every platform SDK/sysroot is enumerated into a complete content-tree
// digest. Platform discovery is deliberately local and fail-closed: this file
// has no download/update path and never accepts a caller-supplied SDK claim.

import { spawnSync } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readlinkSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
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
import { isDeepStrictEqual, TextDecoder } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  M0_HARD_ASSURANCE_LEVEL,
  M0_PLATFORM_IDS,
  readAndValidateM0BuildContract,
} from './build-contract.mjs';
import { assertPinnedChromiumCheckout } from './chromium-checkout.mjs';
import {
  parseJsonWithoutDuplicateKeys,
  verifyDependencyLock,
} from './dependency-lock.mjs';
import { assertPinnedDepotTools } from './depot-tools-checkout.mjs';
import {
  validateEffectiveGnArgsRecord,
} from './effective-gn-args.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = resolve(HERE, '..');
const BUILD_CONTRACT_PATH = join(
  ENGINE_ROOT,
  'build',
  'm0-build-contract.json',
);
const TRUST_CONTRACT_PATH = join(ENGINE_ROOT, 'build', 'm0-trust.json');
const LOCK_SCHEMA_VERSION = '1.0.0';
const LOCK_ASSURANCE = 'complete-build-toolchain-sha256/v1';
const TREE_DOMAIN = Buffer.from(
  'PROTEUS-COMPLETE-TOOLCHAIN-TREE\0v1\0',
  'utf8',
);
const MAX_SMALL_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOOL_FILE_BYTES = 16 * 1024 * 1024 * 1024;
const MAX_TREE_FILE_BYTES = 64 * 1024 * 1024 * 1024;
const MAX_TREE_TOTAL_BYTES = 1024 * 1024 * 1024 * 1024;
const MAX_TREE_ENTRIES = 5_000_000;
const MAX_TREE_DEPTH = 256;
const HASH_BUFFER_BYTES = 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024;
const SHA256_RE = /^[0-9a-f]{64}$/u;
const ID_RE = /^[a-z][a-z0-9-]{0,63}$/u;
const CONTROL_RE = /[\u0000-\u001f\u007f]/u;
const UTF8 = new TextDecoder('utf-8', { fatal: true });

const PLATFORM_TOOLCHAIN_KINDS = Object.freeze({
  'linux-x64': 'linux-sysroot',
  'macos-universal': 'macos-xcode-sdk',
  'windows-x64': 'windows-msvc-sdk',
});

const PLATFORM_ROOT_IDS = Object.freeze({
  'linux-x64': Object.freeze(['linux-sysroot']),
  'macos-universal': Object.freeze(['macos-sdk', 'xcode-installation']),
  'windows-x64': Object.freeze(['visual-studio', 'windows-sdk']),
});

const OFFLINE_PLATFORM_SPECS = Object.freeze({
  'linux-x64': Object.freeze({
    architectures: Object.freeze(['x86_64']),
    entrypoint: 'chrome',
    hostPlatform: 'linux',
  }),
  'macos-universal': Object.freeze({
    architectures: Object.freeze(['x86_64', 'arm64']),
    entrypoint: 'Chromium.app/Contents/MacOS/Chromium',
    hostPlatform: 'darwin',
  }),
  'windows-x64': Object.freeze({
    architectures: Object.freeze(['x86_64']),
    entrypoint: 'chrome.exe',
    hostPlatform: 'win32',
  }),
});

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function hasControl(value) {
  return CONTROL_RE.test(value);
}

function assertSafeString(value, label, maximum = 32 * 1024) {
  if (
    typeof value !== 'string'
    || value === ''
    || value.length > maximum
    || hasControl(value)
  ) {
    throw new TypeError(`${label} must be non-empty control-free text`);
  }
  return value;
}

function assertId(value, label) {
  if (typeof value !== 'string' || !ID_RE.test(value)) {
    throw new TypeError(`${label} must be a canonical lowercase identifier`);
  }
  return value;
}

function portableMode(stat) {
  return Number(stat.mode & 0o777n).toString(8).padStart(3, '0');
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

function sameDirectoryState(left, right) {
  return left.isDirectory()
    && right.isDirectory()
    && left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function sameSymlinkState(left, right) {
  return left.isSymbolicLink()
    && right.isSymbolicLink()
    && left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function ordinaryDirectory(path, label, { requireCanonical = true } = {}) {
  if (typeof path !== 'string' || !isAbsolute(path) || hasControl(path)) {
    throw new TypeError(`${label} must be an absolute control-free path`);
  }
  const normalized = resolve(path);
  let stat;
  try {
    stat = lstatSync(normalized, { bigint: true });
  } catch (error) {
    throw new TypeError(`${label} cannot be inspected: ${error.message}`);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink directory`);
  }
  let canonical;
  try {
    canonical = realpathSync.native(normalized);
  } catch (error) {
    throw new TypeError(`${label} cannot be canonicalized: ${error.message}`);
  }
  if (requireCanonical && canonical !== normalized) {
    throw new TypeError(`${label} path must already be canonical`);
  }
  return Object.freeze({ path: canonical, stat });
}

function assertContained(root, candidate, label, { allowRoot = false } = {}) {
  const rel = relative(root, candidate);
  const contained = rel === '' || (
    rel !== '..'
    && !rel.startsWith(`..${sep}`)
    && !isAbsolute(rel)
  );
  if (!contained || (!allowRoot && rel === '')) {
    throw new TypeError(`${label} is not strictly contained by ${root}`);
  }
  return rel;
}

function assertDisjoint(left, right, label) {
  const leftToRight = relative(left, right);
  const rightToLeft = relative(right, left);
  const contains = (value) => value === '' || (
    value !== '..'
    && !value.startsWith(`..${sep}`)
    && !isAbsolute(value)
  );
  if (contains(leftToRight) || contains(rightToLeft)) {
    throw new TypeError(`${label} must not overlap`);
  }
}

function readStableBytes(path, maximum, label) {
  if (!Number.isSafeInteger(maximum) || maximum <= 0) {
    throw new TypeError('stable-file maximum must be a positive safe integer');
  }
  const normalized = resolve(path);
  const before = lstatSync(normalized, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  if (before.size < 0n || before.size > BigInt(maximum)) {
    throw new TypeError(`${label} exceeds ${maximum} bytes`);
  }
  const fd = openSync(
    normalized,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameFileState(before, opened)) {
      throw new TypeError(`${label} changed while it was opened`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const rebound = lstatSync(normalized, { bigint: true });
    if (
      !sameFileState(opened, after)
      || !sameFileState(after, rebound)
    ) {
      throw new TypeError(`${label} changed or was rebound while it was read`);
    }
    return Object.freeze({
      bytes,
      mode: portableMode(opened),
      path: normalized,
      size: Number(opened.size),
    });
  } finally {
    closeSync(fd);
  }
}

function decodeUtf8(bytes, label) {
  try {
    return UTF8.decode(bytes);
  } catch {
    throw new TypeError(`${label} is not valid UTF-8`);
  }
}

function hashStableOrdinaryFile(
  path,
  label,
  maximum = MAX_TOOL_FILE_BYTES,
) {
  if (!Number.isSafeInteger(maximum) || maximum <= 0) {
    throw new TypeError('stable-file maximum must be a positive safe integer');
  }
  if (typeof path !== 'string' || !isAbsolute(path) || hasControl(path)) {
    throw new TypeError(`${label} must have an absolute control-free path`);
  }
  const normalized = resolve(path);
  const before = lstatSync(normalized, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  const canonical = realpathSync.native(normalized);
  if (canonical !== normalized) {
    throw new TypeError(`${label} path must already be canonical`);
  }
  if (before.size < 0n || before.size > BigInt(maximum)) {
    throw new TypeError(`${label} exceeds ${maximum} bytes`);
  }
  const fd = openSync(
    normalized,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameFileState(before, opened)) {
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
    const rebound = lstatSync(normalized, { bigint: true });
    if (
      !sameFileState(opened, after)
      || !sameFileState(after, rebound)
    ) {
      throw new TypeError(`${label} changed or was rebound while it was hashed`);
    }
    return Object.freeze({
      mode: portableMode(opened),
      path: normalized,
      sha256: hash.digest('hex'),
      size: Number(opened.size),
    });
  } finally {
    closeSync(fd);
  }
}

function stableFileIdentity(path, label, maximum = MAX_SMALL_FILE_BYTES) {
  return hashStableOrdinaryFile(path, label, maximum);
}

function safeDirectoryNames(path, label) {
  let rawNames;
  try {
    rawNames = readdirSync(path, { encoding: 'buffer' });
  } catch (error) {
    throw new TypeError(`${label} cannot be fully enumerated: ${error.message}`);
  }
  const names = rawNames.map((bytes) => {
    const name = decodeUtf8(bytes, `${label} entry name`);
    if (
      name === ''
      || name === '.'
      || name === '..'
      || name.includes('/')
      || name.includes('\\')
      || hasControl(name)
    ) {
      throw new TypeError(`${label} contains an unsafe directory entry`);
    }
    return name;
  });
  names.sort(compareUtf8);
  return names;
}

function updateTreeHash(hash, record) {
  const bytes = Buffer.from(JSON.stringify(record), 'utf8');
  const length = Buffer.allocUnsafe(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  hash.update(length);
  hash.update(bytes);
}

/**
 * Hash a complete directory tree without following symlinks.
 *
 * The digest commits to every relative path, entry type, portable mode, file
 * size and file SHA-256, or symlink target. Directory names are ordered by
 * their UTF-8 bytes. A traversal that cannot enumerate every entry is an error.
 */
export function hashCompleteDirectoryTree(path, {
  label = 'toolchain directory',
  maxEntries = MAX_TREE_ENTRIES,
  maxFileBytes = MAX_TREE_FILE_BYTES,
  maxTotalBytes = MAX_TREE_TOTAL_BYTES,
} = {}) {
  const root = ordinaryDirectory(path, label, { requireCanonical: true });
  for (const [value, name] of [
    [maxEntries, 'maxEntries'],
    [maxFileBytes, 'maxFileBytes'],
    [maxTotalBytes, 'maxTotalBytes'],
  ]) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new TypeError(`${name} must be a positive safe integer`);
    }
  }

  const digest = createHash('sha256').update(TREE_DOMAIN);
  const counts = {
    directories: 0,
    files: 0,
    symlinks: 0,
  };
  let entries = 0;
  let totalBytes = 0n;

  const countEntry = (type) => {
    entries += 1;
    counts[type] += 1;
    if (entries > maxEntries) {
      throw new TypeError(
        `${label} is incomplete: more than ${maxEntries} entries`,
      );
    }
  };

  const relativePath = (candidate) => {
    const rel = relative(root.path, candidate).split(sep).join('/');
    if (
      rel === ''
      || rel.startsWith('/')
      || rel.split('/').some((part) =>
        part === '' || part === '.' || part === '..')
      || hasControl(rel)
    ) {
      throw new TypeError(`${label} produced an unsafe relative path`);
    }
    return rel;
  };

  const hashTreeFile = (candidate, before, rel) => {
    if (before.size < 0n || before.size > BigInt(maxFileBytes)) {
      throw new TypeError(
        `${label} file ${rel} exceeds ${maxFileBytes} bytes; tree is incomplete`,
      );
    }
    const fd = openSync(
      candidate,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    try {
      const opened = fstatSync(fd, { bigint: true });
      if (!sameFileState(before, opened)) {
        throw new TypeError(`${label} file ${rel} changed while opened`);
      }
      const fileHash = createHash('sha256');
      const buffer = Buffer.allocUnsafe(HASH_BUFFER_BYTES);
      for (;;) {
        const count = readSync(fd, buffer, 0, buffer.length, null);
        if (count === 0) break;
        fileHash.update(buffer.subarray(0, count));
      }
      const after = fstatSync(fd, { bigint: true });
      const rebound = lstatSync(candidate, { bigint: true });
      if (
        !sameFileState(opened, after)
        || !sameFileState(after, rebound)
      ) {
        throw new TypeError(
          `${label} file ${rel} changed or was rebound while hashed`,
        );
      }
      totalBytes += opened.size;
      if (totalBytes > BigInt(maxTotalBytes)) {
        throw new TypeError(
          `${label} exceeds ${maxTotalBytes} file bytes; tree is incomplete`,
        );
      }
      return {
        mode: portableMode(opened),
        path: rel,
        sha256: fileHash.digest('hex'),
        size: Number(opened.size),
        type: 'file',
      };
    } finally {
      closeSync(fd);
    }
  };

  const walk = (directory, depth, directoryRelative = '') => {
    if (depth > MAX_TREE_DEPTH) {
      throw new TypeError(
        `${label} exceeds traversal depth ${MAX_TREE_DEPTH}; tree is incomplete`,
      );
    }
    const before = lstatSync(directory, { bigint: true });
    if (!before.isDirectory() || before.isSymbolicLink()) {
      throw new TypeError(`${label} directory was rebound during traversal`);
    }
    countEntry('directories');
    updateTreeHash(digest, {
      mode: portableMode(before),
      path: directoryRelative,
      type: 'directory',
    });
    const names = safeDirectoryNames(directory, `${label} directory`);

    for (const name of names) {
      const candidate = join(directory, name);
      const rel = relativePath(candidate);
      const stat = lstatSync(candidate, { bigint: true });
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        walk(candidate, depth + 1, rel);
      } else if (stat.isFile() && !stat.isSymbolicLink()) {
        const record = hashTreeFile(candidate, stat, rel);
        countEntry('files');
        updateTreeHash(digest, record);
      } else if (stat.isSymbolicLink()) {
        let targetBytes;
        try {
          targetBytes = readlinkSync(candidate, { encoding: 'buffer' });
        } catch (error) {
          throw new TypeError(
            `${label} symlink ${rel} cannot be read: ${error.message}`,
          );
        }
        const target = decodeUtf8(targetBytes, `${label} symlink ${rel}`);
        if (target === '' || hasControl(target)) {
          throw new TypeError(`${label} symlink ${rel} has an unsafe target`);
        }
        const resolvedTarget = resolve(dirname(candidate), target);
        try {
          assertContained(
            root.path,
            resolvedTarget,
            `${label} symlink ${rel}`,
            { allowRoot: true },
          );
        } catch {
          throw new TypeError(
            `${label} symlink ${rel} escapes the enumerated root; `
            + 'tree content is incomplete',
          );
        }
        const after = lstatSync(candidate, { bigint: true });
        const targetAfter = readlinkSync(candidate, { encoding: 'buffer' });
        if (
          !sameSymlinkState(stat, after)
          || !Buffer.from(targetAfter).equals(Buffer.from(targetBytes))
        ) {
          throw new TypeError(
            `${label} symlink ${rel} changed while it was inspected`,
          );
        }
        countEntry('symlinks');
        updateTreeHash(digest, {
          mode: portableMode(stat),
          path: rel,
          target,
          type: 'symlink',
        });
      } else {
        throw new TypeError(
          `${label} entry ${rel} is not a file, directory, or symlink`,
        );
      }
    }

    const namesAfter = safeDirectoryNames(directory, `${label} directory`);
    const after = lstatSync(directory, { bigint: true });
    if (
      !sameDirectoryState(before, after)
      || !isDeepStrictEqual(names, namesAfter)
    ) {
      throw new TypeError(`${label} changed while it was enumerated`);
    }
  };

  walk(root.path, 0);
  const rootAfter = lstatSync(root.path, { bigint: true });
  if (!sameDirectoryState(root.stat, rootAfter)) {
    throw new TypeError(`${label} root changed during complete enumeration`);
  }
  return Object.freeze({
    directories: counts.directories,
    entries,
    files: counts.files,
    path: root.path,
    symlinks: counts.symlinks,
    totalFileBytes: Number(totalBytes),
    treeSha256: digest.digest('hex'),
  });
}

/**
 * Construct the minimal deterministic environment used by local discovery and
 * all validators invoked by this lock collector.
 */
export function controlledToolchainEnvironment(
  source = process.env,
  {
    gitPath = null,
    platform = process.platform,
  } = {},
) {
  if (!['darwin', 'linux', 'win32'].includes(platform)) {
    throw new TypeError(`unsupported controlled-environment platform ${platform}`);
  }
  const environment = Object.create(null);
  environment.DEPOT_TOOLS_METRICS = '0';
  environment.DEPOT_TOOLS_UPDATE = '0';
  environment.LANG = 'C';
  environment.LC_ALL = 'C';
  if (gitPath !== null && (
    typeof gitPath !== 'string'
    || !isAbsolute(gitPath)
    || hasControl(gitPath)
  )) {
    throw new TypeError('controlled Git path must be absolute and control-free');
  }
  const searchRoots = [
    ...(gitPath ? [dirname(resolve(gitPath))] : []),
    ...(platform === 'win32' ? [] : ['/usr/bin', '/bin']),
  ].filter((value, index, values) => values.indexOf(value) === index);
  environment.PATH = searchRoots.join(platform === 'win32' ? ';' : ':');

  if (platform === 'win32') {
    const systemRoot = source.SystemRoot || source.WINDIR;
    if (
      typeof systemRoot !== 'string'
      || !isAbsolute(systemRoot)
      || hasControl(systemRoot)
    ) {
      throw new TypeError(
        'complete Windows toolchain discovery requires an absolute SystemRoot',
      );
    }
    environment.SystemRoot = resolve(systemRoot);
    environment.WINDIR = environment.SystemRoot;
    environment.ComSpec = join(
      environment.SystemRoot,
      'System32',
      'cmd.exe',
    );
  }
  return Object.freeze(environment);
}

/**
 * Run one fixed, absolute local command without a shell or inherited ambient
 * environment. The executable is hashed before and after execution.
 */
export function runControlledCommand(
  executable,
  args,
  {
    cwd,
    environment = process.env,
    invoke = spawnSync,
    platform = process.platform,
  } = {},
) {
  if (!Array.isArray(args) || args.some((arg) =>
    typeof arg !== 'string' || arg.includes('\0'))) {
    throw new TypeError('controlled command arguments must be NUL-free strings');
  }
  const before = hashStableOrdinaryFile(
    executable,
    'controlled command executable',
  );
  const working = ordinaryDirectory(cwd, 'controlled command cwd');
  const env = controlledToolchainEnvironment(environment, { platform });
  const result = invoke(before.path, args, {
    cwd: working.path,
    encoding: 'buffer',
    env,
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
    windowsHide: true,
  });
  if (!result || typeof result !== 'object') {
    throw new TypeError('controlled command returned no process result');
  }
  if (result.error) {
    throw new TypeError(`controlled command failed: ${result.error.message}`);
  }
  if (result.signal) {
    throw new TypeError(`controlled command was terminated by ${result.signal}`);
  }
  if (result.status !== 0) {
    const stderr = Buffer.from(result.stderr || '')
      .toString('utf8')
      .trim()
      .split('\n')[0];
    throw new TypeError(
      `controlled command exited ${String(result.status)}`
      + (stderr ? `: ${stderr}` : ''),
    );
  }
  const stdoutBytes = Buffer.from(result.stdout || '');
  if (stdoutBytes.length > MAX_COMMAND_OUTPUT_BYTES) {
    throw new TypeError('controlled command output exceeds the local limit');
  }
  const stdout = decodeUtf8(stdoutBytes, 'controlled command output').trim();
  const after = hashStableOrdinaryFile(
    executable,
    'controlled command executable',
  );
  if (!isDeepStrictEqual(before, after)) {
    throw new TypeError('controlled command executable changed while invoked');
  }
  return stdout;
}

export function parseEffectiveGnArgs(raw) {
  if (typeof raw !== 'string') {
    throw new TypeError('effective GN args must be UTF-8 text');
  }
  if (Buffer.byteLength(raw, 'utf8') > MAX_SMALL_FILE_BYTES) {
    throw new TypeError('effective GN args exceed the local limit');
  }
  const assignments = Object.create(null);
  for (const line of raw.split(/\r?\n/u)) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    const match = trimmed.match(
      /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/u,
    );
    if (!match) continue;
    const [, name, value] = match;
    if (Object.hasOwn(assignments, name)) {
      throw new TypeError(`effective GN args repeat ${name}`);
    }
    assignments[name] = value;
  }
  if (Object.keys(assignments).length === 0) {
    throw new TypeError('effective GN args contain no assignments');
  }
  return Object.freeze(assignments);
}

function gnBoolean(assignments, name, { required = true } = {}) {
  const value = assignments[name];
  if (value === undefined && !required) return null;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new TypeError(`effective GN arg ${name} is not an explicit boolean`);
}

function gnString(assignments, name, { required = true } = {}) {
  const value = assignments[name];
  if (value === undefined && !required) return null;
  if (typeof value !== 'string' || !value.startsWith('"')) {
    throw new TypeError(`effective GN arg ${name} is not an explicit string`);
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new TypeError(`effective GN arg ${name} is not a JSON-safe GN string`);
  }
  if (typeof parsed !== 'string' || parsed.includes('\0')) {
    throw new TypeError(`effective GN arg ${name} is not a safe string`);
  }
  return parsed;
}

function expectedTargetCpu(architecture) {
  const values = {
    arm64: 'arm64',
    x86_64: 'x64',
  };
  const value = values[architecture];
  if (!value) throw new TypeError(`unsupported M0 architecture ${architecture}`);
  return value;
}

function inspectEffectiveArgs(raw, platform, architecture) {
  const assignments = parseEffectiveGnArgs(raw);
  const targetCpu = gnString(assignments, 'target_cpu');
  const expectedCpu = expectedTargetCpu(architecture);
  if (targetCpu !== expectedCpu) {
    throw new TypeError(
      `effective GN target_cpu ${targetCpu} does not bind ${architecture}`,
    );
  }
  const useSiso = gnBoolean(assignments, 'use_siso');
  return Object.freeze({
    assignments,
    backend: useSiso ? 'siso' : 'ninja',
    platform,
    targetCpu,
  });
}

function incomplete(platform, message) {
  return new TypeError(
    `complete ${platform} toolchain lock is incomplete: ${message}`,
  );
}

function resolveGnPath(source, value, label) {
  if (typeof value !== 'string' || value === '' || value.includes('\0')) {
    throw new TypeError(`${label} is absent`);
  }
  if (value.startsWith('//')) {
    const candidate = resolve(source, value.slice(2));
    assertContained(source, candidate, label);
    return candidate;
  }
  if (!isAbsolute(value)) {
    throw new TypeError(`${label} is neither //-absolute nor host-absolute`);
  }
  return resolve(value);
}

function firstExistingPath(candidates, label) {
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      hashStableOrdinaryFile(candidate, label);
      return resolve(candidate);
    }
  }
  throw new TypeError(`${label} cannot be resolved from the pinned checkout`);
}

function canonicalDiscoveredDirectory(path, label) {
  if (typeof path !== 'string' || !isAbsolute(path) || hasControl(path)) {
    throw new TypeError(`${label} must be an absolute control-free path`);
  }
  let canonical;
  try {
    canonical = realpathSync.native(resolve(path));
  } catch (error) {
    throw new TypeError(`${label} cannot be resolved: ${error.message}`);
  }
  return ordinaryDirectory(canonical, label, { requireCanonical: true }).path;
}

function readVersionEvidence(path, label) {
  const stable = readStableBytes(path, MAX_SMALL_FILE_BYTES, label);
  const text = decodeUtf8(stable.bytes, label).trim();
  if (text === '' || text.includes('\0')) {
    throw new TypeError(`${label} has no usable version evidence`);
  }
  return Object.freeze({ path: stable.path, value: text.slice(0, 4096) });
}

export function discoverLinuxPlatformToolchain({
  source,
  effectiveArgs,
}) {
  try {
    if (gnBoolean(effectiveArgs, 'use_sysroot') !== true) {
      throw new TypeError(
        'use_sysroot is not true; the unbounded host filesystem is not lockable',
      );
    }
    const targetSysroot = gnString(
      effectiveArgs,
      'target_sysroot',
      { required: false },
    ) || '';
    const explicitSysroot = gnString(
      effectiveArgs,
      'sysroot',
      { required: false },
    ) || '';
    let selectedSysroot = targetSysroot || explicitSysroot;
    const selectionEvidence = [];
    let selection = targetSysroot
      ? 'target_sysroot'
      : explicitSysroot
        ? 'sysroot'
        : 'pinned-sysroot-gni-default';
    if (!selectedSysroot) {
      const targetSysrootDir = gnString(
        effectiveArgs,
        'target_sysroot_dir',
      );
      const targetCpu = gnString(effectiveArgs, 'target_cpu');
      const sysrootGniPath = join(
        source,
        'build',
        'config',
        'sysroot.gni',
      );
      const stableGni = readStableBytes(
        sysrootGniPath,
        MAX_SMALL_FILE_BYTES,
        'pinned sysroot.gni',
      );
      const sysrootGni = decodeUtf8(
        stableGni.bytes,
        'pinned sysroot.gni',
      );
      const escapedCpu = targetCpu.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
      const pattern = new RegExp(
        `(?:if|else if)\\s*\\(current_cpu\\s*==\\s*"${escapedCpu}"\\)`
        + '\\s*\\{\\s*sysroot\\s*=\\s*'
        + '"\\$target_sysroot_dir\\/([^"\\r\\n]+)"',
        'gu',
      );
      const matches = [...sysrootGni.matchAll(pattern)];
      if (
        matches.length !== 1
        || !/^[A-Za-z0-9._-]+-sysroot$/u.test(matches[0][1])
      ) {
        throw new TypeError(
          `cannot uniquely derive the ${targetCpu} default from pinned sysroot.gni`,
        );
      }
      selectedSysroot = `${targetSysrootDir}/${matches[0][1]}`;
      selectionEvidence.push({
        id: 'sysroot-selection-gni',
        path: sysrootGniPath,
      });
    }
    const sysrootPath = canonicalDiscoveredDirectory(
      resolveGnPath(source, selectedSysroot, 'selected Linux sysroot'),
      'Linux target sysroot',
    );
    assertContained(source, sysrootPath, 'Linux target sysroot');
    const candidates = [
      join(sysrootPath, 'etc', 'debian_version'),
      join(sysrootPath, 'etc', 'os-release'),
      join(sysrootPath, 'usr', 'lib', 'os-release'),
    ];
    const evidencePath = candidates.find((candidate) => existsSync(candidate));
    if (!evidencePath) {
      throw new TypeError('sysroot has no local OS/version evidence file');
    }
    const version = readVersionEvidence(
      evidencePath,
      'Linux sysroot version evidence',
    );
    return Object.freeze({
      evidence: Object.freeze([
        ...selectionEvidence.map((item) => Object.freeze(item)),
        Object.freeze({ id: 'sysroot-version', path: version.path }),
      ]),
      kind: 'linux-sysroot',
      metadata: Object.freeze({
        selectedSysroot,
        selection,
        targetSysroot,
        version: version.value,
      }),
      roots: Object.freeze([
        Object.freeze({ id: 'linux-sysroot', path: sysrootPath }),
      ]),
    });
  } catch (error) {
    throw incomplete('linux-x64', error.message);
  }
}

function commandOutput(
  executable,
  args,
  {
    environment,
    runCommand,
    source,
  },
) {
  return runCommand(executable, args, {
    cwd: source,
    environment,
    platform: 'darwin',
  });
}

export function discoverMacosPlatformToolchain({
  effectiveArgs,
  environment,
  outDir,
  runCommand = runControlledCommand,
  source,
}) {
  try {
    const xcodeSelect = '/usr/bin/xcode-select';
    const xcrun = '/usr/bin/xcrun';
    const xcodebuild = '/usr/bin/xcodebuild';
    const useSystemXcode = gnBoolean(effectiveArgs, 'use_system_xcode');
    const declaredSdkPath = gnString(
      effectiveArgs,
      'mac_sdk_path',
      { required: false },
    ) || '';
    let developerRoot;
    let installationRoot;
    let sdkPath;
    let sdkVersion;
    let xcodeVersion;
    let discoveryTools;

    if (useSystemXcode) {
      developerRoot = canonicalDiscoveredDirectory(
        commandOutput(xcodeSelect, ['-p'], {
          environment,
          runCommand,
          source,
        }),
        'Xcode developer root',
      );
      sdkPath = canonicalDiscoveredDirectory(
        commandOutput(xcrun, ['--sdk', 'macosx', '--show-sdk-path'], {
          environment,
          runCommand,
          source,
        }),
        'macOS SDK root',
      );
      assertContained(developerRoot, sdkPath, 'macOS SDK root');
      if (declaredSdkPath) {
        let declaredPath;
        if (isAbsolute(declaredSdkPath) || declaredSdkPath.startsWith('//')) {
          declaredPath = resolveGnPath(
            source,
            declaredSdkPath,
            'mac_sdk_path',
          );
        } else {
          declaredPath = resolve(outDir, declaredSdkPath);
          assertContained(outDir, declaredPath, 'relative mac_sdk_path');
        }
        const declaredCanonical = canonicalDiscoveredDirectory(
          declaredPath,
          'effective macOS SDK root',
        );
        if (declaredCanonical !== sdkPath) {
          throw new TypeError(
            'effective mac_sdk_path differs from xcrun active SDK',
          );
        }
      }
      sdkVersion = commandOutput(
        xcrun,
        ['--sdk', 'macosx', '--show-sdk-version'],
        { environment, runCommand, source },
      );
      xcodeVersion = commandOutput(
        xcodebuild,
        ['-version'],
        { environment, runCommand, source },
      );
      const developerSuffix = join('Contents', 'Developer');
      const candidateInstallation = resolve(developerRoot, '..', '..');
      installationRoot = developerRoot.endsWith(developerSuffix)
        && existsSync(candidateInstallation)
        ? canonicalDiscoveredDirectory(
          candidateInstallation,
          'Xcode installation root',
        )
        : developerRoot;
      discoveryTools = [
        { id: 'xcode-select', path: xcodeSelect },
        { id: 'xcodebuild', path: xcodebuild },
        { id: 'xcrun', path: xcrun },
      ];
    } else {
      installationRoot = canonicalDiscoveredDirectory(
        join(source, 'build', 'mac_files', 'xcode_binaries'),
        'hermetic Xcode installation root',
      );
      developerRoot = canonicalDiscoveredDirectory(
        join(installationRoot, 'Contents', 'Developer'),
        'hermetic Xcode developer root',
      );
      const officialSdkVersion = gnString(
        effectiveArgs,
        'mac_sdk_official_version',
      );
      const selectedSdk = declaredSdkPath || (
        '//build/mac_files/xcode_binaries/Contents/Developer/'
        + `Platforms/MacOSX.platform/Developer/SDKs/MacOSX${officialSdkVersion}.sdk`
      );
      const selectedSdkPath = isAbsolute(selectedSdk)
        || selectedSdk.startsWith('//')
        ? resolveGnPath(source, selectedSdk, 'hermetic mac_sdk_path')
        : resolve(outDir, selectedSdk);
      if (!isAbsolute(selectedSdk) && !selectedSdk.startsWith('//')) {
        assertContained(
          source,
          selectedSdkPath,
          'relative hermetic mac_sdk_path',
        );
      }
      sdkPath = canonicalDiscoveredDirectory(
        selectedSdkPath,
        'hermetic macOS SDK root',
      );
      assertContained(developerRoot, sdkPath, 'hermetic macOS SDK root');
      sdkVersion = gnString(
        effectiveArgs,
        'mac_sdk_version',
        { required: false },
      ) || officialSdkVersion;
      xcodeVersion = gnString(
        effectiveArgs,
        'xcode_version',
        { required: false },
      ) || 'bound-by-complete-hermetic-xcode-tree';
      discoveryTools = [];
    }
    if (!sdkVersion || !xcodeVersion) {
      throw new TypeError('Xcode or SDK version evidence is empty');
    }
    const evidenceCandidates = [
      join(sdkPath, 'SDKSettings.json'),
      join(sdkPath, 'SDKSettings.plist'),
      join(
        sdkPath,
        'System',
        'Library',
        'CoreServices',
        'SystemVersion.plist',
      ),
    ];
    const evidencePath = evidenceCandidates.find((candidate) =>
      existsSync(candidate));
    if (!evidencePath) {
      throw new TypeError('macOS SDK contains no SDKSettings evidence');
    }
    return Object.freeze({
      evidence: Object.freeze([
        Object.freeze({ id: 'macos-sdk-settings', path: evidencePath }),
      ]),
      kind: 'macos-xcode-sdk',
      metadata: Object.freeze({
        activeDeveloperRoot: developerRoot,
        sdkVersion,
        useSystemXcode,
        xcodeVersion,
      }),
      roots: Object.freeze([
        Object.freeze({ id: 'macos-sdk', path: sdkPath }),
        Object.freeze({
          id: 'xcode-installation',
          path: installationRoot,
        }),
      ]),
      tools: Object.freeze(
        discoveryTools.map((item) => Object.freeze(item)),
      ),
    });
  } catch (error) {
    throw incomplete('macos-universal', error.message);
  }
}

function windowsPath(assignments, name, { required = true } = {}) {
  const value = gnString(assignments, name, { required });
  if (value === null || value === '') return value;
  if (!isAbsolute(value)) {
    throw new TypeError(`${name} is not an absolute Windows path`);
  }
  return canonicalDiscoveredDirectory(value, name);
}

function assertWindowsToolchainJson(document) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new TypeError('win_toolchain.json must contain an object');
  }
  const expected = ['path', 'runtime_dirs', 'version', 'wdk', 'win_sdk'];
  const actual = Object.keys(document).sort(compareText);
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    throw new TypeError(
      'win_toolchain.json has an unknown or missing path-bearing field',
    );
  }
  for (const key of ['path', 'version', 'wdk', 'win_sdk']) {
    assertSafeString(document[key], `win_toolchain.json ${key}`);
  }
  if (
    !Array.isArray(document.runtime_dirs)
    || document.runtime_dirs.length === 0
    || document.runtime_dirs.some((value) =>
      typeof value !== 'string' || !isAbsolute(value) || hasControl(value))
  ) {
    throw new TypeError(
      'win_toolchain.json runtime_dirs must be non-empty absolute paths',
    );
  }
}

export function discoverWindowsPlatformToolchain({
  effectiveArgs,
  selectionPath = null,
  source,
}) {
  try {
    let selection = effectiveArgs;
    let selectionEvidencePath = null;
    if (selectionPath !== null) {
      if (typeof selectionPath !== 'string' || !isAbsolute(selectionPath)) {
        throw new TypeError(
          'Windows toolchain selection evidence path must be absolute',
        );
      }
      const stable = readStableBytes(
        selectionPath,
        MAX_SMALL_FILE_BYTES,
        'Windows toolchain selection evidence',
      );
      selection = parseEffectiveGnArgs(
        decodeUtf8(stable.bytes, 'Windows toolchain selection evidence'),
      );
      const expectedKeys = [
        'runtime_dirs',
        'sdk_path',
        'sdk_version',
        'vs_path',
        'vs_version',
        'wdk_dir',
      ];
      const actualKeys = Object.keys(selection).sort(compareText);
      if (!isDeepStrictEqual(actualKeys, expectedKeys)) {
        throw new TypeError(
          'Windows toolchain selection evidence has unknown or missing fields',
        );
      }
      selectionEvidencePath = stable.path;
    }
    const declaredVisualStudio = windowsPath(
      selection,
      selectionPath === null ? 'visual_studio_path' : 'vs_path',
      { required: false },
    );
    const sdkVersion = gnString(
      selection,
      selectionPath === null ? 'windows_sdk_version' : 'sdk_version',
      { required: false },
    );
    const vsVersion = gnString(
      selection,
      selectionPath === null ? 'visual_studio_version' : 'vs_version',
      { required: false },
    );
    if (!sdkVersion || !vsVersion) {
      throw new TypeError(
        'effective GN args omit Windows SDK or Visual Studio version evidence',
      );
    }

    let visualStudio;
    let windowsSdk;
    let wdk;
    let runtimeDirs;
    let evidencePath;
    if (declaredVisualStudio) {
      visualStudio = declaredVisualStudio;
      windowsSdk = windowsPath(
        selection,
        selectionPath === null ? 'windows_sdk_path' : 'sdk_path',
      );
      const wdkName = selectionPath === null ? 'wdk_path' : 'wdk_dir';
      const declaredWdk = gnString(selection, wdkName, { required: false });
      wdk = declaredWdk
        ? canonicalDiscoveredDirectory(declaredWdk, wdkName)
        : windowsSdk;
      runtimeDirs = [];
      const sdkHeader = join(
        windowsSdk, 'Include', sdkVersion, 'um', 'Windows.h',
      );
      if (!existsSync(sdkHeader)) {
        throw new TypeError(
          'declared Windows SDK lacks its versioned Windows.h evidence',
        );
      }
      evidencePath = selectionEvidencePath ?? sdkHeader;
    } else {
      const toolchainJsonPath = join(source, 'build', 'win_toolchain.json');
      const stable = readStableBytes(
        toolchainJsonPath,
        MAX_SMALL_FILE_BYTES,
        'win_toolchain.json',
      );
      const document = parseJsonWithoutDuplicateKeys(
        decodeUtf8(stable.bytes, 'win_toolchain.json'),
        'win_toolchain.json',
      );
      assertWindowsToolchainJson(document);
      visualStudio = canonicalDiscoveredDirectory(
        document.path,
        'Visual Studio toolchain root',
      );
      windowsSdk = canonicalDiscoveredDirectory(
        document.win_sdk,
        'Windows SDK root',
      );
      wdk = canonicalDiscoveredDirectory(document.wdk, 'Windows WDK root');
      runtimeDirs = document.runtime_dirs.map((path) =>
        canonicalDiscoveredDirectory(path, 'Visual Studio runtime directory'));
      const enclosingRoots = [visualStudio, windowsSdk, wdk];
      for (const runtime of runtimeDirs) {
        if (!enclosingRoots.some((root) => {
          const rel = relative(root, runtime);
          return rel === '' || (
            rel !== '..'
            && !rel.startsWith(`..${sep}`)
            && !isAbsolute(rel)
          );
        })) {
          throw new TypeError(
            'a Visual Studio runtime directory escapes every locked root',
          );
        }
      }
      evidencePath = toolchainJsonPath;
    }

    const roots = [
      { id: 'visual-studio', path: visualStudio },
      { id: 'windows-sdk', path: windowsSdk },
    ];
    if (wdk !== windowsSdk && wdk !== visualStudio) {
      roots.push({ id: 'windows-wdk', path: wdk });
    }
    return Object.freeze({
      evidence: Object.freeze([
        Object.freeze({ id: 'windows-toolchain-selection', path: evidencePath }),
      ]),
      kind: 'windows-msvc-sdk',
      metadata: Object.freeze({
        runtimeDirectories: Object.freeze(runtimeDirs),
        visualStudioVersion: vsVersion,
        windowsSdkVersion: sdkVersion,
      }),
      roots: Object.freeze(
        roots.map((item) => Object.freeze(item)),
      ),
    });
  } catch (error) {
    throw incomplete('windows-x64', error.message);
  }
}

export function discoverPlatformToolchain({
  effectiveArgs,
  environment,
  outDir,
  platform,
  runCommand = runControlledCommand,
  source,
  windowsToolchainSelectionPath = null,
}) {
  if (platform === 'linux-x64') {
    return discoverLinuxPlatformToolchain({ effectiveArgs, source });
  }
  if (platform === 'macos-universal') {
    return discoverMacosPlatformToolchain({
      effectiveArgs,
      environment,
      outDir,
      runCommand,
      source,
    });
  }
  if (platform === 'windows-x64') {
    return discoverWindowsPlatformToolchain({
      effectiveArgs,
      selectionPath: windowsToolchainSelectionPath,
      source,
    });
  }
  throw incomplete(String(platform), 'unsupported M0 platform');
}

function toolDescriptor(id, path, executable = true) {
  return Object.freeze({ executable, id, path: resolve(path) });
}

function discoverDepotPythonPaths(depotTools, windows) {
  const selectorPath = join(depotTools, 'python3_bin_reldir.txt');
  const selector = readStableBytes(
    selectorPath,
    4096,
    'depot_tools Python selector',
  );
  const selectedRelative = decodeUtf8(
    selector.bytes,
    'depot_tools Python selector',
  ).trim();
  const parts = selectedRelative.split(/[\\/]/u);
  if (
    selectedRelative === ''
    || isAbsolute(selectedRelative)
    || parts.some((part) => part === '' || part === '.' || part === '..')
    || hasControl(selectedRelative)
  ) {
    throw new TypeError(
      'depot_tools Python selector is not a safe relative directory',
    );
  }
  const selectedDirectory = ordinaryDirectory(
    resolve(depotTools, ...parts),
    'depot_tools selected Python directory',
  );
  assertContained(
    depotTools,
    selectedDirectory.path,
    'depot_tools selected Python directory',
  );
  return Object.freeze({
    binary: join(
      selectedDirectory.path,
      windows ? 'python3.exe' : 'python3',
    ),
    selector: selector.path,
    selectorSha256: createHash('sha256')
      .update(selector.bytes)
      .digest('hex'),
    wrapper: join(
      depotTools,
      'python-bin',
      windows ? 'python3.bat' : 'python3',
    ),
  });
}

function discoverBuildToolPaths({
  backend,
  depotTools,
  effectiveArgs,
  git,
  hostPlatform,
  node,
  platform,
  python,
  source,
}) {
  const windows = hostPlatform === 'win32';
  const suffix = windows ? '.exe' : '';
  const wrapperSuffix = windows ? '.bat' : '';
  const gnBinary = firstExistingPath([
    join(source, 'third_party', 'gn', `gn${suffix}`),
    join(
      source,
      'buildtools',
      hostPlatform === 'linux'
        ? 'linux64'
        : hostPlatform === 'darwin'
          ? 'mac'
          : 'win',
      `gn${suffix}`,
    ),
  ], 'resolved GN binary');
  const llvmBin = join(
    source,
    'third_party',
    'llvm-build',
    'Release+Asserts',
    'bin',
  );
  if (gnBoolean(effectiveArgs, 'is_clang') !== true) {
    throw incomplete(platform, 'effective build does not use pinned Clang');
  }
  const clangBasePath = gnString(
    effectiveArgs,
    'clang_base_path',
    { required: false },
  );
  if (clangBasePath) {
    const selectedClangRoot = canonicalDiscoveredDirectory(
      resolveGnPath(source, clangBasePath, 'clang_base_path'),
      'effective Clang root',
    );
    const expectedClangRoot = canonicalDiscoveredDirectory(
      dirname(llvmBin),
      'bundled Clang root',
    );
    if (selectedClangRoot !== expectedClangRoot) {
      throw incomplete(
        platform,
        'effective clang_base_path is not the bundled pinned Clang',
      );
    }
  }
  if (gnBoolean(effectiveArgs, 'use_lld') !== true) {
    throw incomplete(platform, 'effective build does not use bundled LLD');
  }
  const clang = join(llvmBin, windows ? 'clang-cl.exe' : 'clang');
  const lld = join(
    llvmBin,
    windows ? 'lld-link.exe' : hostPlatform === 'darwin' ? 'ld64.lld' : 'ld.lld',
  );
  const depotPython = discoverDepotPythonPaths(depotTools, windows);
  const tools = [
    toolDescriptor('autoninja-driver', join(depotTools, 'autoninja.py'), false),
    toolDescriptor(
      'autoninja-wrapper',
      join(depotTools, `autoninja${wrapperSuffix}`),
    ),
    toolDescriptor('clang', clang),
    Object.freeze({
      ...toolDescriptor('depot-python-selector', depotPython.selector, false),
      expectedSha256: depotPython.selectorSha256,
    }),
    toolDescriptor('depot-python-binary', depotPython.binary),
    toolDescriptor('depot-python-wrapper', depotPython.wrapper),
    toolDescriptor('git', git),
    toolDescriptor('gn-binary', gnBinary),
    toolDescriptor('gn-driver', join(depotTools, 'gn.py'), false),
    toolDescriptor('gn-wrapper', join(depotTools, `gn${wrapperSuffix}`)),
    toolDescriptor('host-python', python),
    toolDescriptor('lld', lld),
    toolDescriptor('node', node),
  ];

  if (backend === 'ninja') {
    const ninja = firstExistingPath([
      join(source, 'third_party', 'ninja', `ninja${suffix}`),
    ], 'resolved Ninja binary');
    tools.push(
      toolDescriptor('ninja-binary', ninja),
      toolDescriptor('ninja-driver', join(depotTools, 'ninja.py'), false),
    );
  } else if (backend === 'siso') {
    const siso = firstExistingPath([
      join(
        source,
        'third_party',
        'siso',
        'cipd',
        `siso${suffix}`,
      ),
      join(source, 'third_party', 'siso', `siso${suffix}`),
    ], 'resolved Siso binary');
    tools.push(
      toolDescriptor('siso-binary', siso),
      toolDescriptor('siso-driver', join(depotTools, 'siso.py'), false),
    );
  } else {
    throw new TypeError(`unsupported build backend ${backend}`);
  }

  return Object.freeze(tools);
}

function mandatoryToolIds(platform, backend) {
  const required = [
    'autoninja-driver',
    'autoninja-wrapper',
    'clang',
    'depot-python-binary',
    'depot-python-selector',
    'depot-python-wrapper',
    'git',
    'gn-binary',
    'gn-driver',
    'gn-wrapper',
    'host-python',
    'lld',
    'node',
    `${backend}-binary`,
    `${backend}-driver`,
  ];
  return required.sort(compareText);
}

function hashToolDescriptors(descriptors, platform, backend) {
  if (!Array.isArray(descriptors)) {
    throw new TypeError('tool inventory must be an array');
  }
  const ids = new Set();
  const nonExecutableInputs = new Set([
    'autoninja-driver',
    'chromium-universalizer',
    'depot-python-selector',
    'gn-driver',
    'ninja-driver',
    'siso-driver',
  ]);
  const records = descriptors.map((descriptor) => {
    if (!descriptor || typeof descriptor !== 'object') {
      throw new TypeError('tool inventory entry must be an object');
    }
    const id = assertId(descriptor.id, 'tool id');
    if (ids.has(id)) throw new TypeError(`duplicate tool id ${id}`);
    ids.add(id);
    const executable = !nonExecutableInputs.has(id);
    if (descriptor.executable === false && executable) {
      throw new TypeError(`executable tool ${id} cannot be downgraded to data`);
    }
    const record = hashStableOrdinaryFile(
      descriptor.path,
      `tool ${id}`,
      MAX_TOOL_FILE_BYTES,
    );
    if (
      descriptor.expectedSha256 !== undefined
      && descriptor.expectedSha256 !== record.sha256
    ) {
      throw new TypeError(
        `tool ${id} changed while its resolved target was selected`,
      );
    }
    if (
      executable
      && platform !== 'windows-x64'
      && (Number.parseInt(record.mode, 8) & 0o111) === 0
    ) {
      throw new TypeError(`tool ${id} is not executable`);
    }
    return Object.freeze({ id, ...record });
  });
  records.sort((left, right) => compareText(left.id, right.id));
  const actual = records.map((item) => item.id);
  const mandatory = mandatoryToolIds(platform, backend);
  for (const id of mandatory) {
    if (!ids.has(id)) throw new TypeError(`tool inventory is missing ${id}`);
  }
  if (actual.length !== ids.size) {
    throw new TypeError('tool inventory contains duplicate identifiers');
  }
  return Object.freeze(records);
}

function toolMap(records) {
  return new Map(records.map((record) => [record.id, record]));
}

function requiredTool(map, id) {
  const record = map.get(id);
  if (!record) throw new TypeError(`hashed tool inventory is missing ${id}`);
  const { id: ignored, ...identity } = record;
  void ignored;
  return Object.freeze(identity);
}

function namedBuildTools(records, backend) {
  const map = toolMap(records);
  return Object.freeze({
    executor: Object.freeze({
      backend,
      binary: requiredTool(map, `${backend}-binary`),
      driver: requiredTool(map, `${backend}-driver`),
      wrapper: requiredTool(map, 'autoninja-wrapper'),
      wrapperDriver: requiredTool(map, 'autoninja-driver'),
    }),
    gn: Object.freeze({
      binary: requiredTool(map, 'gn-binary'),
      driver: requiredTool(map, 'gn-driver'),
      wrapper: requiredTool(map, 'gn-wrapper'),
    }),
    llvm: Object.freeze({
      clang: requiredTool(map, 'clang'),
      lld: requiredTool(map, 'lld'),
    }),
    runtimes: Object.freeze({
      depotPython: Object.freeze({
        binary: requiredTool(map, 'depot-python-binary'),
        selector: requiredTool(map, 'depot-python-selector'),
        wrapper: requiredTool(map, 'depot-python-wrapper'),
      }),
      git: requiredTool(map, 'git'),
      hostPython: requiredTool(map, 'host-python'),
      node: requiredTool(map, 'node'),
    }),
  });
}

function assertSafeJson(value, label, depth = 0) {
  if (depth > 32) throw new TypeError(`${label} is nested too deeply`);
  if (
    value === null
    || typeof value === 'boolean'
    || (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value;
  }
  if (typeof value === 'string') {
    if (value.includes('\0') || value.length > 64 * 1024) {
      throw new TypeError(`${label} contains unsafe text`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) =>
      assertSafeJson(item, `${label}[${index}]`, depth + 1));
  }
  if (!value || typeof value !== 'object') {
    throw new TypeError(`${label} is not canonical JSON data`);
  }
  const output = Object.create(null);
  for (const key of Object.keys(value).sort(compareText)) {
    if (key === '' || hasControl(key)) {
      throw new TypeError(`${label} has an unsafe object key`);
    }
    output[key] = assertSafeJson(value[key], `${label}.${key}`, depth + 1);
  }
  return output;
}

function sourceIdentity(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('source identity must be an object');
  }
  const required = [
    'chromiumCommit',
    'chromiumRepository',
    'chromiumVersion',
    'depotToolsCommit',
    'depotToolsRepository',
    'patchProfile',
    'patchSeriesSha256',
    'repository',
  ];
  const actual = Object.keys(value).sort(compareText);
  const expected = required.slice().sort(compareText);
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    throw new TypeError(`source identity must contain exactly ${expected.join(', ')}`);
  }
  for (const key of required) assertSafeString(value[key], `source.${key}`);
  if (!/^[0-9a-f]{40}$/u.test(value.chromiumCommit)) {
    throw new TypeError('source chromiumCommit is not a full lowercase Git OID');
  }
  if (!/^[0-9a-f]{40}$/u.test(value.depotToolsCommit)) {
    throw new TypeError('source depotToolsCommit is not a full lowercase Git OID');
  }
  if (!SHA256_RE.test(value.patchSeriesSha256)) {
    throw new TypeError('source patchSeriesSha256 is not lowercase SHA-256');
  }
  return Object.freeze({ ...value });
}

function validatePlatform(platform, hostPlatform, platformSpec) {
  if (!M0_PLATFORM_IDS.includes(platform)) {
    throw new TypeError(`unsupported M0 platform ${String(platform)}`);
  }
  if (!platformSpec || typeof platformSpec !== 'object') {
    throw new TypeError(`build contract omits ${platform}`);
  }
  if (hostPlatform !== platformSpec.hostPlatform) {
    throw new TypeError(
      `${platform} requires host ${platformSpec.hostPlatform}, got ${hostPlatform}`,
    );
  }
  if (
    !Array.isArray(platformSpec.architectures)
    || platformSpec.architectures.length === 0
  ) {
    throw new TypeError(`${platform} has no contracted architectures`);
  }
}

function validateBaseLayout({
  clientRoot,
  depotTools,
}) {
  const client = ordinaryDirectory(clientRoot, 'gclient root');
  const source = ordinaryDirectory(join(client.path, 'src'), 'Chromium source');
  const depot = ordinaryDirectory(depotTools, 'depot_tools root');
  assertDisjoint(client.path, depot.path, 'gclient and depot_tools roots');
  return Object.freeze({
    clientRoot: client.path,
    depotTools: depot.path,
    source: source.path,
  });
}

function validateOutputDirectory(source, outDir, label) {
  const output = ordinaryDirectory(outDir, label);
  const outputRelative = assertContained(
    source,
    output.path,
    label,
  );
  const parts = outputRelative.split(sep);
  if (parts.length < 2 || parts[0] !== 'out') {
    throw new TypeError(
      `${label} must be a named child of Chromium out/`,
    );
  }
  return Object.freeze({
    outDir: output.path,
    outDirRelative: outputRelative.split(sep).join('/'),
  });
}

function orderedConfigurations(configurations, platformSpec) {
  if (!Array.isArray(configurations) || configurations.length === 0) {
    throw new TypeError('at least one architecture configuration is required');
  }
  const byArchitecture = new Map();
  for (const configuration of configurations) {
    if (!configuration || typeof configuration !== 'object') {
      throw new TypeError('architecture configuration must be an object');
    }
    const architecture = configuration.architecture;
    if (!platformSpec.architectures.includes(architecture)) {
      throw new TypeError(
        `${architecture} is not an allowed architecture for this platform`,
      );
    }
    if (byArchitecture.has(architecture)) {
      throw new TypeError(`duplicate architecture configuration ${architecture}`);
    }
    byArchitecture.set(architecture, configuration);
  }
  if (
    byArchitecture.size !== platformSpec.architectures.length
    || platformSpec.architectures.some((item) => !byArchitecture.has(item))
  ) {
    throw new TypeError(
      `architecture configurations must contain exactly: `
      + platformSpec.architectures.join(', '),
    );
  }
  return platformSpec.architectures.map((item) => byArchitecture.get(item));
}

function hashNamedFiles(entries, label) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new TypeError(`${label} must contain at least one file`);
  }
  const ids = new Set();
  const records = entries.map((entry) => {
    if (!entry || typeof entry !== 'object') {
      throw new TypeError(`${label} entry must be an object`);
    }
    const id = assertId(entry.id, `${label} id`);
    if (ids.has(id)) throw new TypeError(`${label} repeats ${id}`);
    ids.add(id);
    return Object.freeze({
      id,
      ...stableFileIdentity(entry.path, `${label} ${id}`),
    });
  });
  records.sort((left, right) => compareText(left.id, right.id));
  return Object.freeze(records);
}

function hashDiscoveryTools(entries, platform) {
  if (!Array.isArray(entries)) {
    throw new TypeError('platform discovery tools must be an array');
  }
  const ids = new Set();
  const records = entries.map((entry) => {
    const id = assertId(entry.id, 'platform discovery tool id');
    if (ids.has(id)) {
      throw new TypeError(`platform discovery tools repeat ${id}`);
    }
    ids.add(id);
    const record = hashStableOrdinaryFile(
      entry.path,
      `platform discovery tool ${id}`,
      MAX_TOOL_FILE_BYTES,
    );
    if (
      platform !== 'windows-x64'
      && (Number.parseInt(record.mode, 8) & 0o111) === 0
    ) {
      throw new TypeError(`platform discovery tool ${id} is not executable`);
    }
    return Object.freeze({ id, ...record });
  });
  records.sort((left, right) => compareText(left.id, right.id));
  return Object.freeze(records);
}

function hashPlatformToolchain(platform, descriptor) {
  if (!descriptor || typeof descriptor !== 'object') {
    throw new TypeError('platform toolchain descriptor must be an object');
  }
  const expectedKind = PLATFORM_TOOLCHAIN_KINDS[platform];
  if (descriptor.kind !== expectedKind) {
    throw new TypeError(
      `${platform} platform toolchain kind must be ${expectedKind}`,
    );
  }
  if (!Array.isArray(descriptor.roots) || descriptor.roots.length === 0) {
    throw new TypeError('platform toolchain has no complete content roots');
  }
  const ids = new Set();
  const roots = descriptor.roots.map((entry) => {
    const id = assertId(entry.id, 'platform toolchain root id');
    if (ids.has(id)) {
      throw new TypeError(`platform toolchain repeats root ${id}`);
    }
    ids.add(id);
    try {
      return Object.freeze({
        id,
        ...hashCompleteDirectoryTree(entry.path, {
          label: `platform toolchain root ${id}`,
        }),
      });
    } catch (error) {
      throw incomplete(platform, error.message);
    }
  });
  for (const id of PLATFORM_ROOT_IDS[platform]) {
    if (!ids.has(id)) {
      throw incomplete(platform, `missing complete ${id} content root`);
    }
  }
  roots.sort((left, right) => compareText(left.id, right.id));
  let evidence;
  let discoveryToolRecords;
  try {
    evidence = hashNamedFiles(
      descriptor.evidence,
      'platform toolchain evidence',
    );
    discoveryToolRecords = descriptor.tools?.length
      ? hashDiscoveryTools(descriptor.tools, platform)
      : [];
  } catch (error) {
    throw incomplete(platform, error.message);
  }
  let discoveryTools = Object.freeze({});
  if (discoveryToolRecords.length > 0) {
    const map = toolMap(discoveryToolRecords);
    for (const id of ['xcode-select', 'xcodebuild', 'xcrun']) {
      if (!map.has(id)) {
        throw incomplete(platform, `platform discovery tool ${id} is absent`);
      }
    }
    discoveryTools = Object.freeze({
      xcodeSelect: requiredTool(map, 'xcode-select'),
      xcodebuild: requiredTool(map, 'xcodebuild'),
      xcrun: requiredTool(map, 'xcrun'),
    });
  }
  return Object.freeze({
    discoveryTools,
    evidence,
    kind: descriptor.kind,
    metadata: assertSafeJson(
      descriptor.metadata,
      'platform toolchain metadata',
    ),
    roots: Object.freeze(roots),
  });
}

function readEffectiveArgsRecord(path, platform) {
  const canonicalIdentity = stableFileIdentity(
    path,
    'canonical effective GN args record',
    MAX_SMALL_FILE_BYTES,
  );
  const stable = readStableBytes(
    canonicalIdentity.path,
    MAX_SMALL_FILE_BYTES,
    'canonical effective GN args record',
  );
  const text = decodeUtf8(
    stable.bytes,
    'canonical effective GN args record',
  );
  const record = parseJsonWithoutDuplicateKeys(
    text,
    'canonical effective GN args record',
  );
  const canonical = `${JSON.stringify(record, null, 2)}\n`;
  if (canonical !== text) {
    throw new TypeError(
      'effective GN args record is not canonical pretty JSON',
    );
  }
  const byteSha256 = createHash('sha256').update(stable.bytes).digest('hex');
  if (
    canonicalIdentity.sha256 !== byteSha256
    || canonicalIdentity.size !== stable.size
  ) {
    throw new TypeError(
      'effective GN args record changed between identity and validation',
    );
  }
  validateEffectiveGnArgsRecord(record, { platform });
  return Object.freeze({
    identity: Object.freeze({
      mode: stable.mode,
      path: stable.path,
      sha256: byteSha256,
      size: stable.size,
    }),
    record,
  });
}

function assembleConfiguration({
  configuration,
  effectiveRecordConfiguration,
  platform,
  platformSpec,
  source,
}) {
  const architecture = configuration.architecture;
  const output = validateOutputDirectory(
    source,
    configuration.outDir,
    `${architecture} build output directory`,
  );
  const expectedArgsPath = join(output.outDir, 'effective-args.gn');
  if (
    configuration.effectiveArgsPath
    && resolve(configuration.effectiveArgsPath) !== expectedArgsPath
  ) {
    throw new TypeError(
      `${architecture} effective GN args must be out-dir/effective-args.gn`,
    );
  }
  const effective = readStableBytes(
    expectedArgsPath,
    MAX_SMALL_FILE_BYTES,
    `${architecture} effective GN args`,
  );
  if (effective.size === 0) {
    throw new TypeError(`${architecture} effective GN args are empty`);
  }
  const effectiveText = decodeUtf8(
    effective.bytes,
    `${architecture} effective GN args`,
  );
  if (
    effectiveRecordConfiguration.architecture !== architecture
    || effectiveRecordConfiguration.outDir !== output.outDirRelative
    || effectiveRecordConfiguration.argsSha256
      !== createHash('sha256').update(effective.bytes).digest('hex')
    || effectiveRecordConfiguration.argsSize !== effective.size
    || effectiveRecordConfiguration.argsText !== effectiveText
  ) {
    throw new TypeError(
      `${architecture} live effective args differ from their canonical record`,
    );
  }
  const effectiveAudit = inspectEffectiveArgs(
    effectiveText,
    platform,
    architecture,
  );
  const toolRecords = hashToolDescriptors(
    configuration.toolPaths,
    platform,
    effectiveAudit.backend,
  );
  const outputEntrypoint = join(output.outDir, platformSpec.entrypoint);
  return Object.freeze({
    architecture,
    buildOutput: stableFileIdentity(
      outputEntrypoint,
      `${architecture} Chromium build output`,
      MAX_TOOL_FILE_BYTES,
    ),
    buildTools: namedBuildTools(toolRecords, effectiveAudit.backend),
    effectiveGnArgs: Object.freeze({
      backend: effectiveAudit.backend,
      mode: effective.mode,
      path: effective.path,
      recordOutDir: effectiveRecordConfiguration.outDir,
      recordSha256: effectiveRecordConfiguration.argsSha256,
      sha256: effectiveRecordConfiguration.argsSha256,
      size: effective.size,
      targetCpu: effectiveAudit.targetCpu,
    }),
    outDir: output.outDir,
    outDirRelative: output.outDirRelative,
  });
}

function hashMacosPackaging({
  descriptor,
  platformSpec,
  source,
}) {
  try {
    if (!descriptor || typeof descriptor !== 'object') {
      throw new TypeError(
        'macos-universal requires a universal packaging descriptor',
      );
    }
    const output = validateOutputDirectory(
      source,
      descriptor.universalOutDir,
      'macOS universal output directory',
    );
    if (
      !Array.isArray(descriptor.architectures)
      || JSON.stringify(descriptor.architectures)
        !== JSON.stringify(platformSpec.architectures)
    ) {
      throw new TypeError(
        'universal output must be verified as exactly x86_64 and arm64',
      );
    }
    const universalizer = stableFileIdentity(
      descriptor.universalizerPath,
      'pinned Chromium universalizer',
    );
    const python = hashStableOrdinaryFile(
      descriptor.pythonPath,
      'universalizer Python binary',
    );
    const lipo = hashStableOrdinaryFile(
      descriptor.lipoPath,
      'universal-output lipo binary',
    );
    for (const [record, label] of [
      [python, 'universalizer Python binary'],
      [lipo, 'universal-output lipo binary'],
    ]) {
      if ((Number.parseInt(record.mode, 8) & 0o111) === 0) {
        throw new TypeError(`${label} is not executable`);
      }
    }
    const universalTree = hashCompleteDirectoryTree(
      output.outDir,
      { label: 'macOS universal output tree' },
    );
    const entrypoint = stableFileIdentity(
      join(output.outDir, platformSpec.entrypoint),
      'macOS universal Chromium entrypoint',
      MAX_TOOL_FILE_BYTES,
    );
    return Object.freeze({
      architectures: Object.freeze([...descriptor.architectures]),
      tools: Object.freeze({
        lipo,
        python,
        universalizer,
      }),
      universalOutput: Object.freeze({
        entrypoint,
        outDir: output.outDir,
        outDirRelative: output.outDirRelative,
        tree: universalTree,
      }),
    });
  } catch (error) {
    if (error.message.startsWith('complete macos-universal')) throw error;
    throw incomplete('macos-universal', error.message);
  }
}

/**
 * Build a canonical complete lock from a prevalidated, build-derived
 * inventory. This lower-level entry point is intentionally injectable so the
 * attack tests can use tiny local SDK fixtures; the production CLI always uses
 * collectToolchainLock below.
 */
export function assembleToolchainLock({
  buildContractPath,
  clientRoot,
  configurations,
  dependencyLockPath,
  depotTools,
  effectiveArgsRecordPath,
  hostPlatform,
  packaging = null,
  platform,
  platformSpec,
  platformToolchain,
  source: declaredSource,
  trustContractPath,
}) {
  validatePlatform(platform, hostPlatform, platformSpec);
  const layout = validateBaseLayout({ clientRoot, depotTools });
  const ordered = orderedConfigurations(configurations, platformSpec);
  const effectiveRecord = readEffectiveArgsRecord(
    effectiveArgsRecordPath,
    platform,
  );
  const lockedConfigurations = ordered.map((configuration, index) =>
    assembleConfiguration({
      configuration,
      effectiveRecordConfiguration:
        effectiveRecord.record.configurations[index],
      platform,
      platformSpec,
      source: layout.source,
    }));
  const outDirs = new Set(
    lockedConfigurations.map((configuration) => configuration.outDir),
  );
  if (outDirs.size !== lockedConfigurations.length) {
    throw new TypeError('architecture configurations must use distinct out dirs');
  }

  const contracts = Object.freeze({
    build: stableFileIdentity(
      buildContractPath,
      'M0 build contract',
    ),
    dependency: stableFileIdentity(
      dependencyLockPath,
      'resolved dependency lock',
      MAX_SMALL_FILE_BYTES,
    ),
    trust: stableFileIdentity(
      trustContractPath,
      'M0 trust contract',
    ),
  });
  const lockedPlatformToolchain = hashPlatformToolchain(
    platform,
    platformToolchain,
  );
  let lockedPackaging = null;
  if (platform === 'macos-universal') {
    lockedPackaging = hashMacosPackaging({
      descriptor: packaging,
      platformSpec,
      source: layout.source,
    });
    if (outDirs.has(lockedPackaging.universalOutput.outDir)) {
      throw new TypeError(
        'macOS universal output must differ from both architecture outputs',
      );
    }
  } else if (packaging !== null && packaging !== undefined) {
    throw new TypeError('universal packaging is valid only for macos-universal');
  }

  return Object.freeze({
    architectures: Object.freeze([...platformSpec.architectures]),
    assuranceLevel: M0_HARD_ASSURANCE_LEVEL,
    completeness: 'complete',
    configurations: Object.freeze(lockedConfigurations),
    contracts,
    documentKind: 'complete-toolchain-lock',
    effectiveGnArgsRecord: effectiveRecord.identity,
    hostPlatform,
    lockAssurance: LOCK_ASSURANCE,
    packaging: lockedPackaging,
    platform,
    platformToolchain: lockedPlatformToolchain,
    roots: Object.freeze({
      chromiumSource: layout.source,
      clientRoot: layout.clientRoot,
      depotTools: layout.depotTools,
    }),
    schemaVersion: LOCK_SCHEMA_VERSION,
    source: sourceIdentity(declaredSource),
  });
}

function exactDocumentKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort(compareText);
  const wanted = [...expected].sort(compareText);
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    throw new TypeError(
      `${label} must contain exactly ${wanted.join(', ')}`,
    );
  }
  return value;
}

function offlineAbsolutePath(value, label) {
  if (
    typeof value !== 'string'
    || value === ''
    || value.length > 32 * 1024
    || hasControl(value)
    || !(
      value.startsWith('/')
      || /^[A-Za-z]:[\\/]/u.test(value)
      || value.startsWith('\\\\')
    )
  ) {
    throw new TypeError(`${label} must be an absolute control-free path`);
  }
  return value;
}

function offlineRelativePath(value, label) {
  if (
    typeof value !== 'string'
    || !value.startsWith('out/')
    || value.includes('\\')
    || value.split('/').some((part) =>
      part === '' || part === '.' || part === '..')
    || hasControl(value)
  ) {
    throw new TypeError(`${label} must be a canonical path below out/`);
  }
  return value;
}

function offlineSha256(value, label) {
  if (typeof value !== 'string' || !SHA256_RE.test(value)) {
    throw new TypeError(`${label} must be lowercase SHA-256`);
  }
  return value;
}

function offlineCount(value, label, { positive = false } = {}) {
  if (
    !Number.isSafeInteger(value)
    || value < (positive ? 1 : 0)
  ) {
    throw new TypeError(
      `${label} must be a ${positive ? 'positive' : 'non-negative'} safe integer`,
    );
  }
  return value;
}

function validateOfflineFileIdentity(value, label) {
  exactDocumentKeys(value, ['mode', 'path', 'sha256', 'size'], label);
  if (typeof value.mode !== 'string' || !/^[0-7]{3}$/u.test(value.mode)) {
    throw new TypeError(`${label}.mode must be a three-digit portable mode`);
  }
  offlineAbsolutePath(value.path, `${label}.path`);
  offlineSha256(value.sha256, `${label}.sha256`);
  offlineCount(value.size, `${label}.size`);
  return value;
}

function validateOfflineTree(value, label) {
  exactDocumentKeys(value, [
    'directories',
    'entries',
    'files',
    'path',
    'symlinks',
    'totalFileBytes',
    'treeSha256',
  ], label);
  offlineCount(value.directories, `${label}.directories`, { positive: true });
  offlineCount(value.entries, `${label}.entries`, { positive: true });
  offlineCount(value.files, `${label}.files`);
  offlineCount(value.symlinks, `${label}.symlinks`);
  offlineCount(value.totalFileBytes, `${label}.totalFileBytes`);
  if (
    value.entries
      !== value.directories + value.files + value.symlinks
  ) {
    throw new TypeError(`${label}.entries does not match its type counts`);
  }
  offlineAbsolutePath(value.path, `${label}.path`);
  offlineSha256(value.treeSha256, `${label}.treeSha256`);
  return value;
}

function validateOfflineNamedFiles(values, label) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new TypeError(`${label} must contain at least one file`);
  }
  const ids = new Set();
  let previous = '';
  for (const [index, value] of values.entries()) {
    exactDocumentKeys(
      value,
      ['id', 'mode', 'path', 'sha256', 'size'],
      `${label}[${index}]`,
    );
    assertId(value.id, `${label}[${index}].id`);
    if (ids.has(value.id) || (previous && compareText(previous, value.id) >= 0)) {
      throw new TypeError(`${label} identifiers must be unique and sorted`);
    }
    ids.add(value.id);
    previous = value.id;
    validateOfflineFileIdentity(
      {
        mode: value.mode,
        path: value.path,
        sha256: value.sha256,
        size: value.size,
      },
      `${label}[${index}]`,
    );
  }
  return ids;
}

function validateOfflineBuildTools(value, label, backend) {
  exactDocumentKeys(
    value,
    ['executor', 'gn', 'llvm', 'runtimes'],
    label,
  );
  exactDocumentKeys(
    value.executor,
    ['backend', 'binary', 'driver', 'wrapper', 'wrapperDriver'],
    `${label}.executor`,
  );
  if (value.executor.backend !== backend) {
    throw new TypeError(`${label}.executor.backend does not match effective GN args`);
  }
  for (const name of ['binary', 'driver', 'wrapper', 'wrapperDriver']) {
    validateOfflineFileIdentity(
      value.executor[name],
      `${label}.executor.${name}`,
    );
  }
  exactDocumentKeys(value.gn, ['binary', 'driver', 'wrapper'], `${label}.gn`);
  for (const name of ['binary', 'driver', 'wrapper']) {
    validateOfflineFileIdentity(value.gn[name], `${label}.gn.${name}`);
  }
  exactDocumentKeys(value.llvm, ['clang', 'lld'], `${label}.llvm`);
  validateOfflineFileIdentity(value.llvm.clang, `${label}.llvm.clang`);
  validateOfflineFileIdentity(value.llvm.lld, `${label}.llvm.lld`);
  exactDocumentKeys(
    value.runtimes,
    ['depotPython', 'git', 'hostPython', 'node'],
    `${label}.runtimes`,
  );
  exactDocumentKeys(
    value.runtimes.depotPython,
    ['binary', 'selector', 'wrapper'],
    `${label}.runtimes.depotPython`,
  );
  for (const name of ['binary', 'selector', 'wrapper']) {
    validateOfflineFileIdentity(
      value.runtimes.depotPython[name],
      `${label}.runtimes.depotPython.${name}`,
    );
  }
  for (const name of ['git', 'hostPython', 'node']) {
    validateOfflineFileIdentity(
      value.runtimes[name],
      `${label}.runtimes.${name}`,
    );
  }
}

function normalizedOfflinePath(value) {
  return value.replace(/\\/gu, '/').replace(/\/+$/u, '');
}

function validateOfflineConfiguration(
  value,
  label,
  architecture,
  platformSpec,
  chromiumSource,
) {
  exactDocumentKeys(value, [
    'architecture',
    'buildOutput',
    'buildTools',
    'effectiveGnArgs',
    'outDir',
    'outDirRelative',
  ], label);
  if (value.architecture !== architecture) {
    throw new TypeError(`${label}.architecture is out of contract order`);
  }
  offlineAbsolutePath(value.outDir, `${label}.outDir`);
  offlineRelativePath(value.outDirRelative, `${label}.outDirRelative`);
  const normalizedOut = normalizedOfflinePath(value.outDir);
  const normalizedSource = normalizedOfflinePath(chromiumSource);
  if (
    normalizedOut !== `${normalizedSource}/${value.outDirRelative}`
    || !normalizedOut.startsWith(`${normalizedSource}/out/`)
  ) {
    throw new TypeError(`${label}.outDir does not bind its source-relative path`);
  }
  validateOfflineFileIdentity(value.buildOutput, `${label}.buildOutput`);
  if (
    normalizedOfflinePath(value.buildOutput.path)
      !== `${normalizedOut}/${platformSpec.entrypoint}`
  ) {
    throw new TypeError(`${label}.buildOutput is not the contracted entrypoint`);
  }
  exactDocumentKeys(value.effectiveGnArgs, [
    'backend',
    'mode',
    'path',
    'recordOutDir',
    'recordSha256',
    'sha256',
    'size',
    'targetCpu',
  ], `${label}.effectiveGnArgs`);
  if (!['ninja', 'siso'].includes(value.effectiveGnArgs.backend)) {
    throw new TypeError(`${label}.effectiveGnArgs.backend is unsupported`);
  }
  if (
    typeof value.effectiveGnArgs.mode !== 'string'
    || !/^[0-7]{3}$/u.test(value.effectiveGnArgs.mode)
  ) {
    throw new TypeError(`${label}.effectiveGnArgs.mode is invalid`);
  }
  offlineAbsolutePath(
    value.effectiveGnArgs.path,
    `${label}.effectiveGnArgs.path`,
  );
  if (
    normalizedOfflinePath(value.effectiveGnArgs.path)
      !== `${normalizedOut}/effective-args.gn`
  ) {
    throw new TypeError(`${label}.effectiveGnArgs path is outside its output`);
  }
  if (value.effectiveGnArgs.recordOutDir !== value.outDirRelative) {
    throw new TypeError(`${label}.effectiveGnArgs recordOutDir is wrong`);
  }
  offlineSha256(
    value.effectiveGnArgs.recordSha256,
    `${label}.effectiveGnArgs.recordSha256`,
  );
  if (
    value.effectiveGnArgs.sha256
      !== value.effectiveGnArgs.recordSha256
  ) {
    throw new TypeError(`${label}.effectiveGnArgs digests disagree`);
  }
  offlineCount(
    value.effectiveGnArgs.size,
    `${label}.effectiveGnArgs.size`,
    { positive: true },
  );
  const expectedCpu = architecture === 'x86_64' ? 'x64' : 'arm64';
  if (value.effectiveGnArgs.targetCpu !== expectedCpu) {
    throw new TypeError(`${label}.effectiveGnArgs.targetCpu is wrong`);
  }
  validateOfflineBuildTools(
    value.buildTools,
    `${label}.buildTools`,
    value.effectiveGnArgs.backend,
  );
}

function validateOfflinePlatformToolchain(value, label, platform) {
  exactDocumentKeys(
    value,
    ['discoveryTools', 'evidence', 'kind', 'metadata', 'roots'],
    label,
  );
  if (value.kind !== PLATFORM_TOOLCHAIN_KINDS[platform]) {
    throw new TypeError(`${label}.kind is wrong for ${platform}`);
  }
  if (
    !value.metadata
    || typeof value.metadata !== 'object'
    || Array.isArray(value.metadata)
  ) {
    throw new TypeError(`${label}.metadata must be an object`);
  }
  assertSafeJson(value.metadata, `${label}.metadata`);
  const evidenceIds = validateOfflineNamedFiles(
    value.evidence,
    `${label}.evidence`,
  );
  void evidenceIds;
  exactDocumentKeys(
    value.discoveryTools,
    Object.keys(value.discoveryTools).length === 0
      ? []
      : ['xcodeSelect', 'xcodebuild', 'xcrun'],
    `${label}.discoveryTools`,
  );
  for (const [name, identity] of Object.entries(value.discoveryTools)) {
    validateOfflineFileIdentity(
      identity,
      `${label}.discoveryTools.${name}`,
    );
  }
  if (!Array.isArray(value.roots) || value.roots.length === 0) {
    throw new TypeError(`${label}.roots must be non-empty`);
  }
  const ids = new Set();
  let previous = '';
  for (const [index, root] of value.roots.entries()) {
    exactDocumentKeys(root, [
      'id',
      'directories',
      'entries',
      'files',
      'path',
      'symlinks',
      'totalFileBytes',
      'treeSha256',
    ], `${label}.roots[${index}]`);
    assertId(root.id, `${label}.roots[${index}].id`);
    if (ids.has(root.id) || (previous && compareText(previous, root.id) >= 0)) {
      throw new TypeError(`${label}.roots identifiers must be unique and sorted`);
    }
    ids.add(root.id);
    previous = root.id;
    validateOfflineTree(
      {
        directories: root.directories,
        entries: root.entries,
        files: root.files,
        path: root.path,
        symlinks: root.symlinks,
        totalFileBytes: root.totalFileBytes,
        treeSha256: root.treeSha256,
      },
      `${label}.roots[${index}]`,
    );
  }
  for (const id of PLATFORM_ROOT_IDS[platform]) {
    if (!ids.has(id)) {
      throw new TypeError(`${label}.roots is missing ${id}`);
    }
  }
}

function validateOfflinePackaging(
  value,
  label,
  platform,
  platformSpec,
  chromiumSource,
) {
  if (platform !== 'macos-universal') {
    if (value !== null) {
      throw new TypeError(`${label} must be null outside macos-universal`);
    }
    return;
  }
  exactDocumentKeys(
    value,
    ['architectures', 'tools', 'universalOutput'],
    label,
  );
  if (!isDeepStrictEqual(value.architectures, platformSpec.architectures)) {
    throw new TypeError(`${label}.architectures is wrong`);
  }
  exactDocumentKeys(
    value.tools,
    ['lipo', 'python', 'universalizer'],
    `${label}.tools`,
  );
  for (const name of ['lipo', 'python', 'universalizer']) {
    validateOfflineFileIdentity(value.tools[name], `${label}.tools.${name}`);
  }
  exactDocumentKeys(
    value.universalOutput,
    ['entrypoint', 'outDir', 'outDirRelative', 'tree'],
    `${label}.universalOutput`,
  );
  offlineAbsolutePath(
    value.universalOutput.outDir,
    `${label}.universalOutput.outDir`,
  );
  offlineRelativePath(
    value.universalOutput.outDirRelative,
    `${label}.universalOutput.outDirRelative`,
  );
  const normalizedOut = normalizedOfflinePath(value.universalOutput.outDir);
  if (
    normalizedOut
      !== `${normalizedOfflinePath(chromiumSource)}/${value.universalOutput.outDirRelative}`
  ) {
    throw new TypeError(`${label}.universalOutput path binding is wrong`);
  }
  validateOfflineFileIdentity(
    value.universalOutput.entrypoint,
    `${label}.universalOutput.entrypoint`,
  );
  if (
    normalizedOfflinePath(value.universalOutput.entrypoint.path)
      !== `${normalizedOut}/${platformSpec.entrypoint}`
  ) {
    throw new TypeError(`${label}.universalOutput entrypoint is wrong`);
  }
  validateOfflineTree(
    value.universalOutput.tree,
    `${label}.universalOutput.tree`,
  );
  if (
    normalizedOfflinePath(value.universalOutput.tree.path) !== normalizedOut
  ) {
    throw new TypeError(`${label}.universalOutput tree root is wrong`);
  }
}

/**
 * Strictly validate a captured complete-toolchain-lock document without
 * reading the live build machine. Optional expected digests bind the document
 * to the other snapshotted M0 records.
 */
export function validateToolchainLockDocument(document, {
  platform = document?.platform,
  buildContract = null,
  buildContractSha256,
  trustContractSha256,
  dependencyLockSha256,
  effectiveGnArgs = null,
  effectiveGnArgsSha256,
  repository,
} = {}) {
  exactDocumentKeys(document, [
    'architectures',
    'assuranceLevel',
    'completeness',
    'configurations',
    'contracts',
    'documentKind',
    'effectiveGnArgsRecord',
    'hostPlatform',
    'lockAssurance',
    'packaging',
    'platform',
    'platformToolchain',
    'roots',
    'schemaVersion',
    'source',
  ], 'toolchain lock');
  if (!M0_PLATFORM_IDS.includes(platform) || document.platform !== platform) {
    throw new TypeError(`unsupported toolchain lock platform ${String(platform)}`);
  }
  const platformSpec = OFFLINE_PLATFORM_SPECS[platform];
  if (
    document.schemaVersion !== LOCK_SCHEMA_VERSION
    || document.documentKind !== 'complete-toolchain-lock'
    || document.assuranceLevel !== M0_HARD_ASSURANCE_LEVEL
    || document.completeness !== 'complete'
    || document.lockAssurance !== LOCK_ASSURANCE
    || document.hostPlatform !== platformSpec.hostPlatform
  ) {
    throw new TypeError('toolchain lock assurance or platform metadata is invalid');
  }
  if (!isDeepStrictEqual(document.architectures, platformSpec.architectures)) {
    throw new TypeError('toolchain lock architectures do not match the platform');
  }
  exactDocumentKeys(
    document.roots,
    ['chromiumSource', 'clientRoot', 'depotTools'],
    'toolchain lock roots',
  );
  for (const [name, value] of Object.entries(document.roots)) {
    offlineAbsolutePath(value, `toolchain lock roots.${name}`);
  }
  if (
    !Array.isArray(document.configurations)
    || document.configurations.length !== platformSpec.architectures.length
  ) {
    throw new TypeError('toolchain lock has an incomplete configuration set');
  }
  for (const [index, architecture] of platformSpec.architectures.entries()) {
    validateOfflineConfiguration(
      document.configurations[index],
      `toolchain lock configurations[${index}]`,
      architecture,
      platformSpec,
      document.roots.chromiumSource,
    );
  }
  if (effectiveGnArgs !== null) {
    if (
      !effectiveGnArgs
      || typeof effectiveGnArgs !== 'object'
      || effectiveGnArgs.platform !== platform
      || !Array.isArray(effectiveGnArgs.configurations)
      || effectiveGnArgs.configurations.length
        !== document.configurations.length
    ) {
      throw new TypeError('expected effective GN args record is incompatible');
    }
    for (const [index, configuration] of document.configurations.entries()) {
      const expected = effectiveGnArgs.configurations[index];
      if (
        expected?.architecture !== configuration.architecture
        || expected?.outDir !== configuration.outDirRelative
        || expected?.argsSha256
          !== configuration.effectiveGnArgs.recordSha256
        || expected?.argsSize !== configuration.effectiveGnArgs.size
      ) {
        throw new TypeError(
          `toolchain lock configuration ${index} differs from effective GN args`,
        );
      }
    }
  }
  if (
    new Set(document.configurations.map(({ outDir }) => outDir)).size
      !== document.configurations.length
  ) {
    throw new TypeError('toolchain lock configurations reuse an output directory');
  }
  exactDocumentKeys(
    document.contracts,
    ['build', 'dependency', 'trust'],
    'toolchain lock contracts',
  );
  for (const name of ['build', 'dependency', 'trust']) {
    validateOfflineFileIdentity(
      document.contracts[name],
      `toolchain lock contracts.${name}`,
    );
  }
  validateOfflineFileIdentity(
    document.effectiveGnArgsRecord,
    'toolchain lock effectiveGnArgsRecord',
  );
  for (const [actual, expected, label] of [
    [
      document.contracts.build.sha256,
      buildContractSha256,
      'build contract',
    ],
    [
      document.contracts.trust.sha256,
      trustContractSha256,
      'trust contract',
    ],
    [
      document.contracts.dependency.sha256,
      dependencyLockSha256,
      'dependency lock',
    ],
    [
      document.effectiveGnArgsRecord.sha256,
      effectiveGnArgsSha256,
      'effective GN args record',
    ],
  ]) {
    if (expected !== undefined) {
      offlineSha256(expected, `expected ${label} digest`);
      if (actual !== expected) {
        throw new TypeError(`toolchain lock ${label} digest is wrong`);
      }
    }
  }
  sourceIdentity(document.source);
  if (
    repository !== undefined
    && (
      typeof repository !== 'string'
      || repository === ''
      || document.source.repository !== repository
    )
  ) {
    throw new TypeError('toolchain lock source.repository is wrong');
  }
  if (buildContract !== null) {
    if (!buildContract || typeof buildContract !== 'object') {
      throw new TypeError('expected M0 build contract must be an object');
    }
    const expectedSource = {
      chromiumCommit: buildContract.source?.chromiumCommit,
      chromiumRepository: buildContract.source?.chromiumRepository,
      chromiumVersion: buildContract.source?.chromiumVersion,
      depotToolsCommit: buildContract.source?.depotToolsCommit,
      depotToolsRepository: buildContract.source?.depotToolsRepository,
      patchProfile: buildContract.patches?.profile,
      patchSeriesSha256: buildContract.patches?.activeSeriesSha256,
    };
    for (const [name, expected] of Object.entries(expectedSource)) {
      if (document.source[name] !== expected) {
        throw new TypeError(`toolchain lock source.${name} is wrong`);
      }
    }
  }
  validateOfflinePlatformToolchain(
    document.platformToolchain,
    'toolchain lock platformToolchain',
    platform,
  );
  validateOfflinePackaging(
    document.packaging,
    'toolchain lock packaging',
    platform,
    platformSpec,
    document.roots.chromiumSource,
  );
  return Object.freeze({
    architectures: Object.freeze([...document.architectures]),
    configurations: document.configurations.length,
    platform,
    toolchainRoots: document.platformToolchain.roots.length,
  });
}

function defaultReadContracts(options) {
  return readAndValidateM0BuildContract(options);
}

function dependencyDigestMatches(result, dependencyLockPath) {
  const identity = stableFileIdentity(
    dependencyLockPath,
    'resolved dependency lock',
    MAX_SMALL_FILE_BYTES,
  );
  if (!result || result.sha256 !== identity.sha256) {
    throw new TypeError(
      'dependency verifier digest differs from the locked dependency bytes',
    );
  }
  return identity;
}

function assertBackendMarker(platform, output, effectiveAudit) {
  const marker = join(output.outDir, '.siso_deps');
  if (effectiveAudit.backend === 'siso' && !existsSync(marker)) {
    throw incomplete(
      platform,
      `${output.outDirRelative} uses Siso but lacks .siso_deps`,
    );
  }
  if (effectiveAudit.backend === 'ninja' && existsSync(marker)) {
    throw incomplete(
      platform,
      `${output.outDirRelative} uses Ninja but contains .siso_deps`,
    );
  }
}

function exactArchitectures(raw) {
  const architectures = raw.trim().split(/\s+/u).filter(Boolean);
  if (
    architectures.length !== 2
    || new Set(architectures).size !== 2
    || !architectures.includes('x86_64')
    || !architectures.includes('arm64')
  ) {
    throw new TypeError(
      `universal Mach-O architecture set is not exactly x86_64+arm64: ${raw}`,
    );
  }
  return Object.freeze(['x86_64', 'arm64']);
}

function discoverMacosPackaging({
  configurations,
  environment,
  platformSpec,
  python,
  runCommand,
  source,
  universalOutDir,
}) {
  try {
    const universalOutput = validateOutputDirectory(
      source,
      universalOutDir,
      'macOS universal output directory',
    );
    const lipo = '/usr/bin/lipo';
    const byArchitecture = new Map(
      configurations.map((configuration) => [
        configuration.architecture,
        configuration,
      ]),
    );
    for (const architecture of platformSpec.architectures) {
      const configuration = byArchitecture.get(architecture);
      const entrypoint = join(
        configuration.outDir,
        platformSpec.entrypoint,
      );
      const raw = runCommand(lipo, ['-archs', entrypoint], {
        cwd: source,
        environment,
        platform: 'darwin',
      });
      if (raw.trim() !== architecture) {
        throw new TypeError(
          `${architecture} build output reports unexpected architectures ${raw}`,
        );
      }
    }
    const universalEntrypoint = join(
      universalOutput.outDir,
      platformSpec.entrypoint,
    );
    const architectures = exactArchitectures(
      runCommand(lipo, ['-archs', universalEntrypoint], {
        cwd: source,
        environment,
        platform: 'darwin',
      }),
    );
    return Object.freeze({
      architectures,
      lipoPath: lipo,
      pythonPath: python,
      universalizerPath: join(
        source,
        'chrome',
        'installer',
        'mac',
        'universalizer.py',
      ),
      universalOutDir: universalOutput.outDir,
    });
  } catch (error) {
    throw incomplete('macos-universal', error.message);
  }
}

/**
 * Collect the production lock. Injectable services exist only for isolated
 * fixture tests; no such injection is exposed by the CLI.
 */
export function collectToolchainLock(options, services = {}) {
  const implementations = {
    assertDepotTools: assertPinnedDepotTools,
    assertSource: assertPinnedChromiumCheckout,
    discoverPlatform: discoverPlatformToolchain,
    hostPlatform: process.platform,
    nodePath: process.execPath,
    readContracts: defaultReadContracts,
    runCommand: runControlledCommand,
    verifyDependency: verifyDependencyLock,
    ...services,
  };
  const {
    buildContractPath = BUILD_CONTRACT_PATH,
    clientRoot,
    configurations,
    dependencyLockPath,
    depotTools,
    effectiveArgsRecordPath,
    environment = process.env,
    git,
    platform,
    python,
    trustContractPath = TRUST_CONTRACT_PATH,
    universalOutDir = null,
    windowsToolchainSelectionPath = null,
  } = options || {};

  const contractIdentities = Object.freeze({
    build: stableFileIdentity(
      buildContractPath,
      'M0 build contract',
    ),
    trust: stableFileIdentity(
      trustContractPath,
      'M0 trust contract',
    ),
  });
  const { audit, buildContract, trustContract } =
    implementations.readContracts({
      buildContractPath,
      trustContractPath,
    });
  if (
    !isDeepStrictEqual(
      stableFileIdentity(buildContractPath, 'M0 build contract'),
      contractIdentities.build,
    )
    || !isDeepStrictEqual(
      stableFileIdentity(trustContractPath, 'M0 trust contract'),
      contractIdentities.trust,
    )
  ) {
    throw new TypeError(
      'M0 build or trust contract changed while it was validated',
    );
  }
  if (
    !audit
    || audit.assuranceLevel !== M0_HARD_ASSURANCE_LEVEL
    || !audit.platforms.includes(platform)
  ) {
    throw new TypeError('M0 build/trust contract validation was incomplete');
  }
  const platformSpec = buildContract.platforms[platform];
  validatePlatform(
    platform,
    implementations.hostPlatform,
    platformSpec,
  );
  const layout = validateBaseLayout({ clientRoot, depotTools });
  const requestedConfigurations = orderedConfigurations(
    configurations,
    platformSpec,
  );
  if (
    typeof dependencyLockPath !== 'string'
    || !isAbsolute(dependencyLockPath)
  ) {
    throw new TypeError('dependencyLockPath must be absolute');
  }
  if (
    typeof effectiveArgsRecordPath !== 'string'
    || !isAbsolute(effectiveArgsRecordPath)
  ) {
    throw new TypeError('effectiveArgsRecordPath must be absolute');
  }
  const runtimeIdentities = Object.freeze({
    git: hashStableOrdinaryFile(git, 'Git binary'),
    hostPython: hashStableOrdinaryFile(python, 'host Python binary'),
    node: hashStableOrdinaryFile(
      implementations.nodePath,
      'Node binary',
    ),
  });
  const controlledEnvironment = controlledToolchainEnvironment(
    environment,
    {
      gitPath: git,
      platform: implementations.hostPlatform,
    },
  );

  const baseline = Object.freeze({
    CHROMIUM_COMMIT: buildContract.source.chromiumCommit,
    CHROMIUM_REPOSITORY: buildContract.source.chromiumRepository,
    CHROMIUM_STABLE: buildContract.source.chromiumVersion,
    DEPOT_TOOLS_COMMIT: buildContract.source.depotToolsCommit,
    DEPOT_TOOLS_REPOSITORY: buildContract.source.depotToolsRepository,
    PATCH_PROFILE: buildContract.patches.profile,
  });

  const depotAudit = implementations.assertDepotTools(
    layout.depotTools,
    baseline,
    {
      environment: controlledEnvironment,
      git,
    },
  );
  const sourceAudit = implementations.assertSource(
    layout.source,
    baseline,
    {
      environment: controlledEnvironment,
      git,
      state: 'patched',
    },
  );
  const dependencyVerificationOptions = Object.freeze({
    chromiumState: 'patched',
    clientRoot: layout.clientRoot,
    depotTools: layout.depotTools,
    environment: controlledEnvironment,
    git,
    lockPath: resolve(dependencyLockPath),
  });
  const dependencyAudit = implementations.verifyDependency(
    dependencyVerificationOptions,
  );
  const verifiedDependencyIdentity = dependencyDigestMatches(
    dependencyAudit,
    resolve(dependencyLockPath),
  );
  const effectiveRecord = readEffectiveArgsRecord(
    effectiveArgsRecordPath,
    platform,
  );
  const collectedConfigurations = requestedConfigurations.map(
    (configuration, index) => {
      const output = validateOutputDirectory(
        layout.source,
        configuration.outDir,
        `${configuration.architecture} build output directory`,
      );
      const effectivePath = join(output.outDir, 'effective-args.gn');
      const effectiveBytes = readStableBytes(
        effectivePath,
        MAX_SMALL_FILE_BYTES,
        `${configuration.architecture} effective GN args`,
      );
      const effectiveText = decodeUtf8(
        effectiveBytes.bytes,
        `${configuration.architecture} effective GN args`,
      );
      const recordConfiguration =
        effectiveRecord.record.configurations[index];
      if (
        recordConfiguration.outDir !== output.outDirRelative
        || recordConfiguration.argsText !== effectiveText
      ) {
        throw new TypeError(
          `${configuration.architecture} effective args record does not bind the live output`,
        );
      }
      const effectiveAudit = inspectEffectiveArgs(
        effectiveText,
        platform,
        configuration.architecture,
      );
      assertBackendMarker(platform, output, effectiveAudit);
      let toolPaths;
      try {
        toolPaths = discoverBuildToolPaths({
          backend: effectiveAudit.backend,
          depotTools: layout.depotTools,
          effectiveArgs: effectiveAudit.assignments,
          git,
          hostPlatform: implementations.hostPlatform,
          node: implementations.nodePath,
          platform,
          python,
          source: layout.source,
        });
      } catch (error) {
        if (error.message.startsWith(`complete ${platform}`)) throw error;
        throw incomplete(platform, error.message);
      }
      return Object.freeze({
        architecture: configuration.architecture,
        effectiveArgs: effectiveAudit.assignments,
        effectiveArgsPath: effectivePath,
        outDir: output.outDir,
        toolPaths,
      });
    },
  );

  const discoveredToolchains = collectedConfigurations.map((configuration) =>
    implementations.discoverPlatform({
      effectiveArgs: configuration.effectiveArgs,
      environment: controlledEnvironment,
      outDir: configuration.outDir,
      platform,
      runCommand: implementations.runCommand,
      source: layout.source,
      windowsToolchainSelectionPath,
    }));
  const platformToolchain = discoveredToolchains[0];
  for (const candidate of discoveredToolchains.slice(1)) {
    if (!isDeepStrictEqual(candidate, platformToolchain)) {
      throw incomplete(
        platform,
        'architecture configurations resolved different platform SDKs',
      );
    }
  }

  let packaging = null;
  if (platform === 'macos-universal') {
    if (!universalOutDir) {
      throw new TypeError(
        'macos-universal requires universalOutDir',
      );
    }
    packaging = discoverMacosPackaging({
      configurations: collectedConfigurations,
      environment: controlledEnvironment,
      platformSpec,
      python,
      runCommand: implementations.runCommand,
      source: layout.source,
      universalOutDir,
    });
  } else if (universalOutDir) {
    throw new TypeError('universalOutDir is valid only for macos-universal');
  }
  if (platform !== 'windows-x64' && windowsToolchainSelectionPath) {
    throw new TypeError(
      'windowsToolchainSelectionPath is valid only for windows-x64',
    );
  }

  const lock = assembleToolchainLock({
    buildContractPath,
    clientRoot: layout.clientRoot,
    configurations: collectedConfigurations,
    dependencyLockPath: resolve(dependencyLockPath),
    depotTools: layout.depotTools,
    effectiveArgsRecordPath,
    hostPlatform: implementations.hostPlatform,
    packaging,
    platform,
    platformSpec,
    platformToolchain,
    source: {
      chromiumCommit: buildContract.source.chromiumCommit,
      chromiumRepository: buildContract.source.chromiumRepository,
      chromiumVersion: buildContract.source.chromiumVersion,
      depotToolsCommit: buildContract.source.depotToolsCommit,
      depotToolsRepository: buildContract.source.depotToolsRepository,
      patchProfile: buildContract.patches.profile,
      patchSeriesSha256: buildContract.patches.activeSeriesSha256,
      repository: trustContract.repository.nameWithOwner,
    },
    trustContractPath,
  });
  if (
    !isDeepStrictEqual(lock.contracts.build, contractIdentities.build)
    || !isDeepStrictEqual(lock.contracts.trust, contractIdentities.trust)
  ) {
    throw new TypeError(
      'validated M0 build or trust contract changed before lock assembly',
    );
  }
  if (
    !isDeepStrictEqual(
      lock.contracts.dependency,
      verifiedDependencyIdentity,
    )
  ) {
    throw new TypeError(
      'verified dependency lock changed before lock assembly',
    );
  }
  if (
    !isDeepStrictEqual(
      lock.effectiveGnArgsRecord,
      effectiveRecord.identity,
    )
  ) {
    throw new TypeError(
      'effective GN args record changed before lock assembly',
    );
  }
  for (const configuration of lock.configurations) {
    const lockedRuntimes = configuration.buildTools.runtimes;
    for (const key of ['git', 'hostPython', 'node']) {
      if (!isDeepStrictEqual(lockedRuntimes[key], runtimeIdentities[key])) {
        throw new TypeError(
          `${key} runtime changed before toolchain lock assembly`,
        );
      }
    }
  }

  // Full Xcode/MSVC/sysroot and universal-output enumeration can be long.
  // Recheck the pinned Git identities after every byte identity is complete.
  const finalDepotAudit = implementations.assertDepotTools(
    layout.depotTools,
    baseline,
    {
      environment: controlledEnvironment,
      git,
    },
  );
  const finalSourceAudit = implementations.assertSource(
    layout.source,
    baseline,
    {
      environment: controlledEnvironment,
      git,
      state: 'patched',
    },
  );
  if (
    depotAudit.actualTree !== finalDepotAudit.actualTree
    || sourceAudit.actualTree !== finalSourceAudit.actualTree
  ) {
    throw new TypeError('pinned source or depot_tools changed during collection');
  }
  const finalDependencyAudit = implementations.verifyDependency(
    dependencyVerificationOptions,
  );
  const finalDependencyIdentity = dependencyDigestMatches(
    finalDependencyAudit,
    resolve(dependencyLockPath),
  );
  if (
    !isDeepStrictEqual(finalDependencyIdentity, verifiedDependencyIdentity)
  ) {
    throw new TypeError(
      'resolved dependency state changed during toolchain collection',
    );
  }
  const finalIdentities = [
    [
      lock.contracts.build,
      stableFileIdentity(buildContractPath, 'M0 build contract'),
      'M0 build contract',
    ],
    [
      lock.contracts.trust,
      stableFileIdentity(trustContractPath, 'M0 trust contract'),
      'M0 trust contract',
    ],
    [
      lock.effectiveGnArgsRecord,
      stableFileIdentity(
        effectiveArgsRecordPath,
        'canonical effective GN args record',
        MAX_SMALL_FILE_BYTES,
      ),
      'effective GN args record',
    ],
    [
      runtimeIdentities.git,
      hashStableOrdinaryFile(git, 'Git binary'),
      'Git binary',
    ],
    [
      runtimeIdentities.hostPython,
      hashStableOrdinaryFile(python, 'host Python binary'),
      'host Python binary',
    ],
    [
      runtimeIdentities.node,
      hashStableOrdinaryFile(
        implementations.nodePath,
        'Node binary',
      ),
      'Node binary',
    ],
  ];
  for (const [expected, actual, label] of finalIdentities) {
    if (!isDeepStrictEqual(expected, actual)) {
      throw new TypeError(`${label} changed during toolchain collection`);
    }
  }
  return lock;
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!value || typeof value !== 'object') return value;
  const output = Object.create(null);
  for (const key of Object.keys(value).sort(compareText)) {
    output[key] = sortJson(value[key]);
  }
  return output;
}

export function canonicalToolchainLock(lock) {
  return `${JSON.stringify(sortJson(lock), null, 2)}\n`;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function assertLockOutsideHashedOutputs(lock, lockPath) {
  if (!lock.packaging) return;
  const output = lock.packaging.universalOutput.outDir;
  const candidate = resolve(lockPath);
  const rel = relative(output, candidate);
  if (
    rel === ''
    || (
      rel !== '..'
      && !rel.startsWith(`..${sep}`)
      && !isAbsolute(rel)
    )
  ) {
    throw new TypeError(
      'toolchain lock path must be outside the hashed universal output',
    );
  }
}

function writeAtomic(path, contents) {
  if (typeof path !== 'string' || !isAbsolute(path) || hasControl(path)) {
    throw new TypeError('toolchain lock path must be absolute and control-free');
  }
  const normalized = resolve(path);
  const parent = ordinaryDirectory(
    dirname(normalized),
    'toolchain lock parent',
  );
  if (dirname(normalized) !== parent.path) {
    throw new TypeError('toolchain lock path must already be canonical');
  }
  if (existsSync(normalized)) {
    throw new TypeError(
      'toolchain lock already exists; capture requires a fresh path',
    );
  }
  const temporary = join(
    parent.path,
    `.proteus-toolchain-lock-${process.pid}-${createHash('sha256')
      .update(`${normalized}\0${Date.now()}\0${Math.random()}`)
      .digest('hex')
      .slice(0, 16)}.tmp`,
  );
  try {
    writeFileSync(temporary, contents, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o644,
    });
    renameSync(temporary, normalized);
  } finally {
    rmSync(temporary, { force: true });
  }
}

export function captureToolchainLock(
  options,
  { collector = collectToolchainLock } = {},
) {
  const lock = collector(options);
  assertLockOutsideHashedOutputs(lock, options.lockPath);
  const bytes = canonicalToolchainLock(lock);
  writeAtomic(options.lockPath, bytes);
  return Object.freeze({
    architectures: lock.architectures,
    configurations: lock.configurations.length,
    lockPath: resolve(options.lockPath),
    platform: lock.platform,
    sha256: sha256(bytes),
    toolchainRoots: lock.platformToolchain.roots.length,
  });
}

export function verifyToolchainLock(
  options,
  { collector = collectToolchainLock } = {},
) {
  const stable = readStableBytes(
    options.lockPath,
    MAX_SMALL_FILE_BYTES,
    'toolchain lock',
  );
  const actual = decodeUtf8(stable.bytes, 'toolchain lock');
  const parsed = parseJsonWithoutDuplicateKeys(actual, 'toolchain lock');
  const canonicalActual = canonicalToolchainLock(parsed);
  if (canonicalActual !== actual) {
    throw new TypeError('toolchain lock is not canonical sorted JSON');
  }
  const collected = collector(options);
  assertLockOutsideHashedOutputs(collected, options.lockPath);
  const expected = canonicalToolchainLock(collected);
  const actualBytes = Buffer.from(actual, 'utf8');
  const expectedBytes = Buffer.from(expected, 'utf8');
  if (
    actualBytes.length !== expectedBytes.length
    || !timingSafeEqual(actualBytes, expectedBytes)
  ) {
    throw new TypeError(
      'toolchain lock differs from the complete live build toolchain',
    );
  }
  return Object.freeze({
    architectures: parsed.architectures,
    configurations: parsed.configurations.length,
    lockPath: resolve(options.lockPath),
    platform: parsed.platform,
    sha256: sha256(actual),
    toolchainRoots: parsed.platformToolchain.roots.length,
  });
}

function parseCli(args) {
  if (args.length === 0 || !['capture', 'verify'].includes(args[0])) {
    throw new TypeError(
      'usage: toolchain-lock.mjs capture|verify '
      + '--platform <id> '
      + '--configuration <arch> <absolute-out-dir> [...] '
      + '--client-root <absolute-path> --depot-tools <absolute-path> '
      + '--dependency-lock <absolute-path> '
      + '--effective-args-record <absolute-path> '
      + '--git <absolute-file> --python <absolute-file> '
      + '[--universal-out-dir <absolute-path>] '
      + '[--windows-toolchain-selection <absolute-file>] '
      + '[--lock <absolute-path>]',
    );
  }
  const command = args[0];
  const allowed = new Set([
    '--client-root',
    '--configuration',
    '--dependency-lock',
    '--depot-tools',
    '--effective-args-record',
    '--git',
    '--lock',
    '--platform',
    '--python',
    '--universal-out-dir',
    '--windows-toolchain-selection',
  ]);
  const values = Object.create(null);
  const configurations = [];
  for (let index = 1; index < args.length; index += 1) {
    const key = args[index];
    if (!allowed.has(key)) throw new TypeError(`unknown argument ${key}`);
    if (key === '--configuration') {
      const architecture = args[index + 1];
      const outDir = args[index + 2];
      if (
        !architecture
        || architecture.startsWith('--')
        || hasControl(architecture)
        || !outDir
        || outDir.startsWith('--')
        || hasControl(outDir)
        || !isAbsolute(outDir)
      ) {
        throw new TypeError(
          '--configuration requires <architecture> <absolute-out-dir>',
        );
      }
      configurations.push(Object.freeze({
        architecture,
        outDir: resolve(outDir),
      }));
      index += 2;
      continue;
    }
    if (Object.hasOwn(values, key)) {
      throw new TypeError(`${key} may only be supplied once`);
    }
    const value = args[index + 1];
    if (!value || value.startsWith('--') || hasControl(value)) {
      throw new TypeError(`${key} requires a safe value`);
    }
    values[key] = value;
    index += 1;
  }
  for (const key of [
    '--client-root',
    '--dependency-lock',
    '--depot-tools',
    '--effective-args-record',
    '--git',
    '--platform',
    '--python',
  ]) {
    if (!Object.hasOwn(values, key)) {
      throw new TypeError(`${key} is required`);
    }
  }
  if (configurations.length === 0) {
    throw new TypeError('at least one --configuration is required');
  }
  for (const key of [
    '--client-root',
    '--dependency-lock',
    '--depot-tools',
    '--effective-args-record',
    '--git',
    '--python',
  ]) {
    if (!isAbsolute(values[key])) {
      throw new TypeError(`${key} must be an absolute path`);
    }
  }
  if (values['--lock'] && !isAbsolute(values['--lock'])) {
    throw new TypeError('--lock must be an absolute path');
  }
  if (
    values['--universal-out-dir']
    && !isAbsolute(values['--universal-out-dir'])
  ) {
    throw new TypeError('--universal-out-dir must be an absolute path');
  }
  if (
    values['--windows-toolchain-selection']
    && !isAbsolute(values['--windows-toolchain-selection'])
  ) {
    throw new TypeError(
      '--windows-toolchain-selection must be an absolute path',
    );
  }
  if (
    values['--platform'] === 'windows-x64'
    && !values['--windows-toolchain-selection']
  ) {
    throw new TypeError(
      'windows-x64 requires --windows-toolchain-selection',
    );
  }
  if (
    values['--platform'] !== 'windows-x64'
    && values['--windows-toolchain-selection']
  ) {
    throw new TypeError(
      '--windows-toolchain-selection is valid only for windows-x64',
    );
  }
  const clientRoot = resolve(values['--client-root']);
  const lockPath = values['--lock']
    ? resolve(values['--lock'])
    : join(clientRoot, `.proteus-toolchain-${values['--platform']}.json`);
  if (!isAbsolute(lockPath)) throw new TypeError('--lock must be absolute');
  return Object.freeze({
    clientRoot,
    command,
    configurations: Object.freeze(configurations),
    dependencyLockPath: resolve(values['--dependency-lock']),
    depotTools: resolve(values['--depot-tools']),
    effectiveArgsRecordPath: resolve(values['--effective-args-record']),
    git: resolve(values['--git']),
    lockPath,
    platform: values['--platform'],
    python: resolve(values['--python']),
    universalOutDir: values['--universal-out-dir']
      ? resolve(values['--universal-out-dir'])
      : null,
    windowsToolchainSelectionPath:
      values['--windows-toolchain-selection']
        ? resolve(values['--windows-toolchain-selection'])
        : null,
  });
}

function main() {
  try {
    const options = parseCli(process.argv.slice(2));
    const result = options.command === 'capture'
      ? captureToolchainLock(options)
      : verifyToolchainLock(options);
    writeSync(process.stdout.fd, `${JSON.stringify(result, null, 2)}\n`);
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
