#!/usr/bin/env node
// Create or verify a canonical manifest for a complete unpacked engine bundle.

import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readlinkSync,
  readSync,
  readdirSync,
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
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseStrictJson } from '../../scripts/strict-json.mjs';
import { M0_PLATFORM_IDS } from './build-contract.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = resolve(HERE, '..');
const MANIFEST_SCHEMA_VERSION = '1.0.0';
const TREE_DIGEST_DOMAIN = Buffer.from(
  'PROTEUS-COMPLETE-BUNDLE-TREE\0v1\0',
  'utf8',
);
const MAX_ENTRIES = 200_000;
const MAX_FILE_BYTES = 16 * 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024 * 1024;
const HASH_BUFFER_BYTES = 1024 * 1024;

function ordinaryDirectory(path, label) {
  const stat = lstatSync(path, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink directory`);
  }
  return stat;
}

function stableDirectoryNames(path, before, label) {
  const names = readdirSync(path);
  for (const name of names) {
    if (name === '' || name === '.' || name === '..'
        || name.includes('\0') || name.includes('/') || name.includes('\\')) {
      throw new TypeError(`${label} contains an unsafe directory entry`);
    }
  }
  names.sort(compareUtf8);
  const namesAfter = readdirSync(path).sort(compareUtf8);
  const after = lstatSync(path, { bigint: true });
  if (!sameDirectoryState(before, after)
      || !isDeepStrictEqual(names, namesAfter)) {
    throw new TypeError(`${label} changed while it was enumerated`);
  }
  return names;
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
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

function portableMode(stat, platform, type) {
  // Win32/libuv synthesizes 0777 for directories and executable extensions,
  // while MSYS tar normalizes the same tree to POSIX archive modes. Hard-M0
  // verifies Windows bundles on Linux, so Windows mode values must be defined
  // by the manifest contract instead of either host's emulation layer.
  if (platform === 'windows-x64') {
    return type === 'directory' ? '755' : '644';
  }
  return Number(stat.mode & 0o777n).toString(8).padStart(3, '0');
}

function manifestPath(root, path) {
  const value = relative(root, path).split(sep).join('/');
  if (value === ''
      || value.startsWith('/')
      || value.split('/').some((part) => part === '' || part === '.' || part === '..')
      || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError(`unsafe bundle-relative path ${JSON.stringify(value)}`);
  }
  return value;
}

function hashStableFile(path, before, label) {
  if (before.size < 0n || before.size > BigInt(MAX_FILE_BYTES)) {
    throw new TypeError(`${label} exceeds ${MAX_FILE_BYTES} bytes`);
  }
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
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
    const pathAfter = lstatSync(path, { bigint: true });
    if (!sameFileState(opened, after) || !sameFileState(after, pathAfter)) {
      throw new TypeError(`${label} changed or was rebound while it was hashed`);
    }
    return hash.digest('hex');
  } finally {
    closeSync(fd);
  }
}

function assertSymlinkContained(rootReal, path, target, label) {
  if (target === ''
      || isAbsolute(target)
      || target.includes('\0')
      || /[\u0001-\u001f\u007f]/u.test(target)) {
    throw new TypeError(`${label} has an unsafe link target`);
  }
  const lexical = resolve(dirname(path), target);
  if (!isContained(rootReal, lexical)) {
    throw new TypeError(`${label} escapes the bundle root`);
  }
  let resolvedTarget;
  try {
    resolvedTarget = realpathSync(lexical);
  } catch (error) {
    throw new TypeError(`${label} is dangling: ${error.message}`);
  }
  if (!isContained(rootReal, resolvedTarget)) {
    throw new TypeError(`${label} resolves outside the bundle root`);
  }
}

function isContained(root, candidate) {
  const rel = relative(root, candidate);
  return rel === '' || (
    rel !== '..'
    && !rel.startsWith(`..${sep}`)
    && !isAbsolute(rel)
  );
}

function treeDigest(core) {
  return createHash('sha256')
    .update(TREE_DIGEST_DOMAIN)
    .update(JSON.stringify(core), 'utf8')
    .digest('hex');
}

export function createBundleManifest(root, {
  platform,
  entrypoint,
} = {}) {
  if (!M0_PLATFORM_IDS.includes(platform)) {
    throw new TypeError(`unsupported M0 platform ${String(platform)}`);
  }
  if (typeof entrypoint !== 'string'
      || entrypoint === ''
      || entrypoint.startsWith('/')
      || entrypoint.includes('\\')
      || entrypoint.split('/').some((part) =>
        part === '' || part === '.' || part === '..')) {
    throw new TypeError('entrypoint must be a canonical bundle-relative path');
  }

  const rootPath = resolve(root);
  const rootBefore = ordinaryDirectory(rootPath, 'bundle root');
  const rootReal = realpathSync(rootPath);
  if (rootReal !== rootPath) {
    throw new TypeError('bundle root path must already be canonical');
  }

  const entries = [];
  let totalBytes = 0n;
  const walk = (directory) => {
    const before = ordinaryDirectory(directory, `bundle directory ${directory}`);
    const names = stableDirectoryNames(
      directory,
      before,
      `bundle directory ${directory}`,
    );
    for (const name of names) {
      const path = join(directory, name);
      const rel = manifestPath(rootPath, path);
      const stat = lstatSync(path, { bigint: true });
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        entries.push({
          path: rel,
          type: 'directory',
          mode: portableMode(stat, platform, 'directory'),
        });
        walk(path);
      } else if (stat.isFile() && !stat.isSymbolicLink()) {
        const sha256 = hashStableFile(path, stat, `bundle file ${rel}`);
        totalBytes += stat.size;
        if (totalBytes > BigInt(MAX_TOTAL_BYTES)) {
          throw new TypeError(
            `bundle contents exceed ${MAX_TOTAL_BYTES} bytes`,
          );
        }
        entries.push({
          path: rel,
          type: 'file',
          mode: portableMode(stat, platform, 'file'),
          size: Number(stat.size),
          sha256,
        });
      } else if (stat.isSymbolicLink()) {
        const target = readlinkSync(path, 'utf8');
        const after = lstatSync(path, { bigint: true });
        if (stat.dev !== after.dev
            || stat.ino !== after.ino
            || stat.mode !== after.mode
            || stat.mtimeNs !== after.mtimeNs
            || readlinkSync(path, 'utf8') !== target) {
          throw new TypeError(`bundle symlink ${rel} changed while inspected`);
        }
        assertSymlinkContained(rootReal, path, target, `bundle symlink ${rel}`);
        entries.push({
          path: rel,
          type: 'symlink',
          target,
        });
      } else {
        throw new TypeError(`bundle entry ${rel} is not a file, directory, or symlink`);
      }
      if (entries.length > MAX_ENTRIES) {
        throw new TypeError(`bundle contains more than ${MAX_ENTRIES} entries`);
      }
    }
    const after = lstatSync(directory, { bigint: true });
    if (!sameDirectoryState(before, after)
        || !isDeepStrictEqual(
          names,
          readdirSync(directory).sort(compareUtf8),
        )) {
      throw new TypeError(`bundle directory ${directory} changed during traversal`);
    }
  };
  walk(rootPath);

  entries.sort((left, right) => compareUtf8(left.path, right.path));
  const entry = entries.find((item) => item.path === entrypoint);
  if (!entry || entry.type !== 'file') {
    throw new TypeError(`bundle entrypoint is not a regular file: ${entrypoint}`);
  }
  const rootAfter = lstatSync(rootPath, { bigint: true });
  if (!sameDirectoryState(rootBefore, rootAfter)) {
    throw new TypeError('bundle root changed while the manifest was created');
  }
  const core = {
    schemaVersion: MANIFEST_SCHEMA_VERSION,
    platform,
    entrypoint,
    entries,
  };
  return {
    ...core,
    treeSha256: treeDigest(core),
    totalFileBytes: Number(totalBytes),
  };
}

export function verifyBundleManifest(root, expected) {
  exactManifestKeys(expected);
  const actual = createBundleManifest(root, {
    platform: expected.platform,
    entrypoint: expected.entrypoint,
  });
  if (!isDeepStrictEqual(actual, expected)) {
    throw new TypeError('bundle tree does not match its canonical manifest');
  }
  return actual;
}

function exactManifestKeys(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('bundle manifest must be an object');
  }
  const keys = Object.keys(value).sort();
  const expected = [
    'schemaVersion',
    'platform',
    'entrypoint',
    'entries',
    'treeSha256',
    'totalFileBytes',
  ].sort();
  if (keys.length !== expected.length
      || keys.some((key, index) => key !== expected[index])) {
    throw new TypeError('bundle manifest contains missing or unknown root fields');
  }
  if (value.schemaVersion !== MANIFEST_SCHEMA_VERSION) {
    throw new TypeError(`unsupported bundle manifest ${String(value.schemaVersion)}`);
  }
}

function parseArgs(args) {
  const parsed = {
    root: null,
    platform: null,
    entrypoint: null,
    verify: null,
  };
  const options = new Map([
    ['--root', 'root'],
    ['--platform', 'platform'],
    ['--entrypoint', 'entrypoint'],
    ['--verify', 'verify'],
  ]);
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    const key = options.get(option);
    if (!key) throw new TypeError(`unknown argument ${option}`);
    if (parsed[key] !== null) {
      throw new TypeError(`${option} may only be supplied once`);
    }
    const value = args[index + 1];
    if (!value || value.startsWith('--')) {
      throw new TypeError(`${option} requires a value`);
    }
    parsed[key] = value;
    index += 1;
  }
  if (!parsed.root) throw new TypeError('--root is required');
  if (parsed.verify) {
    if (parsed.platform || parsed.entrypoint) {
      throw new TypeError('--verify is mutually exclusive with platform/entrypoint');
    }
  } else if (!parsed.platform || !parsed.entrypoint) {
    throw new TypeError('--platform and --entrypoint are required when creating');
  }
  return parsed;
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    let manifest;
    if (args.verify) {
      const expected = parseStrictJson(
        readFileSync(resolve(args.verify)),
        'bundle manifest',
      );
      manifest = verifyBundleManifest(resolve(args.root), expected);
    } else {
      manifest = createBundleManifest(resolve(args.root), {
        platform: args.platform,
        entrypoint: args.entrypoint,
      });
    }
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
