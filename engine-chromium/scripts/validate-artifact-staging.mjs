#!/usr/bin/env node
// Validate downloaded builder archives before their trees enter the checked-out
// repository. Extraction happens in a fresh runner-temp directory; this pass
// rejects special files, unsafe names, escaping links, and incomplete A/B
// platform layouts.

import {
  lstatSync,
  readlinkSync,
  readdirSync,
  realpathSync,
} from 'node:fs';
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { pathToFileURL } from 'node:url';

import { M0_PLATFORM_IDS } from './build-contract.mjs';

const SLOTS = Object.freeze(['A', 'B']);
const MAX_NODES = 2_000_000;
const MAX_FILE_BYTES = 8n * 1024n * 1024n * 1024n;
const MAX_TREE_BYTES = 128n * 1024n * 1024n * 1024n;

function assertSafeName(name, label) {
  if (name.length === 0
      || name !== name.normalize('NFC')
      || name === '.'
      || name === '..'
      || name.includes('/')
      || name.includes('\\')
      || name.includes(':')
      || /[\u0000-\u001f\u007f]/u.test(name)
      || /[. ]$/u.test(name)) {
    throw new TypeError(`${label} has an unsafe archive name`);
  }
}

function assertInside(root, candidate, label) {
  const rel = relative(root, candidate);
  if (rel === ''
      || (rel !== '..'
        && !rel.startsWith(`..${sep}`)
        && !isAbsolute(rel))) {
    return;
  }
  throw new TypeError(`${label} escapes the staging root`);
}

function exactDirectoryEntries(path, expected, label) {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary directory`);
  }
  const actual = readdirSync(path).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
      || actual.some((name, index) => name !== wanted[index])) {
    throw new TypeError(
      `${label} must contain exactly ${wanted.join(', ')}`,
    );
  }
}

export function validateArtifactStaging(root) {
  const resolvedRoot = resolve(root);
  const rootStat = lstatSync(resolvedRoot, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new TypeError('artifact staging root must be an ordinary directory');
  }
  if (realpathSync(resolvedRoot) !== resolvedRoot) {
    throw new TypeError('artifact staging root must already be canonical');
  }

  const rootEntries = readdirSync(resolvedRoot);
  const allowedRootEntries = new Set([
    'builds',
    'm0-build-evidence-v2.json',
  ]);
  if (!rootEntries.includes('builds')
      || rootEntries.some((name) => !allowedRootEntries.has(name))) {
    throw new TypeError('artifact staging root has an unexpected layout');
  }
  exactDirectoryEntries(
    join(resolvedRoot, 'builds'),
    M0_PLATFORM_IDS,
    'build staging directory',
  );
  for (const platform of M0_PLATFORM_IDS) {
    const platformRoot = join(resolvedRoot, 'builds', platform);
    exactDirectoryEntries(platformRoot, SLOTS, `${platform} staging directory`);
    for (const slot of SLOTS) {
      exactDirectoryEntries(
        join(platformRoot, slot),
        ['bundle', 'records'],
        `${platform}/${slot} staging directory`,
      );
    }
  }

  let nodes = 0;
  let bytes = 0n;
  const pending = [resolvedRoot];
  while (pending.length > 0) {
    const current = pending.pop();
    const stat = lstatSync(current, { bigint: true });
    nodes += 1;
    if (nodes > MAX_NODES) {
      throw new TypeError(`artifact staging tree exceeds ${MAX_NODES} nodes`);
    }
    if ((stat.mode & 0o6000n) !== 0n) {
      throw new TypeError('artifact staging tree contains set-id permission bits');
    }
    if (stat.isDirectory()) {
      for (const name of readdirSync(current)) {
        assertSafeName(name, relative(resolvedRoot, join(current, name)));
        pending.push(join(current, name));
      }
      continue;
    }
    if (stat.isFile()) {
      if (stat.size > MAX_FILE_BYTES) {
        throw new TypeError('artifact staging tree contains an oversized file');
      }
      bytes += stat.size;
      if (bytes > MAX_TREE_BYTES) {
        throw new TypeError('artifact staging tree exceeds its byte budget');
      }
      continue;
    }
    if (stat.isSymbolicLink()) {
      const target = readlinkSync(current);
      if (target.length === 0
          || target !== target.normalize('NFC')
          || isAbsolute(target)
          || target.includes('\\')
          || target.includes(':')
          || /[\u0000-\u001f\u007f]/u.test(target)) {
        throw new TypeError('artifact staging tree contains an unsafe symlink');
      }
      assertInside(
        resolvedRoot,
        resolve(dirname(current), target),
        'artifact staging symlink',
      );
      continue;
    }
    throw new TypeError('artifact staging tree contains a special file');
  }

  return { ok: true, nodes, bytes: bytes.toString() };
}

function main() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--root') {
    process.stderr.write(
      'usage: validate-artifact-staging.mjs --root <directory>\n',
    );
    process.exitCode = 64;
    return;
  }
  process.stdout.write(
    `${JSON.stringify(validateArtifactStaging(args[1]))}\n`,
  );
}

const isDirect = import.meta.main ?? (
  process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
);
if (isDirect) main();
