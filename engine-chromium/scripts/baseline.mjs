#!/usr/bin/env node
// Strict parser for the immutable Chromium/depot_tools baseline.
//
// CHROMIUM_BASELINE is data, never shell. Keeping parsing here prevents a
// reviewed baseline change from becoming arbitrary code execution in the build
// farm and gives every consumer one validation contract.

import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  writeSync,
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { TextDecoder } from 'node:util';

const HERE = dirname(fileURLToPath(import.meta.url));

export const DEFAULT_BASELINE_PATH = resolve(HERE, '..', 'CHROMIUM_BASELINE');
export const M0_PATCH_PROFILE = 'm0-layer0-v1';
export const CHROMIUM_REPOSITORY =
  'https://chromium.googlesource.com/chromium/src.git';
export const DEPOT_TOOLS_REPOSITORY =
  'https://chromium.googlesource.com/chromium/tools/depot_tools.git';
export const BASELINE_KEYS = Object.freeze([
  'SCHEMA_VERSION',
  'CHROMIUM_REPOSITORY',
  'CHROMIUM_STABLE',
  'CHROMIUM_COMMIT',
  'DEPOT_TOOLS_REPOSITORY',
  'DEPOT_TOOLS_COMMIT',
  'PATCH_PROFILE',
  'CHANNEL',
  'MILESTONE',
  'PINNED_AT',
]);

const BASELINE_KEY_SET = new Set(BASELINE_KEYS);
const MAX_BASELINE_BYTES = 64 * 1024;

export function parseChromiumBaseline(raw, label = 'CHROMIUM_BASELINE') {
  if (typeof raw !== 'string') {
    throw new TypeError(`${label} must be UTF-8 text`);
  }
  if (Buffer.byteLength(raw, 'utf8') > MAX_BASELINE_BYTES) {
    throw new TypeError(`${label} exceeds ${MAX_BASELINE_BYTES} bytes`);
  }

  const values = Object.create(null);
  const lines = raw.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const lineNumber = index + 1;
    if (line === '') continue;
    if (line.includes('\r') || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(line)) {
      throw new TypeError(`${label}:${lineNumber}: control character is forbidden`);
    }
    if (line.startsWith('#')) continue;
    if (line.trim() !== line) {
      throw new TypeError(
        `${label}:${lineNumber}: leading or trailing whitespace is forbidden`,
      );
    }

    const match = line.match(/^([A-Z][A-Z0-9_]*)=(.+)$/u);
    if (!match) {
      throw new TypeError(
        `${label}:${lineNumber}: expected a literal KEY=VALUE assignment`,
      );
    }
    const [, key, value] = match;
    if (!BASELINE_KEY_SET.has(key)) {
      throw new TypeError(`${label}:${lineNumber}: unknown key ${key}`);
    }
    if (Object.hasOwn(values, key)) {
      throw new TypeError(`${label}:${lineNumber}: duplicate key ${key}`);
    }
    if (value.trim() !== value) {
      throw new TypeError(`${label}:${lineNumber}: ${key} has surrounding whitespace`);
    }
    values[key] = value;
  }

  const missing = BASELINE_KEYS.filter((key) => !Object.hasOwn(values, key));
  if (missing.length > 0) {
    throw new TypeError(`${label}: missing required key(s): ${missing.join(', ')}`);
  }

  if (values.SCHEMA_VERSION !== '1') {
    throw new TypeError(`${label}: unsupported SCHEMA_VERSION ${values.SCHEMA_VERSION}`);
  }
  if (values.CHROMIUM_REPOSITORY !== CHROMIUM_REPOSITORY) {
    throw new TypeError(`${label}: CHROMIUM_REPOSITORY must be the canonical upstream`);
  }
  if (values.DEPOT_TOOLS_REPOSITORY !== DEPOT_TOOLS_REPOSITORY) {
    throw new TypeError(`${label}: DEPOT_TOOLS_REPOSITORY must be the canonical upstream`);
  }

  const version = values.CHROMIUM_STABLE.match(
    /^([1-9][0-9]*)\.([0-9]+)\.([0-9]+)\.([0-9]+)$/u,
  );
  if (!version) {
    throw new TypeError(`${label}: CHROMIUM_STABLE must have four numeric components`);
  }
  for (const key of ['CHROMIUM_COMMIT', 'DEPOT_TOOLS_COMMIT']) {
    if (!/^[0-9a-f]{40}$/u.test(values[key])) {
      throw new TypeError(`${label}: ${key} must be a lowercase 40-hex Git commit`);
    }
    if (/^0{40}$/u.test(values[key])) {
      throw new TypeError(`${label}: ${key} cannot be the all-zero sentinel`);
    }
  }
  if (values.PATCH_PROFILE !== M0_PATCH_PROFILE) {
    throw new TypeError(
      `${label}: PATCH_PROFILE must be ${M0_PATCH_PROFILE} for the current M0 contract`,
    );
  }
  if (values.CHANNEL !== 'stable') {
    throw new TypeError(`${label}: CHANNEL must be stable`);
  }
  if (!/^[1-9][0-9]*$/u.test(values.MILESTONE)
      || values.MILESTONE !== version[1]) {
    throw new TypeError(
      `${label}: MILESTONE must equal the CHROMIUM_STABLE major version`,
    );
  }
  if (!isCanonicalDate(values.PINNED_AT)) {
    throw new TypeError(`${label}: PINNED_AT must be a real YYYY-MM-DD date`);
  }

  return Object.freeze(Object.fromEntries(
    BASELINE_KEYS.map((key) => [key, values[key]]),
  ));
}

export function readChromiumBaseline(path = DEFAULT_BASELINE_PATH) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${path} must be an ordinary non-symlink file`);
  }
  if (before.size > BigInt(MAX_BASELINE_BYTES)) {
    throw new TypeError(`${path} exceeds ${MAX_BASELINE_BYTES} bytes`);
  }
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameStableFile(before, opened)) {
      throw new TypeError(`${path} changed while it was opened`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    if (!sameStableFile(opened, after) || !sameStableFile(after, pathAfter)) {
      throw new TypeError(`${path} changed or was rebound while it was read`);
    }
    const raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return parseChromiumBaseline(raw, path);
  } finally {
    closeSync(fd);
  }
}

function sameStableFile(left, right) {
  return left.isFile()
    && right.isFile()
    && left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function isCanonicalDate(value) {
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/u.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.valueOf())
    && parsed.toISOString().slice(0, 10) === value;
}

function parseCli(args) {
  let file = DEFAULT_BASELINE_PATH;
  let command = 'check';
  let getKey = null;
  let commandSeen = false;
  let fileSeen = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--file') {
      if (fileSeen) throw new TypeError('--file may only be supplied once');
      const value = args[index + 1];
      if (!value || value.startsWith('--')) throw new TypeError('--file requires a path');
      file = resolve(value);
      fileSeen = true;
      index += 1;
      continue;
    }
    if (arg === '--check' || arg === '--json') {
      if (commandSeen) throw new TypeError('choose exactly one output mode');
      command = arg.slice(2);
      commandSeen = true;
      continue;
    }
    if (arg === '--get') {
      if (commandSeen) throw new TypeError('choose exactly one output mode');
      const value = args[index + 1];
      if (!value || value.startsWith('--')) throw new TypeError('--get requires a key');
      if (!BASELINE_KEY_SET.has(value)) throw new TypeError(`unknown baseline key ${value}`);
      command = 'get';
      getKey = value;
      commandSeen = true;
      index += 1;
      continue;
    }
    throw new TypeError(`unknown argument ${arg}`);
  }
  return { command, file, getKey };
}

function main() {
  try {
    const { command, file, getKey } = parseCli(process.argv.slice(2));
    const baseline = readChromiumBaseline(file);
    if (command === 'get') {
      writeSync(process.stdout.fd, `${baseline[getKey]}\n`);
    } else if (command === 'json') {
      writeSync(process.stdout.fd, `${JSON.stringify(baseline, null, 2)}\n`);
    } else {
      writeSync(
        process.stdout.fd,
        `baseline valid: Chromium ${baseline.CHROMIUM_STABLE} @ ${baseline.CHROMIUM_COMMIT}\n`,
      );
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
