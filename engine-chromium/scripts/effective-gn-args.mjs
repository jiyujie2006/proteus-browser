#!/usr/bin/env node
// Canonicalize the complete `gn args <out> --list --short` output used by an
// M0 build. A macOS universal build has two independent GN configurations, so
// a single text file is deliberately not accepted for that platform.

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
import { resolve } from 'node:path';
import { TextDecoder } from 'node:util';
import { pathToFileURL } from 'node:url';

import { parseStrictJson } from '../../scripts/strict-json.mjs';
import {
  M0_PLATFORM_IDS,
  readAndValidateM0BuildContract,
} from './build-contract.mjs';

const MAX_EFFECTIVE_ARGS_BYTES = 8 * 1024 * 1024;
const SHA256_RE = /^[0-9a-f]{64}$/u;
const GN_CPU = Object.freeze({
  x86_64: 'x64',
  arm64: 'arm64',
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

function readStableBytes(path, label) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  if (before.size > BigInt(MAX_EFFECTIVE_ARGS_BYTES)) {
    throw new TypeError(`${label} exceeds ${MAX_EFFECTIVE_ARGS_BYTES} bytes`);
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

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function decodeNormalizedArgs(bytes, label) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new TypeError(`${label} must be valid UTF-8`);
  }
  if (text.length === 0 || !text.endsWith('\n')) {
    throw new TypeError(`${label} must be non-empty and end in LF`);
  }
  if (text.includes('\r') || text.includes('\0')) {
    throw new TypeError(`${label} must use normalized LF text without NUL`);
  }
  return text;
}

function assignmentCount(text, name, valuePattern) {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const expression = new RegExp(
    `^${escapedName} = ${valuePattern}$`,
    'gmu',
  );
  return text.match(expression)?.length ?? 0;
}

function requireAssignment(text, name, valuePattern, label) {
  if (assignmentCount(text, name, valuePattern) !== 1) {
    throw new TypeError(
      `${label} must contain exactly one ${name} assignment with the locked value`,
    );
  }
}

export function validateEffectiveGnArgsText(text, architecture, label = 'effective GN args') {
  if (typeof text !== 'string') {
    throw new TypeError(`${label} must be text`);
  }
  const gnCpu = GN_CPU[architecture];
  if (!gnCpu) {
    throw new TypeError(`${label} has unsupported architecture ${String(architecture)}`);
  }
  requireAssignment(text, 'target_cpu', `"${gnCpu}"`, label);
  requireAssignment(text, 'is_official_build', 'true', label);
  requireAssignment(text, 'is_debug', 'false', label);
  requireAssignment(text, 'generate_about_credits', 'true', label);
  requireAssignment(text, 'use_official_google_api_keys', 'false', label);
  for (const name of [
    'google_api_key',
    'google_default_client_id',
    'google_default_client_secret',
  ]) {
    requireAssignment(text, name, '""', label);
  }
  if (/^(?:cc_wrapper = "(?!").*"|use_remoteexec = true|use_goma = true|disable_sandbox = true|use_sandbox = false)$/mu.test(text)) {
    throw new TypeError(`${label} enables an unlocked compiler, remote cache, or sandbox bypass`);
  }
  return Object.freeze({
    architecture,
    gnTargetCpu: gnCpu,
  });
}

function canonicalOutDir(value, label) {
  if (typeof value !== 'string'
      || !value.startsWith('out/')
      || value.includes('\\')
      || value.split('/').some((part) =>
        part === '' || part === '.' || part === '..')
      || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError(`${label} must be a canonical source-relative out/ path`);
  }
  return value;
}

function validateConfiguration(configuration, expectedArchitecture, index) {
  exactKeys(
    configuration,
    [
      'architecture',
      'outDir',
      'argsSha256',
      'argsSize',
      'argsText',
    ],
    `effective GN configuration ${index}`,
  );
  if (configuration.architecture !== expectedArchitecture) {
    throw new TypeError(
      `effective GN configuration ${index} must be ${expectedArchitecture}`,
    );
  }
  canonicalOutDir(
    configuration.outDir,
    `effective GN configuration ${index} outDir`,
  );
  if (!SHA256_RE.test(configuration.argsSha256)) {
    throw new TypeError(`effective GN configuration ${index} has invalid SHA-256`);
  }
  if (!Number.isSafeInteger(configuration.argsSize)
      || configuration.argsSize <= 0
      || configuration.argsSize > MAX_EFFECTIVE_ARGS_BYTES) {
    throw new TypeError(`effective GN configuration ${index} has invalid byte size`);
  }
  const bytes = Buffer.from(configuration.argsText, 'utf8');
  if (bytes.length !== configuration.argsSize
      || sha256(bytes) !== configuration.argsSha256) {
    throw new TypeError(`effective GN configuration ${index} text binding is wrong`);
  }
  const text = decodeNormalizedArgs(
    bytes,
    `effective GN configuration ${index}`,
  );
  validateEffectiveGnArgsText(
    text,
    expectedArchitecture,
    `effective GN configuration ${index}`,
  );
}

export function validateEffectiveGnArgsRecord(record, {
  platform,
} = {}) {
  exactKeys(
    record,
    ['schemaVersion', 'documentKind', 'platform', 'configurations'],
    'effective GN args record',
  );
  if (record.schemaVersion !== '1.0.0'
      || record.documentKind !== 'effective-gn-args') {
    throw new TypeError('unsupported effective GN args record');
  }
  if (record.platform !== platform || !M0_PLATFORM_IDS.includes(platform)) {
    throw new TypeError('effective GN args record platform mismatch');
  }
  const { buildContract } = readAndValidateM0BuildContract();
  const expected = buildContract.platforms[platform].architectures;
  if (!Array.isArray(record.configurations)
      || record.configurations.length !== expected.length) {
    throw new TypeError(
      `effective GN args must contain exactly ${expected.length} architecture configurations`,
    );
  }
  for (const [index, architecture] of expected.entries()) {
    validateConfiguration(record.configurations[index], architecture, index);
  }
  if (new Set(record.configurations.map(({ outDir }) => outDir)).size
      !== record.configurations.length) {
    throw new TypeError('effective GN configurations must use distinct output directories');
  }
  return Object.freeze({
    ok: true,
    platform,
    configurations: expected.length,
    sha256: sha256(Buffer.from(
      `${JSON.stringify(record, null, 2)}\n`,
      'utf8',
    )),
  });
}

export function createEffectiveGnArgsRecord({
  platform,
  configurations,
}) {
  if (!M0_PLATFORM_IDS.includes(platform)) {
    throw new TypeError(`unsupported M0 platform ${String(platform)}`);
  }
  const { buildContract } = readAndValidateM0BuildContract();
  const expected = buildContract.platforms[platform].architectures;
  if (!Array.isArray(configurations)
      || configurations.length !== expected.length) {
    throw new TypeError(
      `${platform} requires ${expected.length} effective GN configurations`,
    );
  }
  const records = [];
  for (const [index, architecture] of expected.entries()) {
    const input = configurations[index];
    exactKeys(
      input,
      ['architecture', 'outDir', 'argsPath'],
      `effective GN input ${index}`,
    );
    if (input.architecture !== architecture) {
      throw new TypeError(
        `effective GN input ${index} must be architecture ${architecture}`,
      );
    }
    const outDir = canonicalOutDir(
      input.outDir,
      `effective GN input ${index} outDir`,
    );
    const bytes = readStableBytes(
      resolve(input.argsPath),
      `effective GN input ${index} args`,
    );
    const argsText = decodeNormalizedArgs(
      bytes,
      `effective GN input ${index} args`,
    );
    validateEffectiveGnArgsText(
      argsText,
      architecture,
      `effective GN input ${index} args`,
    );
    records.push(Object.freeze({
      architecture,
      outDir,
      argsSha256: sha256(bytes),
      argsSize: bytes.length,
      argsText,
    }));
  }
  const record = Object.freeze({
    schemaVersion: '1.0.0',
    documentKind: 'effective-gn-args',
    platform,
    configurations: Object.freeze(records),
  });
  validateEffectiveGnArgsRecord(record, { platform });
  return record;
}

function parseArgs(args) {
  const result = {
    command: null,
    configurations: [],
    platform: null,
    record: null,
  };
  if (args[0] === 'create' || args[0] === 'verify') {
    [result.command] = args;
    args = args.slice(1);
  }
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (option === '--platform' || option === '--record') {
      const key = option === '--platform' ? 'platform' : 'record';
      if (result[key] !== null) throw new TypeError(`${option} supplied twice`);
      const value = args[index + 1];
      if (!value || value.startsWith('--')) {
        throw new TypeError(`${option} requires a value`);
      }
      result[key] = value;
      index += 1;
    } else if (option === '--configuration') {
      const values = args.slice(index + 1, index + 4);
      if (values.length !== 3 || values.some((value) =>
        !value || value.startsWith('--'))) {
        throw new TypeError(
          '--configuration requires <architecture> <out-dir> <args-file>',
        );
      }
      result.configurations.push({
        architecture: values[0],
        outDir: values[1],
        argsPath: values[2],
      });
      index += 3;
    } else {
      throw new TypeError(`unknown argument ${option}`);
    }
  }
  if (!result.command || !result.platform) {
    throw new TypeError(
      'usage: effective-gn-args.mjs <create|verify> --platform <id> '
      + '[--configuration <arch> <out-dir> <args-file> ... | --record <file>]',
    );
  }
  if (result.command === 'create'
      && (result.configurations.length === 0 || result.record)
      || result.command === 'verify'
      && (result.configurations.length !== 0 || !result.record)) {
    throw new TypeError(
      'create requires configurations; verify requires exactly one record',
    );
  }
  return result;
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.command === 'create') {
      const record = createEffectiveGnArgsRecord(args);
      writeSync(process.stdout.fd, `${JSON.stringify(record, null, 2)}\n`);
    } else {
      const record = parseStrictJson(
        readStableBytes(resolve(args.record), 'effective GN args record'),
        'effective GN args record',
      );
      const audit = validateEffectiveGnArgsRecord(record, {
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
