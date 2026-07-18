// Shared active/backlog patch-catalog parsing and active-series hashing.

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
} from 'node:fs';
import { join } from 'node:path';
import { TextDecoder } from 'node:util';
import { sanitizedGitEnvironment } from './git-env.mjs';

export const PATCH_SERIES_DEFINITIONS = Object.freeze([
  Object.freeze({
    id: 'active',
    file: 'series',
    kind: 'active',
    targetMilestone: 'M0',
  }),
  Object.freeze({
    id: 'm1-backlog',
    file: 'backlog/m1.series',
    kind: 'backlog',
    targetMilestone: 'M1',
  }),
  Object.freeze({
    id: 'm3-backlog',
    file: 'backlog/m3.series',
    kind: 'backlog',
    targetMilestone: 'M3',
  }),
]);

export const REQUIRED_PATCH_HEADERS = Object.freeze([
  '# Rationale:',
  '# Surface:',
  '# Upstream-risk:',
  '# Tests:',
  '# Target-milestone:',
  '# Status:',
]);

const PATCH_PATH_RE =
  /^layer[0-9]+-[a-z0-9-]+\/[0-9]{4}-[a-z0-9-]+\.patch$/u;
const ACTIVE_HASH_DOMAIN =
  Buffer.from('PROTEUS-ACTIVE-PATCH-SERIES\0v1\0', 'utf8');

export function parseSeriesText(raw, label) {
  if (typeof raw !== 'string') throw new TypeError(`${label} must be UTF-8 text`);
  const entries = [];
  const seen = new Set();
  const lines = raw.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line === '') continue;
    if (hasControlCharacter(line)) {
      throw new TypeError(`${label}:${index + 1}: control character is forbidden`);
    }
    if (line.startsWith('#')) continue;
    if (line.trim() !== line) {
      throw new TypeError(`${label}:${index + 1}: surrounding whitespace is forbidden`);
    }
    if (!PATCH_PATH_RE.test(line)) {
      throw new TypeError(`${label}:${index + 1}: invalid patch path ${line}`);
    }
    if (seen.has(line)) {
      throw new TypeError(`${label}:${index + 1}: duplicate patch ${line}`);
    }
    seen.add(line);
    entries.push(line);
  }
  return entries;
}

export function readSeriesFile(patchesRoot, definition) {
  const path = join(patchesRoot, definition.file);
  const bytes = readOrdinaryFile(path, `${definition.id} series`);
  return parseSeriesText(decodeUtf8(bytes, definition.file), definition.file);
}

export function readActivePatchSeries(patchesRoot) {
  return readSeriesFile(patchesRoot, PATCH_SERIES_DEFINITIONS[0]);
}

export function patchHasPayload(path) {
  try {
    execFileSync('git', ['apply', '--numstat', path], {
      env: sanitizedGitEnvironment(),
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    return true;
  } catch {
    return false;
  }
}

export function auditActivePatchSeries(patchesRoot, patchProfile) {
  const errors = [];
  let active = [];
  const definition = PATCH_SERIES_DEFINITIONS[0];
  try {
    active = readSeriesFile(patchesRoot, definition);
  } catch (error) {
    errors.push(error.message);
  }
  validateSeriesEntries(patchesRoot, { ...definition, entries: active }, errors);
  validateActiveProfile(active, patchProfile, errors);
  return { active, errors };
}

export function activePatchSeriesSha256(engineRoot, patchProfile) {
  const patchesRoot = join(engineRoot, 'patches');
  const audit = auditActivePatchSeries(patchesRoot, patchProfile);
  if (audit.errors.length > 0) {
    throw new TypeError(`invalid active patch series: ${audit.errors.join('; ')}`);
  }

  const hash = createHash('sha256');
  hash.update(ACTIVE_HASH_DOMAIN);
  hash.update(patchProfile, 'utf8');
  hash.update('\0');
  for (const entry of audit.active) {
    const bytes = readOrdinaryFile(
      join(patchesRoot, entry),
      `active patch ${entry}`,
    );
    hash.update(entry, 'utf8');
    hash.update('\0');
    hash.update(String(bytes.length), 'ascii');
    hash.update('\0');
    hash.update(bytes);
    hash.update('\0');
  }
  return hash.digest('hex');
}

export function auditPatchCatalog(patchesRoot, patchProfile) {
  const errors = [];
  const series = [];

  for (const definition of PATCH_SERIES_DEFINITIONS) {
    try {
      series.push({
        ...definition,
        entries: readSeriesFile(patchesRoot, definition),
      });
    } catch (error) {
      errors.push(error.message);
      series.push({ ...definition, entries: [] });
    }
  }

  const owners = new Map();
  for (const item of series) {
    for (const entry of item.entries) {
      if (owners.has(entry)) {
        errors.push(
          `${entry} is listed in both ${owners.get(entry)} and ${item.id}`,
        );
      } else {
        owners.set(entry, item.id);
      }
    }
    validateSeriesEntries(patchesRoot, item, errors);
  }

  const onDisk = listPatchFiles(patchesRoot, errors);
  for (const entry of onDisk) {
    if (!owners.has(entry)) errors.push(`${entry} exists but is not catalogued`);
  }

  const active = series.find(({ kind }) => kind === 'active')?.entries ?? [];
  validateActiveProfile(active, patchProfile, errors);

  return {
    active,
    backlog: series
      .filter(({ kind }) => kind === 'backlog')
      .flatMap(({ entries }) => entries),
    errors,
    onDisk,
    series,
  };
}

function validateSeriesEntries(patchesRoot, item, errors) {
  let previousSortKey = null;
  for (const entry of item.entries) {
    const sortKey = patchSortKey(entry);
    if (previousSortKey !== null && sortKey.localeCompare(previousSortKey) < 0) {
      errors.push(`${item.file} is out of layer/path order at ${entry}`);
    }
    previousSortKey = sortKey;

    const path = join(patchesRoot, entry);
    if (!existsSync(path)) {
      errors.push(`${item.file} lists ${entry}, but the patch does not exist`);
      continue;
    }

    let lines;
    try {
      lines = decodeUtf8(
        readOrdinaryFile(path, `patch ${entry}`),
        `patch ${entry}`,
      ).split(/\r?\n/);
    } catch (error) {
      errors.push(error.message);
      continue;
    }
    const diffStart = lines.findIndex((line) => line.startsWith('diff --git '));
    const hasPayload = patchHasPayload(path);
    if (hasPayload && diffStart === -1) {
      errors.push(
        `${entry} has a payload but is not a git-format patch beginning with "diff --git"`,
      );
    }
    const preamble = diffStart === -1 ? lines : lines.slice(0, diffStart);
    for (const header of REQUIRED_PATCH_HEADERS) {
      const count = preamble.filter((line) => line.startsWith(header)).length;
      if (count !== 1) {
        errors.push(
          `${entry} must contain ${header} exactly once before its first diff (found ${count})`,
        );
      }
    }

    const target = uniqueHeaderValue(preamble, '# Target-milestone:');
    if (target !== item.targetMilestone) {
      errors.push(
        `${entry} target milestone ${target || '(missing/ambiguous)'} does not match ${item.targetMilestone}`,
      );
    }
    const status = uniqueHeaderValue(preamble, '# Status:');
    if (item.kind === 'active') {
      const expectedStatus = hasPayload ? 'ACTIVE' : 'ACTIVE PLACEHOLDER';
      if (status !== expectedStatus) {
        errors.push(
          `${entry} must have exactly "# Status: ${expectedStatus}" for its payload state`,
        );
      }
      if (!entry.startsWith('layer0-')) {
        errors.push(`${entry} is not allowed in the M0 layer0 profile`);
      }
    } else if (status !== 'BACKLOG') {
      errors.push(`${entry} must have exactly "# Status: BACKLOG"`);
    }
  }
}

function validateActiveProfile(active, patchProfile, errors) {
  if (patchProfile !== 'm0-layer0-v1') {
    errors.push(`unsupported active patch profile ${patchProfile}`);
    return;
  }
  if (active.length === 0) {
    errors.push('PATCH_PROFILE=m0-layer0-v1 requires at least one active layer0 patch');
  }
}

function listPatchFiles(patchesRoot, errors) {
  const out = [];
  for (const layer of readdirSync(patchesRoot, { withFileTypes: true })) {
    if (!layer.name.startsWith('layer')) continue;
    if (!layer.isDirectory() || layer.isSymbolicLink()) {
      errors.push(`${layer.name} must be an ordinary layer directory`);
      continue;
    }
    for (const entry of readdirSync(join(patchesRoot, layer.name), {
      withFileTypes: true,
    })) {
      if (!entry.name.endsWith('.patch')) continue;
      const relative = `${layer.name}/${entry.name}`;
      if (!entry.isFile() || entry.isSymbolicLink()) {
        errors.push(`${relative} must be an ordinary non-symlink file`);
      }
      out.push(relative);
    }
  }
  return out.sort((left, right) => patchSortKey(left).localeCompare(patchSortKey(right)));
}

function patchSortKey(path) {
  const layer = path.match(/^layer([0-9]+)/u)?.[1] ?? '9999';
  return `${layer.padStart(8, '0')}/${path}`;
}

function uniqueHeaderValue(lines, prefix) {
  const matches = lines.filter((line) => line.startsWith(prefix));
  if (matches.length !== 1) return '';
  return matches[0].slice(prefix.length).trim();
}

function decodeUtf8(bytes, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new TypeError(`${label} must contain valid UTF-8`);
  }
}

function hasControlCharacter(value) {
  return value.includes('\r')
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value);
}

function readOrdinaryFile(path, label) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameStableFile(before, opened)) {
      throw new TypeError(`${label} changed while it was opened`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    if (!sameStableFile(opened, after) || !sameStableFile(after, pathAfter)) {
      throw new TypeError(`${label} changed or was rebound while it was read`);
    }
    return bytes;
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
