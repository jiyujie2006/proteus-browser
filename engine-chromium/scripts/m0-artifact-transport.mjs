#!/usr/bin/env node
// Hard-M0 artifact transport boundary.
//
// GitHub artifact ZIPs and the tar files inside them are untrusted until their
// API identity, byte digests, archive headers, and per-artifact path scope have
// all been checked. This module deliberately validates an entire tar before it
// creates the extraction directory, extracts into a fresh directory, compares
// the resulting filesystem with the validated headers, and only then permits a
// no-overwrite merge.

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  rmdirSync,
  statfsSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { posix } from 'node:path';
import { pathToFileURL } from 'node:url';

import { M0_PLATFORM_IDS } from './build-contract.mjs';
import { parseStrictJson } from '../../scripts/strict-json.mjs';

const BLOCK_BYTES = 512;
const GITHUB_API = 'https://api.github.com';
const GITHUB_API_VERSION = '2022-11-28';
const GITHUB_ACCEPT = 'application/vnd.github+json';
const SHA256_RE = /^[0-9a-f]{64}$/u;
const GITHUB_ID_RE = /^[1-9][0-9]{0,19}$/u;
const SAFE_ARTIFACT_NAME_RE = /^m0-(?:payload|metadata|index)-[A-Za-z0-9._-]{1,180}$/u;
const SAFE_MEMBER_COMPONENT_RE =
  /^(?![. ]*$)(?!.*[. ]$)(?!.*[\u0000-\u001f\u007f])[^/\\:]+$/u;
const WINDOWS_DEVICE_RE =
  /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const MAX_PAX_BYTES = 4 * 1024 * 1024;
const MAX_LONG_NAME_BYTES = 64 * 1024;
const MAX_TRAILING_ZERO_BYTES = 1024 * 1024;
const MAX_UNZIP_STDERR_BYTES = 1024 * 1024;
const DISK_RESERVE_BYTES = 1024n * 1024n * 1024n;

const PAYLOAD_RECORD_FILES = Object.freeze([
  'build-sbom.cdx.json',
  'bundle-manifest.json',
  'complete-toolchain-lock.json',
  'effective-gn-args.json',
  'live-report.json',
  'resolved-dependency-lock.json',
  'runtime-deps.txt',
]);
const METADATA_RECORD_FILES = Object.freeze([
  'attestations/build.sigstore.json',
  'attestations/provenance.sigstore.json',
  'attestations/sbom.sigstore.json',
  'build-predicate.json',
  'build-record-core.json',
  'build-record.json',
  'provenance-predicate.json',
]);
const OPTIONAL_RECORD_FILES = Object.freeze(['runner-receipt.json']);
const COMPLETE_RECORD_FILES = Object.freeze([
  ...PAYLOAD_RECORD_FILES,
  ...METADATA_RECORD_FILES,
]);

const LIMITS = Object.freeze({
  payload: Object.freeze({
    archiveBytes: 40n * 1024n * 1024n * 1024n,
    artifactBytes: 42n * 1024n * 1024n * 1024n,
    fileBytes: 16n * 1024n * 1024n * 1024n,
    members: 250_000,
    treeBytes: 34n * 1024n * 1024n * 1024n,
  }),
  metadata: Object.freeze({
    archiveBytes: 256n * 1024n * 1024n,
    artifactBytes: 300n * 1024n * 1024n,
    fileBytes: 64n * 1024n * 1024n,
    members: 256,
    treeBytes: 192n * 1024n * 1024n,
  }),
  index: Object.freeze({
    archiveBytes: 2n * 1024n * 1024n * 1024n,
    artifactBytes: 3n * 1024n * 1024n * 1024n,
    fileBytes: 64n * 1024n * 1024n,
    members: 4096,
    treeBytes: 1536n * 1024n * 1024n,
  }),
});

const UTF8 = new TextDecoder('utf-8', { fatal: true });

function exactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} has missing or unknown fields`);
  }
}

function githubId(value, label) {
  const text = typeof value === 'number' && Number.isSafeInteger(value)
    ? String(value)
    : value;
  if (typeof text !== 'string' || !GITHUB_ID_RE.test(text)) {
    throw new TypeError(`${label} must be a positive decimal GitHub ID`);
  }
  return text;
}

function safeInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`${label} must be a bounded positive safe integer`);
  }
  return value;
}

function artifactName(value, label = 'artifact name') {
  if (typeof value !== 'string'
      || !SAFE_ARTIFACT_NAME_RE.test(value)
      || value !== value.normalize('NFC')) {
    throw new TypeError(`${label} is unsafe`);
  }
  return value;
}

function sha256(value, label) {
  if (typeof value !== 'string' || !SHA256_RE.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function normalizedArtifactDigest(value, label = 'artifact digest') {
  if (typeof value !== 'string') {
    throw new TypeError(`${label} must be a SHA-256 digest`);
  }
  const normalized = value.startsWith('sha256:') ? value.slice(7) : value;
  return sha256(normalized, label);
}

function repositoryName(value) {
  if (typeof value !== 'string' || value.length > 150) {
    throw new TypeError('GitHub repository must be owner/name');
  }
  const parts = value.split('/');
  if (parts.length !== 2
      || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/u.test(parts[0])
      || !/^[A-Za-z0-9_.-]{1,100}$/u.test(parts[1])) {
    throw new TypeError('GitHub repository must be canonical owner/name');
  }
  return value;
}

function platformAndSlot(platform, slot) {
  if (!M0_PLATFORM_IDS.includes(platform)) {
    throw new TypeError(`unsupported M0 platform ${String(platform)}`);
  }
  if (!['A', 'B'].includes(slot)) {
    throw new TypeError(`M0 slot must be A or B, got ${String(slot)}`);
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

function stableFileDigest(path, label, maximum) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  if (before.size < 1n || before.size > maximum) {
    throw new TypeError(`${label} has an unsafe size`);
  }
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameStableFile(before, opened)) {
      throw new TypeError(`${label} changed while opened`);
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const count = readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
    }
    const after = fstatSync(fd, { bigint: true });
    const rebound = lstatSync(path, { bigint: true });
    if (!sameStableFile(opened, after) || !sameStableFile(after, rebound)) {
      throw new TypeError(`${label} changed while read`);
    }
    return {
      sha256: hash.digest('hex'),
      size: Number(opened.size),
    };
  } finally {
    closeSync(fd);
  }
}

function readStableJson(path, label, maximum = MAX_JSON_BYTES) {
  const snapshot = stableFileDigest(path, label, BigInt(maximum));
  if (snapshot.size > maximum) {
    throw new TypeError(`${label} exceeds ${maximum} bytes`);
  }
  return parseStrictJson(readFileSync(path), label);
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function writeFreshJson(path, value, label) {
  const destination = resolve(path);
  const parent = dirname(destination);
  if (realpathSync(parent) !== parent) {
    throw new TypeError(`${label} parent must be canonical`);
  }
  writeFileSync(destination, canonicalJson(value), {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
}

function safeNativeRoot(path, label) {
  const resolved = resolve(path);
  const stat = lstatSync(resolved, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary directory`);
  }
  if (realpathSync(resolved) !== resolved) {
    throw new TypeError(`${label} must already be canonical`);
  }
  return resolved;
}

function assertContained(root, candidate, label) {
  const rel = relative(root, candidate);
  if (rel === ''
      || (rel !== '..'
        && !rel.startsWith(`..${sep}`)
        && !isAbsolute(rel))) {
    return;
  }
  throw new TypeError(`${label} escapes its controlled root`);
}

function decodeField(block, offset, length, label) {
  const field = block.subarray(offset, offset + length);
  const nul = field.indexOf(0);
  const bytes = nul < 0 ? field : field.subarray(0, nul);
  if (nul >= 0
      && field.subarray(nul + 1).some((byte) => byte !== 0 && byte !== 0x20)) {
    throw new TypeError(`${label} has non-padding bytes after NUL`);
  }
  try {
    return UTF8.decode(bytes);
  } catch {
    throw new TypeError(`${label} is not valid UTF-8`);
  }
}

function parseTarNumber(field, label) {
  if ((field[0] & 0x80) !== 0) {
    if ((field[0] & 0x40) !== 0) {
      throw new TypeError(`${label} may not be negative`);
    }
    let value = BigInt(field[0] & 0x7f);
    for (let index = 1; index < field.length; index += 1) {
      value = (value << 8n) | BigInt(field[index]);
    }
    return value;
  }
  const text = Buffer.from(field)
    .toString('ascii')
    .replace(/\0.*$/u, '')
    .trim();
  if (text === '') return 0n;
  if (!/^[0-7]+$/u.test(text)) {
    throw new TypeError(`${label} is not an octal tar number`);
  }
  return BigInt(`0o${text}`);
}

function tarChecksum(block) {
  const expected = parseTarNumber(
    block.subarray(148, 156),
    'tar header checksum',
  );
  let unsigned = 0n;
  let signed = 0n;
  for (let index = 0; index < block.length; index += 1) {
    const byte = index >= 148 && index < 156 ? 0x20 : block[index];
    unsigned += BigInt(byte);
    signed += BigInt(byte > 0x7f ? byte - 0x100 : byte);
  }
  if (expected !== unsigned && expected !== signed) {
    throw new TypeError('tar header checksum is invalid');
  }
}

function allZero(bytes) {
  return bytes.every((byte) => byte === 0);
}

function readAt(fd, position, length, label) {
  const bytes = Buffer.allocUnsafe(length);
  let offset = 0;
  while (offset < length) {
    const count = readSync(fd, bytes, offset, length - offset, position + offset);
    if (count === 0) throw new TypeError(`${label} is truncated`);
    offset += count;
  }
  return bytes;
}

function paddedSize(size) {
  return ((size + 511n) / 512n) * 512n;
}

function paxRecords(bytes, label) {
  const records = new Map();
  let offset = 0;
  while (offset < bytes.length) {
    const space = bytes.indexOf(0x20, offset);
    if (space < 0) throw new TypeError(`${label} has a malformed PAX length`);
    const lengthText = bytes.subarray(offset, space).toString('ascii');
    if (!/^[1-9][0-9]{1,9}$/u.test(lengthText)) {
      throw new TypeError(`${label} has a non-canonical PAX length`);
    }
    const length = Number(lengthText);
    if (!Number.isSafeInteger(length)
        || length <= space - offset + 2
        || offset + length > bytes.length
        || bytes[offset + length - 1] !== 0x0a) {
      throw new TypeError(`${label} has an invalid PAX record boundary`);
    }
    const record = bytes.subarray(space + 1, offset + length - 1);
    const equals = record.indexOf(0x3d);
    if (equals <= 0) throw new TypeError(`${label} has a malformed PAX record`);
    const key = record.subarray(0, equals).toString('ascii');
    if (!/^[A-Za-z0-9_.-]{1,128}$/u.test(key) || records.has(key)) {
      throw new TypeError(`${label} has an unsafe or duplicate PAX key`);
    }
    const lower = key.toLowerCase();
    if (lower.includes('sparse')
        || lower.includes('realsize')
        || lower.includes('filetype')) {
      throw new TypeError(`${label} requests an unsupported sparse or special file`);
    }
    let value;
    try {
      value = UTF8.decode(record.subarray(equals + 1));
    } catch {
      throw new TypeError(`${label} has a non-UTF-8 PAX value`);
    }
    records.set(key, value);
    offset += length;
  }
  return records;
}

function longName(bytes, label) {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end -= 1;
  if (end === 0) throw new TypeError(`${label} is empty`);
  try {
    return UTF8.decode(bytes.subarray(0, end));
  } catch {
    throw new TypeError(`${label} is not valid UTF-8`);
  }
}

function canonicalArchivePath(raw, type, label) {
  if (typeof raw !== 'string'
      || raw.length === 0
      || raw.length > 4096
      || raw !== raw.normalize('NFC')
      || raw.startsWith('/')
      || raw.startsWith('\\')
      || raw.includes('\\')
      || /[\u0000-\u001f\u007f]/u.test(raw)) {
    throw new TypeError(`${label} has an unsafe path`);
  }
  let path = raw;
  if (type === 'directory') {
    path = path.replace(/\/+$/u, '');
  } else if (path.endsWith('/')) {
    throw new TypeError(`${label} has a directory alias for a non-directory`);
  }
  const parts = path.split('/');
  if (path.length === 0
      || parts.some((part) =>
        part === ''
        || part === '.'
        || part === '..'
        || part.length > 255
        || !SAFE_MEMBER_COMPONENT_RE.test(part)
        || WINDOWS_DEVICE_RE.test(part))) {
    throw new TypeError(`${label} is not a canonical portable path`);
  }
  return path;
}

function canonicalSymlinkTarget(memberPath, target, scopeRoot) {
  if (typeof target !== 'string'
      || target.length === 0
      || target.length > 4096
      || target !== target.normalize('NFC')
      || target.startsWith('/')
      || target.startsWith('\\')
      || target.includes('\\')
      || target.includes(':')
      || /[\u0000-\u001f\u007f]/u.test(target)) {
    throw new TypeError(`tar symlink ${memberPath} has an unsafe target`);
  }
  const resolved = posix.normalize(posix.join(posix.dirname(memberPath), target));
  if (resolved !== scopeRoot && !resolved.startsWith(`${scopeRoot}/`)) {
    throw new TypeError(`tar symlink ${memberPath} escapes its payload bundle`);
  }
  return target;
}

function tarHeader(block) {
  tarChecksum(block);
  const name = decodeField(block, 0, 100, 'tar member name');
  const prefix = decodeField(block, 345, 155, 'tar member prefix');
  const path = prefix ? `${prefix}/${name}` : name;
  const link = decodeField(block, 157, 100, 'tar member link target');
  const typeByte = block[156];
  return {
    link,
    path,
    size: parseTarNumber(block.subarray(124, 136), 'tar member size'),
    type: typeByte === 0 ? '0' : String.fromCharCode(typeByte),
  };
}

function expectedPayloadName(platform, slot, runAttempt) {
  platformAndSlot(platform, slot);
  const attempt = safeInteger(runAttempt, 'workflow run attempt', 999_999_999);
  return `m0-payload-${platform}-${slot}-attempt-${attempt}`;
}

function kindLimits(kind) {
  if (!Object.hasOwn(LIMITS, kind)) {
    throw new TypeError(`unsupported M0 transport kind ${String(kind)}`);
  }
  return LIMITS[kind];
}

function memberType(type) {
  if (type === '0') return 'file';
  if (type === '5') return 'directory';
  if (type === '2') return 'symlink';
  if (type === '1') {
    throw new TypeError('tar hard links are forbidden');
  }
  throw new TypeError(`tar member type ${JSON.stringify(type)} is forbidden`);
}

function assertMemberScope(path, type, { kind, platform, slot }) {
  if (kind === 'payload') {
    platformAndSlot(platform, slot);
    const root = `builds/${platform}/${slot}`;
    if (path !== root && !path.startsWith(`${root}/`)) {
      throw new TypeError(`${kind} tar member is outside ${root}`);
    }
    if (type === 'symlink'
        && !path.startsWith(`${root}/bundle/`)) {
      throw new TypeError('payload symlinks are allowed only inside bundle');
    }
    return;
  }
  if (kind === 'metadata') {
    platformAndSlot(platform, slot);
    const root = `builds/${platform}/${slot}/records`;
    if (path !== root && !path.startsWith(`${root}/`)) {
      throw new TypeError(`${kind} tar member is outside ${root}`);
    }
    if (type === 'symlink') {
      throw new TypeError('metadata tar may not contain symlinks');
    }
    return;
  }
  if (kind === 'index') {
    if (path === 'm0-build-evidence-v2.json') return;
    const parts = path.split('/');
    if (parts[0] !== 'builds'
        || !M0_PLATFORM_IDS.includes(parts[1])
        || !['A', 'B'].includes(parts[2])
        || parts[3] !== 'records') {
      throw new TypeError('index tar member is outside the canonical record roots');
    }
    if (type === 'symlink') {
      throw new TypeError('index tar may not contain symlinks');
    }
    return;
  }
  throw new TypeError(`unsupported M0 transport kind ${String(kind)}`);
}

function expectedDirectories(members) {
  const entries = new Map();
  for (const member of members.values()) {
    const parts = member.path.split('/');
    for (let count = 1; count < parts.length; count += 1) {
      const parent = parts.slice(0, count).join('/');
      const existing = entries.get(parent);
      if (existing && existing.type !== 'directory') {
        throw new TypeError(`tar member traverses non-directory ${parent}`);
      }
      if (!existing) entries.set(parent, { path: parent, type: 'directory' });
    }
    const existing = entries.get(member.path);
    if (existing && existing.type !== member.type) {
      throw new TypeError(`tar member conflicts with implicit directory ${member.path}`);
    }
    entries.set(member.path, member);
  }
  for (const member of entries.values()) {
    if (member.type !== 'symlink') continue;
    for (const candidate of entries.keys()) {
      if (candidate.startsWith(`${member.path}/`)) {
        throw new TypeError(`tar member traverses symlink ${member.path}`);
      }
    }
  }
  return entries;
}

function relativeRecordFiles(members, recordRoot) {
  return [...members.values()]
    .filter((member) =>
      member.type === 'file' && member.path.startsWith(`${recordRoot}/`))
    .map((member) => member.path.slice(recordRoot.length + 1))
    .sort();
}

function exactStringSet(actual, expected, label, optional = []) {
  const actualSet = new Set(actual);
  const allowed = new Set([...expected, ...optional]);
  if (actual.length !== actualSet.size
      || expected.some((name) => !actualSet.has(name))
      || actual.some((name) => !allowed.has(name))) {
    throw new TypeError(`${label} has missing or unexpected files`);
  }
}

function validateScopeContents(members, { kind, platform, slot }) {
  if (kind === 'payload') {
    const root = `builds/${platform}/${slot}`;
    const bundleRoot = `${root}/bundle`;
    const recordsRoot = `${root}/records`;
    if (![...members.keys()].some((path) => path.startsWith(`${bundleRoot}/`))) {
      throw new TypeError('payload bundle is empty');
    }
    exactStringSet(
      relativeRecordFiles(members, recordsRoot),
      PAYLOAD_RECORD_FILES,
      'payload records',
    );
    return;
  }
  if (kind === 'metadata') {
    const root = `builds/${platform}/${slot}/records`;
    exactStringSet(
      relativeRecordFiles(members, root),
      METADATA_RECORD_FILES,
      'metadata records',
    );
    return;
  }
  if (kind === 'index') {
    const rootFile = members.get('m0-build-evidence-v2.json');
    if (!rootFile || rootFile.type !== 'file') {
      throw new TypeError('index tar is missing m0-build-evidence-v2.json');
    }
    for (const expectedPlatform of M0_PLATFORM_IDS) {
      for (const expectedSlot of ['A', 'B']) {
        const root = `builds/${expectedPlatform}/${expectedSlot}/records`;
        exactStringSet(
          relativeRecordFiles(members, root),
          COMPLETE_RECORD_FILES,
          `${expectedPlatform}/${expectedSlot} index records`,
          OPTIONAL_RECORD_FILES,
        );
      }
    }
  }
}

function parseTarArchive(archive, scope) {
  const limits = kindLimits(scope.kind);
  const resolved = resolve(archive);
  const before = lstatSync(resolved, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()
      || before.size < 1024n || before.size > limits.archiveBytes) {
    throw new TypeError(`${scope.kind} tar is not a bounded ordinary file`);
  }
  const fd = openSync(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  const members = new Map();
  let fileBytes = 0n;
  let position = 0n;
  let terminated = false;
  let localPax = null;
  let globalPax = new Map();
  let pendingLongName = null;
  let pendingLongLink = null;
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameStableFile(before, opened)) {
      throw new TypeError(`${scope.kind} tar changed while opened`);
    }
    while (position + 512n <= opened.size) {
      const block = readAt(
        fd,
        Number(position),
        BLOCK_BYTES,
        `${scope.kind} tar header`,
      );
      position += 512n;
      if (allZero(block)) {
        if (position + 512n > opened.size
            || !allZero(readAt(
              fd,
              Number(position),
              BLOCK_BYTES,
              `${scope.kind} tar terminator`,
            ))) {
          throw new TypeError(`${scope.kind} tar lacks two zero terminator blocks`);
        }
        position += 512n;
        terminated = true;
        break;
      }
      const header = tarHeader(block);
      if (header.size > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new TypeError('tar member size is not safely addressable');
      }
      const extension = ['x', 'g', 'L', 'K'].includes(header.type);
      let preliminaryType = null;
      if (!extension) {
        preliminaryType = memberType(header.type);
        if (preliminaryType === 'file' && header.size > limits.fileBytes) {
          throw new TypeError('tar member exceeds its file-size budget');
        }
        if (preliminaryType !== 'file' && header.size !== 0n) {
          throw new TypeError(`tar ${preliminaryType} member has non-zero data`);
        }
      }
      const dataEnd = position + paddedSize(header.size);
      if (dataEnd > opened.size) {
        throw new TypeError(`${scope.kind} tar member is truncated`);
      }

      if (extension) {
        const maximum = ['L', 'K'].includes(header.type)
          ? MAX_LONG_NAME_BYTES
          : MAX_PAX_BYTES;
        if (header.size < 1n || header.size > BigInt(maximum)) {
          throw new TypeError('tar extension header has an unsafe size');
        }
        const payload = readAt(
          fd,
          Number(position),
          Number(header.size),
          'tar extension payload',
        );
        if (header.type === 'x') {
          if (localPax !== null) {
            throw new TypeError('tar has stacked local PAX headers');
          }
          localPax = paxRecords(payload, 'local PAX header');
        } else if (header.type === 'g') {
          const next = paxRecords(payload, 'global PAX header');
          if (next.has('path') || next.has('linkpath') || next.has('size')) {
            throw new TypeError('global PAX header may not redefine member identity');
          }
          globalPax = new Map([...globalPax, ...next]);
        } else if (header.type === 'L') {
          if (pendingLongName !== null) {
            throw new TypeError('tar has stacked GNU long-name headers');
          }
          pendingLongName = longName(payload, 'GNU long member name');
        } else {
          if (pendingLongLink !== null) {
            throw new TypeError('tar has stacked GNU long-link headers');
          }
          pendingLongLink = longName(payload, 'GNU long link target');
        }
        position = dataEnd;
        continue;
      }

      const pathOverrides = [
        localPax?.get('path'),
        pendingLongName,
      ].filter((value) => value !== undefined && value !== null);
      if (pathOverrides.length > 1) {
        throw new TypeError('tar member has ambiguous path extensions');
      }
      const linkOverrides = [
        localPax?.get('linkpath'),
        pendingLongLink,
      ].filter((value) => value !== undefined && value !== null);
      if (linkOverrides.length > 1) {
        throw new TypeError('tar member has ambiguous link extensions');
      }
      const paxSize = localPax?.get('size');
      if (paxSize !== undefined) {
        if (!/^(?:0|[1-9][0-9]{0,19})$/u.test(paxSize)
            || BigInt(paxSize) !== header.size) {
          throw new TypeError('PAX size must exactly match the physical tar member');
        }
      }
      for (const [key] of [...globalPax, ...(localPax ?? [])]) {
        const lower = key.toLowerCase();
        if (lower.includes('sparse')
            || lower.includes('realsize')
            || lower.includes('filetype')) {
          throw new TypeError('tar PAX metadata requests an unsafe file representation');
        }
      }

      const type = preliminaryType;
      const path = canonicalArchivePath(
        pathOverrides[0] ?? header.path,
        type,
        'tar member',
      );
      assertMemberScope(path, type, scope);
      if (members.has(path)) {
        throw new TypeError(`tar repeats or aliases member ${path}`);
      }
      if (type === 'file') {
        fileBytes += header.size;
        if (fileBytes > limits.treeBytes) {
          throw new TypeError(`${scope.kind} tar exceeds its expanded byte budget`);
        }
      }
      const member = {
        path,
        size: header.size,
        type,
      };
      if (type === 'symlink') {
        const bundleRoot = `builds/${scope.platform}/${scope.slot}/bundle`;
        member.target = canonicalSymlinkTarget(
          path,
          linkOverrides[0] ?? header.link,
          bundleRoot,
        );
      } else if (linkOverrides.length > 0 || header.link !== '') {
        throw new TypeError(`non-link tar member ${path} has a link target`);
      }
      members.set(path, member);
      if (members.size > limits.members) {
        throw new TypeError(`${scope.kind} tar exceeds its member budget`);
      }
      localPax = null;
      pendingLongName = null;
      pendingLongLink = null;
      position = dataEnd;
    }
    if (!terminated) throw new TypeError(`${scope.kind} tar has no terminator`);
    if (localPax !== null || pendingLongName !== null || pendingLongLink !== null) {
      throw new TypeError(`${scope.kind} tar ends with an unbound extension header`);
    }
    const trailing = opened.size - position;
    if (trailing > BigInt(MAX_TRAILING_ZERO_BYTES)) {
      throw new TypeError(`${scope.kind} tar has excessive trailing data`);
    }
    if (trailing > 0n
        && !allZero(readAt(
          fd,
          Number(position),
          Number(trailing),
          `${scope.kind} tar trailing padding`,
        ))) {
      throw new TypeError(`${scope.kind} tar has non-zero trailing data`);
    }
    const after = fstatSync(fd, { bigint: true });
    const rebound = lstatSync(resolved, { bigint: true });
    if (!sameStableFile(opened, after) || !sameStableFile(after, rebound)) {
      throw new TypeError(`${scope.kind} tar changed during preflight`);
    }
  } finally {
    closeSync(fd);
  }
  if (members.size === 0) throw new TypeError(`${scope.kind} tar is empty`);
  expectedDirectories(members);
  validateScopeContents(members, scope);
  return {
    archive: resolved,
    archiveBytes: before.size,
    entries: expectedDirectories(members),
    fileBytes,
    members,
  };
}

export function preflightM0Tar(archive, scope) {
  const parsed = parseTarArchive(archive, scope);
  return {
    ok: true,
    archiveBytes: parsed.archiveBytes.toString(),
    fileBytes: parsed.fileBytes.toString(),
    kind: scope.kind,
    members: parsed.members.size,
  };
}

function availableBytes(path) {
  const stats = statfsSync(path, { bigint: true });
  return stats.bavail * stats.bsize;
}

function exactExtractedTree(destination, parsed) {
  const root = safeNativeRoot(destination, 'fresh extraction root');
  const actual = new Map();
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      const rel = relative(root, path).split(sep).join('/');
      const canonical = canonicalArchivePath(
        rel,
        lstatSync(path).isDirectory() ? 'directory' : 'file',
        'extracted member',
      );
      if (canonical !== rel) {
        throw new TypeError('extracted tree contains a non-canonical path');
      }
      const stat = lstatSync(path, { bigint: true });
      let type;
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        type = 'directory';
        pending.push(path);
      } else if (stat.isFile() && !stat.isSymbolicLink()) {
        type = 'file';
        if (stat.nlink !== 1n) {
          throw new TypeError(`extracted file ${rel} is hard-linked`);
        }
      } else if (stat.isSymbolicLink()) {
        type = 'symlink';
      } else {
        throw new TypeError(`extracted member ${rel} is special`);
      }
      actual.set(rel, { path, stat, type });
    }
  }
  if (actual.size !== parsed.entries.size) {
    throw new TypeError('extracted tree differs from preflighted tar headers');
  }
  for (const [path, expected] of parsed.entries) {
    const item = actual.get(path);
    if (!item || item.type !== expected.type) {
      throw new TypeError(`extracted member ${path} has an unexpected type`);
    }
    if (item.type === 'file' && item.stat.size !== expected.size) {
      throw new TypeError(`extracted member ${path} has an unexpected size`);
    }
    if (item.type === 'symlink'
        && readlinkSync(item.path, 'utf8') !== expected.target) {
      throw new TypeError(`extracted symlink ${path} changed target`);
    }
  }
}

export function extractM0Tar({
  archive,
  destination,
  kind,
  platform,
  slot,
  tarPath = '/usr/bin/tar',
}) {
  const scope = { kind, platform, slot };
  const parsed = parseTarArchive(archive, scope);
  const destinationPath = resolve(destination);
  if (existsSync(destinationPath)) {
    throw new TypeError('tar extraction destination must not exist');
  }
  const parent = safeNativeRoot(dirname(destinationPath), 'extraction parent');
  assertContained(parent, destinationPath, 'extraction destination');
  const required = parsed.fileBytes + parsed.archiveBytes + DISK_RESERVE_BYTES;
  if (availableBytes(parent) < required) {
    throw new TypeError('insufficient free disk for bounded tar extraction');
  }
  mkdirSync(destinationPath, { mode: 0o700 });
  try {
    const result = spawnSync(tarPath, [
      '--extract',
      '--file',
      parsed.archive,
      '--directory',
      destinationPath,
      '--no-same-owner',
      '--no-same-permissions',
      '--no-acls',
      '--no-xattrs',
      '--no-selinux',
      '--delay-directory-restore',
    ], {
      stdio: ['ignore', 'inherit', 'inherit'],
      windowsHide: true,
    });
    if (result.error && result.status === null) throw result.error;
    if (result.status !== 0) {
      throw new TypeError(`tar extraction failed with status ${result.status}`);
    }
    exactExtractedTree(destinationPath, parsed);
    return {
      ok: true,
      destination: destinationPath,
      fileBytes: parsed.fileBytes.toString(),
      members: parsed.members.size,
    };
  } catch (error) {
    rmSync(destinationPath, { force: true, recursive: true });
    throw error;
  }
}

function safeMergeEntryName(name) {
  if (canonicalArchivePath(name, 'file', 'merge entry') !== name
      || name.includes('/')) {
    throw new TypeError('merge entry must be one canonical path component');
  }
  return name;
}

function mergeEntry(source, destination) {
  const sourceStat = lstatSync(source, { bigint: true });
  if ((sourceStat.mode & 0o6000n) !== 0n) {
    throw new TypeError('merge source contains set-id permission bits');
  }
  if (!existsSync(destination)) {
    renameSync(source, destination);
    return;
  }
  const destinationStat = lstatSync(destination, { bigint: true });
  if (!sourceStat.isDirectory()
      || sourceStat.isSymbolicLink()
      || !destinationStat.isDirectory()
      || destinationStat.isSymbolicLink()) {
    throw new TypeError(`no-overwrite merge collision at ${destination}`);
  }
  for (const name of readdirSync(source)) {
    safeMergeEntryName(name);
    mergeEntry(join(source, name), join(destination, name));
  }
  rmdirSync(source);
}

export function mergeM0Tree({
  source,
  destination,
  entry = null,
}) {
  const sourceRoot = safeNativeRoot(source, 'merge source');
  const destinationRoot = safeNativeRoot(destination, 'merge destination');
  if (sourceRoot === destinationRoot) {
    throw new TypeError('merge source and destination must be distinct');
  }
  if (entry !== null) {
    const name = safeMergeEntryName(entry);
    const sourceEntry = join(sourceRoot, name);
    if (!existsSync(sourceEntry)) {
      throw new TypeError(`merge source lacks requested entry ${name}`);
    }
    mergeEntry(sourceEntry, join(destinationRoot, name));
    return { ok: true, entries: 1 };
  }
  const names = readdirSync(sourceRoot);
  for (const name of names) safeMergeEntryName(name);
  for (const name of names) {
    mergeEntry(join(sourceRoot, name), join(destinationRoot, name));
  }
  return { ok: true, entries: names.length };
}

export function validateArtifactApiDocument(document, {
  artifactId,
  runId,
  name,
  digest = null,
  size = null,
  runScoped = false,
} = {}) {
  if (!document || typeof document !== 'object' || Array.isArray(document)
      || (document.workflow_run !== undefined
        && document.workflow_run !== null
        && (typeof document.workflow_run !== 'object'
          || Array.isArray(document.workflow_run)))) {
    throw new TypeError('GitHub artifact API response is incomplete');
  }
  const expectedRunId = runId === undefined
    ? null
    : githubId(runId, 'expected workflow run id');
  let responseRunId = null;
  if (document.workflow_run !== undefined && document.workflow_run !== null) {
    responseRunId = githubId(
      document.workflow_run.id,
      'artifact API workflow run id',
    );
  } else if (expectedRunId !== null && !runScoped) {
    throw new TypeError(
      'artifact API response lacks a workflow run outside a run-scoped query',
    );
  }
  const actual = {
    artifactId: githubId(document.id, 'artifact API id'),
    artifactName: artifactName(document.name, 'artifact API name'),
    artifactDigest: normalizedArtifactDigest(
      document.digest,
      'artifact API digest',
    ),
    artifactSize: safeInteger(
      document.size_in_bytes,
      'artifact API size',
      Number(LIMITS.payload.artifactBytes),
    ),
    workflowRunId: responseRunId ?? expectedRunId,
  };
  if (document.expired !== false) {
    throw new TypeError('GitHub artifact is expired');
  }
  if (artifactId !== undefined
      && actual.artifactId !== githubId(artifactId, 'expected artifact id')) {
    throw new TypeError('GitHub artifact ID does not match');
  }
  if (expectedRunId !== null
      && actual.workflowRunId !== expectedRunId) {
    throw new TypeError('GitHub artifact workflow run does not match');
  }
  if (name !== undefined
      && actual.artifactName !== artifactName(name, 'expected artifact name')) {
    throw new TypeError('GitHub artifact name does not match');
  }
  if (digest !== null
      && actual.artifactDigest
        !== normalizedArtifactDigest(digest, 'expected artifact digest')) {
    throw new TypeError('GitHub artifact digest does not match');
  }
  if (size !== null
      && actual.artifactSize !== safeInteger(
        size,
        'expected artifact size',
        Number(LIMITS.payload.artifactBytes),
      )) {
    throw new TypeError('GitHub artifact size does not match');
  }
  return actual;
}

export function payloadBindingFromRecord(record, {
  platform,
  slot,
  runId,
} = {}) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new TypeError('build record must be an object');
  }
  platformAndSlot(platform, slot);
  const binding = {
    artifactId: githubId(record.artifactId, 'record artifactId'),
    artifactName: artifactName(record.artifactName, 'record artifactName'),
    artifactDigest: sha256(record.artifactDigest, 'record artifactDigest'),
    artifactSize: safeInteger(
      record.artifactSize,
      'record artifactSize',
      Number(LIMITS.payload.artifactBytes),
    ),
    artifactInnerSha256: sha256(
      record.artifactInnerSha256,
      'record artifactInnerSha256',
    ),
    artifactInnerSize: safeInteger(
      record.artifactInnerSize,
      'record artifactInnerSize',
      Number(LIMITS.payload.archiveBytes),
    ),
    runId: githubId(record.runId, 'record runId'),
    runAttempt: safeInteger(
      record.runAttempt,
      'record runAttempt',
      999_999_999,
    ),
  };
  if (binding.artifactName
      !== expectedPayloadName(platform, slot, binding.runAttempt)) {
    throw new TypeError('build record payload artifact name is wrong');
  }
  if (runId !== undefined
      && binding.runId !== githubId(runId, 'expected build run id')) {
    throw new TypeError('build record run ID does not match the download plan');
  }
  return binding;
}

function githubToken() {
  const token = process.env.GITHUB_TOKEN;
  if (typeof token !== 'string'
      || token.length < 1
      || token.length > 4096
      || /[\u0000-\u001f\u007f]/u.test(token)) {
    throw new TypeError('GITHUB_TOKEN is missing or unsafe');
  }
  return token;
}

function githubHeaders() {
  return {
    Accept: GITHUB_ACCEPT,
    Authorization: `Bearer ${githubToken()}`,
    'User-Agent': 'proteus-m0-artifact-transport',
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
  };
}

async function githubJson(endpoint) {
  if (typeof endpoint !== 'string'
      || !endpoint.startsWith('/repos/')
      || endpoint.includes('\\')
      || /[\u0000-\u001f\u007f]/u.test(endpoint)) {
    throw new TypeError('GitHub API endpoint is unsafe');
  }
  const response = await fetch(`${GITHUB_API}${endpoint}`, {
    headers: githubHeaders(),
    method: 'GET',
    redirect: 'error',
  });
  if (!response.ok) {
    throw new TypeError(`GitHub API request failed with HTTP ${response.status}`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length < 2 || bytes.length > MAX_JSON_BYTES) {
    throw new TypeError('GitHub API response has an unsafe size');
  }
  return parseStrictJson(bytes, 'GitHub artifact API response');
}

async function getArtifact(repository, artifactId) {
  const repo = repositoryName(repository);
  const id = githubId(artifactId, 'artifact id');
  return githubJson(`/repos/${repo}/actions/artifacts/${id}`);
}

async function findNamedArtifact(repository, runId, name) {
  const repo = repositoryName(repository);
  const run = githubId(runId, 'workflow run id');
  const expectedName = artifactName(name);
  const document = await githubJson(
    `/repos/${repo}/actions/runs/${run}/artifacts`
    + `?name=${encodeURIComponent(expectedName)}&per_page=100`,
  );
  if (!document || typeof document !== 'object'
      || !Array.isArray(document.artifacts)
      || document.total_count !== 1
      || document.artifacts.length !== 1) {
    throw new TypeError('workflow run must contain exactly one named artifact');
  }
  const listed = validateArtifactApiDocument(document.artifacts[0], {
    runId: run,
    name: expectedName,
    runScoped: true,
  });
  const fetched = validateArtifactApiDocument(
    await getArtifact(repo, listed.artifactId),
    {
      artifactId: listed.artifactId,
      runId: run,
      name: expectedName,
      digest: listed.artifactDigest,
      size: listed.artifactSize,
      runScoped: true,
    },
  );
  return fetched;
}

async function findBoundArtifact(repository, {
  artifactId,
  artifactName: expectedName,
  artifactDigest,
  artifactSize = null,
  runId,
}) {
  const listed = await findNamedArtifact(repository, runId, expectedName);
  if (listed.artifactId !== artifactId
      || listed.artifactDigest !== artifactDigest
      || (artifactSize !== null && listed.artifactSize !== artifactSize)) {
    throw new TypeError('run-scoped artifact metadata does not match its binding');
  }
  return listed;
}

function zipMemberInfo(zipPath, innerName) {
  const expected = basename(innerName);
  if (expected !== innerName
      || !/^[A-Za-z0-9._-]{1,128}$/u.test(expected)) {
    throw new TypeError('artifact ZIP inner name is unsafe');
  }
  const names = spawnSync('/usr/bin/unzip', ['-Z1', zipPath], {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  if (names.error && names.status === null) throw names.error;
  if (names.status !== 0 || names.stdout !== `${expected}\n`) {
    throw new TypeError('artifact ZIP must contain exactly the expected tar file');
  }
  const listing = spawnSync('/usr/bin/unzip', ['-l', zipPath], {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  if (listing.error && listing.status === null) throw listing.error;
  if (listing.status !== 0) throw new TypeError('artifact ZIP listing failed');
  const matches = listing.stdout.split(/\r?\n/u)
    .map((line) => line.match(/^\s*([0-9]+)\s+\S+\s+\S+\s+(.+)$/u))
    .filter((match) => match && match[2] === expected);
  if (matches.length !== 1) {
    throw new TypeError('artifact ZIP has ambiguous inner size metadata');
  }
  const size = Number(matches[0][1]);
  safeInteger(size, 'artifact ZIP inner size', Number(LIMITS.payload.archiveBytes));
  return { name: expected, size };
}

function writeAllSync(fd, value) {
  let offset = 0;
  while (offset < value.byteLength) {
    const written = writeSync(
      fd,
      value,
      offset,
      value.byteLength - offset,
    );
    if (written <= 0) {
      throw new TypeError('artifact transport made no write progress');
    }
    offset += written;
  }
}

export function writeBoundedZipChunk(fd, value, state) {
  if (!state || typeof state !== 'object'
      || !Number.isSafeInteger(state.bytes)
      || state.bytes < 0
      || !Number.isSafeInteger(state.maximumBytes)
      || state.maximumBytes < 0
      || state.bytes > state.maximumBytes) {
    throw new TypeError('bounded ZIP writer state is invalid');
  }
  if (!(value instanceof Uint8Array)) {
    throw new TypeError('bounded ZIP writer requires a byte array');
  }
  if (value.byteLength > state.maximumBytes - state.bytes) {
    throw new TypeError('artifact ZIP inflated beyond its declared inner size');
  }
  writeAllSync(fd, value);
  state.bytes += value.byteLength;
}

async function downloadZip(repository, metadata, destination) {
  const repo = repositoryName(repository);
  const output = resolve(destination);
  if (existsSync(output)) throw new TypeError('artifact ZIP output already exists');
  const response = await fetch(
    `${GITHUB_API}/repos/${repo}/actions/artifacts/${metadata.artifactId}/zip`,
    {
      headers: githubHeaders(),
      method: 'GET',
      redirect: 'follow',
    },
  );
  if (!response.ok || !response.body) {
    throw new TypeError(`artifact download failed with HTTP ${response.status}`);
  }
  if (!response.url.startsWith('https://')) {
    throw new TypeError('artifact download redirected to a non-HTTPS URL');
  }
  const fd = openSync(output, 'wx', 0o600);
  const hash = createHash('sha256');
  let bytes = 0;
  try {
    const reader = response.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > metadata.artifactSize) {
        await reader.cancel();
        throw new TypeError('artifact download exceeds its API size');
      }
      hash.update(value);
      writeAllSync(fd, value);
    }
  } catch (error) {
    closeSync(fd);
    rmSync(output, { force: true });
    throw error;
  }
  closeSync(fd);
  if (bytes !== metadata.artifactSize
      || hash.digest('hex') !== metadata.artifactDigest) {
    rmSync(output, { force: true });
    throw new TypeError('downloaded artifact bytes do not match GitHub API metadata');
  }
}

function inflateZipMember(zipPath, memberName, fd, maximumBytes) {
  return new Promise((resolveInflation, rejectInflation) => {
    const child = spawn(
      '/usr/bin/unzip',
      ['-p', zipPath, memberName],
      {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      },
    );
    const state = { bytes: 0, maximumBytes };
    let failure = null;
    let stderrBytes = 0;
    const fail = (error) => {
      if (!failure) failure = error;
      child.stdout?.destroy();
      child.stderr?.destroy();
      child.kill('SIGKILL');
    };
    child.stdout.on('data', (chunk) => {
      if (failure) return;
      try {
        writeBoundedZipChunk(fd, chunk, state);
      } catch (error) {
        fail(error);
      }
    });
    child.stdout.on('error', fail);
    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.byteLength;
      if (stderrBytes > MAX_UNZIP_STDERR_BYTES) {
        fail(new TypeError('artifact ZIP extraction emitted excessive diagnostics'));
      }
    });
    child.stderr.on('error', fail);
    child.on('error', fail);
    child.on('close', (status, signal) => {
      if (failure) {
        rejectInflation(failure);
      } else if (status !== 0) {
        rejectInflation(new TypeError(
          `artifact ZIP extraction failed with ${signal ?? `status ${status}`}`,
        ));
      } else {
        resolveInflation(state.bytes);
      }
    });
  });
}

export async function extractZipInner(zipPath, innerName, output, {
  expectedSha256 = null,
  expectedSize = null,
  maximumSize,
}) {
  const info = zipMemberInfo(zipPath, innerName);
  if (BigInt(info.size) > maximumSize
      || (expectedSize !== null && info.size !== expectedSize)) {
    throw new TypeError('artifact ZIP inner tar has an unexpected size');
  }
  const destination = resolve(output);
  if (existsSync(destination)) {
    throw new TypeError('inner tar output already exists');
  }
  const parent = safeNativeRoot(dirname(destination), 'inner tar parent');
  if (availableBytes(parent)
      < BigInt(info.size) + DISK_RESERVE_BYTES) {
    throw new TypeError('insufficient free disk for artifact inner tar');
  }
  const fd = openSync(destination, 'wx', 0o600);
  try {
    await inflateZipMember(zipPath, info.name, fd, info.size);
  } catch (error) {
    closeSync(fd);
    rmSync(destination, { force: true });
    throw error;
  }
  closeSync(fd);
  let snapshot;
  try {
    snapshot = stableFileDigest(
      destination,
      'artifact inner tar',
      maximumSize,
    );
  } catch (error) {
    rmSync(destination, { force: true });
    throw error;
  }
  if (snapshot.size !== info.size
      || (expectedSize !== null && snapshot.size !== expectedSize)
      || (expectedSha256 !== null && snapshot.sha256 !== expectedSha256)) {
    rmSync(destination, { force: true });
    throw new TypeError('artifact inner tar does not match its signed binding');
  }
  return snapshot;
}

async function downloadArtifactInner({
  repository,
  metadata,
  innerName,
  output,
  kind,
  expectedInnerSha256 = null,
  expectedInnerSize = null,
}) {
  const limits = kindLimits(kind);
  if (BigInt(metadata.artifactSize) > limits.artifactBytes) {
    throw new TypeError(`${kind} GitHub artifact exceeds its size budget`);
  }
  const zip = `${resolve(output)}.artifact.zip`;
  try {
    await downloadZip(repository, metadata, zip);
    return await extractZipInner(zip, innerName, output, {
      expectedSha256: expectedInnerSha256,
      expectedSize: expectedInnerSize,
      maximumSize: limits.archiveBytes,
    });
  } finally {
    rmSync(zip, { force: true });
  }
}

async function captureArtifactBinding(options) {
  const metadata = await findBoundArtifact(options.repository, {
    artifactId: githubId(options.artifactId, 'artifact id'),
    artifactName: artifactName(options.name),
    artifactDigest: normalizedArtifactDigest(
      options.actionDigest,
      'upload action artifact digest',
    ),
    runId: githubId(options.runId, 'workflow run id'),
  });
  const inner = stableFileDigest(
    resolve(options.inner),
    'payload inner tar',
    LIMITS.payload.archiveBytes,
  );
  writeFreshJson(options.output, {
    artifactId: metadata.artifactId,
    artifactName: metadata.artifactName,
    artifactDigest: metadata.artifactDigest,
    artifactSize: metadata.artifactSize,
    artifactInnerSha256: inner.sha256,
    artifactInnerSize: inner.size,
  }, 'payload artifact binding');
}

async function fetchNamed(options) {
  const metadata = await findNamedArtifact(
    options.repository,
    options.runId,
    options.name,
  );
  await downloadArtifactInner({
    repository: options.repository,
    metadata,
    innerName: options.innerName,
    output: options.output,
    kind: options.kind,
  });
}

async function fetchBound(options) {
  const record = readStableJson(options.record, 'signed build record');
  const binding = payloadBindingFromRecord(record, {
    platform: options.platform,
    slot: options.slot,
    runId: options.runId,
  });
  const metadata = await findBoundArtifact(options.repository, binding);
  await downloadArtifactInner({
    repository: options.repository,
    metadata,
    innerName: options.innerName,
    output: options.output,
    kind: 'payload',
    expectedInnerSha256: binding.artifactInnerSha256,
    expectedInnerSize: binding.artifactInnerSize,
  });
}

function parseOptions(args, allowed) {
  const options = Object.create(null);
  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    if (!allowed.has(key) || Object.hasOwn(options, key)) {
      throw new TypeError(`unknown or repeated option ${String(key)}`);
    }
    const value = args[index + 1];
    if (!value || value.startsWith('--')) {
      throw new TypeError(`${key} requires a value`);
    }
    options[key.slice(2).replace(/-([a-z])/gu, (_, letter) =>
      letter.toUpperCase())] = value;
    index += 1;
  }
  return options;
}

function requireOptions(options, names) {
  for (const name of names) {
    if (!Object.hasOwn(options, name)) {
      throw new TypeError(`--${name.replace(/[A-Z]/gu, (letter) =>
        `-${letter.toLowerCase()}`)} is required`);
    }
  }
}

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'capture') {
    const options = parseOptions(args, new Set([
      '--repository',
      '--run-id',
      '--artifact-id',
      '--name',
      '--action-digest',
      '--inner',
      '--output',
    ]));
    requireOptions(options, [
      'repository',
      'runId',
      'artifactId',
      'name',
      'actionDigest',
      'inner',
      'output',
    ]);
    await captureArtifactBinding(options);
    return;
  }
  if (command === 'fetch-named') {
    const options = parseOptions(args, new Set([
      '--repository',
      '--run-id',
      '--name',
      '--inner-name',
      '--output',
      '--kind',
    ]));
    requireOptions(options, [
      'repository',
      'runId',
      'name',
      'innerName',
      'output',
      'kind',
    ]);
    await fetchNamed(options);
    return;
  }
  if (command === 'fetch-bound') {
    const options = parseOptions(args, new Set([
      '--repository',
      '--run-id',
      '--platform',
      '--slot',
      '--record',
      '--inner-name',
      '--output',
    ]));
    requireOptions(options, [
      'repository',
      'runId',
      'platform',
      'slot',
      'record',
      'innerName',
      'output',
    ]);
    await fetchBound(options);
    return;
  }
  if (command === 'extract') {
    const options = parseOptions(args, new Set([
      '--archive',
      '--destination',
      '--kind',
      '--platform',
      '--slot',
      '--tar',
    ]));
    requireOptions(options, ['archive', 'destination', 'kind']);
    output(extractM0Tar({
      archive: options.archive,
      destination: options.destination,
      kind: options.kind,
      platform: options.platform,
      slot: options.slot,
      tarPath: options.tar ?? '/usr/bin/tar',
    }));
    return;
  }
  if (command === 'preflight') {
    const options = parseOptions(args, new Set([
      '--archive',
      '--kind',
      '--platform',
      '--slot',
    ]));
    requireOptions(options, ['archive', 'kind']);
    output(preflightM0Tar(options.archive, {
      kind: options.kind,
      platform: options.platform,
      slot: options.slot,
    }));
    return;
  }
  if (command === 'merge') {
    const options = parseOptions(args, new Set([
      '--source',
      '--destination',
      '--entry',
    ]));
    requireOptions(options, ['source', 'destination']);
    output(mergeM0Tree(options));
    return;
  }
  throw new TypeError(
    'usage: m0-artifact-transport.mjs '
    + 'capture|fetch-named|fetch-bound|preflight|extract|merge [options]',
  );
}

const isDirect = import.meta.main ?? (
  process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
);
if (isDirect) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error}\n`);
    process.exitCode = 1;
  });
}
