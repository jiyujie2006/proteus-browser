import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from 'node:fs';

import { parseStrictJson } from '../../scripts/strict-json.mjs';

export const NETWORK_TIME_AUDIT_SCHEMA_VERSION = '1.0.0';
export const NETWORK_TIME_ENDPOINT =
  'http://clients2.google.com/time/1/current';

const HOST = 'clients2.google.com';
const PATH = '/time/1/current';
const MAX_EVENT_NODES = 100_000;
const DEFAULT_MAX_NET_LOG_BYTES = 64 * 1024 * 1024;

function sameStableFile(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function eventStrings(value, output, budget) {
  if (budget.remaining <= 0) {
    throw new TypeError('Chromium NetLog event exceeds the audit node budget');
  }
  budget.remaining -= 1;
  if (typeof value === 'string') {
    output.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) eventStrings(item, output, budget);
    return;
  }
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) {
      eventStrings(item, output, budget);
    }
  }
}

export function auditNetworkTimeNetLog(document) {
  if (!document || typeof document !== 'object'
      || Array.isArray(document)
      || !Array.isArray(document.events)
      || document.events.length === 0) {
    throw new TypeError('Chromium NetLog must contain at least one event');
  }
  let matchingEventCount = 0;
  for (const event of document.events) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) {
      throw new TypeError('Chromium NetLog events must be objects');
    }
    const strings = [];
    eventStrings(event, strings, { remaining: MAX_EVENT_NODES });
    if (strings.some((value) =>
      value.includes(HOST) && value.includes(PATH))
      || (
        strings.some((value) => value.includes(HOST))
        && strings.some((value) => value.includes(PATH))
      )) {
      matchingEventCount += 1;
    }
  }
  return {
    schemaVersion: NETWORK_TIME_AUDIT_SCHEMA_VERSION,
    source: 'chromium-net-log',
    endpoint: NETWORK_TIME_ENDPOINT,
    eventCount: document.events.length,
    matchingEventCount,
    defaultQueryAbsent: matchingEventCount === 0,
  };
}

export function validateNetworkTimeAudit(audit) {
  if (!audit || typeof audit !== 'object' || Array.isArray(audit)) {
    throw new TypeError('Network Time audit must be an object');
  }
  const actual = Object.keys(audit).sort();
  const expected = [
    'schemaVersion',
    'source',
    'endpoint',
    'eventCount',
    'matchingEventCount',
    'defaultQueryAbsent',
  ].sort();
  if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError('Network Time audit has unknown or missing fields');
  }
  if (audit.schemaVersion !== NETWORK_TIME_AUDIT_SCHEMA_VERSION
      || audit.source !== 'chromium-net-log'
      || audit.endpoint !== NETWORK_TIME_ENDPOINT
      || !Number.isSafeInteger(audit.eventCount)
      || audit.eventCount < 1
      || audit.matchingEventCount !== 0
      || audit.defaultQueryAbsent !== true) {
    throw new TypeError(
      'Network Time audit does not prove the default query endpoint was absent',
    );
  }
  return audit;
}

export function readNetworkTimeAuditFile(
  path,
  { maxBytes = DEFAULT_MAX_NET_LOG_BYTES } = {},
) {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0')) {
    throw new TypeError('Chromium NetLog path must be a non-empty safe string');
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new TypeError('Chromium NetLog byte limit must be a positive integer');
  }
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError('Chromium NetLog is not an ordinary non-symlink file');
  }
  if (before.size < 1n || before.size > BigInt(maxBytes)) {
    throw new TypeError(`Chromium NetLog size must be 1..${maxBytes} bytes`);
  }
  const realBefore = realpathSync(path);
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  let bytes;
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameStableFile(before, opened)) {
      throw new Error('Chromium NetLog changed while it was opened');
    }
    if (opened.size < 1n || opened.size > BigInt(maxBytes)) {
      throw new TypeError(`Chromium NetLog size must be 1..${maxBytes} bytes`);
    }
    const size = Number(opened.size);
    bytes = Buffer.allocUnsafe(size);
    let position = 0;
    while (position < size) {
      const count = readSync(
        fd,
        bytes,
        position,
        size - position,
        position,
      );
      if (count === 0) {
        throw new Error('Chromium NetLog shrank while it was read');
      }
      position += count;
    }
    const extra = Buffer.allocUnsafe(1);
    if (readSync(fd, extra, 0, 1, size) !== 0) {
      throw new Error('Chromium NetLog grew while it was read');
    }
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    if (!pathAfter.isFile()
        || pathAfter.isSymbolicLink()
        || !sameStableFile(opened, after)
        || !sameStableFile(after, pathAfter)
        || realpathSync(path) !== realBefore) {
      throw new Error('Chromium NetLog changed or was rebound while it was read');
    }
  } finally {
    closeSync(fd);
  }
  return validateNetworkTimeAudit(
    auditNetworkTimeNetLog(parseStrictJson(bytes, 'Chromium NetLog')),
  );
}
