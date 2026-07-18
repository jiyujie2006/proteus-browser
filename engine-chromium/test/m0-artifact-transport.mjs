#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  closeSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  truncateSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  extractM0Tar,
  mergeM0Tree,
  payloadBindingFromRecord,
  preflightM0Tar,
  validateArtifactApiDocument,
  writeBoundedZipChunk,
} from '../scripts/m0-artifact-transport.mjs';

const PAYLOAD_RECORD_FILES = [
  'build-sbom.cdx.json',
  'bundle-manifest.json',
  'complete-toolchain-lock.json',
  'effective-gn-args.json',
  'live-report.json',
  'resolved-dependency-lock.json',
  'runtime-deps.txt',
];

function temporary() {
  return realpathSync(mkdtempSync(
    join(realpathSync(tmpdir()), 'proteus-m0-transport-'),
  ));
}

function payloadFixture(root, platform = 'linux-x64', slot = 'A') {
  const tree = join(root, 'tree');
  const build = join(tree, 'builds', platform, slot);
  mkdirSync(join(build, 'bundle'), { recursive: true });
  mkdirSync(join(build, 'records'), { recursive: true });
  writeFileSync(join(build, 'bundle', 'chrome'), 'fixture chrome\n');
  for (const name of PAYLOAD_RECORD_FILES) {
    writeFileSync(join(build, 'records', name), `${name}\n`);
  }
  const archive = join(root, 'payload.tar');
  const result = spawnSync('/usr/bin/tar', [
    '-cf',
    archive,
    '-C',
    tree,
    `builds/${platform}/${slot}`,
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.status !== 0) {
    throw new Error(`fixture tar failed with status ${result.status}`);
  }
  return { archive, build, tree };
}

function octal(value, length) {
  return `${value.toString(8).padStart(length - 1, '0')}\0`;
}

function tarHeader({
  name,
  type = '0',
  link = '',
  size = 0,
}) {
  const header = Buffer.alloc(512);
  const field = (offset, length, value) => {
    header.write(value, offset, Math.min(length, Buffer.byteLength(value)), 'utf8');
  };
  field(0, 100, name);
  field(100, 8, octal(0o644, 8));
  field(108, 8, octal(0, 8));
  field(116, 8, octal(0, 8));
  field(124, 12, octal(size, 12));
  field(136, 12, octal(0, 12));
  header.fill(0x20, 148, 156);
  field(156, 1, type);
  field(157, 100, link);
  field(257, 6, 'ustar\0');
  field(263, 2, '00');
  let checksum = 0;
  for (const byte of header) checksum += byte;
  field(148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
  return header;
}

function rawTar(path, members) {
  const chunks = [];
  for (const member of members) {
    const bytes = Buffer.from(member.bytes ?? '');
    chunks.push(tarHeader({ ...member, size: bytes.length }));
    chunks.push(bytes);
    const padding = (512 - (bytes.length % 512)) % 512;
    if (padding > 0) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  writeFileSync(path, Buffer.concat(chunks));
}

test('preflights and extracts one canonical payload into a fresh directory', {
  skip: process.platform !== 'linux',
}, () => {
  const root = temporary();
  try {
    const { archive } = payloadFixture(root);
    const preflight = preflightM0Tar(archive, {
      kind: 'payload',
      platform: 'linux-x64',
      slot: 'A',
    });
    assert.equal(preflight.ok, true);
    assert.ok(preflight.members > PAYLOAD_RECORD_FILES.length);

    const destination = join(root, 'extracted');
    const extracted = extractM0Tar({
      archive,
      destination,
      kind: 'payload',
      platform: 'linux-x64',
      slot: 'A',
    });
    assert.equal(extracted.ok, true);
    assert.equal(
      readFileSync(
        join(destination, 'builds', 'linux-x64', 'A', 'bundle', 'chrome'),
        'utf8',
      ),
      'fixture chrome\n',
    );
    assert.throws(
      () => extractM0Tar({
        archive,
        destination,
        kind: 'payload',
        platform: 'linux-x64',
        slot: 'A',
      }),
      /must not exist/u,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('rejects traversal, another slot, duplicate paths, and hard links in headers', () => {
  const root = temporary();
  try {
    const cases = [
      {
        label: 'traversal',
        member: { name: '../escape' },
        error: /unsafe path|canonical portable path/u,
      },
      {
        label: 'wrong slot',
        member: { name: 'builds/linux-x64/B/bundle/chrome' },
        error: /outside builds\/linux-x64\/A/u,
      },
      {
        label: 'hard link',
        member: {
          name: 'builds/linux-x64/A/bundle/chrome',
          type: '1',
          link: 'builds/linux-x64/A/records/runtime-deps.txt',
        },
        error: /hard links are forbidden/u,
      },
    ];
    for (const item of cases) {
      const archive = join(root, `${item.label}.tar`);
      rawTar(archive, [item.member]);
      assert.throws(
        () => preflightM0Tar(archive, {
          kind: 'payload',
          platform: 'linux-x64',
          slot: 'A',
        }),
        item.error,
      );
    }

    const duplicate = join(root, 'duplicate.tar');
    rawTar(duplicate, [
      { name: 'builds/linux-x64/A/bundle/chrome' },
      { name: 'builds/linux-x64/A/bundle/chrome' },
    ]);
    assert.throws(
      () => preflightM0Tar(duplicate, {
        kind: 'payload',
        platform: 'linux-x64',
        slot: 'A',
      }),
      /repeats or aliases/u,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('rejects an archive larger than its kind budget before extraction', () => {
  const root = temporary();
  try {
    const archive = join(root, 'oversized-metadata.tar');
    writeFileSync(archive, Buffer.alloc(1024));
    truncateSync(archive, 256 * 1024 * 1024 + 1);
    assert.throws(
      () => preflightM0Tar(archive, {
        kind: 'metadata',
        platform: 'linux-x64',
        slot: 'A',
      }),
      /bounded ordinary file/u,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('no-overwrite merge permits directory composition and rejects file collision', () => {
  const root = temporary();
  try {
    const source = join(root, 'source');
    const destination = join(root, 'destination');
    mkdirSync(join(source, 'builds', 'linux-x64'), { recursive: true });
    mkdirSync(join(destination, 'builds', 'windows-x64'), { recursive: true });
    writeFileSync(join(source, 'builds', 'linux-x64', 'one'), 'one');
    writeFileSync(join(destination, 'builds', 'windows-x64', 'two'), 'two');
    mergeM0Tree({ source, destination });
    assert.equal(
      readFileSync(join(destination, 'builds', 'linux-x64', 'one'), 'utf8'),
      'one',
    );

    const conflicting = join(root, 'conflicting');
    mkdirSync(join(conflicting, 'builds', 'linux-x64'), { recursive: true });
    writeFileSync(join(conflicting, 'builds', 'linux-x64', 'one'), 'replacement');
    assert.throws(
      () => mergeM0Tree({ source: conflicting, destination }),
      /no-overwrite merge collision/u,
    );
    assert.equal(
      readFileSync(join(destination, 'builds', 'linux-x64', 'one'), 'utf8'),
      'one',
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('artifact API metadata and signed payload binding cover name and both layers', () => {
  const digest = 'a'.repeat(64);
  const innerDigest = 'b'.repeat(64);
  const api = validateArtifactApiDocument({
    id: 123,
    name: 'm0-payload-linux-x64-A-attempt-1',
    digest: `sha256:${digest}`,
    size_in_bytes: 4096,
    expired: false,
    workflow_run: { id: 456 },
  }, {
    artifactId: '123',
    runId: '456',
    name: 'm0-payload-linux-x64-A-attempt-1',
    digest,
    size: 4096,
  });
  assert.equal(api.artifactDigest, digest);
  const scopedWithoutOptionalRun = validateArtifactApiDocument({
    id: 123,
    name: 'm0-payload-linux-x64-A-attempt-1',
    digest: `sha256:${digest}`,
    size_in_bytes: 4096,
    expired: false,
  }, {
    artifactId: '123',
    runId: '456',
    name: 'm0-payload-linux-x64-A-attempt-1',
    runScoped: true,
  });
  assert.equal(scopedWithoutOptionalRun.workflowRunId, '456');
  assert.throws(
    () => validateArtifactApiDocument({
      id: 123,
      name: 'm0-payload-linux-x64-B-attempt-1',
      digest: `sha256:${digest}`,
      size_in_bytes: 4096,
      expired: false,
      workflow_run: { id: 456 },
    }, {
      artifactId: '123',
      runId: '456',
      name: 'm0-payload-linux-x64-A-attempt-1',
    }),
    /name does not match/u,
  );

  const binding = payloadBindingFromRecord({
    runId: '456',
    runAttempt: 1,
    artifactId: '123',
    artifactName: 'm0-payload-linux-x64-A-attempt-1',
    artifactDigest: digest,
    artifactSize: 4096,
    artifactInnerSha256: innerDigest,
    artifactInnerSize: 2048,
  }, {
    platform: 'linux-x64',
    slot: 'A',
    runId: '456',
  });
  assert.equal(binding.artifactInnerSha256, innerDigest);
  assert.throws(
    () => payloadBindingFromRecord({
      runId: '456',
      runAttempt: 1,
      artifactId: '123',
      artifactName: 'm0-payload-windows-x64-A-attempt-1',
      artifactDigest: digest,
      artifactSize: 4096,
      artifactInnerSha256: innerDigest,
      artifactInnerSize: 2048,
    }, {
      platform: 'linux-x64',
      slot: 'A',
      runId: '456',
    }),
    /name is wrong/u,
  );
});

test('ZIP extraction writer enforces the declared size before writing overflow', () => {
  const root = temporary();
  try {
    const output = join(root, 'm0-index.tar');
    const fd = openSync(output, 'wx', 0o600);
    const state = { bytes: 0, maximumBytes: 1024 };
    try {
      writeBoundedZipChunk(fd, Buffer.alloc(768, 0x61), state);
      assert.throws(
        () => writeBoundedZipChunk(fd, Buffer.alloc(257, 0x62), state),
        /inflated beyond its declared inner size/u,
      );
    } finally {
      closeSync(fd);
    }
    assert.equal(readFileSync(output).length, 768);
    assert.equal(state.bytes, 768);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});
