#!/usr/bin/env node

import assert from 'node:assert/strict';
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { M0_PLATFORM_IDS } from '../scripts/build-contract.mjs';
import {
  validateArtifactStaging,
} from '../scripts/validate-artifact-staging.mjs';

function fixture() {
  const root = realpathSync(mkdtempSync(
    join(realpathSync(tmpdir()), 'proteus-m0-staging-'),
  ));
  for (const platform of M0_PLATFORM_IDS) {
    for (const slot of ['A', 'B']) {
      const build = join(root, 'builds', platform, slot);
      mkdirSync(join(build, 'bundle'), { recursive: true });
      mkdirSync(join(build, 'records'), { recursive: true });
      writeFileSync(join(build, 'bundle', 'chrome.bin'), `${platform}/${slot}`);
      writeFileSync(join(build, 'records', 'record.json'), '{}\n');
    }
  }
  return root;
}

test('accepts the exact six-build staging layout', () => {
  const root = fixture();
  try {
    const audit = validateArtifactStaging(root);
    assert.equal(audit.ok, true);
    assert.ok(audit.nodes > 1);
    assert.ok(Number(audit.bytes) > 0);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('accepts a relative symlink which remains inside the staging root', {
  skip: process.platform === 'win32',
}, () => {
  const root = fixture();
  try {
    symlinkSync(
      'chrome.bin',
      join(root, 'builds', 'linux-x64', 'A', 'bundle', 'chrome-link'),
    );
    assert.equal(validateArtifactStaging(root).ok, true);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('rejects symlinks which escape the staging root', {
  skip: process.platform === 'win32',
}, () => {
  const root = fixture();
  try {
    symlinkSync(
      '../../../../../../outside',
      join(root, 'builds', 'linux-x64', 'A', 'bundle', 'escape'),
    );
    assert.throws(
      () => validateArtifactStaging(root),
      /escapes the staging root/u,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('rejects unexpected top-level content', () => {
  const root = fixture();
  try {
    writeFileSync(join(root, 'surprise.txt'), 'no');
    assert.throws(
      () => validateArtifactStaging(root),
      /unexpected layout/u,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});
