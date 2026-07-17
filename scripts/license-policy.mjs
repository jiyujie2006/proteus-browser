#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Repository licensing assertions. This checks that current declarations agree
// with the source tree; it is intentionally not a release-compliance scanner.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  closeSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const EXPECTED_APACHE_2_NORMALIZED_SHA256 =
  '0ffddef9e48f8a09aed5caf2d44f7ba1c1be2d9b8e0a6f693b1635b2d5566645';
const PLANNED_UPSTREAM_NAMES = /\b(?:Chromium|Firefox|Camoufox|uTLS|uquic|ungoogled-chromium)\b/i;

function read(relativePath) {
  return readFileSync(join(ROOT, relativePath), 'utf8');
}

function normalizedTextSha256(text) {
  return createHash('sha256')
    .update(text.replace(/\s+/g, ' ').trim())
    .digest('hex');
}

function manifest() {
  // File-backed stdio keeps the check compatible with constrained sandboxes
  // that deny nested child-process pipes while still allowing an ordinary
  // subprocess with bounded temporary outputs.
  const temp = mkdtempSync(join(tmpdir(), 'proteus-license-policy-'));
  const stdoutPath = join(temp, 'manifest.json');
  const stderrPath = join(temp, 'manifest.stderr');
  const stdoutFd = openSync(stdoutPath, 'w');
  const stderrFd = openSync(stderrPath, 'w');
  let result;
  try {
    result = spawnSync(
      process.execPath,
      [join(ROOT, 'engine-chromium', 'scripts', 'sbom.mjs'), '--json'],
      {
        cwd: ROOT,
        stdio: ['ignore', stdoutFd, stderrFd],
        windowsHide: true,
      },
    );
  } finally {
    closeSync(stdoutFd);
    closeSync(stderrFd);
  }

  try {
    const stderr = readFileSync(stderrPath, 'utf8');
    if (result.error || result.status !== 0) {
      const reason = result.error?.message
        ?? (result.signal ? `signal ${result.signal}` : `exit ${result.status}`);
      throw new Error(`component manifest failed (${reason}): ${stderr.trim()}`);
    }
    return JSON.parse(readFileSync(stdoutPath, 'utf8'));
  } finally {
    rmSync(temp, { force: true, recursive: true });
  }
}

const checks = [
  [
    'LICENSE is the unmodified Apache-2.0 text',
    () => {
      assert.equal(
        normalizedTextSha256(read('LICENSE')),
        EXPECTED_APACHE_2_NORMALIZED_SHA256,
      );
    },
  ],
  [
    'NOTICE contains current attribution only',
    () => {
      const notice = read('NOTICE');
      assert.match(notice, /^Proteus\nCopyright 2026 jiyujie2006 and Proteus contributors\n/);
      assert.doesNotMatch(notice, PLANNED_UPSTREAM_NAMES);
      assert.ok(Buffer.byteLength(notice) < 1024, 'NOTICE should remain attribution-only');
    },
  ],
  [
    'acceptable-use statement does not add license restrictions',
    () => {
      const policy = read('ACCEPTABLE_USE.md');
      assert.match(policy, /not part of the Apache-2\.0 license/i);
      assert.match(policy, /does not add restrictions/i);
    },
  ],
  [
    'first-party package metadata declares Apache-2.0',
    () => {
      assert.equal(JSON.parse(read('package.json')).license, 'Apache-2.0');
      assert.equal(
        JSON.parse(read('verify-lab/package.json')).license,
        'Apache-2.0',
      );
      assert.match(read('fingerprint/Cargo.toml'), /^license = "Apache-2\.0"$/m);
    },
  ],
  [
    'third-party plan distinguishes current and future contents',
    () => {
      const plan = read('docs/10-third-party-licensing.md');
      assert.match(plan, /does \*\*not\*\* contain or distribute/);
      assert.match(plan, /artifact-specific SBOM and third-party notice bundle/);
      assert.match(plan, /not proof that redistribution\s+obligations have been met/);
    },
  ],
  [
    'component manifest contains current first-party components only',
    () => {
      const document = manifest();
      const properties = Object.fromEntries(
        document.metadata.properties.map(({ name, value }) => [name, value]),
      );
      assert.equal(
        properties['proteus:document-kind'],
        'repository-component-manifest-stub',
      );
      assert.equal(properties['proteus:build-derived'], 'false');
      assert.deepEqual(
        document.components.map(({ name }) => name),
        [
          'proteus-fingerprint',
          'proteus-verify-lab',
          'proteus-chromium-scaffold',
          'proteus-repository-tooling',
        ],
      );
      assert.ok(
        document.components.every(({ licenses }) => (
          licenses.length === 1 && licenses[0].license.id === 'Apache-2.0'
        )),
      );
      const absentUpstreamComponents = new Set([
        'chromium',
        'firefox',
        'firefox-camoufox',
        'camoufox',
        'ungoogled-chromium-patches',
        'utls',
        'uquic',
      ]);
      assert.ok(
        document.components.every(({ name }) => !absentUpstreamComponents.has(name.toLowerCase())),
        'planned upstreams must not appear as current repository components',
      );
    },
  ],
];

let passed = 0;
try {
  for (const [name, check] of checks) {
    check();
    passed += 1;
    console.log(`ok ${passed} - ${name}`);
  }
  console.log(`\n${passed}/${checks.length} repository license-policy checks passed.`);
} catch (error) {
  console.error(`not ok ${passed + 1} - ${checks[passed]?.[0] ?? 'unknown check'}`);
  console.error(error.message);
  process.exitCode = 1;
}
