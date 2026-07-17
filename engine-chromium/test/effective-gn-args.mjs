#!/usr/bin/env node

import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createEffectiveGnArgsRecord,
  validateEffectiveGnArgsRecord,
  validateEffectiveGnArgsText,
} from '../scripts/effective-gn-args.mjs';

const root = mkdtempSync(join(tmpdir(), 'proteus-effective-args-'));
let passed = 0;

function test(label, fn) {
  try {
    fn();
    passed += 1;
    process.stdout.write(`ok - ${label}\n`);
  } catch (error) {
    process.stderr.write(`not ok - ${label}: ${error.stack || error}\n`);
    process.exitCode = 1;
  }
}

function argsText(cpu, extra = '') {
  return [
    'cc_wrapper = ""',
    'disable_sandbox = false',
    'generate_about_credits = true',
    'google_api_key = ""',
    'google_default_client_id = ""',
    'google_default_client_secret = ""',
    'is_debug = false',
    'is_official_build = true',
    `target_cpu = "${cpu}"`,
    'use_goma = false',
    'use_official_google_api_keys = false',
    'use_remoteexec = false',
    extra,
  ].filter(Boolean).join('\n') + '\n';
}

function configuration(architecture, outDir, cpu, name) {
  const argsPath = join(root, name);
  writeFileSync(argsPath, argsText(cpu));
  return { architecture, outDir, argsPath };
}

try {
  test('locked Linux effective args are accepted', () => {
    assert.deepEqual(
      validateEffectiveGnArgsText(argsText('x64'), 'x86_64'),
      { architecture: 'x86_64', gnTargetCpu: 'x64' },
    );
  });

  test('a non-empty compiler wrapper is rejected', () => {
    assert.throws(
      () => validateEffectiveGnArgsText(
        argsText('x64').replace('cc_wrapper = ""', 'cc_wrapper = "/tmp/cc"'),
        'x86_64',
      ),
      /unlocked compiler/u,
    );
  });

  test('sample credits mode is rejected', () => {
    assert.throws(
      () => validateEffectiveGnArgsText(
        argsText('x64').replace(
          'generate_about_credits = true',
          'generate_about_credits = false',
        ),
        'x86_64',
      ),
      /generate_about_credits/u,
    );
  });

  test('wrong target CPU is rejected', () => {
    assert.throws(
      () => validateEffectiveGnArgsText(argsText('arm64'), 'x86_64'),
      /target_cpu/u,
    );
  });

  let linux;
  test('Linux record embeds and hashes one complete configuration', () => {
    linux = createEffectiveGnArgsRecord({
      platform: 'linux-x64',
      configurations: [
        configuration('x86_64', 'out/Proteus', 'x64', 'linux.gn'),
      ],
    });
    assert.equal(linux.configurations.length, 1);
    assert.match(linux.configurations[0].argsSha256, /^[0-9a-f]{64}$/u);
    assert.equal(
      validateEffectiveGnArgsRecord(linux, { platform: 'linux-x64' }).ok,
      true,
    );
  });

  test('embedded text tampering is rejected', () => {
    const changed = structuredClone(linux);
    changed.configurations[0].argsText =
      changed.configurations[0].argsText.replace('is_debug = false', 'is_debug = true');
    assert.throws(
      () => validateEffectiveGnArgsRecord(changed, {
        platform: 'linux-x64',
      }),
      /text binding is wrong/u,
    );
  });

  test('macOS universal record requires both ordered architectures', () => {
    const mac = createEffectiveGnArgsRecord({
      platform: 'macos-universal',
      configurations: [
        configuration(
          'x86_64',
          'out/Proteus-x64',
          'x64',
          'mac-x64.gn',
        ),
        configuration(
          'arm64',
          'out/Proteus-arm64',
          'arm64',
          'mac-arm64.gn',
        ),
      ],
    });
    assert.deepEqual(
      mac.configurations.map(({ architecture }) => architecture),
      ['x86_64', 'arm64'],
    );
  });

  test('macOS cannot omit the arm64 configuration', () => {
    assert.throws(
      () => createEffectiveGnArgsRecord({
        platform: 'macos-universal',
        configurations: [
          configuration(
            'x86_64',
            'out/Only-x64',
            'x64',
            'mac-only-x64.gn',
          ),
        ],
      }),
      /requires 2/u,
    );
  });

  test('architectures cannot share an output directory', () => {
    const mac = structuredClone(createEffectiveGnArgsRecord({
      platform: 'macos-universal',
      configurations: [
        configuration('x86_64', 'out/Same', 'x64', 'same-x64.gn'),
        configuration('arm64', 'out/Different', 'arm64', 'same-arm64.gn'),
      ],
    }));
    mac.configurations[1].outDir = 'out/Same';
    assert.throws(
      () => validateEffectiveGnArgsRecord(mac, {
        platform: 'macos-universal',
      }),
      /distinct output/u,
    );
  });

  test('unknown record fields are rejected', () => {
    assert.throws(
      () => validateEffectiveGnArgsRecord(
        { ...linux, trusted: true },
        { platform: 'linux-x64' },
      ),
      /missing or unknown/u,
    );
  });
} finally {
  rmSync(root, { force: true, recursive: true });
}

if (!process.exitCode) {
  process.stdout.write(`${passed} effective-GN-args tests passed\n`);
}
