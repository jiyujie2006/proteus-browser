#!/usr/bin/env node

import assert from 'node:assert/strict';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createBundleManifest,
  verifyBundleManifest,
} from '../scripts/bundle-manifest.mjs';
import { parseRuntimeDependencies } from '../scripts/package-engine.mjs';

const root = mkdtempSync(join(tmpdir(), 'proteus-bundle-manifest-'));
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

try {
  const bundle = join(root, 'bundle');
  mkdirSync(join(bundle, 'locales'), { recursive: true });
  writeFileSync(join(bundle, 'chrome'), Buffer.from('engine-bytes\n'));
  writeFileSync(join(bundle, 'locales', 'en-US.pak'), Buffer.from('locale\n'));
  if (process.platform !== 'win32') chmodSync(join(bundle, 'chrome'), 0o755);

  test('manifest is deterministic and covers the complete tree', () => {
    const first = createBundleManifest(bundle, {
      platform: 'linux-x64',
      entrypoint: 'chrome',
    });
    const second = createBundleManifest(bundle, {
      platform: 'linux-x64',
      entrypoint: 'chrome',
    });
    assert.deepEqual(first, second);
    assert.match(first.treeSha256, /^[0-9a-f]{64}$/u);
    assert.deepEqual(
      first.entries.map(({ path }) => path),
      ['chrome', 'locales', 'locales/en-US.pak'],
    );
  });

  test('verification rehashes bytes instead of trusting the manifest', () => {
    const manifest = createBundleManifest(bundle, {
      platform: 'linux-x64',
      entrypoint: 'chrome',
    });
    writeFileSync(join(bundle, 'locales', 'en-US.pak'), Buffer.from('tampered\n'));
    assert.throws(
      () => verifyBundleManifest(bundle, manifest),
      /does not match/u,
    );
    writeFileSync(join(bundle, 'locales', 'en-US.pak'), Buffer.from('locale\n'));
  });

  test('entrypoint must be a regular file inside the bundle', () => {
    assert.throws(
      () => createBundleManifest(bundle, {
        platform: 'linux-x64',
        entrypoint: '../chrome',
      }),
      /canonical bundle-relative/u,
    );
    assert.throws(
      () => createBundleManifest(bundle, {
        platform: 'linux-x64',
        entrypoint: 'locales',
      }),
      /not a regular file/u,
    );
  });

  test('unknown platforms cannot mint M0 manifests', () => {
    assert.throws(
      () => createBundleManifest(bundle, {
        platform: 'freebsd-x64',
        entrypoint: 'chrome',
      }),
      /unsupported M0 platform/u,
    );
  });

  if (process.platform !== 'win32') {
    test('symlinks that escape the bundle are rejected', () => {
      const outside = join(root, 'outside');
      writeFileSync(outside, 'outside\n');
      symlinkSync('../outside', join(bundle, 'escape'));
      assert.throws(
        () => createBundleManifest(bundle, {
          platform: 'linux-x64',
          entrypoint: 'chrome',
        }),
        /escapes the bundle root/u,
      );
      rmSync(join(bundle, 'escape'));
    });

    test('contained relative symlinks are represented without dereferencing', () => {
      symlinkSync('locales/en-US.pak', join(bundle, 'locale-link'));
      const manifest = createBundleManifest(bundle, {
        platform: 'linux-x64',
        entrypoint: 'chrome',
      });
      assert.deepEqual(
        manifest.entries.find(({ path }) => path === 'locale-link'),
        {
          path: 'locale-link',
          type: 'symlink',
          target: 'locales/en-US.pak',
        },
      );
    });
  }

  test('manifest root parser rejects unknown fields', () => {
    const manifest = createBundleManifest(bundle, {
      platform: 'linux-x64',
      entrypoint: 'chrome',
    });
    assert.throws(
      () => verifyBundleManifest(bundle, { ...manifest, trusted: true }),
      /missing or unknown root fields/u,
    );
  });

  test('manifest never depends on file timestamps', () => {
    const manifest = createBundleManifest(bundle, {
      platform: 'linux-x64',
      entrypoint: 'chrome',
    });
    const serialized = JSON.stringify(manifest);
    assert.equal(serialized.includes('mtime'), false);
    assert.equal(serialized.includes('ctime'), false);
    assert.equal(
      readFileSync(join(bundle, 'chrome'), 'utf8'),
      'engine-bytes\n',
    );
  });

  test('Windows manifest modes survive Windows-to-Linux tar normalization', () => {
    const windowsBundle = join(root, 'windows-bundle');
    mkdirSync(join(windowsBundle, 'locales'), { recursive: true });
    writeFileSync(join(windowsBundle, 'chrome.exe'), 'windows-engine\n');
    writeFileSync(join(windowsBundle, 'locales', 'en-US.pak'), 'locale\n');
    const manifest = createBundleManifest(windowsBundle, {
      platform: 'windows-x64',
      entrypoint: 'chrome.exe',
    });
    assert.deepEqual(
      manifest.entries.map(({ path, mode }) => [path, mode]),
      [
        ['chrome.exe', '644'],
        ['locales', '755'],
        ['locales/en-US.pak', '644'],
      ],
    );
    if (process.platform !== 'win32') {
      chmodSync(join(windowsBundle, 'chrome.exe'), 0o755);
      chmodSync(join(windowsBundle, 'locales', 'en-US.pak'), 0o600);
      assert.deepEqual(verifyBundleManifest(windowsBundle, manifest), manifest);
    }
  });

  test('runtime dependency parser accepts only unique build-relative paths', () => {
    assert.deepEqual(
      parseRuntimeDependencies('./chrome\nlocales/\nresources.pak\n'),
      ['chrome', 'locales', 'resources.pak'],
    );
    for (const unsafe of [
      '/etc/passwd\n',
      '../chrome\n',
      './../chrome\n',
      '././chrome\n',
      './/chrome\n',
      'dir/../chrome\n',
      'dir/./chrome\n',
      'C:/chrome.exe\n',
      'dir\\chrome.exe\n',
      './chrome\nchrome\n',
      'chrome\nchrome\n',
      ' chrome\n',
    ]) {
      assert.throws(() => parseRuntimeDependencies(unsafe));
    }
  });
} finally {
  rmSync(root, { force: true, recursive: true });
}

if (!process.exitCode) {
  process.stdout.write(`${passed} bundle-manifest tests passed\n`);
}
