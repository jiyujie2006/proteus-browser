#!/usr/bin/env node
// Focused regression tests for the resolved dependency lock. These tests use
// local temporary Git repositories and a fake CIPD process callback; they do
// not fetch Chromium or access the network.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  appendFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assembleDependencyLock,
  auditCipdDependencyPaths,
  auditGcsDependencies,
  assertDepotToolsBootstrapReady,
  assertCipdDryRunResult,
  assertGcsDependenciesLockable,
  auditNestedGitDependencies,
  bindGcsDependencyMetadata,
  canonicalDependencyLock,
  detectDependencyRuntime,
  parseGclientRevinfo,
  parseJsonWithoutDuplicateKeys,
  renderCipdEnsureFile,
  renderDepotToolsIntegrityEnsure,
  runCipdIntegrityAudit,
  runDepotToolsBootstrapIntegrityAudit,
  runPinnedGclientRevinfo,
  runPinnedGclientResolution,
  validatePinnedCipdClient,
} from '../scripts/dependency-lock.mjs';
import { sanitizedGitEnvironment } from '../scripts/git-env.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const TEMP = realpathSync(mkdtempSync(
  join(realpathSync(tmpdir()), 'proteus-dependency-lock-test-'),
));
const GIT = process.env.PROTEUS_GIT_BIN || 'git';
const GIT_ENV = sanitizedGitEnvironment(process.env);
const RUNTIME = detectDependencyRuntime({ platform: 'linux', architecture: 'x64' });
const COMMIT = '1111111111111111111111111111111111111111';
const NESTED_COMMIT = '2222222222222222222222222222222222222222';
const INSTANCE = '23KzzymTNWIhH-z3xLGvHkE6uUJtNBDjpv83nkKMWBEC';
const BASELINE = Object.freeze({
  CHROMIUM_COMMIT: COMMIT,
  CHROMIUM_REPOSITORY: 'https://chromium.googlesource.com/chromium/src.git',
  CHROMIUM_STABLE: '150.0.7871.124',
  DEPOT_TOOLS_COMMIT: '3333333333333333333333333333333333333333',
  DEPOT_TOOLS_REPOSITORY:
    'https://chromium.googlesource.com/chromium/tools/depot_tools.git',
});

let passed = 0;

function check(name, body) {
  try {
    body();
  } catch (error) {
    throw new Error(`${name}: ${error.message}`, { cause: error });
  }
  passed += 1;
  console.log(`ok ${passed} - ${name}`);
}

check('sanitized Git environment pins Windows long-path handling only in-process', () => {
  const environment = sanitizedGitEnvironment({
    GIT_CONFIG_COUNT: '99',
    GIT_CONFIG_KEY_0: 'attacker.key',
    GIT_CONFIG_VALUE_0: 'attacker-value',
    GIT_DIR: '/attacker/repository',
    PATH: process.env.PATH ?? '',
  });
  assert.equal(Object.hasOwn(environment, 'GIT_DIR'), false);
  assert.equal(environment.GIT_CONFIG_NOSYSTEM, '1');
  assert.equal(
    environment.GIT_CONFIG_GLOBAL,
    process.platform === 'win32' ? 'NUL' : '/dev/null',
  );
  if (process.platform === 'win32') {
    assert.equal(environment.GIT_CONFIG_COUNT, '1');
    assert.equal(environment.GIT_CONFIG_KEY_0, 'core.longpaths');
    assert.equal(environment.GIT_CONFIG_VALUE_0, 'true');
  } else {
    assert.equal(Object.hasOwn(environment, 'GIT_CONFIG_COUNT'), false);
    assert.equal(Object.hasOwn(environment, 'GIT_CONFIG_KEY_0'), false);
    assert.equal(Object.hasOwn(environment, 'GIT_CONFIG_VALUE_0'), false);
  }
});

function revinfo(entries = {}) {
  return JSON.stringify({
    src: {
      rev: COMMIT,
      url: BASELINE.CHROMIUM_REPOSITORY,
    },
    ...entries,
  });
}

function git(root, args) {
  return execFileSync(GIT, ['-C', root, ...args], {
    env: GIT_ENV,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).toString().trim();
}

let fixtureNumber = 0;
function nestedGitFixture() {
  fixtureNumber += 1;
  const clientRoot = join(TEMP, `git-fixture-${fixtureNumber}`);
  const checkout = join(clientRoot, 'src', 'third_party', 'example');
  mkdirSync(checkout, { recursive: true });
  git(checkout, ['init', '--quiet']);
  git(checkout, ['config', 'user.email', 'dependency-lock@example.invalid']);
  git(checkout, ['config', 'user.name', 'Dependency Lock Test']);
  writeFileSync(join(checkout, 'tracked.txt'), 'pinned\n');
  git(checkout, ['add', 'tracked.txt']);
  git(checkout, ['commit', '--quiet', '-m', 'fixture']);
  git(checkout, ['remote', 'add', 'origin', 'https://example.test/example.git']);
  const commit = git(checkout, ['rev-parse', 'HEAD']);
  const dependency = Object.freeze({
    commit,
    path: 'src/third_party/example',
    type: 'git',
    url: 'https://example.test/example.git',
  });
  return { checkout, clientRoot, dependency };
}

function depotBootstrapFixture(label) {
  const depot = join(TEMP, label);
  const root = join(depot, '.cipd_bin');
  mkdirSync(root, { recursive: true });
  const manifest = '# depot_tools bootstrap fixture\n'
    + '$ResolvedVersions cipd_manifest.versions\n'
    + 'infra/tools/vpython/${platform} git_revision:fixture\n';
  const versions = 'infra/tools/vpython/linux-amd64 '
    + `${INSTANCE}\n`;
  for (const [sourceName, cachedName, bytes] of [
    ['cipd_manifest.txt', '.cipd_manifest.txt', manifest],
    ['cipd_manifest.versions', '.cipd_manifest.versions', versions],
    ['cipd_client_version', '.cipd_client_version', 'git_revision:fixture\n'],
  ]) {
    writeFileSync(join(depot, sourceName), bytes);
    writeFileSync(join(root, cachedName), bytes);
  }
  writeFileSync(
    join(root, process.platform === 'win32' ? 'vpython3.exe' : 'vpython3'),
    'vpython fixture\n',
  );
  writeFileSync(join(depot, '.vpython3'), 'python_version: "3.11"\n');
  return {
    depot,
    manifest,
    root,
    versions,
  };
}

try {
  check('duplicate-aware JSON parser rejects duplicate keys at every depth', () => {
    assert.throws(
      () => parseJsonWithoutDuplicateKeys('{"a":{"b":1,"b":2}}', 'fixture'),
      /duplicate object key "b"/,
    );
    assert.equal(
      JSON.stringify(parseJsonWithoutDuplicateKeys('{"a":[true,null,3]}')),
      '{"a":[true,null,3]}',
    );
  });

  check('revinfo parser classifies and canonically sorts Git and CIPD pins', () => {
    const parsed = parseGclientRevinfo(
      revinfo({
        'src/z-dependency': {
          rev: NESTED_COMMIT,
          url: 'https://example.test/z.git',
        },
        'src/cipd:${platform}/tool': {
          rev: null,
          url:
            'https://chrome-infra-packages.appspot.com/p/'
            + `linux-amd64/tool/+/${INSTANCE}`,
        },
      }),
      BASELINE,
      RUNTIME,
    );
    assert.deepEqual(
      parsed.dependencies.map((entry) => [entry.type, entry.path]),
      [
        ['git', 'src'],
        ['cipd', 'src/cipd'],
        ['git', 'src/z-dependency'],
      ],
    );
    assert.equal(parsed.dependencies[1].declaredPackage, '${platform}/tool');
    assert.equal(parsed.dependencies[1].package, 'linux-amd64/tool');
    assert.match(parsed.revinfoSha256, /^[0-9a-f]{64}$/u);
  });

  check('revinfo parser rejects partial revisions and unexpected entry fields', () => {
    assert.throws(
      () => parseGclientRevinfo(
        revinfo({
          'src/bad': {
            rev: '1234567',
            url: 'https://example.test/bad.git',
          },
        }),
        BASELINE,
        RUNTIME,
      ),
      /full lowercase commit/,
    );
    assert.throws(
      () => parseGclientRevinfo(
        '{"src":{"url":"https://chromium.googlesource.com/chromium/src.git",'
        + `"rev":"${COMMIT}","extra":true}}`,
        BASELINE,
        RUNTIME,
      ),
      /must contain exactly rev, url/,
    );
  });

  check('revinfo parser binds the root solution to the Chromium baseline', () => {
    assert.throws(
      () => parseGclientRevinfo(
        JSON.stringify({
          src: {
            rev: NESTED_COMMIT,
            url: BASELINE.CHROMIUM_REPOSITORY,
          },
        }),
        BASELINE,
        RUNTIME,
      ),
      /commit differs from CHROMIUM_BASELINE/,
    );
  });

  check('GCS revinfo is strictly joined to complete DEPS object metadata', () => {
    const parsed = parseGclientRevinfo(
      revinfo({
        'src/gcs:objects/archive.tar.gz': {
          rev: null,
          url: 'gs://chromium-example/objects/archive.tar.gz',
        },
      }),
      BASELINE,
      RUNTIME,
    );
    assert.deepEqual(
      parsed.dependencies.find((entry) => entry.type === 'gcs'),
      {
        bucket: 'chromium-example',
        object: 'objects/archive.tar.gz',
        path: 'src/gcs',
        type: 'gcs',
        url: 'gs://chromium-example/objects/archive.tar.gz',
      },
    );
    const locked = bindGcsDependencyMetadata(
      JSON.stringify({
        dependencies: [{
          bucket: 'chromium-example',
          generation: 1742338539536352,
          object: 'objects/archive.tar.gz',
          output: '.objects_archive.tar.gz',
          path: 'src/gcs',
          sha256: 'a'.repeat(64),
          size: 19,
        }],
        schemaVersion: 1,
      }),
      parsed.dependencies,
    );
    assert.deepEqual(
      locked.find((entry) => entry.type === 'gcs'),
      {
        bucket: 'chromium-example',
        generation: 1742338539536352,
        object: 'objects/archive.tar.gz',
        output: '.objects_archive.tar.gz',
        path: 'src/gcs',
        sha256: 'a'.repeat(64),
        size: 19,
        type: 'gcs',
        url: 'gs://chromium-example/objects/archive.tar.gz',
      },
    );
    assert.doesNotThrow(() => assertGcsDependenciesLockable(locked));
    assert.throws(
      () => parseGclientRevinfo(
        revinfo({
          'src/gcs:different-object': {
            rev: null,
            url: 'gs://chromium-example/objects/archive.tar.gz',
          },
        }),
        BASELINE,
        RUNTIME,
      ),
      /object does not match its URL/,
    );
    assert.throws(
      () => bindGcsDependencyMetadata(
        JSON.stringify({
          dependencies: [{
            bucket: 'other-bucket',
            generation: 1742338539536352,
            object: 'objects/archive.tar.gz',
            output: '.objects_archive.tar.gz',
            path: 'src/gcs',
            sha256: 'a'.repeat(64),
            size: 19,
          }],
          schemaVersion: 1,
        }),
        parsed.dependencies,
      ),
      /metadata differs from revinfo|metadata is missing|does not describe exactly/,
    );
    assert.throws(
      () => bindGcsDependencyMetadata(
        JSON.stringify({
          dependencies: [{
            bucket: 'chromium-example',
            generation: 0,
            object: 'objects/archive.tar.gz',
            output: '../archive.tar.gz',
            path: 'src/gcs',
            sha256: 'not-a-digest',
            size: -1,
          }],
          schemaVersion: 1,
        }),
        parsed.dependencies,
      ),
      /unsafe segment|invalid/,
    );
  });

  check('GCS audit re-hashes the retained object and requires completion markers', () => {
    const clientRoot = join(TEMP, 'gcs-audit-root');
    const dependencyRoot = join(clientRoot, 'src', 'gcs');
    mkdirSync(dependencyRoot, { recursive: true });
    const bytes = Buffer.from('pinned GCS object fixture\n');
    const digest = createHash('sha256').update(bytes).digest('hex');
    const output = '.objects_archive.tar.gz';
    const prefix = 'objects_archive_tar_gz';
    writeFileSync(join(dependencyRoot, output), bytes);
    writeFileSync(join(dependencyRoot, `.${prefix}_hash`), `${digest}\n`);
    writeFileSync(
      join(dependencyRoot, `.${prefix}_is_first_class_gcs`),
      '1\n',
    );
    const dependency = {
      bucket: 'chromium-example',
      generation: 1742338539536352,
      object: 'objects/archive.tar.gz',
      output,
      path: 'src/gcs',
      sha256: digest,
      size: bytes.length,
      type: 'gcs',
      url: 'gs://chromium-example/objects/archive.tar.gz',
    };
    assert.deepEqual(
      auditGcsDependencies(clientRoot, [dependency]),
      ['src/gcs:objects/archive.tar.gz'],
    );

    appendFileSync(join(dependencyRoot, output), 'tampered');
    assert.throws(
      () => auditGcsDependencies(clientRoot, [dependency]),
      /byte size differs from DEPS/,
    );
    writeFileSync(join(dependencyRoot, output), bytes);
    writeFileSync(join(dependencyRoot, `.${prefix}_hash`), `${'0'.repeat(64)}\n`);
    assert.throws(
      () => auditGcsDependencies(clientRoot, [dependency]),
      /hash marker is stale/,
    );
  });

  check('GCS audit rejects output symlinks even when their target has pinned bytes', () => {
    const clientRoot = join(TEMP, 'gcs-symlink-root');
    const dependencyRoot = join(clientRoot, 'src', 'gcs');
    mkdirSync(dependencyRoot, { recursive: true });
    const bytes = Buffer.from('pinned GCS symlink fixture\n');
    const digest = createHash('sha256').update(bytes).digest('hex');
    const target = join(clientRoot, 'target.bin');
    writeFileSync(target, bytes);
    symlinkSync(target, join(dependencyRoot, 'output.bin'));
    writeFileSync(join(dependencyRoot, '.object_bin_hash'), `${digest}\n`);
    writeFileSync(
      join(dependencyRoot, '.object_bin_is_first_class_gcs'),
      '1\n',
    );
    assert.throws(
      () => auditGcsDependencies(clientRoot, [{
        bucket: 'chromium-example',
        generation: 1742338539536352,
        object: 'object.bin',
        output: 'output.bin',
        path: 'src/gcs',
        sha256: digest,
        size: bytes.length,
        type: 'gcs',
        url: 'gs://chromium-example/object.bin',
      }]),
      /escapes or aliases|ordinary non-symlink file/,
    );
  });

  check('clean nested Git checkout passes the complete local audit', () => {
    const fixture = nestedGitFixture();
    assert.deepEqual(
      auditNestedGitDependencies(
        fixture.clientRoot,
        [fixture.dependency],
        { environment: process.env, git: GIT },
      ),
      ['src/third_party/example'],
    );
  });

  check('nested Git dependency path must be the repository root', () => {
    const fixture = nestedGitFixture();
    const child = join(fixture.checkout, 'child');
    mkdirSync(child);
    assert.throws(
      () => auditNestedGitDependencies(
        fixture.clientRoot,
        [{
          ...fixture.dependency,
          path: 'src/third_party/example/child',
        }],
        { git: GIT },
      ),
      /not a repository root/,
    );
  });

  check('nested Git audit rejects tracked worktree and index modifications', () => {
    const dirtyWorktree = nestedGitFixture();
    appendFileSync(join(dirtyWorktree.checkout, 'tracked.txt'), 'dirty\n');
    assert.throws(
      () => auditNestedGitDependencies(
        dirtyWorktree.clientRoot,
        [dirtyWorktree.dependency],
        { git: GIT },
      ),
      /worktree differs from its index/,
    );

    const dirtyIndex = nestedGitFixture();
    appendFileSync(join(dirtyIndex.checkout, 'tracked.txt'), 'staged\n');
    git(dirtyIndex.checkout, ['add', 'tracked.txt']);
    assert.throws(
      () => auditNestedGitDependencies(
        dirtyIndex.clientRoot,
        [dirtyIndex.dependency],
        { git: GIT },
      ),
      /index tree is modified/,
    );
  });

  check('nested Git audit rejects untracked files and non-default index flags', () => {
    const untracked = nestedGitFixture();
    writeFileSync(join(untracked.checkout, 'untracked.txt'), 'not locked\n');
    assert.throws(
      () => auditNestedGitDependencies(
        untracked.clientRoot,
        [untracked.dependency],
        { git: GIT },
      ),
      /untracked non-ignored files/,
    );

    const flagged = nestedGitFixture();
    git(flagged.checkout, ['update-index', '--assume-unchanged', 'tracked.txt']);
    assert.throws(
      () => auditNestedGitDependencies(
        flagged.clientRoot,
        [flagged.dependency],
        { git: GIT },
      ),
      /non-default index flags/,
    );
  });

  check('nested Git audit ignores ambient GIT_DIR and GIT_WORK_TREE redirects', () => {
    const fixture = nestedGitFixture();
    const decoy = nestedGitFixture();
    const environment = {
      ...process.env,
      GIT_DIR: join(decoy.checkout, '.git'),
      GIT_WORK_TREE: decoy.checkout,
    };
    assert.deepEqual(
      auditNestedGitDependencies(
        fixture.clientRoot,
        [fixture.dependency],
        { environment, git: GIT },
      ),
      ['src/third_party/example'],
    );
  });

  check('nested Git audit binds the exact origin and HEAD from revinfo', () => {
    const fixture = nestedGitFixture();
    assert.throws(
      () => auditNestedGitDependencies(
        fixture.clientRoot,
        [{ ...fixture.dependency, url: 'https://example.test/other.git' }],
        { git: GIT },
      ),
      /origin differs from revinfo/,
    );
    assert.throws(
      () => auditNestedGitDependencies(
        fixture.clientRoot,
        [{ ...fixture.dependency, commit: NESTED_COMMIT }],
        { git: GIT },
      ),
      /is unusable|HEAD differs from revinfo/,
    );
  });

  check('CIPD ensure file uses exact instances with paranoid integrity', () => {
    const contents = renderCipdEnsureFile([
      {
        declaredPackage: 'tools/example/${platform}',
        instanceId: INSTANCE,
        package: 'tools/example/linux-amd64',
        path: 'src/tools',
        serviceUrl: 'https://chrome-infra-packages.appspot.com',
        type: 'cipd',
      },
    ]);
    assert.equal(
      contents,
      '$ServiceURL https://chrome-infra-packages.appspot.com\n'
      + '$ParanoidMode CheckIntegrity\n'
      + '$OverrideInstallMode copy\n\n'
      + '@Subdir src/tools\n'
      + `tools/example/linux-amd64 ${INSTANCE}\n\n`,
    );
  });

  check('CIPD dry-run result requires status 5 and an empty action map', () => {
    assert.deepEqual(
      assertCipdDryRunResult('{"result":{}}', 5),
      { actions: 0, status: 5 },
    );
    assert.deepEqual(
      assertCipdDryRunResult('{"result":null}', 5),
      { actions: 0, status: 5 },
    );
    assert.throws(
      () => assertCipdDryRunResult(
        '{"result":{"src/tools":{"to_install":["example"]}}}',
        0,
      ),
      /planned one or more/,
    );
    assert.throws(
      () => assertCipdDryRunResult('{"error":"offline resolution failed"}', 0),
      /offline resolution failed/,
    );
    assert.throws(
      () => assertCipdDryRunResult('{"result":{},"result":{}}', 5),
      /duplicate object key "result"/,
    );
  });

  check('CIPD audit invokes the pinned client offline and never accepts repairs', () => {
    const clientRoot = join(TEMP, 'cipd-root');
    mkdirSync(join(clientRoot, 'src', 'tools'), { recursive: true });
    let invoked = false;
    const audit = runCipdIntegrityAudit(
      clientRoot,
      [{
        declaredPackage: 'tools/example/${platform}',
        instanceId: INSTANCE,
        package: 'tools/example/linux-amd64',
        path: 'src/tools',
        serviceUrl: 'https://chrome-infra-packages.appspot.com',
        type: 'cipd',
      }],
      { path: join(TEMP, 'fake-cipd') },
      {
        environment: {
          ...process.env,
          CIPD_PROXY_URL: 'unix:///attacker',
          GIT_DIR: '/attacker',
        },
        invoke(executable, args, environment) {
          invoked = true;
          assert.equal(executable, join(TEMP, 'fake-cipd'));
          assert.ok(args.includes('-disable-network'));
          assert.equal(environment.CIPD_DISABLE_NETWORK, '1');
          assert.equal(environment.CIPD_PROXY_URL, undefined);
          assert.equal(environment.GIT_DIR, undefined);
          const ensurePath = args[args.indexOf('-ensure-file') + 1];
          const resultPath = args[args.indexOf('-json-output') + 1];
          assert.match(readFileSync(ensurePath, 'utf8'), /\$ParanoidMode CheckIntegrity/u);
          writeFileSync(resultPath, '{"result":{}}');
          return { error: undefined, signal: null, status: 5 };
        },
      },
    );
    assert.equal(invoked, true);
    assert.deepEqual(audit, {
      actions: 0,
      packages: 1,
      skipped: false,
      status: 5,
    });
  });

  check('CIPD dependency roots must resolve to ordinary contained directories', () => {
    const clientRoot = join(TEMP, 'cipd-contained-root');
    mkdirSync(join(clientRoot, 'src', 'tools'), { recursive: true });
    assert.deepEqual(
      auditCipdDependencyPaths(clientRoot, [{
        path: 'src/tools',
        type: 'cipd',
      }]),
      ['src/tools'],
    );
    assert.throws(
      () => auditCipdDependencyPaths(clientRoot, [{
        path: '../outside',
        type: 'cipd',
      }]),
      /escapes or aliases/,
    );
  });

  check('pinned gclient revinfo receives sanitized Git and CIPD environment', () => {
    const depot = join(TEMP, 'gclient-invocation-depot');
    mkdirSync(depot);
    const cipdPath = join(TEMP, 'pinned-cipd');
    const cipdBytes = Buffer.from('pinned gclient CIPD fixture\n');
    writeFileSync(cipdPath, cipdBytes);
    let invoked = false;
    const output = runPinnedGclientRevinfo(
      TEMP,
      depot,
      {
        path: cipdPath,
        sha256: createHash('sha256').update(cipdBytes).digest('hex'),
      },
      {
        environment: {
          ...process.env,
          CIPD_PROXY_URL: 'unix:///attacker',
          GCLIENT_FILE: '/attacker/.gclient',
          GIT_DIR: '/attacker/.git',
          PYTHONPATH: '/attacker/python',
        },
        invoke(executable, args, cwd, environment) {
          invoked = true;
          assert.equal(
            executable,
            join(depot, process.platform === 'win32' ? 'gclient.bat' : 'gclient'),
          );
          assert.deepEqual(args, ['revinfo', '--actual', '--output-json=-']);
          assert.equal(cwd, TEMP);
          assert.equal(environment.CIPD_PROXY_URL, undefined);
          assert.equal(environment.GCLIENT_FILE, undefined);
          assert.equal(environment.GIT_DIR, undefined);
          assert.equal(environment.PYTHONPATH, undefined);
          if (process.platform === 'win32') {
            assert.equal(environment.CUSTOM_CIPD_CLIENT, undefined);
            assert.match(environment.PATH, /proteus-cipd-command-/u);
          } else {
            assert.equal(environment.CUSTOM_CIPD_CLIENT, cipdPath);
          }
          assert.equal(environment.DEPOT_TOOLS_UPDATE, '0');
          return revinfo();
        },
      },
    );
    assert.equal(invoked, true);
    assert.equal(output, revinfo());
  });

  check('pinned gclient resolution exporter writes revinfo and GCS metadata together', () => {
    const fixture = depotBootstrapFixture('gclient-resolution-depot');
    const cipdPath = join(TEMP, 'resolution-pinned-cipd');
    writeFileSync(cipdPath, 'pinned resolution CIPD fixture\n');
    const gcsMetadata = JSON.stringify({
      dependencies: [{
        bucket: 'chromium-example',
        generation: 1742338539536352,
        object: 'objects/archive.tar.gz',
        output: '.objects_archive.tar.gz',
        path: 'src/gcs',
        sha256: 'a'.repeat(64),
        size: 19,
      }],
      schemaVersion: 1,
    });
    let invoked = false;
    const resolution = runPinnedGclientResolution(
      TEMP,
      fixture.depot,
      {
        path: cipdPath,
        sha256: createHash('sha256')
          .update(readFileSync(cipdPath))
          .digest('hex'),
      },
      {
        environment: {
          ...process.env,
          CIPD_PROXY_URL: 'unix:///attacker',
          GCLIENT_FILE: '/attacker/.gclient',
          GIT_DIR: '/attacker/.git',
          PYTHONPATH: '/attacker/python',
        },
        invoke(executable, args, cwd, environment) {
          invoked = true;
          assert.equal(executable, join(
            fixture.root,
            process.platform === 'win32' ? 'vpython3.exe' : 'vpython3',
          ));
          assert.equal(cwd, TEMP);
          assert.equal(args.length, 7);
          assert.deepEqual(
            args.slice(0, 3),
            ['-vpython-spec', join(fixture.depot, '.vpython3'), '--'],
          );
          assert.equal(args[4], fixture.depot);
          assert.equal(environment.CIPD_PROXY_URL, undefined);
          assert.equal(environment.GCLIENT_FILE, undefined);
          assert.equal(environment.GIT_DIR, undefined);
          assert.equal(environment.PYTHONPATH, undefined);
          assert.equal(environment.DEPOT_TOOLS_UPDATE, '0');
          writeFileSync(args[5], revinfo({
            'src/gcs:objects/archive.tar.gz': {
              rev: null,
              url: 'gs://chromium-example/objects/archive.tar.gz',
            },
          }));
          writeFileSync(args[6], gcsMetadata);
          return { error: undefined, signal: null, status: 0 };
        },
      },
    );
    assert.equal(invoked, true);
    assert.match(resolution.revinfoRaw, /chromium-example/u);
    assert.equal(resolution.gcsMetadataRaw, gcsMetadata);
  });

  check('pinned CIPD client validation binds depot digest, platform, and version', () => {
    const depot = join(TEMP, 'fake-depot-tools');
    mkdirSync(depot);
    const binaryName = process.platform === 'win32'
      ? '.cipd_client.exe'
      : '.cipd_client';
    const binary = join(depot, binaryName);
    const bytes = Buffer.from('pinned cipd client fixture\n');
    const digest = createHash('sha256').update(bytes).digest('hex');
    writeFileSync(binary, bytes);
    writeFileSync(
      join(depot, 'cipd_client_version'),
      'git_revision:4444444444444444444444444444444444444444\n',
    );
    writeFileSync(
      join(depot, 'cipd_client_version.digests'),
      `linux-amd64 sha256 ${digest}\n`,
    );
    const client = validatePinnedCipdClient(depot, RUNTIME);
    assert.equal(client.sha256, digest);
    assert.equal(client.platform, 'linux-amd64');
    assert.equal(
      client.version,
      'git_revision:4444444444444444444444444444444444444444',
    );
    appendFileSync(binary, 'tampered');
    assert.throws(
      () => validatePinnedCipdClient(depot, RUNTIME),
      /bytes differ from the pinned depot_tools digest/,
    );
  });

  check('depot_tools bootstrap manifest cache mismatch is rejected before gclient', () => {
    const { depot, root } = depotBootstrapFixture('bootstrap-ready-depot');
    const ready = assertDepotToolsBootstrapReady(depot);
    assert.equal(ready.root, root);
    assert.match(ready.vpythonSha256, /^[0-9a-f]{64}$/u);
    appendFileSync(join(root, '.cipd_manifest.txt'), 'attacker-controlled\n');
    assert.throws(
      () => assertDepotToolsBootstrapReady(depot),
      /is stale; refusing an implicit repair/,
    );
  });

  check('depot_tools integrity ensure fixes paranoid mode and binds resolved versions', () => {
    const rendered = renderDepotToolsIntegrityEnsure(
      '$ParanoidMode VerifyPresence\n'
      + '$ResolvedVersions cipd_manifest.versions\n'
      + 'infra/tools/vpython/${platform} git_revision:fixture\n',
    );
    assert.match(
      rendered,
      /^\$ServiceURL https:\/\/chrome-infra-packages\.appspot\.com\n/u,
    );
    assert.equal(
      rendered.match(/\$ParanoidMode CheckIntegrity/gu)?.length,
      1,
    );
    assert.equal(
      rendered.match(/\$ResolvedVersions cipd_manifest\.versions/gu)?.length,
      1,
    );
    assert.throws(
      () => renderDepotToolsIntegrityEnsure(
        '$ResolvedVersions attacker-controlled.versions\n',
      ),
      /ResolvedVersions must name cipd_manifest\.versions/,
    );
    assert.throws(
      () => renderDepotToolsIntegrityEnsure(
        '$ResolvedVersions cipd_manifest.versions\n'
        + '$ResolvedVersions cipd_manifest.versions\n',
      ),
      /exactly one ResolvedVersions/,
    );
  });

  check('depot_tools bootstrap integrity audit is offline and action-free', () => {
    const fixture = depotBootstrapFixture('bootstrap-integrity-depot');
    const fakeClient = join(TEMP, 'bootstrap-fake-cipd');
    let invoked = false;
    const audit = runDepotToolsBootstrapIntegrityAudit(
      fixture.depot,
      { path: fakeClient },
      {
        environment: {
          ...process.env,
          CIPD_PROXY_URL: 'unix:///attacker',
          GIT_DIR: '/attacker',
        },
        invoke(executable, args, environment) {
          invoked = true;
          assert.equal(executable, fakeClient);
          assert.ok(args.includes('-disable-network'));
          assert.equal(
            args[args.indexOf('-root') + 1],
            fixture.root,
          );
          assert.equal(environment.CIPD_DISABLE_NETWORK, '1');
          assert.equal(environment.CIPD_PROXY_URL, undefined);
          assert.equal(environment.GIT_DIR, undefined);
          const ensurePath = args[args.indexOf('-ensure-file') + 1];
          const versionsPath = join(dirname(ensurePath), 'cipd_manifest.versions');
          const resultPath = args[args.indexOf('-json-output') + 1];
          assert.match(
            readFileSync(ensurePath, 'utf8'),
            /\$ParanoidMode CheckIntegrity/u,
          );
          assert.equal(readFileSync(versionsPath, 'utf8'), fixture.versions);
          writeFileSync(resultPath, '{"result":{}}');
          return { error: undefined, signal: null, status: 5 };
        },
      },
    );
    assert.equal(invoked, true);
    assert.equal(audit.actions, 0);
    assert.equal(audit.status, 5);
    assert.match(audit.manifestSha256, /^[0-9a-f]{64}$/u);
    assert.match(audit.versionsSha256, /^[0-9a-f]{64}$/u);
    assert.match(audit.vpythonSha256, /^[0-9a-f]{64}$/u);
  });

  check('depot_tools bootstrap audit rejects tamper repairs and planned installs', () => {
    const fixture = depotBootstrapFixture('bootstrap-attack-depot');
    const auditWithResult = (raw, status) => runDepotToolsBootstrapIntegrityAudit(
      fixture.depot,
      { path: join(TEMP, 'bootstrap-attack-fake-cipd') },
      {
        invoke(_executable, args) {
          const resultPath = args[args.indexOf('-json-output') + 1];
          writeFileSync(resultPath, raw);
          return { error: undefined, signal: null, status };
        },
      },
    );
    assert.throws(
      () => auditWithResult(
        '{"result":{"":{"to_repair":["infra/tools/vpython/linux-amd64"]}}}',
        0,
      ),
      /bootstrap CIPD integrity audit failed: .*planned one or more/,
    );
    assert.throws(
      () => auditWithResult(
        '{"result":{"":{"to_install":["infra/tools/new-tool/linux-amd64"]}}}',
        0,
      ),
      /bootstrap CIPD integrity audit failed: .*planned one or more/,
    );
  });

  check('canonical dependency lock is deterministic and newline terminated', () => {
    const { dependencies, revinfoSha256 } = parseGclientRevinfo(
      revinfo({
        'src/dependency': {
          rev: NESTED_COMMIT,
          url: 'https://example.test/dependency.git',
        },
      }),
      BASELINE,
      RUNTIME,
    );
    const lock = assembleDependencyLock({
      baseline: BASELINE,
      depotBootstrap: {
        manifestSha256: '8'.repeat(64),
        vpythonSha256: '7'.repeat(64),
        versionsSha256: '9'.repeat(64),
      },
      cipdClient: {
        platform: 'linux-amd64',
        sha256: '5'.repeat(64),
        version: 'git_revision:4444444444444444444444444444444444444444',
      },
      dependencies,
      gclientConfigSha256: '6'.repeat(64),
      revinfoSha256,
      runtime: RUNTIME,
    });
    const first = canonicalDependencyLock(lock);
    const second = canonicalDependencyLock({ ...lock });
    assert.equal(first, second);
    assert.ok(first.endsWith('\n'));
    assert.equal(JSON.parse(first).schemaVersion, 1);
    assert.equal(JSON.parse(first).dependencies.length, 2);
    assert.equal(
      JSON.parse(first).depotTools.cipdBootstrap.resolvedVersionsSha256,
      '9'.repeat(64),
    );
  });

  console.log(`1..${passed}`);
} finally {
  rmSync(TEMP, { force: true, recursive: true });
}
