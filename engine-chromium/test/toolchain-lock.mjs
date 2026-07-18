#!/usr/bin/env node
// Standalone attack-oriented tests for the complete M0 toolchain lock.
// Fixtures are deliberately tiny and local; no Chromium checkout, SDK, or
// network access is required.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  appendFileSync,
  chmodSync,
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
  assembleToolchainLock,
  canonicalToolchainLock,
  captureToolchainLock,
  controlledToolchainEnvironment,
  discoverLinuxPlatformToolchain,
  discoverWindowsPlatformToolchain,
  hashCompleteDirectoryTree,
  parseEffectiveGnArgs,
  runControlledCommand,
  validateToolchainLockDocument,
  verifyToolchainLock,
} from '../scripts/toolchain-lock.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const TEMP = realpathSync(mkdtempSync(
  join(realpathSync(tmpdir()), 'proteus-toolchain-lock-test-'),
));
const ZERO_COMMIT = '1'.repeat(40);
const OTHER_COMMIT = '2'.repeat(40);
const SHA256 = '3'.repeat(64);
const REQUIRED_NINJA_TOOLS = Object.freeze([
  'autoninja-driver',
  'autoninja-wrapper',
  'clang',
  'depot-python-binary',
  'depot-python-selector',
  'depot-python-wrapper',
  'git',
  'gn-binary',
  'gn-driver',
  'gn-wrapper',
  'host-python',
  'lld',
  'ninja-binary',
  'ninja-driver',
  'node',
]);
const NON_EXECUTABLE = new Set([
  'autoninja-driver',
  'depot-python-selector',
  'gn-driver',
  'ninja-driver',
]);

let passed = 0;
let fixtureNumber = 0;

function check(name, body) {
  try {
    body();
  } catch (error) {
    throw new Error(`${name}: ${error.message}`, { cause: error });
  }
  passed += 1;
  console.log(`ok ${passed} - ${name}`);
}

function makeExecutable(path, contents) {
  writeFileSync(path, contents);
  chmodSync(path, 0o755);
}

function fixture() {
  fixtureNumber += 1;
  const root = join(TEMP, `fixture-${fixtureNumber}`);
  const clientRoot = join(root, 'client');
  const source = join(clientRoot, 'src');
  const outDir = join(source, 'out', 'Proteus');
  const depotTools = join(root, 'depot_tools');
  const sysroot = join(source, 'build', 'linux', 'fixture-sysroot');
  const toolRoot = join(root, 'tools');
  mkdirSync(outDir, { recursive: true });
  mkdirSync(depotTools, { recursive: true });
  mkdirSync(join(sysroot, 'etc'), { recursive: true });
  mkdirSync(join(sysroot, 'usr', 'lib'), { recursive: true });
  mkdirSync(toolRoot, { recursive: true });

  const effectiveArgsPath = join(outDir, 'effective-args.gn');
  const effectiveArgsText = [
    'cc_wrapper = ""',
    'disable_sandbox = false',
    'generate_about_credits = true',
    'google_api_key = ""',
    'google_default_client_id = ""',
    'google_default_client_secret = ""',
    'is_debug = false',
    'is_official_build = true',
    'target_cpu = "x64"',
    'target_sysroot = "//build/linux/fixture-sysroot"',
    'use_goma = false',
    'use_official_google_api_keys = false',
    'use_remoteexec = false',
    'use_siso = false',
    'use_sysroot = true',
    '',
  ].join('\n');
  writeFileSync(effectiveArgsPath, effectiveArgsText);
  makeExecutable(join(outDir, 'chrome'), '#!/bin/sh\nexit 0\n');
  const versionPath = join(sysroot, 'etc', 'debian_version');
  writeFileSync(versionPath, 'fixture-1\n');
  writeFileSync(join(sysroot, 'usr', 'lib', 'libfixture.a'), 'archive\n');

  const buildContractPath = join(root, 'm0-build-contract.json');
  const trustContractPath = join(root, 'm0-trust.json');
  const dependencyLockPath = join(root, 'dependencies.json');
  const effectiveArgsRecordPath = join(root, 'effective-args.json');
  writeFileSync(buildContractPath, '{"fixture":"build"}\n');
  writeFileSync(trustContractPath, '{"fixture":"trust"}\n');
  writeFileSync(dependencyLockPath, '{"fixture":"dependencies"}\n');
  writeFileSync(
    effectiveArgsRecordPath,
    `${JSON.stringify({
      schemaVersion: '1.0.0',
      documentKind: 'effective-gn-args',
      platform: 'linux-x64',
      configurations: [{
        architecture: 'x86_64',
        outDir: 'out/Proteus',
        argsSha256: createHash('sha256')
          .update(effectiveArgsText)
          .digest('hex'),
        argsSize: Buffer.byteLength(effectiveArgsText),
        argsText: effectiveArgsText,
      }],
    }, null, 2)}\n`,
  );

  const toolPaths = REQUIRED_NINJA_TOOLS.map((id) => {
    const path = join(toolRoot, id);
    makeExecutable(path, `#!/bin/sh\n# ${id}\nexit 0\n`);
    return {
      executable: !NON_EXECUTABLE.has(id),
      id,
      path,
    };
  });
  const platformSpec = Object.freeze({
    architectures: Object.freeze(['x86_64']),
    entrypoint: 'chrome',
    hostPlatform: 'linux',
  });
  const platformToolchain = Object.freeze({
    evidence: Object.freeze([
      Object.freeze({ id: 'sysroot-version', path: versionPath }),
    ]),
    kind: 'linux-sysroot',
    metadata: Object.freeze({
      targetSysroot: '//build/linux/fixture-sysroot',
      version: 'fixture-1',
    }),
    roots: Object.freeze([
      Object.freeze({ id: 'linux-sysroot', path: sysroot }),
    ]),
  });
  const inventory = {
    buildContractPath,
    clientRoot,
    configurations: [{
      architecture: 'x86_64',
      effectiveArgsPath,
      outDir,
      toolPaths,
    }],
    dependencyLockPath,
    depotTools,
    effectiveArgsRecordPath,
    hostPlatform: 'linux',
    platform: 'linux-x64',
    platformSpec,
    platformToolchain,
    source: {
      chromiumCommit: ZERO_COMMIT,
      chromiumRepository:
        'https://chromium.googlesource.com/chromium/src.git',
      chromiumVersion: '150.0.7871.124',
      depotToolsCommit: OTHER_COMMIT,
      depotToolsRepository:
        'https://chromium.googlesource.com/chromium/tools/depot_tools.git',
      patchProfile: 'm0-layer0-v1',
      patchSeriesSha256: SHA256,
      repository: 'example/proteus',
    },
    trustContractPath,
  };
  return {
    dependencyLockPath,
    effectiveArgsPath,
    effectiveArgsRecordPath,
    inventory,
    lockPath: join(root, 'toolchain-lock.json'),
    outDir,
    root,
    source,
    sysroot,
    toolPaths,
  };
}

function collectorFor(item) {
  return () => assembleToolchainLock(item.inventory);
}

function macFixture() {
  fixtureNumber += 1;
  const root = join(TEMP, `mac-fixture-${fixtureNumber}`);
  const clientRoot = join(root, 'client');
  const source = join(clientRoot, 'src');
  const depotTools = join(root, 'depot_tools');
  const xcode = join(root, 'Xcode.app');
  const sdk = join(
    xcode,
    'Contents',
    'Developer',
    'Platforms',
    'MacOSX.platform',
    'Developer',
    'SDKs',
    'MacOSX.sdk',
  );
  const universalOutDir = join(source, 'out', 'Proteus-universal');
  const entrypoint = join('Chromium.app', 'Contents', 'MacOS', 'Chromium');
  mkdirSync(depotTools, { recursive: true });
  mkdirSync(join(sdk, 'usr', 'include'), { recursive: true });
  mkdirSync(dirname(join(universalOutDir, entrypoint)), { recursive: true });
  writeFileSync(join(sdk, 'SDKSettings.json'), '{"Version":"fixture"}\n');
  writeFileSync(join(sdk, 'usr', 'include', 'fixture.h'), '/* sdk */\n');
  makeExecutable(
    join(universalOutDir, entrypoint),
    '#!/bin/sh\n# universal\nexit 0\n',
  );

  const configurations = [];
  const recordConfigurations = [];
  for (const [architecture, cpu, name] of [
    ['x86_64', 'x64', 'Proteus-x64'],
    ['arm64', 'arm64', 'Proteus-arm64'],
  ]) {
    const outDir = join(source, 'out', name);
    mkdirSync(dirname(join(outDir, entrypoint)), { recursive: true });
    makeExecutable(
      join(outDir, entrypoint),
      `#!/bin/sh\n# ${architecture}\nexit 0\n`,
    );
    const text = [
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
      'use_siso = false',
      '',
    ].join('\n');
    const effectiveArgsPath = join(outDir, 'effective-args.gn');
    writeFileSync(effectiveArgsPath, text);
    const toolRoot = join(root, 'tools', architecture);
    mkdirSync(toolRoot, { recursive: true });
    const toolPaths = REQUIRED_NINJA_TOOLS.map((id) => {
      const path = join(toolRoot, id);
      makeExecutable(path, `#!/bin/sh\n# ${architecture}-${id}\nexit 0\n`);
      return {
        executable: !NON_EXECUTABLE.has(id),
        id,
        path,
      };
    });
    configurations.push({
      architecture,
      effectiveArgsPath,
      outDir,
      toolPaths,
    });
    recordConfigurations.push({
      architecture,
      outDir: `out/${name}`,
      argsSha256: createHash('sha256').update(text).digest('hex'),
      argsSize: Buffer.byteLength(text),
      argsText: text,
    });
  }

  const effectiveArgsRecordPath = join(root, 'effective-args.json');
  writeFileSync(
    effectiveArgsRecordPath,
    `${JSON.stringify({
      schemaVersion: '1.0.0',
      documentKind: 'effective-gn-args',
      platform: 'macos-universal',
      configurations: recordConfigurations,
    }, null, 2)}\n`,
  );
  const buildContractPath = join(root, 'm0-build-contract.json');
  const trustContractPath = join(root, 'm0-trust.json');
  const dependencyLockPath = join(root, 'dependencies.json');
  writeFileSync(buildContractPath, '{"fixture":"build"}\n');
  writeFileSync(trustContractPath, '{"fixture":"trust"}\n');
  writeFileSync(dependencyLockPath, '{"fixture":"dependencies"}\n');
  const universalizerPath = join(
    source,
    'chrome',
    'installer',
    'mac',
    'universalizer.py',
  );
  mkdirSync(dirname(universalizerPath), { recursive: true });
  writeFileSync(universalizerPath, '# fixture universalizer\n');
  const pythonPath = join(root, 'python3');
  const lipoPath = join(root, 'lipo');
  makeExecutable(pythonPath, '#!/bin/sh\nexit 0\n');
  makeExecutable(lipoPath, '#!/bin/sh\nexit 0\n');

  return {
    inventory: {
      buildContractPath,
      clientRoot,
      configurations,
      dependencyLockPath,
      depotTools,
      effectiveArgsRecordPath,
      hostPlatform: 'darwin',
      packaging: {
        architectures: ['x86_64', 'arm64'],
        lipoPath,
        pythonPath,
        universalizerPath,
        universalOutDir,
      },
      platform: 'macos-universal',
      platformSpec: {
        architectures: ['x86_64', 'arm64'],
        entrypoint,
        hostPlatform: 'darwin',
      },
      platformToolchain: {
        evidence: [
          { id: 'macos-sdk-settings', path: join(sdk, 'SDKSettings.json') },
        ],
        kind: 'macos-xcode-sdk',
        metadata: {
          sdkVersion: 'fixture',
          useSystemXcode: false,
          xcodeVersion: 'fixture',
        },
        roots: [
          { id: 'macos-sdk', path: sdk },
          { id: 'xcode-installation', path: xcode },
        ],
        tools: [],
      },
      source: {
        chromiumCommit: ZERO_COMMIT,
        chromiumRepository:
          'https://chromium.googlesource.com/chromium/src.git',
        chromiumVersion: '150.0.7871.124',
        depotToolsCommit: OTHER_COMMIT,
        depotToolsRepository:
          'https://chromium.googlesource.com/chromium/tools/depot_tools.git',
        patchProfile: 'm0-layer0-v1',
        patchSeriesSha256: SHA256,
        repository: 'example/proteus',
      },
      trustContractPath,
    },
    root,
  };
}

if (process.platform === 'win32') {
  try {
    check('effective GN parser rejects ambiguous duplicates', () => {
      assert.throws(
        () => parseEffectiveGnArgs(
          'target_cpu = "x64"\ntarget_cpu = "arm64"\n',
        ),
        /repeat target_cpu/,
      );
      assert.deepEqual(
        { ...parseEffectiveGnArgs('target_cpu = "x64"\nuse_siso = false\n') },
        { target_cpu: '"x64"', use_siso: 'false' },
      );
    });

    check('Windows toolchain uses pinned Chromium selection evidence', () => {
      const root = join(TEMP, 'windows-selection');
      const source = join(root, 'source');
      const visualStudio = join(root, 'Visual Studio');
      const windowsSdk = join(root, 'Windows SDK');
      const sdkVersion = '10.0.26100.0';
      mkdirSync(source, { recursive: true });
      mkdirSync(visualStudio, { recursive: true });
      mkdirSync(
        join(windowsSdk, 'Include', sdkVersion, 'um'),
        { recursive: true },
      );
      writeFileSync(
        join(windowsSdk, 'Include', sdkVersion, 'um', 'Windows.h'),
        '// fixture\n',
      );
      const selectionPath = join(root, 'windows-toolchain-selection.gn');
      writeFileSync(selectionPath, [
        `vs_path = ${JSON.stringify(visualStudio)}`,
        `sdk_version = ${JSON.stringify(sdkVersion)}`,
        `sdk_path = ${JSON.stringify(windowsSdk)}`,
        'vs_version = "2022"',
        'wdk_dir = ""',
        'runtime_dirs = "ignored-by-content-root-audit"',
        '',
      ].join('\n'));
      const discovered = discoverWindowsPlatformToolchain({
        effectiveArgs: Object.freeze({}),
        selectionPath,
        source,
      });
      assert.equal(discovered.metadata.visualStudioVersion, '2022');
      assert.equal(discovered.metadata.windowsSdkVersion, sdkVersion);
      assert.deepEqual(
        discovered.roots.map(({ id }) => id),
        ['visual-studio', 'windows-sdk'],
      );
      assert.equal(discovered.evidence[0].path, selectionPath);
    });

    console.log(`1..${passed}`);
    console.log(`native Windows toolchain contract tests passed from ${HERE}`);
  } finally {
    rmSync(TEMP, { force: true, recursive: true });
  }
} else try {
  check('fixture assembles a complete content-derived lock', () => {
    const item = fixture();
    const lock = assembleToolchainLock(item.inventory);
    assert.equal(lock.schemaVersion, '1.0.0');
    assert.equal(lock.completeness, 'complete');
    assert.equal(lock.platform, 'linux-x64');
    assert.deepEqual(lock.architectures, ['x86_64']);
    assert.equal(lock.configurations[0].architecture, 'x86_64');
    assert.equal(lock.configurations[0].effectiveGnArgs.backend, 'ninja');
    assert.equal(lock.configurations[0].buildTools.executor.backend, 'ninja');
    assert.match(
      lock.configurations[0].buildTools.runtimes.depotPython.binary.sha256,
      /^[0-9a-f]{64}$/u,
    );
    assert.match(
      lock.configurations[0].buildTools.runtimes.depotPython.selector.sha256,
      /^[0-9a-f]{64}$/u,
    );
    assert.match(
      lock.configurations[0].buildTools.runtimes.depotPython.wrapper.sha256,
      /^[0-9a-f]{64}$/u,
    );
    assert.equal(lock.platformToolchain.roots.length, 1);
    assert.match(
      lock.platformToolchain.roots[0].treeSha256,
      /^[0-9a-f]{64}$/u,
    );
    assert.equal(
      canonicalToolchainLock(lock),
      `${JSON.stringify(JSON.parse(canonicalToolchainLock(lock)), null, 2)}\n`,
    );
    assert.deepEqual(
      validateToolchainLockDocument(lock),
      {
        architectures: ['x86_64'],
        configurations: 1,
        platform: 'linux-x64',
        toolchainRoots: 1,
      },
    );
  });

  check('offline document validation rejects incomplete or rebound locks', () => {
    const item = fixture();
    const lock = structuredClone(assembleToolchainLock(item.inventory));
    const dependencyLockSha256 = lock.contracts.dependency.sha256;
    assert.equal(
      validateToolchainLockDocument(lock, {
        dependencyLockSha256,
      }).platform,
      'linux-x64',
    );
    lock.contracts.dependency.sha256 = '0'.repeat(64);
    assert.throws(
      () => validateToolchainLockDocument(lock, {
        dependencyLockSha256,
      }),
      /dependency lock digest is wrong/,
    );

    const incomplete = structuredClone(assembleToolchainLock(item.inventory));
    delete incomplete.configurations[0].buildTools.llvm.lld;
    assert.throws(
      () => validateToolchainLockDocument(incomplete),
      /must contain exactly/,
    );
  });

  check('capture and verify regenerate and compare the exact lock', () => {
    const item = fixture();
    const options = { lockPath: item.lockPath };
    const collector = collectorFor(item);
    const captured = captureToolchainLock(options, { collector });
    const verified = verifyToolchainLock(options, { collector });
    assert.equal(captured.sha256, verified.sha256);
    assert.equal(captured.configurations, 1);
    assert.equal(readFileSync(item.lockPath, 'utf8').endsWith('\n'), true);
  });

  check('macOS lock requires and binds both architecture outputs plus universal output', () => {
    const item = macFixture();
    const lock = assembleToolchainLock(item.inventory);
    assert.deepEqual(lock.architectures, ['x86_64', 'arm64']);
    assert.deepEqual(
      lock.configurations.map(({ architecture }) => architecture),
      ['x86_64', 'arm64'],
    );
    assert.equal(lock.configurations[0].effectiveGnArgs.targetCpu, 'x64');
    assert.equal(lock.configurations[1].effectiveGnArgs.targetCpu, 'arm64');
    assert.deepEqual(lock.packaging.architectures, ['x86_64', 'arm64']);
    assert.match(
      lock.packaging.universalOutput.tree.treeSha256,
      /^[0-9a-f]{64}$/u,
    );

    const missingArm = macFixture();
    missingArm.inventory.configurations =
      missingArm.inventory.configurations.slice(0, 1);
    assert.throws(
      () => assembleToolchainLock(missingArm.inventory),
      /must contain exactly: x86_64, arm64/,
    );

    const missingUniversal = macFixture();
    missingUniversal.inventory.packaging = null;
    assert.throws(
      () => assembleToolchainLock(missingUniversal.inventory),
      /complete macos-universal toolchain lock is incomplete/,
    );

    assert.throws(
      () => captureToolchainLock(
        {
          lockPath: join(
            item.inventory.packaging.universalOutDir,
            'toolchain-lock.json',
          ),
        },
        { collector: () => lock },
      ),
      /lock path must be outside the hashed universal output/,
    );
  });

  check('verification detects a modified build tool binary', () => {
    const item = fixture();
    const options = { lockPath: item.lockPath };
    const collector = collectorFor(item);
    captureToolchainLock(options, { collector });
    appendFileSync(
      item.toolPaths.find((entry) => entry.id === 'gn-binary').path,
      '# modified\n',
    );
    assert.throws(
      () => verifyToolchainLock(options, { collector }),
      /differ from their canonical record|differs from the complete live build toolchain/,
    );
  });

  check('verification detects modified effective GN args bytes', () => {
    const item = fixture();
    const options = { lockPath: item.lockPath };
    const collector = collectorFor(item);
    captureToolchainLock(options, { collector });
    appendFileSync(item.effectiveArgsPath, '# byte-level modification\n');
    assert.throws(
      () => verifyToolchainLock(options, { collector }),
      /differ from their canonical record|differs from the complete live build toolchain/,
    );
  });

  check('verification detects modified SDK/sysroot content', () => {
    const item = fixture();
    const options = { lockPath: item.lockPath };
    const collector = collectorFor(item);
    captureToolchainLock(options, { collector });
    writeFileSync(join(item.sysroot, 'usr', 'lib', 'added.a'), 'new input\n');
    assert.throws(
      () => verifyToolchainLock(options, { collector }),
      /differs from the complete live build toolchain/,
    );
  });

  check('wrong platform, host, and architecture are rejected', () => {
    const wrongPlatform = fixture();
    wrongPlatform.inventory.platform = 'unknown-platform';
    assert.throws(
      () => assembleToolchainLock(wrongPlatform.inventory),
      /unsupported M0 platform/,
    );

    const wrongHost = fixture();
    wrongHost.inventory.hostPlatform = 'darwin';
    assert.throws(
      () => assembleToolchainLock(wrongHost.inventory),
      /requires host linux, got darwin/,
    );

    const wrongArchitecture = fixture();
    wrongArchitecture.inventory.configurations[0].architecture = 'arm64';
    assert.throws(
      () => assembleToolchainLock(wrongArchitecture.inventory),
      /not an allowed architecture/,
    );
  });

  check('output and effective-args path substitution are rejected', () => {
    const outside = fixture();
    const foreignOut = join(outside.root, 'foreign-out');
    mkdirSync(foreignOut);
    outside.inventory.configurations[0].outDir = foreignOut;
    assert.throws(
      () => assembleToolchainLock(outside.inventory),
      /not strictly contained/,
    );

    const substitutedArgs = fixture();
    const foreignArgs = join(substitutedArgs.root, 'effective-args.gn');
    writeFileSync(foreignArgs, 'target_cpu = "x64"\nuse_siso = false\n');
    substitutedArgs.inventory.configurations[0].effectiveArgsPath = foreignArgs;
    assert.throws(
      () => assembleToolchainLock(substitutedArgs.inventory),
      /must be out-dir\/effective-args\.gn/,
    );
  });

  check('symlinked tools, roots, and external tree targets are rejected', () => {
    const linkedTool = fixture();
    const target = linkedTool.toolPaths[0].path;
    const link = join(linkedTool.root, 'linked-tool');
    symlinkSync(target, link);
    linkedTool.inventory.configurations[0].toolPaths =
      linkedTool.toolPaths.map((entry, index) =>
      index === 0 ? { ...entry, path: link } : entry);
    assert.throws(
      () => assembleToolchainLock(linkedTool.inventory),
      /ordinary non-symlink file/,
    );

    const linkedRoot = fixture();
    const rootLink = join(linkedRoot.root, 'linked-sysroot');
    symlinkSync(linkedRoot.sysroot, rootLink, 'dir');
    assert.throws(
      () => hashCompleteDirectoryTree(rootLink),
      /ordinary non-symlink directory/,
    );

    const escapingTree = join(linkedRoot.root, 'escaping-tree');
    mkdirSync(escapingTree);
    symlinkSync(linkedRoot.outDir, join(escapingTree, 'outside'), 'dir');
    assert.throws(
      () => hashCompleteDirectoryTree(escapingTree),
      /escapes the enumerated root/,
    );
  });

  check('ambient Git, SDK, loader, proxy, and runtime variables are removed', () => {
    const item = fixture();
    const git = item.toolPaths.find((entry) => entry.id === 'git').path;
    const poisoned = {
      DEVELOPER_DIR: '/attacker/xcode',
      GIT_CONFIG_GLOBAL: '/attacker/gitconfig',
      GIT_DIR: '/attacker/repository',
      GIT_WORK_TREE: '/attacker/worktree',
      HTTP_PROXY: 'http://attacker.invalid',
      LD_PRELOAD: '/attacker/inject.so',
      NODE_OPTIONS: '--require=/attacker/inject.cjs',
      PATH: '/attacker/bin',
      SDKROOT: '/attacker/sdk',
    };
    const clean = controlledToolchainEnvironment(poisoned, {
      gitPath: git,
      platform: 'linux',
    });
    for (const key of [
      'DEVELOPER_DIR',
      'GIT_CONFIG_GLOBAL',
      'GIT_DIR',
      'GIT_WORK_TREE',
      'HTTP_PROXY',
      'LD_PRELOAD',
      'NODE_OPTIONS',
      'SDKROOT',
    ]) {
      assert.equal(Object.hasOwn(clean, key), false, key);
    }
    assert.equal(clean.PATH.startsWith(dirname(git)), true);
    assert.equal(clean.PATH.includes('/attacker'), false);

    let invocation;
    const output = runControlledCommand(git, ['--fixture'], {
      cwd: item.outDir,
      environment: poisoned,
      invoke(executable, args, options) {
        invocation = { args, executable, options };
        return {
          signal: null,
          status: 0,
          stderr: Buffer.alloc(0),
          stdout: Buffer.from('controlled\n'),
        };
      },
      platform: 'linux',
    });
    assert.equal(output, 'controlled');
    assert.equal(invocation.executable, git);
    assert.equal(invocation.options.shell, false);
    assert.equal(Object.hasOwn(invocation.options.env, 'GIT_DIR'), false);
    assert.equal(invocation.options.env.PATH, '/usr/bin:/bin');
  });

  check('controlled commands reject relative or symlink executables', () => {
    const item = fixture();
    assert.throws(
      () => runControlledCommand('git', [], { cwd: item.outDir }),
      /absolute control-free path/,
    );
    const target = item.toolPaths[0].path;
    const link = join(item.root, 'command-link');
    symlinkSync(target, link);
    assert.throws(
      () => runControlledCommand(link, [], { cwd: item.outDir }),
      /ordinary non-symlink file/,
    );
  });

  check('effective GN parser rejects ambiguous duplicates', () => {
    assert.throws(
      () => parseEffectiveGnArgs(
        'target_cpu = "x64"\ntarget_cpu = "arm64"\n',
      ),
      /repeat target_cpu/,
    );
    assert.deepEqual(
      { ...parseEffectiveGnArgs('target_cpu = "x64"\nuse_siso = false\n') },
      { target_cpu: '"x64"', use_siso: 'false' },
    );
  });

  check('a version-only or host-sysroot Linux claim fails explicitly incomplete', () => {
    const item = fixture();
    assert.throws(
      () => discoverLinuxPlatformToolchain({
        effectiveArgs: parseEffectiveGnArgs(
          'use_sysroot = false\n'
            + 'target_sysroot = "//build/linux/fixture-sysroot"\n',
        ),
        source: item.source,
      }),
      /complete linux-x64 toolchain lock is incomplete: use_sysroot is not true/,
    );
    assert.throws(
      () => discoverLinuxPlatformToolchain({
        effectiveArgs: parseEffectiveGnArgs(
          'use_sysroot = true\n'
            + 'target_sysroot = "//build/linux/missing-sysroot"\n',
        ),
        source: item.source,
      }),
      /complete linux-x64 toolchain lock is incomplete/,
    );
  });

  check('Linux default sysroot is derived from the pinned GN selection file', () => {
    const item = fixture();
    const configRoot = join(item.source, 'build', 'config');
    mkdirSync(configRoot, { recursive: true });
    writeFileSync(
      join(configRoot, 'sysroot.gni'),
      'if (current_cpu == "x64") {\n'
        + '  sysroot = "$target_sysroot_dir/fixture-sysroot"\n'
        + '}\n',
    );
    const discovered = discoverLinuxPlatformToolchain({
      effectiveArgs: parseEffectiveGnArgs(
        'target_cpu = "x64"\n'
          + 'target_sysroot = ""\n'
          + 'target_sysroot_dir = "//build/linux"\n'
          + 'sysroot = ""\n'
          + 'use_sysroot = true\n',
      ),
      source: item.source,
    });
    assert.equal(
      discovered.metadata.selection,
      'pinned-sysroot-gni-default',
    );
    assert.equal(discovered.roots[0].path, item.sysroot);
    assert.equal(discovered.evidence.length, 2);
  });

  check('Windows toolchain uses pinned Chromium selection evidence', () => {
    const root = join(TEMP, 'windows-selection');
    const source = join(root, 'source');
    const visualStudio = join(root, 'Visual Studio');
    const windowsSdk = join(root, 'Windows SDK');
    const sdkVersion = '10.0.26100.0';
    mkdirSync(source, { recursive: true });
    mkdirSync(visualStudio, { recursive: true });
    mkdirSync(
      join(windowsSdk, 'Include', sdkVersion, 'um'),
      { recursive: true },
    );
    writeFileSync(
      join(windowsSdk, 'Include', sdkVersion, 'um', 'Windows.h'),
      '// fixture\n',
    );
    const selectionPath = join(root, 'windows-toolchain-selection.gn');
    writeFileSync(selectionPath, [
      `vs_path = ${JSON.stringify(visualStudio)}`,
      `sdk_version = ${JSON.stringify(sdkVersion)}`,
      `sdk_path = ${JSON.stringify(windowsSdk)}`,
      'vs_version = "2022"',
      'wdk_dir = ""',
      'runtime_dirs = "ignored-by-content-root-audit"',
      '',
    ].join('\n'));
    const discovered = discoverWindowsPlatformToolchain({
      effectiveArgs: Object.freeze({}),
      selectionPath,
      source,
    });
    assert.equal(discovered.metadata.visualStudioVersion, '2022');
    assert.equal(discovered.metadata.windowsSdkVersion, sdkVersion);
    assert.deepEqual(
      discovered.roots.map(({ id }) => id),
      ['visual-studio', 'windows-sdk'],
    );
    assert.equal(discovered.evidence[0].path, selectionPath);
  });

  console.log(`1..${passed}`);
  console.log(`toolchain lock tests passed from ${HERE}`);
} finally {
  rmSync(TEMP, { force: true, recursive: true });
}
