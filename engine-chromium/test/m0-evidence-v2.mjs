#!/usr/bin/env node

import Ajv2020 from 'ajv/dist/2020.js';
import {
  createHash,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  cpSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import {
  M0_EVIDENCE_V2_ASSURANCE_LEVEL,
  M0_EVIDENCE_V2_SCHEMA_VERSION,
  buildGhAttestationVerifyInvocation,
  defaultGithubApiVerifier,
  runnerReceiptSigningInput,
  verifyM0EvidenceV2,
  verifyM0EvidenceV2Document,
  verifySourcePolicyCheckout,
} from '../../scripts/m0-evidence-v2.mjs';
import {
  M0_EXTERNAL_EXECUTION_ISOLATION,
} from '../../scripts/m0-evidence.mjs';
import {
  createBundleManifest,
} from '../scripts/bundle-manifest.mjs';
import {
  createBuildDerivedSbom,
} from '../scripts/build-sbom.mjs';
import {
  createPackageRecord,
} from '../scripts/package-record.mjs';
import {
  sanitizedGitEnvironment,
} from '../scripts/git-env.mjs';
import {
  buildArtifactBaselineReport,
} from '../../verify-lab/src/artifact-report.mjs';
import {
  buildControlledProbeBinding,
} from '../../verify-lab/src/controlled-probe.mjs';
import {
  auditNetworkTimeNetLog,
} from '../../verify-lab/src/network-time-audit.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');
const PLATFORMS = [
  'windows-x64',
  'macos-universal',
  'linux-x64',
];
const SLOTS = ['A', 'B'];
const SIGNER_DIGEST = 'b'.repeat(40);
const GIT_PATH = process.platform === 'win32'
  ? 'C:\\Program Files\\Git\\cmd\\git.exe'
  : '/usr/bin/git';
const ENTRYPOINTS = {
  'windows-x64': 'chrome.exe',
  'macos-universal': 'Chromium.app/Contents/MacOS/Chromium',
  'linux-x64': 'chrome',
};
const HOST_PLATFORMS = {
  'windows-x64': 'win32',
  'macos-universal': 'darwin',
  'linux-x64': 'linux',
};
const RUNNER_LABELS = {
  'windows-x64': ['windows-latest'],
  'macos-universal': ['macos-latest'],
  'linux-x64': ['ubuntu-latest'],
};
const SELF_HOSTED_RUNNER_LABELS = {
  'windows-x64': ['self-hosted', 'Windows'],
  'macos-universal': ['self-hosted', 'macOS'],
  'linux-x64': ['self-hosted', 'Linux'],
};

let passed = 0;
let failed = 0;

function check(name, body) {
  let fixture;
  try {
    fixture = createFixture();
    body(fixture);
    passed += 1;
    console.log(`  ✅ ${name}`);
  } catch (error) {
    failed += 1;
    console.log(`  ❌ ${name}: ${error.message}`);
  } finally {
    if (fixture) {
      rmSync(fixture.repo, {
        force: true,
        maxRetries: 5,
        recursive: true,
      });
    }
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function createFixture() {
  const repo = realpathSync(mkdtempSync(
    join(realpathSync(tmpdir()), 'proteus-m0-evidence-v2-'),
  ));
  const artifacts = join(repo, 'engine-chromium', 'artifacts');
  const build = join(repo, 'engine-chromium', 'build');
  const layer0 = join(
    repo,
    'engine-chromium',
    'patches',
    'layer0-degoogle',
  );
  const keys = join(repo, '.github', 'keys');
  mkdirSync(artifacts, { recursive: true });
  mkdirSync(build, { recursive: true });
  mkdirSync(layer0, { recursive: true });
  mkdirSync(keys, { recursive: true });

  for (const name of ['m0-build-contract.json', 'm0-trust.json', 'args.gn']) {
    cpSync(
      join(REPO, 'engine-chromium', 'build', name),
      join(build, name),
    );
  }
  cpSync(
    join(REPO, 'engine-chromium', 'CHROMIUM_BASELINE'),
    join(repo, 'engine-chromium', 'CHROMIUM_BASELINE'),
  );
  cpSync(
    join(REPO, 'engine-chromium', 'patches', 'series'),
    join(repo, 'engine-chromium', 'patches', 'series'),
  );
  cpSync(
    join(
      REPO,
      'engine-chromium',
      'patches',
      'layer0-degoogle',
      '0001-disable-google-network-time.patch',
    ),
    join(layer0, '0001-disable-google-network-time.patch'),
  );

  const trust = JSON.parse(
    readFileSync(join(build, 'm0-trust.json'), 'utf8'),
  );
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPath = join(
    repo,
    trust.runnerTrust.externalEphemeral.publicKeyPath,
  );
  writeFileSync(
    publicKeyPath,
    publicKey.export({ format: 'pem', type: 'spki' }),
  );
  const keyId = createHash('sha256')
    .update(publicKey.export({ format: 'der', type: 'spki' }))
    .digest('hex');
  installPolicyCheckout(repo);
  const sourceDigest = git(repo, ['rev-parse', 'HEAD']).trim();
  const buildContractSha256 = sha256File(
    join(build, 'm0-build-contract.json'),
  );
  const buildContract = JSON.parse(
    readFileSync(join(build, 'm0-build-contract.json'), 'utf8'),
  );
  const trustContractSha256 = sha256File(join(build, 'm0-trust.json'));

  const evidence = {
    schemaVersion: M0_EVIDENCE_V2_SCHEMA_VERSION,
    assuranceLevel: M0_EVIDENCE_V2_ASSURANCE_LEVEL,
    repository: {
      nameWithOwner: trust.repository.nameWithOwner,
      repositoryId: trust.repository.repositoryId,
      ownerId: trust.repository.ownerId,
      visibility: trust.repository.visibility,
    },
    source: {
      digest: sourceDigest,
      ref: trust.sourceRef,
    },
    signer: {
      workflow: trust.workflows.builder,
      digest: SIGNER_DIGEST,
    },
    platforms: {},
  };
  const records = new Map();
  let id = 100000;
  for (const platform of PLATFORMS) {
    evidence.platforms[platform] = {};
    for (const slot of SLOTS) {
      id += 10;
      const relativeRoot = `v2/${platform}/${slot}`;
      const record = createBuildRecord({
        artifactId: String(id + 3),
        artifacts,
        buildContract,
        buildContractSha256,
        checkRunId: String(id + 2),
        keyId,
        platform,
        privateKey,
        relativeRoot,
        repo,
        repository: evidence.repository,
        runId: String(id + 1),
        signerWorkflow: evidence.signer.workflow,
        slot,
        sourceRef: evidence.source.ref,
        sourceDigest,
        signerDigest: SIGNER_DIGEST,
        trustContractSha256,
      });
      evidence.platforms[platform][slot] = record;
      records.set(`${platform}/${slot}`, record);
    }
  }

  const invocations = [];
  const fixture = {
    artifacts,
    buildContract,
    evidence,
    invocations,
    keyId,
    privateKey,
    publicKeyPath,
    records,
    repo,
    sourceDigest,
    trust,
  };
  fixture.attestationVerifier = goodAttestationVerifier(invocations);
  fixture.githubVerifier = goodGithubVerifier();
  writeEvidence(fixture);
  return fixture;
}

function git(repo, args) {
  const sourceEnvironment = {
    HOME: repo,
    PATH: dirname(GIT_PATH),
  };
  if (process.platform === 'win32') {
    sourceEnvironment.SystemRoot =
      process.env.SystemRoot ?? 'C:\\Windows';
    sourceEnvironment.TEMP = tmpdir();
    sourceEnvironment.TMP = tmpdir();
  } else {
    sourceEnvironment.TMPDIR = tmpdir();
  }
  return execFileSync(GIT_PATH, ['-C', repo, ...args], {
    encoding: 'utf8',
    env: sanitizedGitEnvironment(sourceEnvironment),
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
}

function installPolicyCheckout(repo) {
  const copies = [
    '.gitattributes',
    'package.json',
    'package-lock.json',
    'scripts/license-policy.mjs',
    'scripts/m0-exit-criteria.mjs',
    'scripts/m0-evidence-v2.mjs',
    'scripts/m0-evidence.mjs',
    'scripts/strict-json.mjs',
    'engine-chromium/scripts/artifact-licenses.mjs',
    'engine-chromium/scripts/build-contract.mjs',
    'engine-chromium/scripts/build-sbom.mjs',
    'engine-chromium/scripts/bundle-manifest.mjs',
    'engine-chromium/scripts/dependency-lock.mjs',
    'engine-chromium/scripts/effective-gn-args.mjs',
    'engine-chromium/scripts/git-env.mjs',
    'engine-chromium/scripts/package-engine.mjs',
    'engine-chromium/scripts/package-record.mjs',
    'engine-chromium/scripts/toolchain-lock.mjs',
    'engine-chromium/tracking-bot/pipeline.mjs',
    'verify-lab/data/reference.json',
    'verify-lab/probe-page/collect.js',
    'verify-lab/probe-page/headless.html',
    'verify-lab/src/controlled-probe.mjs',
    'verify-lab/src/network-time-audit.mjs',
    'verify-lab/src/normalize.mjs',
    'verify-lab/src/reference-util.mjs',
    'verify-lab/src/rules.mjs',
    'verify-lab/src/score.mjs',
    'verify-lab/src/static-path.mjs',
  ];
  for (const relative of copies) {
    const destination = join(repo, ...relative.split('/'));
    mkdirSync(dirname(destination), { recursive: true });
    cpSync(join(REPO, ...relative.split('/')), destination);
  }
  for (const name of ['m0-builder.yml', 'm0-aggregate.yml', 'm0-hard-gate.yml']) {
    const path = join(repo, '.github', 'workflows', name);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(
      path,
      `name: ${name}\non:\n  workflow_dispatch:\njobs:\n  fixture:\n    runs-on: ubuntu-latest\n    steps:\n      - run: 'true'\n`,
    );
  }
  git(repo, ['init', '-q', '-b', 'main']);
  git(repo, ['config', 'user.name', 'M0 fixture']);
  git(repo, ['config', 'user.email', 'm0-fixture@example.invalid']);
  git(repo, [
    'remote',
    'add',
    'origin',
    'https://github.com/jiyujie2006/proteus-browser.git',
  ]);
  git(repo, ['add', '.']);
  git(repo, ['commit', '-q', '-m', 'trusted M0 policy fixture']);
}

function createBuildRecord({
  artifactId,
  artifacts,
  buildContract,
  buildContractSha256,
  checkRunId,
  keyId,
  platform,
  privateKey,
  relativeRoot,
  repo,
  repository,
  runId,
  signerWorkflow,
  slot,
  sourceRef,
  sourceDigest,
  signerDigest,
  trustContractSha256,
}) {
  const bundleRootRelative = `${relativeRoot}/bundle`;
  const bundleRoot = join(artifacts, ...bundleRootRelative.split('/'));
  mkdirSync(bundleRoot, { recursive: true });
  const entrypoint = join(bundleRoot, ...ENTRYPOINTS[platform].split('/'));
  mkdirSync(dirname(entrypoint), { recursive: true });
  writeFileSync(entrypoint, executableFixture(platform));
  chmodSync(entrypoint, 0o755);
  writeFileSync(join(bundleRoot, 'resources.pak'), `resources ${platform}\n`);
  chmodSync(join(bundleRoot, 'resources.pak'), 0o644);
  writeFileSync(
    join(bundleRoot, 'BUILD-CONTRACT.json'),
    readFileSync(join(REPO, 'engine-chromium', 'build', 'm0-build-contract.json')),
  );
  chmodSync(join(bundleRoot, 'BUILD-CONTRACT.json'), 0o644);
  const licenseFiles = [
    {
      path: 'LICENSES/Proteus-Apache-2.0.txt',
      role: 'first-party-license',
      bytes: readFileSync(join(REPO, 'LICENSE')),
    },
    {
      path: 'LICENSES/Chromium-BSD-3-Clause.txt',
      role: 'engine-license',
      bytes: readFileSync(
        join(REPO, 'LICENSES', 'Chromium-BSD-3-Clause.txt'),
      ),
    },
    {
      path: 'LICENSES/Chromium-Third-Party-Credits.html',
      role: 'build-derived-third-party-notices',
      bytes: generatedCreditsFixture(),
    },
    {
      path: 'NOTICE',
      role: 'project-attribution',
      bytes: readFileSync(join(REPO, 'NOTICE')),
    },
  ];
  for (const file of licenseFiles) {
    const path = join(bundleRoot, ...file.path.split('/'));
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, file.bytes);
    chmodSync(path, 0o644);
  }

  const licenseManifest = {
    schemaVersion: '1.0.0',
    documentKind: 'artifact-license-bundle',
    platform,
    chromium: {
      repository: buildContract.source.chromiumRepository,
      version: buildContract.source.chromiumVersion,
      commit: buildContract.source.chromiumCommit,
    },
    buildContract: {
      path: 'BUILD-CONTRACT.json',
      sha256: buildContractSha256,
    },
    credits: {
      buildTarget: '//components/resources:about_credits',
      generator: '//tools/licenses/licenses.py credits',
      generatedPath: 'gen/components/resources/about_credits.html',
      architectures: [...buildContract.platforms[platform].architectures],
      entries: 25,
    },
    files: licenseFiles.map(({ path, role, bytes }) => ({
      path,
      role,
      sha256: digest(bytes),
      size: bytes.length,
    })),
  };
  const licenseBundle = writeBoundJson(
    artifacts,
    `${bundleRootRelative}/LICENSES/artifact-license-manifest.json`,
    licenseManifest,
  );
  const dependencyDocument = {
    architecture: 'x64',
    chromium: {
      commit: buildContract.source.chromiumCommit,
      repository: buildContract.source.chromiumRepository,
      stable: buildContract.source.chromiumVersion,
    },
    dependencies: [{
      commit: buildContract.source.chromiumCommit,
      path: 'src',
      type: 'git',
      url: buildContract.source.chromiumRepository,
    }],
    depotTools: {
      cipdBootstrap: {
        manifestSha256: '1'.repeat(64),
        resolvedVersionsSha256: '2'.repeat(64),
      },
      cipdClient: {
        platform: 'linux-amd64',
        sha256: '3'.repeat(64),
        version: 'git_revision:fixture',
      },
      commit: buildContract.source.depotToolsCommit,
      repository: buildContract.source.depotToolsRepository,
      vpython3: {
        platform: 'linux-amd64',
        sha256: '4'.repeat(64),
      },
    },
    gclientConfigSha256: 'd'.repeat(64),
    gclientRevinfoSha256: 'e'.repeat(64),
    platform: HOST_PLATFORMS[platform],
    schemaVersion: 1,
  };
  const dependencyLock = writeBoundJson(
    artifacts,
    `${relativeRoot}/dependencies.json`,
    dependencyDocument,
  );
  const effectiveDocument = effectiveGnArgsFixture(platform, buildContract);
  const effectiveGnArgs = writeBoundJson(
    artifacts,
    `${relativeRoot}/effective-args.json`,
    effectiveDocument,
  );
  const toolchainDocument = completeToolchainFixture({
    buildContract,
    buildContractSha256,
    dependencyLock,
    effectiveDocument,
    effectiveGnArgs,
    platform,
    repo,
    repository,
    trustContractSha256,
  });
  const toolchainLock = writeBoundJson(
    artifacts,
    `${relativeRoot}/toolchain.json`,
    toolchainDocument,
  );
  const packageRecord = createPackageRecord({
    platform,
    outDirRelative: platform === 'macos-universal'
      ? 'out/Proteus-universal'
      : effectiveDocument.configurations[0].outDir,
    runtimeDependencies: [
      ENTRYPOINTS[platform],
      'resources.pak',
    ],
    dependencyLockBytes: readFileSync(absoluteDescriptor(
      artifacts,
      dependencyLock,
    )),
    effectiveGnArgsBytes: readFileSync(absoluteDescriptor(
      artifacts,
      effectiveGnArgs,
    )),
    toolchainLockBytes: readFileSync(absoluteDescriptor(
      artifacts,
      toolchainLock,
    )),
    licenseManifestBytes: readFileSync(absoluteDescriptor(
      artifacts,
      licenseBundle,
    )),
    repoRoot: repo,
  });
  writeFileSync(
    join(bundleRoot, 'PACKAGE-RECORD.json'),
    `${JSON.stringify(packageRecord, null, 2)}\n`,
  );
  chmodSync(join(bundleRoot, 'PACKAGE-RECORD.json'), 0o644);

  const completeManifest = createBundleManifest(bundleRoot, {
    platform,
    entrypoint: ENTRYPOINTS[platform],
  });
  const treeSha256 = completeManifest.treeSha256;
  const bundleManifest = writeBoundJson(
    artifacts,
    `${relativeRoot}/bundle-manifest.json`,
    completeManifest,
    { treeSha256 },
  );
  const bindings = {
    bundleTreeSha256: treeSha256,
    bundleManifestSha256: bundleManifest.sha256,
    dependencyLockSha256: dependencyLock.sha256,
    toolchainLockSha256: toolchainLock.sha256,
    effectiveGnArgsSha256: effectiveGnArgs.sha256,
    licenseBundleSha256: licenseBundle.sha256,
    buildContractSha256,
    trustContractSha256,
    patchSeriesSha256: buildContract.patches.activeSeriesSha256,
  };
  const sbom = writeBoundJson(
    artifacts,
    `${relativeRoot}/sbom.cdx.json`,
    createBuildDerivedSbom({
      platform,
      slot,
      createdAt: '2026-07-18T00:12:00.000Z',
      bundleManifest: completeManifest,
      dependencyLock: dependencyDocument,
      bindings,
      buildContract,
    }),
  );
  const record = {
    runId,
    runAttempt: 1,
    checkRunId,
    artifactId,
    artifactName: `m0-payload-${platform}-${slot}-attempt-1`,
    artifactDigest: digest(Buffer.from(`artifact-zip-${platform}-${slot}`)),
    artifactSize: 8192 + Number(artifactId),
    artifactInnerSha256: digest(
      Buffer.from(`artifact-inner-tar-${platform}-${slot}`),
    ),
    artifactInnerSize: 4096 + Number(artifactId),
    runner: { kind: 'github-hosted' },
    bundleRoot: bundleRootRelative,
    bundleManifest,
    dependencyLock,
    toolchainLock,
    effectiveGnArgs,
    sbom,
    licenseBundle,
    liveReport: writeBoundJson(
      artifacts,
      `${relativeRoot}/live-report.json`,
      buildArtifactBaselineReport({
        artifactPath: entrypoint,
        executionIsolation: M0_EXTERNAL_EXECUTION_ISOLATION,
        networkTimeAudit: auditNetworkTimeNetLog({
          events: [{
            params: {
              url: 'http://127.0.0.1/probe',
            },
          }],
        }),
        observation: JSON.parse(readFileSync(
          join(
            REPO,
            'verify-lab',
            'fixtures',
            'bad-v5-automation-tells.json',
          ),
          'utf8',
        )),
        platform,
        probe: buildControlledProbeBinding(join(repo, 'verify-lab')),
      }),
    ),
    attestations: {},
  };
  for (const type of ['provenance', 'sbom', 'build']) {
    record.attestations[type] = writeBoundText(
      artifacts,
      `${relativeRoot}/${type}.sigstore.json`,
      `{"fixture":"${platform}/${slot}/${type}"}\n`,
    );
  }

  if (platform === 'linux-x64') {
    const output = outputFromRecord(record);
    const receipt = {
      schemaVersion: '1.0.0',
      keyId,
      instanceId: `external-${platform}-${slot}`,
      imageDigest: digest(Buffer.from(`image-${slot}`)),
      measurementDigest: digest(Buffer.from(`measurement-${slot}`)),
      singleUse: true,
      destroyed: true,
      startedAt: '2026-07-18T00:00:00.000Z',
      finishedAt: '2026-07-18T00:10:00.000Z',
      destroyedAt: '2026-07-18T00:11:00.000Z',
      repository: { ...repository },
      source: {
        digest: sourceDigest,
        ref: sourceRef,
      },
      workflow: {
        path: signerWorkflow,
        digest: signerDigest,
      },
      build: {
        platform,
        slot,
        runId,
        runAttempt: 1,
        checkRunId,
        artifactId,
        artifactName: record.artifactName,
        artifactDigest: record.artifactDigest,
        artifactSize: record.artifactSize,
        artifactInnerSha256: record.artifactInnerSha256,
        artifactInnerSize: record.artifactInnerSize,
      },
      output: {
        ...output,
        buildContractSha256,
        trustContractSha256,
      },
      signature: '',
    };
    signReceipt(receipt, privateKey);
    record.runner = {
      kind: 'external-ephemeral',
      receipt: writeBoundJson(
        artifacts,
        `${relativeRoot}/runner-receipt.json`,
        receipt,
      ),
    };
  }
  return record;
}

function absoluteDescriptor(artifacts, descriptor) {
  return join(artifacts, ...descriptor.path.split('/'));
}

function completeToolchainFixture({
  buildContract,
  buildContractSha256,
  dependencyLock,
  effectiveDocument,
  effectiveGnArgs,
  platform,
  repo,
  repository,
  trustContractSha256,
}) {
  const fixtureRoot = join(repo, 'toolchain-fixture', platform);
  const clientRoot = join(fixtureRoot, 'client');
  const chromiumSource = join(clientRoot, 'src');
  const depotTools = join(fixtureRoot, 'depot_tools');
  const toolRoot = join(fixtureRoot, 'tools');
  const identity = (
    path,
    {
      mode = '755',
      sha256 = digest(Buffer.from(path, 'utf8')),
      size = 64,
    } = {},
  ) => ({
    mode,
    path,
    sha256,
    size,
  });
  const tool = (name) => identity(join(toolRoot, name));
  const buildTools = (architecture, backend = 'ninja') => {
    const prefix = `${architecture}-${backend}`;
    return {
      executor: {
        backend,
        binary: tool(`${prefix}-executor-binary`),
        driver: tool(`${prefix}-executor-driver`),
        wrapper: tool(`${prefix}-executor-wrapper`),
        wrapperDriver: tool(`${prefix}-executor-wrapper-driver`),
      },
      gn: {
        binary: tool(`${prefix}-gn-binary`),
        driver: tool(`${prefix}-gn-driver`),
        wrapper: tool(`${prefix}-gn-wrapper`),
      },
      llvm: {
        clang: tool(`${prefix}-clang`),
        lld: tool(`${prefix}-lld`),
      },
      runtimes: {
        depotPython: {
          binary: tool(`${prefix}-depot-python-binary`),
          selector: tool(`${prefix}-depot-python-selector`),
          wrapper: tool(`${prefix}-depot-python-wrapper`),
        },
        git: tool(`${prefix}-git`),
        hostPython: tool(`${prefix}-host-python`),
        node: tool(`${prefix}-node`),
      },
    };
  };
  const configurations = effectiveDocument.configurations.map(
    (configuration) => {
      const outDir = join(
        chromiumSource,
        ...configuration.outDir.split('/'),
      );
      return {
        architecture: configuration.architecture,
        buildOutput: identity(
          join(outDir, ...ENTRYPOINTS[platform].split('/')),
          {
            sha256: digest(executableFixture(platform)),
            size: executableFixture(platform).length,
          },
        ),
        buildTools: buildTools(configuration.architecture),
        effectiveGnArgs: {
          backend: 'ninja',
          mode: '644',
          path: join(outDir, 'effective-args.gn'),
          recordOutDir: configuration.outDir,
          recordSha256: configuration.argsSha256,
          sha256: configuration.argsSha256,
          size: configuration.argsSize,
          targetCpu:
            configuration.architecture === 'x86_64' ? 'x64' : 'arm64',
        },
        outDir,
        outDirRelative: configuration.outDir,
      };
    },
  );
  const tree = (path) => ({
    directories: 1,
    entries: 2,
    files: 1,
    path,
    symlinks: 0,
    totalFileBytes: 64,
    treeSha256: digest(Buffer.from(`tree:${path}`, 'utf8')),
  });
  const rootIds = {
    'linux-x64': ['linux-sysroot'],
    'macos-universal': ['macos-sdk', 'xcode-installation'],
    'windows-x64': ['visual-studio', 'windows-sdk'],
  }[platform];
  const platformKinds = {
    'linux-x64': 'linux-sysroot',
    'macos-universal': 'macos-xcode-sdk',
    'windows-x64': 'windows-msvc-sdk',
  };
  const buildContractPath = join(
    repo,
    'engine-chromium',
    'build',
    'm0-build-contract.json',
  );
  const trustContractPath = join(
    repo,
    'engine-chromium',
    'build',
    'm0-trust.json',
  );
  let packaging = null;
  if (platform === 'macos-universal') {
    const outDirRelative = 'out/Proteus-universal';
    const outDir = join(chromiumSource, ...outDirRelative.split('/'));
    packaging = {
      architectures: [...buildContract.platforms[platform].architectures],
      tools: {
        lipo: tool('macos-lipo'),
        python: tool('macos-python'),
        universalizer: tool('macos-universalizer'),
      },
      universalOutput: {
        entrypoint: identity(
          join(outDir, ...ENTRYPOINTS[platform].split('/')),
          {
            sha256: digest(executableFixture(platform)),
            size: executableFixture(platform).length,
          },
        ),
        outDir,
        outDirRelative,
        tree: tree(outDir),
      },
    };
  }
  return {
    architectures: [...buildContract.platforms[platform].architectures],
    assuranceLevel: buildContract.assuranceLevel,
    completeness: 'complete',
    configurations,
    contracts: {
      build: identity(buildContractPath, {
        mode: '644',
        sha256: buildContractSha256,
        size: readFileSync(buildContractPath).length,
      }),
      dependency: identity(
        join(fixtureRoot, 'records', 'resolved-dependency-lock.json'),
        {
          mode: '644',
          sha256: dependencyLock.sha256,
          size: readFileSync(
            absoluteDescriptor(
              join(repo, 'engine-chromium', 'artifacts'),
              dependencyLock,
            ),
          ).length,
        },
      ),
      trust: identity(trustContractPath, {
        mode: '644',
        sha256: trustContractSha256,
        size: readFileSync(trustContractPath).length,
      }),
    },
    documentKind: 'complete-toolchain-lock',
    effectiveGnArgsRecord: identity(
      join(fixtureRoot, 'records', 'effective-gn-args.json'),
      {
        mode: '644',
        sha256: effectiveGnArgs.sha256,
        size: readFileSync(
          absoluteDescriptor(
            join(repo, 'engine-chromium', 'artifacts'),
            effectiveGnArgs,
          ),
        ).length,
      },
    ),
    hostPlatform: HOST_PLATFORMS[platform],
    lockAssurance: 'complete-build-toolchain-sha256/v1',
    packaging,
    platform,
    platformToolchain: {
      discoveryTools: {},
      evidence: [{
        id: 'platform-version',
        ...identity(join(fixtureRoot, 'platform-version.txt'), {
          mode: '644',
        }),
      }],
      kind: platformKinds[platform],
      metadata: { fixture: true },
      roots: rootIds.map((id) => ({
        id,
        ...tree(join(fixtureRoot, 'platform-roots', id)),
      })),
    },
    roots: {
      chromiumSource,
      clientRoot,
      depotTools,
    },
    schemaVersion: '1.0.0',
    source: {
      chromiumCommit: buildContract.source.chromiumCommit,
      chromiumRepository: buildContract.source.chromiumRepository,
      chromiumVersion: buildContract.source.chromiumVersion,
      depotToolsCommit: buildContract.source.depotToolsCommit,
      depotToolsRepository: buildContract.source.depotToolsRepository,
      patchProfile: buildContract.patches.profile,
      patchSeriesSha256: buildContract.patches.activeSeriesSha256,
      repository: repository.nameWithOwner,
    },
  };
}

function executableFixture(platform) {
  if (platform === 'windows-x64') {
    const bytes = Buffer.alloc(512);
    bytes.write('MZ', 0, 'ascii');
    bytes.writeUInt32LE(0x80, 0x3c);
    bytes.write('PE\0\0', 0x80, 'binary');
    bytes.writeUInt16LE(0x8664, 0x84);
    bytes.writeUInt16LE(1, 0x86);
    bytes.writeUInt16LE(0x20b, 0x98);
    bytes.write('proteus-m0-v2-windows', 0x120, 'ascii');
    return bytes;
  }
  if (platform === 'linux-x64') {
    const bytes = Buffer.alloc(256);
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(bytes);
    bytes.writeUInt16LE(3, 16);
    bytes.writeUInt16LE(0x3e, 18);
    bytes.writeUInt32LE(1, 20);
    bytes.write('proteus-m0-v2-linux', 0x80, 'ascii');
    return bytes;
  }
  if (platform === 'macos-universal') {
    const bytes = Buffer.alloc(320);
    bytes.writeUInt32BE(0xcafebabe, 0);
    bytes.writeUInt32BE(2, 4);
    writeFatArch(bytes, 8, 0x01000007, 64, 96);
    writeFatArch(bytes, 28, 0x0100000c, 160, 96);
    writeMachOSlice(bytes, 64, 0x01000007);
    writeMachOSlice(bytes, 160, 0x0100000c);
    bytes.write('proteus-m0-v2-macos-universal', 256, 'ascii');
    return bytes;
  }
  throw new TypeError(`unsupported fixture platform ${platform}`);
}

function writeFatArch(bytes, offset, cpuType, sliceOffset, sliceSize) {
  bytes.writeInt32BE(cpuType, offset);
  bytes.writeInt32BE(0, offset + 4);
  bytes.writeUInt32BE(sliceOffset, offset + 8);
  bytes.writeUInt32BE(sliceSize, offset + 12);
  bytes.writeUInt32BE(2, offset + 16);
}

function writeMachOSlice(bytes, offset, cpuType) {
  bytes.writeUInt32LE(0xfeedfacf, offset);
  bytes.writeInt32LE(cpuType, offset + 4);
}

function generatedCreditsFixture() {
  const records = Array.from({ length: 25 }, (_, index) =>
    `<div class="product">Fixture dependency ${index + 1}</div>`
    + `<div class="license">Fixture license ${index + 1}</div>`)
    .join('\n');
  return Buffer.from(
    '<!-- Generated by licenses.py; do not edit. -->\n'
    + '<!doctype html>\n<html><head><title>Credits</title></head><body>\n'
    + '<!-- Chromium <3s the following projects -->\n'
    + records
    + `\n<!-- ${'build-derived-fixture '.repeat(4096)} -->\n`
    + '</body></html>\n',
    'utf8',
  );
}

function effectiveGnArgsFixture(platform, buildContract) {
  const configurations =
    buildContract.platforms[platform].architectures.map((architecture) => {
      const targetCpu = architecture === 'x86_64' ? 'x64' : 'arm64';
      const argsText =
        `target_cpu = "${targetCpu}"\n`
        + 'is_official_build = true\n'
        + 'is_debug = false\n'
        + 'generate_about_credits = true\n'
        + 'use_official_google_api_keys = false\n'
        + 'google_api_key = ""\n'
        + 'google_default_client_id = ""\n'
        + 'google_default_client_secret = ""\n'
        + 'use_siso = false\n';
      const bytes = Buffer.from(argsText, 'utf8');
      return {
        architecture,
        outDir: `out/Proteus-${architecture}`,
        argsSha256: digest(bytes),
        argsSize: bytes.length,
        argsText,
      };
    });
  return {
    schemaVersion: '1.0.0',
    documentKind: 'effective-gn-args',
    platform,
    configurations,
  };
}

function writeBoundJson(artifacts, relative, value, extra = {}) {
  mkdirSync(dirname(join(artifacts, ...relative.split('/'))), {
    recursive: true,
  });
  writeFileSync(
    join(artifacts, ...relative.split('/')),
    `${JSON.stringify(value)}\n`,
  );
  return {
    path: relative,
    sha256: sha256File(join(artifacts, ...relative.split('/'))),
    ...extra,
  };
}

function writeBoundText(artifacts, relative, value) {
  mkdirSync(dirname(join(artifacts, ...relative.split('/'))), {
    recursive: true,
  });
  writeFileSync(join(artifacts, ...relative.split('/')), value);
  return {
    path: relative,
    sha256: sha256File(join(artifacts, ...relative.split('/'))),
  };
}

function sha256File(path) {
  return digest(readFileSync(path));
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function signReceipt(receipt, privateKey) {
  receipt.signature = sign(
    null,
    runnerReceiptSigningInput(receipt),
    privateKey,
  ).toString('base64');
}

function outputFromRecord(record) {
  return {
    bundleTreeSha256: record.bundleManifest.treeSha256,
    bundleManifestSha256: record.bundleManifest.sha256,
    dependencyLockSha256: record.dependencyLock.sha256,
    toolchainLockSha256: record.toolchainLock.sha256,
    effectiveGnArgsSha256: record.effectiveGnArgs.sha256,
    sbomSha256: record.sbom.sha256,
    licenseBundleSha256: record.licenseBundle.sha256,
    liveReportSha256: record.liveReport.sha256,
  };
}

function goodAttestationVerifier(invocations, mutate = null) {
  return (input) => {
    invocations.push(input.invocation);
    const result = [{
      attestation: {
        mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
      },
      verificationResult: {
        signature: {
          certificate: {
            issuer: 'https://token.actions.githubusercontent.com',
            subjectAlternativeName:
              `https://github.com/${input.buildFacts.repository.nameWithOwner}`
              + `/${input.buildFacts.workflow}@refs/heads/main`,
            githubWorkflowSHA: input.buildFacts.signerDigest,
            githubWorkflowRepository:
              input.buildFacts.repository.nameWithOwner,
            githubWorkflowRef: 'refs/heads/main',
            buildSignerURI:
              `https://github.com/${input.buildFacts.repository.nameWithOwner}`
              + `/${input.buildFacts.workflow}@refs/heads/main`,
            buildSignerDigest: input.buildFacts.signerDigest,
            runnerEnvironment: input.invocation.args.includes(
              '--deny-self-hosted-runners',
            ) ? 'github-hosted' : 'self-hosted',
            sourceRepositoryURI:
              `https://github.com/${input.buildFacts.repository.nameWithOwner}`,
            sourceRepositoryDigest: input.buildFacts.sourceDigest,
            sourceRepositoryRef: 'refs/heads/main',
            sourceRepositoryIdentifier:
              input.buildFacts.repository.repositoryId,
            sourceRepositoryOwnerURI: 'https://github.com/jiyujie2006',
            sourceRepositoryOwnerIdentifier:
              input.buildFacts.repository.ownerId,
            buildConfigURI:
              `https://github.com/${input.buildFacts.repository.nameWithOwner}`
              + `/${input.buildFacts.workflow}@refs/heads/main`,
            buildConfigDigest: input.buildFacts.signerDigest,
            buildTrigger: 'workflow_dispatch',
            runInvocationURI:
              `https://github.com/${input.buildFacts.repository.nameWithOwner}`
              + `/actions/runs/${input.buildFacts.runId}`
              + `/attempts/${input.buildFacts.runAttempt}`,
            sourceRepositoryVisibilityAtSigning:
              input.buildFacts.repository.visibility,
          },
        },
        verifiedTimestamps: [{
          type: 'transparency-log',
          timestamp: '2026-07-18T00:20:00.000Z',
        }],
        statement: structuredClone(input.expectedStatement),
      },
    }];
    if (mutate) mutate(result, input);
    return result;
  };
}

function goodGithubVerifier(mutate = null) {
  return ({ expected }) => {
    const result = structuredClone(expected);
    if (mutate) mutate(result);
    return result;
  };
}

function githubApiFixture(fixture, mutate = null) {
  const repository = fixture.evidence.repository.nameWithOwner;
  const repositoryEndpoint = `repos/${repository}`;
  const owner = repository.split('/')[0];
  const repositoryId = Number(fixture.evidence.repository.repositoryId);
  const ownerId = Number(fixture.evidence.repository.ownerId);
  const repositoryDocument = {
    id: repositoryId,
    full_name: repository,
    visibility: fixture.evidence.repository.visibility,
    owner: {
      id: ownerId,
      login: owner,
    },
  };
  const nestedRepository = {
    id: repositoryId,
    full_name: repository,
    owner: {
      id: ownerId,
      login: owner,
    },
  };
  const sourceBranch = fixture.evidence.source.ref.replace(
    /^refs\/heads\//u,
    '',
  );
  const responses = {
    [repositoryEndpoint]: repositoryDocument,
  };
  const endpoints = new Map();
  let runnerId = 500000;
  for (const platform of PLATFORMS) {
    for (const slot of SLOTS) {
      runnerId += 1;
      const record = fixture.records.get(`${platform}/${slot}`);
      const runEndpoint =
        `${repositoryEndpoint}/actions/runs/${record.runId}`;
      const jobsEndpoint =
        `${runEndpoint}/attempts/${record.runAttempt}/jobs?per_page=100`;
      const checkEndpoint =
        `${repositoryEndpoint}/check-runs/${record.checkRunId}`;
      const artifactEndpoint =
        `${repositoryEndpoint}/actions/artifacts/${record.artifactId}`;
      const runArtifactsEndpoint =
        `${runEndpoint}/artifacts?name=${encodeURIComponent(record.artifactName)}`
        + '&per_page=100';
      const checkRunUrl =
        `https://api.github.com/${repositoryEndpoint}`
        + `/check-runs/${record.checkRunId}`;
      responses[runEndpoint] = {
        id: Number(record.runId),
        run_attempt: record.runAttempt,
        head_sha: fixture.sourceDigest,
        head_branch: sourceBranch,
        path: `${fixture.evidence.signer.workflow}@${sourceBranch}`,
        event: 'workflow_dispatch',
        status: 'completed',
        conclusion: 'success',
        repository: structuredClone(nestedRepository),
        head_repository: structuredClone(nestedRepository),
      };
      responses[jobsEndpoint] = [{
        total_count: 1,
        jobs: [{
          id: Number(record.checkRunId) + 1000000,
          run_id: Number(record.runId),
          head_sha: fixture.sourceDigest,
          check_run_url: checkRunUrl,
          status: 'completed',
          conclusion: 'success',
          runner_id: runnerId,
          runner_name: `fixture-${platform}-${slot}`,
          labels: record.runner.kind === 'external-ephemeral'
            ? [...SELF_HOSTED_RUNNER_LABELS[platform]]
            : [...RUNNER_LABELS[platform]],
        }],
      }];
      responses[checkEndpoint] = {
        id: Number(record.checkRunId),
        head_sha: fixture.sourceDigest,
        status: 'completed',
        conclusion: 'success',
      };
      responses[artifactEndpoint] = {
        id: Number(record.artifactId),
        name: record.artifactName,
        digest: `sha256:${record.artifactDigest}`,
        size_in_bytes: record.artifactSize,
        expired: false,
        expires_at: '2099-01-01T00:00:00Z',
        workflow_run: {
          id: Number(record.runId),
          repository_id: repositoryId,
          head_repository_id: repositoryId,
          head_sha: fixture.sourceDigest,
        },
      };
      responses[runArtifactsEndpoint] = {
        total_count: 1,
        artifacts: [structuredClone(responses[artifactEndpoint])],
      };
      endpoints.set(`${platform}/${slot}`, {
        artifactEndpoint,
        checkEndpoint,
        jobsEndpoint,
        runArtifactsEndpoint,
        runEndpoint,
      });
    }
  }
  if (mutate) mutate(responses, endpoints);

  const apiInvoker = (args) => {
    const endpoint = args[1];
    const option = (name) => {
      const index = args.indexOf(name);
      return index < 0 ? null : args[index + 1];
    };
    if (args[0] !== 'api'
        || option('--hostname') !== 'github.com'
        || option('--method') !== 'GET'
        || !args.includes('Accept: application/vnd.github+json')
        || !args.includes('X-GitHub-Api-Version: 2022-11-28')
        || !Object.hasOwn(responses, endpoint)) {
      throw new Error(`unexpected trusted gh API invocation: ${endpoint}`);
    }
    const response = responses[endpoint];
    if (Array.isArray(response)
        && (!args.includes('--paginate') || !args.includes('--slurp'))) {
      throw new Error('workflow jobs request omitted pagination');
    }
    return Buffer.from(JSON.stringify(response), 'utf8');
  };
  return {
    githubVerifier: (input) =>
      defaultGithubApiVerifier({ ...input, apiInvoker }),
  };
}

function verifyFixture(fixture, overrides = {}) {
  return verifyM0EvidenceV2Document(
    fixture.repo,
    fixture.evidence,
    {
      expectedSourceDigest: fixture.sourceDigest,
      expectedSignerDigest: SIGNER_DIGEST,
      expectedRunnerControllerKeySha256:
        Object.hasOwn(overrides, 'expectedRunnerControllerKeySha256')
          ? overrides.expectedRunnerControllerKeySha256
          : fixture.keyId,
      attestationVerifier:
        overrides.attestationVerifier ?? fixture.attestationVerifier,
      githubVerifier: Object.hasOwn(overrides, 'githubVerifier')
        ? overrides.githubVerifier
        : fixture.githubVerifier,
      expectedGhSha256: overrides.expectedGhSha256,
      ghPath: overrides.ghPath,
      policyCheckoutVerifier: overrides.policyCheckoutVerifier,
    },
  );
}

function expectFailure(fixture, pattern, overrides = {}) {
  const audit = verifyFixture(fixture, overrides);
  assert(!audit.ok, 'tampered evidence unexpectedly passed');
  assert(
    audit.failures.some((failure) => pattern.test(failure)),
    `expected failure ${pattern}, got:\n${audit.failures.join('\n')}`,
  );
}

function writeEvidence(fixture) {
  writeFileSync(
    join(
      fixture.repo,
      'engine-chromium',
      'artifacts',
      'm0-build-evidence-v2.json',
    ),
    `${JSON.stringify(fixture.evidence)}\n`,
  );
}

function absoluteArtifact(fixture, descriptor) {
  return join(fixture.artifacts, ...descriptor.path.split('/'));
}

function rewriteDescriptor(fixture, descriptor, value, asJson = true) {
  const path = absoluteArtifact(fixture, descriptor);
  writeFileSync(path, asJson ? `${JSON.stringify(value)}\n` : value);
  descriptor.sha256 = sha256File(path);
}

function readReceipt(fixture, record) {
  return JSON.parse(
    readFileSync(absoluteArtifact(fixture, record.runner.receipt), 'utf8'),
  );
}

function rewriteReceipt(fixture, record, receipt) {
  signReceipt(receipt, fixture.privateKey);
  rewriteDescriptor(fixture, record.runner.receipt, receipt);
}

function updateSbomProperty(fixture, record, name, value) {
  const sbom = JSON.parse(
    readFileSync(absoluteArtifact(fixture, record.sbom), 'utf8'),
  );
  const property = sbom.metadata.properties.find(
    (candidate) => candidate.name === name,
  );
  if (!property) throw new Error(`fixture SBOM is missing ${name}`);
  property.value = value;
  rewriteDescriptor(fixture, record.sbom, sbom);
}

function rebindBundleDerivedRecords(
  fixture,
  platform,
  slot,
  {
    rebuildPackage = true,
    rebindToolchain = true,
  } = {},
) {
  const record = fixture.records.get(`${platform}/${slot}`);
  const root = join(fixture.artifacts, ...record.bundleRoot.split('/'));
  const toolchain = JSON.parse(readFileSync(
    absoluteArtifact(fixture, record.toolchainLock),
    'utf8',
  ));
  const dependencyBytes = readFileSync(
    absoluteArtifact(fixture, record.dependencyLock),
  );
  const effectiveBytes = readFileSync(
    absoluteArtifact(fixture, record.effectiveGnArgs),
  );
  if (rebindToolchain) {
    toolchain.contracts.dependency.sha256 = digest(dependencyBytes);
    toolchain.contracts.dependency.size = dependencyBytes.length;
    toolchain.effectiveGnArgsRecord.sha256 = digest(effectiveBytes);
    toolchain.effectiveGnArgsRecord.size = effectiveBytes.length;
    rewriteDescriptor(fixture, record.toolchainLock, toolchain);
  }
  const packagePath = join(root, 'PACKAGE-RECORD.json');
  if (rebuildPackage) {
    const existingPackage = JSON.parse(readFileSync(packagePath, 'utf8'));
    const packageRecord = createPackageRecord({
      platform,
      outDirRelative: existingPackage.outputDirectory,
      runtimeDependencies: existingPackage.runtimeDependencies.entries,
      dependencyLockBytes: dependencyBytes,
      effectiveGnArgsBytes: effectiveBytes,
      toolchainLockBytes: readFileSync(
        absoluteArtifact(fixture, record.toolchainLock),
      ),
      licenseManifestBytes: readFileSync(
        absoluteArtifact(fixture, record.licenseBundle),
      ),
      repoRoot: fixture.repo,
    });
    writeFileSync(
      packagePath,
      `${JSON.stringify(packageRecord, null, 2)}\n`,
    );
  }
  const manifest = createBundleManifest(root, {
    platform,
    entrypoint: ENTRYPOINTS[platform],
  });
  const treeSha256 = manifest.treeSha256;
  rewriteDescriptor(
    fixture,
    record.bundleManifest,
    manifest,
  );
  record.bundleManifest.treeSha256 = treeSha256;
  const dependencyLock = JSON.parse(
    readFileSync(absoluteArtifact(fixture, record.dependencyLock), 'utf8'),
  );
  const existingSbom = JSON.parse(
    readFileSync(absoluteArtifact(fixture, record.sbom), 'utf8'),
  );
  const sbom = createBuildDerivedSbom({
    platform,
    slot,
    createdAt: existingSbom.metadata.timestamp,
    bundleManifest: manifest,
    dependencyLock,
    bindings: {
      bundleTreeSha256: treeSha256,
      bundleManifestSha256: record.bundleManifest.sha256,
      dependencyLockSha256: record.dependencyLock.sha256,
      toolchainLockSha256: record.toolchainLock.sha256,
      effectiveGnArgsSha256: record.effectiveGnArgs.sha256,
      licenseBundleSha256: record.licenseBundle.sha256,
      buildContractSha256: sha256File(join(
        fixture.repo,
        'engine-chromium',
        'build',
        'm0-build-contract.json',
      )),
      trustContractSha256: sha256File(join(
        fixture.repo,
        'engine-chromium',
        'build',
        'm0-trust.json',
      )),
      patchSeriesSha256: fixture.buildContract.patches.activeSeriesSha256,
    },
    buildContract: fixture.buildContract,
  });
  rewriteDescriptor(fixture, record.sbom, sbom);
}

console.log('\n  M0 hard evidence v2 offline verifier tests');
console.log('  ' + '─'.repeat(62));

check('schema accepts the exact six-build evidence document', (fixture) => {
  const schema = JSON.parse(readFileSync(
    join(
      REPO,
      'engine-chromium',
      'artifacts',
      'm0-evidence-v2.schema.json',
    ),
    'utf8',
  ));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(schema);
  assert(validate(fixture.evidence), JSON.stringify(validate.errors));
});

check('valid three-platform A/B evidence reaches hard assurance v2', (fixture) => {
  const audit = verifyFixture(fixture);
  assert(audit.ok, audit.failures.join('\n'));
  assert(audit.verifiedBuilds === 6, 'expected exactly six verified builds');
  assert(
    audit.assuranceLevel === M0_EVIDENCE_V2_ASSURANCE_LEVEL,
    'wrong assurance level',
  );
  assert(fixture.invocations.length === 18, 'expected three attestations per build');
  const report = JSON.parse(readFileSync(
    absoluteArtifact(
      fixture,
      fixture.records.get('linux-x64/A').liveReport,
    ),
    'utf8',
  ));
  assert(
    report.suites[0].verdict === 'detectable'
      && report.suites[0].gated === true,
    'a completed non-green baseline should remain valid evidence',
  );
});

check('gh invocation pins bundle, repo, workflow, digests, ref, predicate, and JSON', (fixture) => {
  const audit = verifyFixture(fixture);
  assert(audit.ok, audit.failures.join('\n'));
  for (const invocation of fixture.invocations) {
    assert(invocation.command === 'gh', 'wrong verifier command');
    const args = invocation.args;
    for (const flag of [
      '--bundle',
      '--repo',
      '--signer-workflow',
      '--signer-digest',
      '--source-digest',
      '--source-ref',
      '--predicate-type',
      '--cert-oidc-issuer',
      '--format',
    ]) {
      assert(args.includes(flag), `missing ${flag}`);
    }
    assert(
      args[args.indexOf('--repo') + 1] === 'jiyujie2006/proteus-browser',
      'wrong repository policy argument',
    );
    assert(args[args.indexOf('--format') + 1] === 'json', 'format is not JSON');
  }
  const denied = fixture.invocations.filter(({ args }) =>
    args.includes('--deny-self-hosted-runners')).length;
  assert(denied === 12, 'only four GitHub-hosted builds should deny self-hosted');
});

check('reused GitHub workflow run ID is rejected globally', (fixture) => {
  fixture.records.get('linux-x64/B').runId =
    fixture.records.get('linux-x64/A').runId;
  expectFailure(fixture, /runId is reused/);
});

check('reused check-run IDs are rejected globally', (fixture) => {
  const left = fixture.records.get('windows-x64/A');
  const right = fixture.records.get('macos-universal/B');
  right.checkRunId = left.checkRunId;
  expectFailure(fixture, /checkRunId is reused/);
});

check('reused artifact IDs are rejected globally', (fixture) => {
  const left = fixture.records.get('windows-x64/A');
  const right = fixture.records.get('macos-universal/B');
  right.artifactId = left.artifactId;
  expectFailure(fixture, /artifactId is reused/);
});

check('one complete bundle root cannot be relabelled as independent A/B builds', (fixture) => {
  const pair = fixture.evidence.platforms['windows-x64'];
  pair.B.bundleRoot = pair.A.bundleRoot;
  expectFailure(fixture, /bundle root identity is reused|reuse the same complete bundle root/);
});

check('hardlinked bundle files cannot stand in for an independent rebuild', (fixture) => {
  const pair = fixture.evidence.platforms['windows-x64'];
  const left = join(
    fixture.artifacts,
    ...pair.A.bundleRoot.split('/'),
    'resources.pak',
  );
  const right = join(
    fixture.artifacts,
    ...pair.B.bundleRoot.split('/'),
    'resources.pak',
  );
  unlinkSync(right);
  linkSync(left, right);
  expectFailure(fixture, /complete bundle file identity is reused/);
});

check('copied raw Sigstore bundle bytes cannot prove a second build', (fixture) => {
  const pair = fixture.evidence.platforms['windows-x64'];
  const source = absoluteArtifact(fixture, pair.A.attestations.build);
  const target = absoluteArtifact(fixture, pair.B.attestations.build);
  writeFileSync(target, readFileSync(source));
  pair.B.attestations.build.sha256 = sha256File(target);
  expectFailure(fixture, /raw Sigstore bundle digest is reused/);
});

check('a cryptographically accepted but forged predicate is rejected', (fixture) => {
  const verifier = goodAttestationVerifier([], (result, input) => {
    if (input.type === 'build'
        && input.buildFacts.platform === 'windows-x64'
        && input.buildFacts.slot === 'A') {
      result[0].verificationResult.statement.predicate.outputs.liveReportSha256 =
        '0'.repeat(64);
    }
  });
  expectFailure(fixture, /predicate or subject does not match/, {
    attestationVerifier: verifier,
  });
});

check('a success string cannot replace structured gh verification results', (fixture) => {
  expectFailure(fixture, /invalid JSON value|verification output/, {
    attestationVerifier: () => 'verification succeeded',
  });
});

check('verified certificate evidence is mandatory', (fixture) => {
  const verifier = goodAttestationVerifier([], (result, input) => {
    if (input.type === 'build'
        && input.buildFacts.platform === 'windows-x64'
        && input.buildFacts.slot === 'A') {
      result[0].verificationResult.signature.certificate = {};
    }
  });
  expectFailure(fixture, /verified certificate/, {
    attestationVerifier: verifier,
  });
});

check('verified certificate identity must match the trusted workflow', (fixture) => {
  const verifier = goodAttestationVerifier([], (result, input) => {
    if (input.type === 'build'
        && input.buildFacts.platform === 'windows-x64'
        && input.buildFacts.slot === 'A') {
      result[0].verificationResult.signature.certificate
        .subjectAlternativeName = 'example/evil/.github/workflows/evil.yml';
    }
  });
  expectFailure(fixture, /verified certificate identity/, {
    attestationVerifier: verifier,
  });
});

check('verified timestamp evidence is mandatory', (fixture) => {
  const verifier = goodAttestationVerifier([], (result, input) => {
    if (input.type === 'build'
        && input.buildFacts.platform === 'windows-x64'
        && input.buildFacts.slot === 'A') {
      result[0].verificationResult.verifiedTimestamps = [];
    }
  });
  expectFailure(fixture, /verified timestamps/, {
    attestationVerifier: verifier,
  });
});

check('verified timestamps must be valid RFC 3339 values', (fixture) => {
  const verifier = goodAttestationVerifier([], (result, input) => {
    if (input.type === 'build'
        && input.buildFacts.platform === 'windows-x64'
        && input.buildFacts.slot === 'A') {
      result[0].verificationResult.verifiedTimestamps[0].timestamp =
        'not-a-timestamp';
    }
  });
  expectFailure(fixture, /verified timestamp is not valid RFC 3339/, {
    attestationVerifier: verifier,
  });
});

check('duplicate keys in raw gh JSON are rejected before predicate policy', (fixture) => {
  const verifier = (input) => {
    const result = goodAttestationVerifier([])(input);
    return JSON.stringify(result).replace(
      '"verificationResult":{',
      '"verificationResult":{"statement":"ambiguous",',
    );
  };
  expectFailure(fixture, /duplicate object key.*statement/, {
    attestationVerifier: verifier,
  });
});

check('default synchronous GitHub API verifier derives all facts from trusted gh', (fixture) => {
  const audit = verifyFixture(fixture, githubApiFixture(fixture));
  assert(audit.ok, audit.failures.join('\n'));
  assert(audit.verifiedBuilds === 6, 'production API verifier missed M0 builds');
});

check('artifact ownership uses the run-scoped list when workflow_run is omitted', (fixture) => {
  const optionalOmitted = githubApiFixture(
    fixture,
    (responses, endpoints) => {
      for (const {
        artifactEndpoint,
        runArtifactsEndpoint,
      } of endpoints.values()) {
        delete responses[artifactEndpoint].workflow_run;
        delete responses[runArtifactsEndpoint].artifacts[0].workflow_run;
      }
    },
  );
  const audit = verifyFixture(fixture, optionalOmitted);
  assert(audit.ok, audit.failures.join('\n'));

  const wrongRunScope = githubApiFixture(
    fixture,
    (responses, endpoints) => {
      const { runArtifactsEndpoint } = endpoints.get('windows-x64/A');
      responses[runArtifactsEndpoint].artifacts[0].id += 99;
    },
  );
  expectFailure(
    fixture,
    /run-scoped signed identity/,
    wrongRunScope,
  );
});

check('default GitHub verifier rejects repository API and job-membership mismatches', (fixture) => {
  const repositoryMismatch = githubApiFixture(
    fixture,
    (responses) => {
      responses[`repos/${fixture.evidence.repository.nameWithOwner}`].id += 1;
    },
  );
  expectFailure(
    fixture,
    /workflow run repository does not match the repository response/,
    repositoryMismatch,
  );

  const membershipMismatch = githubApiFixture(
    fixture,
    (responses, endpoints) => {
      const { jobsEndpoint } = endpoints.get('windows-x64/A');
      responses[jobsEndpoint][0].jobs[0].check_run_url =
        'https://api.github.com/repos/jiyujie2006/proteus-browser/check-runs/1';
    },
  );
  expectFailure(
    fixture,
    /check run is not uniquely bound to the workflow run attempt jobs/,
    membershipMismatch,
  );
});

check('default GitHub verifier derives runner environment and OS only from API labels', (fixture) => {
  const wrongEnvironment = githubApiFixture(
    fixture,
    (responses, endpoints) => {
      const { jobsEndpoint } = endpoints.get('linux-x64/A');
      responses[jobsEndpoint][0].jobs[0].labels = ['ubuntu-latest'];
    },
  );
  expectFailure(
    fixture,
    /GitHub API facts do not match the evidence contract/,
    wrongEnvironment,
  );

  const wrongOs = githubApiFixture(
    fixture,
    (responses, endpoints) => {
      const { jobsEndpoint } = endpoints.get('windows-x64/A');
      responses[jobsEndpoint][0].jobs[0].labels = ['ubuntu-latest'];
    },
  );
  expectFailure(
    fixture,
    /GitHub API facts do not match the evidence contract/,
    wrongOs,
  );
});

check('default GitHub verifier rejects API run path, event, and attempt substitution', (fixture) => {
  const wrongPath = githubApiFixture(
    fixture,
    (responses, endpoints) => {
      const { runEndpoint } = endpoints.get('windows-x64/A');
      responses[runEndpoint].path =
        '.github/workflows/not-the-builder.yml@main';
    },
  );
  expectFailure(
    fixture,
    /GitHub API facts do not match the evidence contract/,
    wrongPath,
  );

  const wrongEvent = githubApiFixture(
    fixture,
    (responses, endpoints) => {
      const { runEndpoint } = endpoints.get('windows-x64/A');
      responses[runEndpoint].event = 'workflow_call';
    },
  );
  expectFailure(
    fixture,
    /GitHub API facts do not match the evidence contract/,
    wrongEvent,
  );

  const wrongAttempt = githubApiFixture(
    fixture,
    (responses, endpoints) => {
      const { jobsEndpoint, runEndpoint } = endpoints.get('windows-x64/A');
      responses[runEndpoint].run_attempt = 2;
      const attemptTwo = `${runEndpoint}/attempts/2/jobs?per_page=100`;
      responses[attemptTwo] = responses[jobsEndpoint];
      delete responses[jobsEndpoint];
    },
  );
  expectFailure(
    fixture,
    /GitHub API facts do not match the evidence contract/,
    wrongAttempt,
  );
});

check('default GitHub verifier rejects expired artifact API metadata', (fixture) => {
  const expiredFlag = githubApiFixture(
    fixture,
    (responses, endpoints) => {
      const { artifactEndpoint } = endpoints.get('windows-x64/A');
      responses[artifactEndpoint].expired = true;
    },
  );
  expectFailure(
    fixture,
    /GitHub API facts do not match the evidence contract/,
    expiredFlag,
  );

  const expiredTimestamp = githubApiFixture(
    fixture,
    (responses, endpoints) => {
      const { artifactEndpoint } = endpoints.get('windows-x64/A');
      responses[artifactEndpoint].expires_at = '2020-01-01T00:00:00Z';
    },
  );
  expectFailure(
    fixture,
    /GitHub API facts do not match the evidence contract/,
    expiredTimestamp,
  );
});

check('default GitHub verifier requires the pinned gh executable digest', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  let message = '';
  try {
    defaultGithubApiVerifier({
      artifactId: record.artifactId,
      artifactName: record.artifactName,
      artifactDigest: record.artifactDigest,
      artifactSize: record.artifactSize,
      checkRunId: record.checkRunId,
      repository: fixture.evidence.repository.nameWithOwner,
      runId: record.runId,
      ghPath: process.execPath,
      expectedGhSha256: '0'.repeat(64),
    });
  } catch (error) {
    message = error.message;
  }
  assert(
    /does not match its trusted SHA-256/.test(message),
    `untrusted gh digest did not fail closed: ${message}`,
  );
});

check('runner self-report cannot override GitHub API runner facts', (fixture) => {
  const api = goodGithubVerifier((result) => {
    result.runner.environment = 'self-hosted';
  });
  expectFailure(fixture, /GitHub API facts do not match/, {
    githubVerifier: api,
  });
});

check('GitHub API runner OS must match the platform build contract', (fixture) => {
  const api = goodGithubVerifier((result) => {
    result.runner.os = 'linux';
  });
  expectFailure(fixture, /GitHub API facts do not match/, {
    githubVerifier: api,
  });
});

check('rerun or workflow-call metadata cannot replace six dispatch runs', (fixture) => {
  const api = goodGithubVerifier((result) => {
    result.workflowRun.event = 'workflow_call';
  });
  expectFailure(fixture, /GitHub API facts do not match/, {
    githubVerifier: api,
  });
});

check('wrong repository ID is rejected from evidence and API facts', (fixture) => {
  fixture.evidence.repository.repositoryId = '999';
  const api = goodGithubVerifier((result) => {
    result.repository.repositoryId = '999';
  });
  const audit = verifyFixture(fixture, { githubVerifier: api });
  assert(!audit.ok, 'wrong repository ID unexpectedly passed');
  assert(
    audit.failures.some((failure) => /repository identity/.test(failure)),
    'evidence repository ID was not checked',
  );
  assert(
    audit.failures.some((failure) => /GitHub API facts/.test(failure)),
    'API repository ID was not checked',
  );
});

check('wrong source digest and signer workflow are rejected', (fixture) => {
  fixture.evidence.source.digest = 'd'.repeat(40);
  fixture.evidence.signer.workflow = '.github/workflows/evil.yml';
  const audit = verifyFixture(fixture);
  assert(!audit.ok, 'wrong source/workflow unexpectedly passed');
  assert(
    audit.failures.some((failure) => /source digest/.test(failure)),
    'source digest was not checked',
  );
  assert(
    audit.failures.some((failure) => /signer workflow/.test(failure)),
    'signer workflow was not checked',
  );
});

check('local policy substitution is rejected before contracts are trusted', (fixture) => {
  const argsPath = join(
    fixture.repo,
    'engine-chromium',
    'build',
    'args.gn',
  );
  writeFileSync(
    argsPath,
    `${readFileSync(argsPath, 'utf8')}\n# attacker-local policy\n`,
  );
  expectFailure(fixture, /source policy checkout|differs from trusted commit/);
});

check('line-ending policy substitution is covered by source policy', (fixture) => {
  const attributesPath = join(fixture.repo, '.gitattributes');
  writeFileSync(
    attributesPath,
    `${readFileSync(attributesPath, 'utf8')}\n*.gn text eol=crlf\n`,
  );
  expectFailure(fixture, /source policy checkout|differs from trusted commit/);
});

check('package command substitution is covered by source policy', (fixture) => {
  const packagePath = join(fixture.repo, 'package.json');
  const document = JSON.parse(readFileSync(packagePath, 'utf8'));
  document.scripts['m0:milestone'] = 'node attacker-local.mjs';
  writeFileSync(packagePath, JSON.stringify(document));
  expectFailure(fixture, /source policy checkout|differs from trusted commit/);
});

check('tracking control-flow substitution is covered by source policy', (fixture) => {
  const pipelinePath = join(
    fixture.repo,
    'engine-chromium',
    'tracking-bot',
    'pipeline.mjs',
  );
  writeFileSync(
    pipelinePath,
    `${readFileSync(pipelinePath, 'utf8')}\n// attacker-local policy\n`,
  );
  expectFailure(fixture, /source policy checkout|differs from trusted commit/);
});

check('foreign Git origin cannot supply the trusted policy checkout', (fixture) => {
  git(fixture.repo, [
    'remote',
    'set-url',
    'origin',
    'https://github.com/example/evil.git',
  ]);
  expectFailure(fixture, /untrusted Git origin/);
});

check('source policy checkout path must be the Git worktree root', (fixture) => {
  const child = join(fixture.repo, 'child');
  mkdirSync(child);
  let rejected = false;
  try {
    verifySourcePolicyCheckout({
      expectedSourceDigest: fixture.sourceDigest,
      gitPath: GIT_PATH,
      repoRoot: realpathSync(child),
    });
  } catch (error) {
    rejected = /not the Git worktree root/.test(error.message);
  }
  assert(rejected, 'a Git worktree child directory passed as its repository root');
});

check('missing raw Sigstore bundle fails closed', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  unlinkSync(absoluteArtifact(fixture, record.attestations.provenance));
  expectFailure(fixture, /provenance\.sigstore\.json|ENOENT/);
});

check('missing build-derived SBOM fails closed', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  unlinkSync(absoluteArtifact(fixture, record.sbom));
  expectFailure(fixture, /sbom\.cdx\.json|ENOENT/);
});

check('missing artifact-driven live report fails closed', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  unlinkSync(absoluteArtifact(fixture, record.liveReport));
  expectFailure(fixture, /live-report\.json|ENOENT/);
});

check('toolchain lock must contain the full strict builder inventory', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  const toolchain = JSON.parse(readFileSync(
    absoluteArtifact(fixture, record.toolchainLock),
    'utf8',
  ));
  delete toolchain.configurations[0].buildTools.llvm.lld;
  rewriteDescriptor(fixture, record.toolchainLock, toolchain);
  rebindBundleDerivedRecords(fixture, 'windows-x64', 'A', {
    rebindToolchain: false,
  });
  expectFailure(fixture, /buildTools\.llvm must contain exactly/);
});

check('PACKAGE-RECORD.json is recomputed from the bound package inputs', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  const path = join(
    fixture.artifacts,
    ...record.bundleRoot.split('/'),
    'PACKAGE-RECORD.json',
  );
  const packageRecord = JSON.parse(readFileSync(path, 'utf8'));
  packageRecord.records.dependencyLock.sha256 = '0'.repeat(64);
  writeFileSync(path, `${JSON.stringify(packageRecord, null, 2)}\n`);
  rebindBundleDerivedRecords(fixture, 'windows-x64', 'A', {
    rebuildPackage: false,
  });
  expectFailure(fixture, /package record differs from recomputed runtime closure/);
});

check('live V1-V5 summaries are recomputed from observations', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  const report = JSON.parse(readFileSync(
    absoluteArtifact(fixture, record.liveReport),
    'utf8',
  ));
  report.suites[0].aggregate = 1;
  rewriteDescriptor(fixture, record.liveReport, report);
  expectFailure(
    fixture,
    /verification report is not a complete artifact-driven baseline report/,
  );
});

check('rebound live report cannot substitute a failing Network Time audit', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  const report = JSON.parse(readFileSync(
    absoluteArtifact(fixture, record.liveReport),
    'utf8',
  ));
  report.networkTimeAudit.matchingEventCount = 1;
  report.networkTimeAudit.defaultQueryAbsent = false;
  rewriteDescriptor(fixture, record.liveReport, report);
  expectFailure(
    fixture,
    /verification report is not a complete artifact-driven baseline report/,
  );
});

check('artifact license manifest bytes are covered by the complete tree', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  const manifest = JSON.parse(
    readFileSync(absoluteArtifact(fixture, record.licenseBundle), 'utf8'),
  );
  manifest.files[3].sha256 = '0'.repeat(64);
  rewriteDescriptor(fixture, record.licenseBundle, manifest);
  expectFailure(fixture, /bundle tree does not match its canonical manifest/);
});

check('generated Chromium credits cannot be replaced by placeholder HTML', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  const creditsPath = join(
    fixture.artifacts,
    ...record.bundleRoot.split('/'),
    'LICENSES',
    'Chromium-Third-Party-Credits.html',
  );
  const placeholder = Buffer.from(
    '<!doctype html><html><head><title>Credits</title></head>'
    + '<body><!-- Chromium <3s the following projects --></body></html>\n',
  );
  writeFileSync(creditsPath, placeholder);
  const licenseManifest = JSON.parse(
    readFileSync(absoluteArtifact(fixture, record.licenseBundle), 'utf8'),
  );
  const credits = licenseManifest.files.find(({ role }) =>
    role === 'build-derived-third-party-notices');
  credits.sha256 = digest(placeholder);
  credits.size = placeholder.length;
  rewriteDescriptor(fixture, record.licenseBundle, licenseManifest);
  rebindBundleDerivedRecords(fixture, 'windows-x64', 'A');
  expectFailure(fixture, /Chromium credits are too small to be build-derived/);
});

check('macOS universal evidence requires both effective GN configurations', (fixture) => {
  const record = fixture.records.get('macos-universal/A');
  const effective = JSON.parse(
    readFileSync(absoluteArtifact(fixture, record.effectiveGnArgs), 'utf8'),
  );
  effective.configurations.pop();
  rewriteDescriptor(fixture, record.effectiveGnArgs, effective);
  expectFailure(
    fixture,
    /effective GN args must contain exactly 2 architecture configurations/,
  );
});

check('A/B resolved dependency mismatch is rejected', (fixture) => {
  const pair = fixture.evidence.platforms['windows-x64'];
  const lock = JSON.parse(
    readFileSync(absoluteArtifact(fixture, pair.B.dependencyLock), 'utf8'),
  );
  lock.gclientRevinfoSha256 = 'f'.repeat(64);
  rewriteDescriptor(
    fixture,
    pair.B.dependencyLock,
    lock,
  );
  rebindBundleDerivedRecords(fixture, 'windows-x64', 'B');
  expectFailure(fixture, /dependencyLockSha256 values do not match/);
});

check('CycloneDX SBOM must bind dependency and toolchain lock bytes', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  updateSbomProperty(
    fixture,
    record,
    'proteus:toolchain-lock-sha256',
    '0'.repeat(64),
  );
  expectFailure(fixture, /CycloneDX SBOM differs from recomputed build inputs/);
});

check('A/B complete bundle tree mismatch is rejected', (fixture) => {
  const pair = fixture.evidence.platforms['windows-x64'];
  const resource = join(
    fixture.artifacts,
    ...pair.B.bundleRoot.split('/'),
    'resources.pak',
  );
  writeFileSync(resource, 'different complete tree\n');
  rebindBundleDerivedRecords(fixture, 'windows-x64', 'B');
  expectFailure(fixture, /bundleTreeSha256 values do not match/);
});

check('bundle entrypoint architecture is verified from executable bytes', (fixture) => {
  const record = fixture.records.get('windows-x64/A');
  const entrypoint = join(
    fixture.artifacts,
    ...record.bundleRoot.split('/'),
    ENTRYPOINTS['windows-x64'],
  );
  writeFileSync(entrypoint, Buffer.alloc(512));
  chmodSync(entrypoint, 0o755);
  rebindBundleDerivedRecords(fixture, 'windows-x64', 'A');
  expectFailure(fixture, /not a PE file|entrypoint architectures/);
});

check('external runner instance IDs must be unique across all builds', (fixture) => {
  const left = fixture.records.get('linux-x64/A');
  const right = fixture.records.get('linux-x64/B');
  const leftReceipt = readReceipt(fixture, left);
  const rightReceipt = readReceipt(fixture, right);
  rightReceipt.instanceId = leftReceipt.instanceId;
  rewriteReceipt(fixture, right, rightReceipt);
  expectFailure(fixture, /external runner instanceId is reused/);
});

check('external receipt must prove single-use destruction', (fixture) => {
  const record = fixture.records.get('linux-x64/A');
  const receipt = readReceipt(fixture, record);
  receipt.destroyed = false;
  rewriteReceipt(fixture, record, receipt);
  expectFailure(fixture, /singleUse=true and destroyed=true/);
});

check('external receipt signature is verified with the pinned Ed25519 key', (fixture) => {
  const record = fixture.records.get('linux-x64/A');
  const receipt = readReceipt(fixture, record);
  receipt.signature =
    `${receipt.signature[0] === 'A' ? 'B' : 'A'}${receipt.signature.slice(1)}`;
  rewriteDescriptor(fixture, record.runner.receipt, receipt);
  expectFailure(fixture, /signature is invalid/);
});

check('controller key substitution is rejected against external trust', (fixture) => {
  const {
    privateKey: attackerPrivate,
    publicKey: attackerPublic,
  } = generateKeyPairSync('ed25519');
  writeFileSync(
    fixture.publicKeyPath,
    attackerPublic.export({ format: 'pem', type: 'spki' }),
  );
  const attackerKeyId = digest(
    attackerPublic.export({ format: 'der', type: 'spki' }),
  );
  for (const slot of SLOTS) {
    const record = fixture.records.get(`linux-x64/${slot}`);
    const receipt = readReceipt(fixture, record);
    receipt.keyId = attackerKeyId;
    receipt.signature = sign(
      null,
      runnerReceiptSigningInput(receipt),
      attackerPrivate,
    ).toString('base64');
    rewriteDescriptor(fixture, record.runner.receipt, receipt);
  }
  expectFailure(
    fixture,
    /does not match the trusted controller key/,
    { policyCheckoutVerifier: () => ({ ok: true }) },
  );
});

check('external runners require an independently trusted controller key digest', (fixture) => {
  expectFailure(
    fixture,
    /trusted external runner controller SPKI SHA-256 is required/,
    { expectedRunnerControllerKeySha256: null },
  );
});

check('external receipt must bind the exact recomputed output', (fixture) => {
  const record = fixture.records.get('linux-x64/A');
  const receipt = readReceipt(fixture, record);
  receipt.output.liveReportSha256 = '0'.repeat(64);
  rewriteReceipt(fixture, record, receipt);
  expectFailure(fixture, /output binding is wrong/);
});

check('missing external controller key fails closed', (fixture) => {
  unlinkSync(fixture.publicKeyPath);
  expectFailure(fixture, /external runner controller public key|ENOENT/);
});

check('path traversal is rejected before evidence files are consumed', (fixture) => {
  fixture.records.get('windows-x64/A').sbom.path = '../outside.json';
  expectFailure(fixture, /canonical relative POSIX path/);
});

check('portable evidence paths reject Windows ADS and device aliases', (fixture) => {
  fixture.records.get('windows-x64/A').sbom.path = 'v2/windows-x64/A/NUL.json';
  fixture.records.get('macos-universal/A').sbom.path =
    'v2/macos-universal/A/sbom.json:stream';
  const audit = verifyFixture(fixture);
  assert(!audit.ok, 'portable path aliases unexpectedly passed');
  assert(
    audit.failures.filter((failure) =>
      /canonical relative POSIX path/.test(failure)).length >= 2,
    audit.failures.join('\n'),
  );
});

check('duplicate evidence JSON keys are rejected by the file entrypoint', (fixture) => {
  const evidencePath = join(
    fixture.repo,
    'engine-chromium',
    'artifacts',
    'm0-build-evidence-v2.json',
  );
  const bytes = JSON.stringify(fixture.evidence).replace(
    '{"schemaVersion":"2.0.0"',
    '{"schemaVersion":"ignored","schemaVersion":"2.0.0"',
  );
  writeFileSync(evidencePath, bytes);
  const audit = verifyM0EvidenceV2(fixture.repo, {
    expectedSourceDigest: fixture.sourceDigest,
    expectedSignerDigest: SIGNER_DIGEST,
    expectedRunnerControllerKeySha256: fixture.keyId,
    attestationVerifier: fixture.attestationVerifier,
    githubVerifier: fixture.githubVerifier,
  });
  assert(!audit.ok, 'duplicate evidence key unexpectedly passed');
  assert(
    audit.failures.some((failure) => /duplicate object key/.test(failure)),
    audit.failures.join('\n'),
  );
});

check('invocation builder never omits deny-self-hosted when requested', () => {
  const invocation = buildGhAttestationVerifyInvocation({
    artifactPath: '/tmp/artifact',
    bundlePath: '/tmp/bundle',
    repository: 'jiyujie2006/proteus-browser',
    signerWorkflow:
      'jiyujie2006/proteus-browser/.github/workflows/m0-builder.yml',
    signerDigest: SIGNER_DIGEST,
    sourceDigest: 'a'.repeat(40),
    sourceRef: 'refs/heads/main',
    predicateType: 'https://proteus.example/attestations/m0-build/v2',
    oidcIssuer: 'https://token.actions.githubusercontent.com',
    denySelfHosted: true,
  });
  assert(
    invocation.args.at(-1) === '--deny-self-hosted-runners',
    'deny-self-hosted flag missing',
  );
});

console.log('  ' + '─'.repeat(62));
console.log(`  ${passed} passed, ${failed} failed\n`);
process.exitCode = failed === 0 ? 0 : 1;
