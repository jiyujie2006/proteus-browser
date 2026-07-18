#!/usr/bin/env node
// Validate the immutable M0 build/trust contracts against the repository bytes.

import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  writeSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseStrictJson } from '../../scripts/strict-json.mjs';
import { readChromiumBaseline } from './baseline.mjs';
import { activePatchSeriesSha256 } from './patch-series.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = resolve(HERE, '..');
const REPO_ROOT = resolve(ENGINE_ROOT, '..');
const BUILD_CONTRACT_PATH = join(ENGINE_ROOT, 'build', 'm0-build-contract.json');
const TRUST_CONTRACT_PATH = join(ENGINE_ROOT, 'build', 'm0-trust.json');
const SHA256_RE = /^[0-9a-f]{64}$/u;

export const M0_HARD_ASSURANCE_LEVEL =
  'full-bundle-builder-attested/v2';
export const M0_PLATFORM_IDS = Object.freeze([
  'windows-x64',
  'macos-universal',
  'linux-x64',
]);

function exactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} must contain exactly: ${keys.join(', ')}`);
  }
  return value;
}

function exactString(value, expected, label) {
  if (value !== expected) {
    throw new TypeError(`${label} must equal ${expected}`);
  }
}

function nonEmptyStrings(value, label) {
  if (!Array.isArray(value)
      || value.length === 0
      || value.some((item) => typeof item !== 'string' || item.length === 0)
      || new Set(value).size !== value.length) {
    throw new TypeError(`${label} must be a non-empty unique string array`);
  }
  return value;
}

function readStableOrdinaryFile(path, label, maxBytes = 1024 * 1024) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  if (before.size > BigInt(maxBytes)) {
    throw new TypeError(`${label} exceeds ${maxBytes} bytes`);
  }
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameStableFile(before, opened)) {
      throw new TypeError(`${label} changed while it was opened`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    if (!sameStableFile(opened, after) || !sameStableFile(after, pathAfter)) {
      throw new TypeError(`${label} changed or was rebound while it was read`);
    }
    return bytes;
  } finally {
    closeSync(fd);
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

function readContract(path, label) {
  return parseStrictJson(
    readStableOrdinaryFile(path, label),
    label,
  );
}

function sha256File(path, label) {
  return createHash('sha256')
    .update(readStableOrdinaryFile(path, label, 4 * 1024 * 1024))
    .digest('hex');
}

export function validateM0BuildContract(
  buildContract,
  trustContract,
  {
    engineRoot = ENGINE_ROOT,
    repoRoot = REPO_ROOT,
  } = {},
) {
  const baseline = readChromiumBaseline(
    join(engineRoot, 'CHROMIUM_BASELINE'),
  );

  exactKeys(buildContract, [
    'schemaVersion',
    'milestone',
    'assuranceLevel',
    'source',
    'patches',
    'gn',
    'bundle',
    'platforms',
    'requiredRecords',
  ], 'M0 build contract');
  exactString(buildContract.schemaVersion, '1.0.0', 'schemaVersion');
  exactString(buildContract.milestone, 'M0', 'milestone');
  exactString(
    buildContract.assuranceLevel,
    M0_HARD_ASSURANCE_LEVEL,
    'assuranceLevel',
  );

  const source = exactKeys(buildContract.source, [
    'chromiumRepository',
    'chromiumVersion',
    'chromiumCommit',
    'depotToolsRepository',
    'depotToolsCommit',
  ], 'source');
  const sourceMapping = {
    chromiumRepository: 'CHROMIUM_REPOSITORY',
    chromiumVersion: 'CHROMIUM_STABLE',
    chromiumCommit: 'CHROMIUM_COMMIT',
    depotToolsRepository: 'DEPOT_TOOLS_REPOSITORY',
    depotToolsCommit: 'DEPOT_TOOLS_COMMIT',
  };
  for (const [contractKey, baselineKey] of Object.entries(sourceMapping)) {
    exactString(source[contractKey], baseline[baselineKey], `source.${contractKey}`);
  }

  const patches = exactKeys(
    buildContract.patches,
    ['profile', 'activeSeriesSha256'],
    'patches',
  );
  exactString(patches.profile, baseline.PATCH_PROFILE, 'patches.profile');
  const activeHash = activePatchSeriesSha256(
    engineRoot,
    baseline.PATCH_PROFILE,
  );
  exactString(
    patches.activeSeriesSha256,
    activeHash,
    'patches.activeSeriesSha256',
  );

  const gn = exactKeys(buildContract.gn, [
    'template',
    'templateSha256',
    'effectiveArgsCommand',
    'cachePolicy',
  ], 'gn');
  exactString(gn.template, 'engine-chromium/build/args.gn', 'gn.template');
  if (!SHA256_RE.test(gn.templateSha256)) {
    throw new TypeError('gn.templateSha256 must be lowercase SHA-256');
  }
  exactString(
    gn.templateSha256,
    sha256File(join(repoRoot, gn.template), 'GN args template'),
    'gn.templateSha256',
  );
  exactString(
    gn.effectiveArgsCommand,
    'gn args <out-dir> --list --short',
    'gn.effectiveArgsCommand',
  );
  exactString(gn.cachePolicy, 'disabled', 'gn.cachePolicy');

  const bundle = exactKeys(buildContract.bundle, [
    'manifestSchemaVersion',
    'comparison',
    'runtimeDependencyCommand',
    'transportArchivesAreEvidenceSubjects',
  ], 'bundle');
  exactString(
    bundle.manifestSchemaVersion,
    '1.0.0',
    'bundle.manifestSchemaVersion',
  );
  exactString(
    bundle.comparison,
    'unsigned-complete-tree-sha256',
    'bundle.comparison',
  );
  exactString(
    bundle.runtimeDependencyCommand,
    'gn desc <out-dir> chrome runtime_deps',
    'bundle.runtimeDependencyCommand',
  );
  if (bundle.transportArchivesAreEvidenceSubjects !== false) {
    throw new TypeError(
      'transport archives must not replace the canonical complete-tree subject',
    );
  }

  exactKeys(buildContract.platforms, M0_PLATFORM_IDS, 'platforms');
  const expectedPlatforms = {
    'windows-x64': {
      hostPlatform: 'win32',
      architectures: ['x86_64'],
      entrypoint: 'chrome.exe',
      extra: [],
    },
    'macos-universal': {
      hostPlatform: 'darwin',
      architectures: ['x86_64', 'arm64'],
      entrypoint: 'Chromium.app/Contents/MacOS/Chromium',
      extra: ['universalizer'],
    },
    'linux-x64': {
      hostPlatform: 'linux',
      architectures: ['x86_64'],
      entrypoint: 'chrome',
      extra: [],
    },
  };
  for (const platform of M0_PLATFORM_IDS) {
    const expected = expectedPlatforms[platform];
    const keys = [
      'hostPlatform',
      'architectures',
      'buildTargets',
      'entrypoint',
      'independentBuilds',
      ...expected.extra,
    ];
    const item = exactKeys(
      buildContract.platforms[platform],
      keys,
      `platforms.${platform}`,
    );
    exactString(
      item.hostPlatform,
      expected.hostPlatform,
      `${platform}.hostPlatform`,
    );
    if (JSON.stringify(item.architectures)
        !== JSON.stringify(expected.architectures)) {
      throw new TypeError(`${platform}.architectures does not match the contract`);
    }
    if (JSON.stringify(nonEmptyStrings(item.buildTargets, `${platform}.buildTargets`))
        !== JSON.stringify(['chrome', 'components_unittests'])) {
      throw new TypeError(
        `${platform}.buildTargets must contain chrome and components_unittests`,
      );
    }
    exactString(item.entrypoint, expected.entrypoint, `${platform}.entrypoint`);
    if (item.independentBuilds !== 2) {
      throw new TypeError(`${platform}.independentBuilds must equal 2`);
    }
    if (platform === 'macos-universal') {
      exactString(
        item.universalizer,
        'chrome/installer/mac/universalizer.py',
        `${platform}.universalizer`,
      );
    }
  }

  const requiredRecords = nonEmptyStrings(
    buildContract.requiredRecords,
    'requiredRecords',
  );
  const mandatory = [
    'resolved-dependency-lock',
    'effective-gn-args',
    'complete-toolchain-lock',
    'runtime-dependency-package-record',
    'complete-bundle-manifest',
    'build-derived-cyclonedx-sbom',
    'artifact-license-bundle',
    'artifact-driven-live-report',
    'slsa-provenance-attestation',
    'sbom-attestation',
    'proteus-build-attestation',
    'raw-sigstore-bundles',
  ];
  if (JSON.stringify(requiredRecords) !== JSON.stringify(mandatory)) {
    throw new TypeError('requiredRecords is missing or reorders a hard-M0 record');
  }

  exactKeys(trustContract, [
    'schemaVersion',
    'repository',
    'sourceRef',
    'oidcIssuer',
    'workflows',
    'predicateTypes',
    'runnerTrust',
  ], 'M0 trust contract');
  exactString(trustContract.schemaVersion, '1.0.0', 'trust.schemaVersion');
  exactString(trustContract.sourceRef, 'refs/heads/main', 'trust.sourceRef');
  exactString(
    trustContract.oidcIssuer,
    'https://token.actions.githubusercontent.com',
    'trust.oidcIssuer',
  );
  exactKeys(trustContract.repository, [
    'nameWithOwner',
    'repositoryId',
    'owner',
    'ownerId',
    'visibility',
  ], 'trust.repository');
  exactString(
    trustContract.repository.nameWithOwner,
    'jiyujie2006/proteus-browser',
    'trust.repository.nameWithOwner',
  );
  exactString(
    trustContract.repository.repositoryId,
    '1304085575',
    'trust.repository.repositoryId',
  );
  exactString(
    trustContract.repository.owner,
    'jiyujie2006',
    'trust.repository.owner',
  );
  exactString(
    trustContract.repository.ownerId,
    '49909156',
    'trust.repository.ownerId',
  );
  exactString(
    trustContract.repository.visibility,
    'public',
    'trust.repository.visibility',
  );
  exactKeys(
    trustContract.workflows,
    ['builder', 'aggregate', 'hardGate'],
    'trust.workflows',
  );
  exactString(
    trustContract.workflows.builder,
    '.github/workflows/m0-builder.yml',
    'trust.workflows.builder',
  );
  exactString(
    trustContract.workflows.aggregate,
    '.github/workflows/m0-aggregate.yml',
    'trust.workflows.aggregate',
  );
  exactString(
    trustContract.workflows.hardGate,
    '.github/workflows/m0-hard-gate.yml',
    'trust.workflows.hardGate',
  );
  exactKeys(
    trustContract.predicateTypes,
    ['provenance', 'sbom', 'build', 'aggregate'],
    'trust.predicateTypes',
  );
  const predicateTypes = trustContract.predicateTypes;
  exactString(
    predicateTypes.provenance,
    'https://slsa.dev/provenance/v1',
    'trust.predicateTypes.provenance',
  );
  exactString(
    predicateTypes.sbom,
    'https://cyclonedx.org/bom',
    'trust.predicateTypes.sbom',
  );
  exactString(
    predicateTypes.build,
    'https://proteus.example/attestations/m0-build/v2',
    'trust.predicateTypes.build',
  );
  exactString(
    predicateTypes.aggregate,
    'https://proteus.example/attestations/m0-aggregate/v2',
    'trust.predicateTypes.aggregate',
  );
  const runnerTrust = exactKeys(
    trustContract.runnerTrust,
    ['githubHosted', 'externalEphemeral'],
    'trust.runnerTrust',
  );
  exactKeys(
    runnerTrust.githubHosted,
    ['requireDenySelfHostedVerification'],
    'trust.runnerTrust.githubHosted',
  );
  if (runnerTrust.githubHosted.requireDenySelfHostedVerification !== true) {
    throw new TypeError('GitHub-hosted attestations must deny self-hosted runners');
  }
  const external = exactKeys(runnerTrust.externalEphemeral, [
    'receiptSchemaVersion',
    'publicKeyPath',
    'requireSingleUse',
    'requireDestroyed',
    'requireUniqueInstancePerBuild',
  ], 'trust.runnerTrust.externalEphemeral');
  exactString(
    external.receiptSchemaVersion,
    '1.0.0',
    'external receipt schema',
  );
  exactString(
    external.publicKeyPath,
    '.github/keys/m0-runner-controller-ed25519.pub',
    'external receipt key path',
  );
  for (const key of [
    'requireSingleUse',
    'requireDestroyed',
    'requireUniqueInstancePerBuild',
  ]) {
    if (external[key] !== true) {
      throw new TypeError(`externalEphemeral.${key} must be true`);
    }
  }

  return {
    assuranceLevel: buildContract.assuranceLevel,
    chromiumCommit: source.chromiumCommit,
    patchSeriesSha256: activeHash,
    platforms: [...M0_PLATFORM_IDS],
    repository: trustContract.repository.nameWithOwner,
  };
}

export function readAndValidateM0BuildContract({
  buildContractPath = BUILD_CONTRACT_PATH,
  trustContractPath = TRUST_CONTRACT_PATH,
} = {}) {
  const buildContract = readContract(
    buildContractPath,
    'M0 build contract',
  );
  const trustContract = readContract(
    trustContractPath,
    'M0 trust contract',
  );
  const audit = validateM0BuildContract(buildContract, trustContract);
  return {
    audit,
    buildContract,
    buildContractSha256: sha256File(
      buildContractPath,
      'M0 build contract',
    ),
    trustContract,
    trustContractSha256: sha256File(
      trustContractPath,
      'M0 trust contract',
    ),
  };
}

function main() {
  try {
    const args = process.argv.slice(2);
    if (args.length > 1 || (args[0] && !['--check', '--json'].includes(args[0]))) {
      throw new TypeError('usage: build-contract.mjs [--check|--json]');
    }
    const { audit } = readAndValidateM0BuildContract();
    if (args[0] === '--json') {
      writeSync(process.stdout.fd, `${JSON.stringify(audit, null, 2)}\n`);
    } else {
      writeSync(
        process.stdout.fd,
        `M0 build contract valid: ${audit.platforms.length} platforms, ${audit.assuranceLevel}\n`,
      );
    }
  } catch (error) {
    writeSync(process.stderr.fd, `ERROR: ${error.message}\n`);
    process.exitCode = 2;
  }
}

const isDirect = import.meta.main ?? (
  process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
);
if (isDirect) main();
