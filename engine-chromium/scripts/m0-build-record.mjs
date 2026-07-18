#!/usr/bin/env node
// Produce the canonical predicates and evidence index consumed by the hard-M0
// verifier. This script never signs anything: GitHub OIDC/Sigstore signs the
// emitted predicates, and the hard gate reconstructs every byte independently.

import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  M0_PLATFORM_IDS,
  readAndValidateM0BuildContract,
} from './build-contract.mjs';
import {
  createM0BuildPredicate,
  createM0ProvenancePredicate,
  M0_EVIDENCE_V2_ASSURANCE_LEVEL,
  M0_EVIDENCE_V2_SCHEMA_VERSION,
} from './m0-predicates.mjs';
import { parseStrictJson } from '../../scripts/strict-json.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = resolve(HERE, '..');
const DEFAULT_ARTIFACT_ROOT = join(ENGINE_ROOT, 'artifacts');
const SHA256_RE = /^[0-9a-f]{64}$/u;
const GIT_COMMIT_RE = /^[0-9a-f]{40}$/u;
const GITHUB_ID_RE = /^[1-9][0-9]{0,19}$/u;
const ARTIFACT_NAME_RE =
  /^m0-payload-(?:windows-x64|macos-universal|linux-x64)-[AB]-attempt-[1-9][0-9]{0,8}$/u;
const SLOTS = Object.freeze(['A', 'B']);
const MAX_RECORD_BYTES = 64 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 42 * 1024 * 1024 * 1024;
const MAX_INNER_TAR_BYTES = 40 * 1024 * 1024 * 1024;

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

function readStableBytes(path, label, maximum = MAX_RECORD_BYTES) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  if (before.size > BigInt(maximum)) {
    throw new TypeError(`${label} exceeds ${maximum} bytes`);
  }
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameStableFile(before, opened)) {
      throw new TypeError(`${label} changed while it was opened`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const rebound = lstatSync(path, { bigint: true });
    if (!sameStableFile(opened, after) || !sameStableFile(after, rebound)) {
      throw new TypeError(`${label} changed or was rebound while it was read`);
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function assertCanonicalRelativePath(value, label) {
  if (typeof value !== 'string'
      || value.length === 0
      || value.length > 1024
      || value !== value.normalize('NFC')
      || isAbsolute(value)
      || value.includes('\\')
      || value.includes(':')
      || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError(`${label} must be a canonical relative POSIX path`);
  }
  if (value.split('/').some((part) =>
    part === '' || part === '.' || part === '..' || /[. ]$/u.test(part))) {
    throw new TypeError(`${label} must be a canonical relative POSIX path`);
  }
  return value;
}

function assertContained(root, path, label) {
  const rel = relative(root, path);
  if (rel === ''
      || (rel !== '..'
        && !rel.startsWith(`..${sep}`)
        && !isAbsolute(rel))) {
    return;
  }
  throw new TypeError(`${label} escapes the artifact root`);
}

function artifactPath(root, relativePath, label) {
  assertCanonicalRelativePath(relativePath, label);
  const rootReal = realpathSync(root);
  const path = resolve(rootReal, ...relativePath.split('/'));
  assertContained(rootReal, path, label);
  return path;
}

function freshArtifactPath(root, relativePath, label) {
  assertCanonicalRelativePath(relativePath, label);
  const rootReal = realpathSync(root);
  const path = resolve(rootReal, ...relativePath.split('/'));
  assertContained(rootReal, path, label);
  const parent = dirname(path);
  if (realpathSync(parent) !== parent) {
    throw new TypeError(`${label} parent is not canonical`);
  }
  return path;
}

function descriptor(root, relativePath, label, extra = {}) {
  const path = artifactPath(root, relativePath, label);
  const bytes = readStableBytes(path, label);
  return {
    path: relativePath,
    sha256: sha256(bytes),
    ...extra,
  };
}

function positiveGithubId(value, label) {
  const text = String(value);
  if (!GITHUB_ID_RE.test(text)) {
    throw new TypeError(`${label} must be a positive decimal GitHub ID`);
  }
  return text;
}

function positiveSafeInteger(value, label, maximum) {
  const number = typeof value === 'string' && /^[1-9][0-9]{0,15}$/u.test(value)
    ? Number(value)
    : value;
  if (!Number.isSafeInteger(number) || number < 1 || number > maximum) {
    throw new TypeError(`${label} must be a bounded positive safe integer`);
  }
  return number;
}

function artifactBinding(value, platform, slot, runAttempt) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('payload artifact binding must be an object');
  }
  const keys = [
    'artifactId',
    'artifactName',
    'artifactDigest',
    'artifactSize',
    'artifactInnerSha256',
    'artifactInnerSize',
  ];
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError('payload artifact binding has missing or unknown fields');
  }
  const expectedName = `m0-payload-${platform}-${slot}-attempt-${runAttempt}`;
  if (typeof value.artifactName !== 'string'
      || !ARTIFACT_NAME_RE.test(value.artifactName)
      || value.artifactName !== expectedName) {
    throw new TypeError('payload artifact name does not match platform and slot');
  }
  for (const [field, label] of [
    ['artifactDigest', 'payload artifact digest'],
    ['artifactInnerSha256', 'payload inner tar digest'],
  ]) {
    if (!SHA256_RE.test(value[field] ?? '')) {
      throw new TypeError(`${label} must be a lowercase SHA-256`);
    }
  }
  return {
    artifactId: positiveGithubId(value.artifactId, 'artifactId'),
    artifactName: value.artifactName,
    artifactDigest: value.artifactDigest,
    artifactSize: positiveSafeInteger(
      value.artifactSize,
      'artifactSize',
      MAX_ARTIFACT_BYTES,
    ),
    artifactInnerSha256: value.artifactInnerSha256,
    artifactInnerSize: positiveSafeInteger(
      value.artifactInnerSize,
      'artifactInnerSize',
      MAX_INNER_TAR_BYTES,
    ),
  };
}

function gitCommit(value, label) {
  if (!GIT_COMMIT_RE.test(value ?? '')) {
    throw new TypeError(`${label} must be a lowercase 40-hex Git commit`);
  }
  return value;
}

function platformAndSlot(platform, slot) {
  if (!M0_PLATFORM_IDS.includes(platform)) {
    throw new TypeError(`unsupported M0 platform ${String(platform)}`);
  }
  if (!SLOTS.includes(slot)) {
    throw new TypeError(`build slot must be A or B, got ${String(slot)}`);
  }
}

function buildRootFor(platform, slot) {
  platformAndSlot(platform, slot);
  return `builds/${platform}/${slot}`;
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function writeFreshAtomic(path, contents, label) {
  const destination = resolve(path);
  const parent = dirname(destination);
  const parentStat = lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
    throw new TypeError(`${label} parent must be an ordinary directory`);
  }
  if (existsSync(destination)) {
    throw new TypeError(`${label} already exists`);
  }
  const temporary = join(
    parent,
    `.proteus-${process.pid}-${createHash('sha256')
      .update(`${destination}\0${Date.now()}\0${Math.random()}`)
      .digest('hex')
      .slice(0, 16)}.tmp`,
  );
  try {
    writeFileSync(temporary, contents, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o644,
    });
    renameSync(temporary, destination);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function policyFromContracts(buildContract, trustContract) {
  return {
    buildContract,
    predicateTypes: trustContract.predicateTypes,
    sourceRef: trustContract.sourceRef,
  };
}

export function prepareM0BuildRecord({
  artifactRoot = DEFAULT_ARTIFACT_ROOT,
  platform,
  slot,
  runId,
  runAttempt,
  checkRunId,
  artifactId,
  artifactName,
  artifactDigest,
  artifactSize,
  artifactInnerSha256,
  artifactInnerSize,
  runnerKind,
  sourceDigest,
  signerDigest = sourceDigest,
}) {
  platformAndSlot(platform, slot);
  const normalizedRunAttempt = positiveSafeInteger(
    runAttempt,
    'runAttempt',
    999_999_999,
  );
  const artifact = artifactBinding({
    artifactId,
    artifactName,
    artifactDigest,
    artifactSize,
    artifactInnerSha256,
    artifactInnerSize,
  }, platform, slot, normalizedRunAttempt);
  const root = realpathSync(resolve(artifactRoot));
  const buildRoot = buildRootFor(platform, slot);
  const recordRoot = `${buildRoot}/records`;
  const bundleRoot = `${buildRoot}/bundle`;
  const manifestPath = `${recordRoot}/bundle-manifest.json`;
  const manifestBytes = readStableBytes(
    artifactPath(root, manifestPath, 'complete bundle manifest'),
    'complete bundle manifest',
  );
  const manifest = parseStrictJson(manifestBytes, 'complete bundle manifest');
  if (!SHA256_RE.test(manifest.treeSha256 ?? '')) {
    throw new TypeError('complete bundle manifest lacks a lowercase tree SHA-256');
  }

  const {
    buildContract,
    buildContractSha256,
    trustContract,
    trustContractSha256,
  } = readAndValidateM0BuildContract();
  if (runnerKind !== 'github-hosted'
      && runnerKind !== 'external-ephemeral') {
    throw new TypeError('runnerKind must be github-hosted or external-ephemeral');
  }
  const runner = runnerKind === 'github-hosted'
    ? { kind: runnerKind }
    : {
      kind: runnerKind,
      receipt: descriptor(
        root,
        `${recordRoot}/runner-receipt.json`,
        'external runner receipt',
      ),
    };
  const bundleManifest = descriptor(
    root,
    manifestPath,
    'complete bundle manifest',
    { treeSha256: manifest.treeSha256 },
  );
  const dependencyLock = descriptor(
    root,
    `${recordRoot}/resolved-dependency-lock.json`,
    'resolved dependency lock',
  );
  const toolchainLock = descriptor(
    root,
    `${recordRoot}/complete-toolchain-lock.json`,
    'complete toolchain lock',
  );
  const effectiveGnArgs = descriptor(
    root,
    `${recordRoot}/effective-gn-args.json`,
    'effective GN args record',
  );
  const sbom = descriptor(
    root,
    `${recordRoot}/build-sbom.cdx.json`,
    'build-derived CycloneDX SBOM',
  );
  const licenseBundle = descriptor(
    root,
    `${bundleRoot}/LICENSES/artifact-license-manifest.json`,
    'artifact license bundle',
  );
  const liveReport = descriptor(
    root,
    `${recordRoot}/live-report.json`,
    'artifact-driven live report',
  );
  const outputs = {
    bundleTreeSha256: manifest.treeSha256,
    bundleManifestSha256: bundleManifest.sha256,
    dependencyLockSha256: dependencyLock.sha256,
    toolchainLockSha256: toolchainLock.sha256,
    effectiveGnArgsSha256: effectiveGnArgs.sha256,
    sbomSha256: sbom.sha256,
    licenseBundleSha256: licenseBundle.sha256,
    liveReportSha256: liveReport.sha256,
  };
  const buildFacts = {
    ...artifact,
    buildContractSha256,
    checkRunId: positiveGithubId(checkRunId, 'checkRunId'),
    outputs,
    platform,
    repository: {
      nameWithOwner: trustContract.repository.nameWithOwner,
      repositoryId: trustContract.repository.repositoryId,
      ownerId: trustContract.repository.ownerId,
      visibility: trustContract.repository.visibility,
    },
    runAttempt: normalizedRunAttempt,
    runId: positiveGithubId(runId, 'runId'),
    signerDigest: gitCommit(signerDigest, 'signerDigest'),
    slot,
    sourceDigest: gitCommit(sourceDigest, 'sourceDigest'),
    trustContractSha256,
    workflow: trustContract.workflows.builder,
  };
  const core = {
    runId: buildFacts.runId,
    runAttempt: buildFacts.runAttempt,
    checkRunId: buildFacts.checkRunId,
    artifactId: buildFacts.artifactId,
    artifactName: buildFacts.artifactName,
    artifactDigest: buildFacts.artifactDigest,
    artifactSize: buildFacts.artifactSize,
    artifactInnerSha256: buildFacts.artifactInnerSha256,
    artifactInnerSize: buildFacts.artifactInnerSize,
    runner,
    bundleRoot,
    bundleManifest,
    dependencyLock,
    toolchainLock,
    effectiveGnArgs,
    sbom,
    licenseBundle,
    liveReport,
  };
  const policy = policyFromContracts(buildContract, trustContract);
  return {
    buildFacts,
    buildPredicate: createM0BuildPredicate(buildFacts, policy),
    provenancePredicate: createM0ProvenancePredicate(buildFacts, policy),
    recordCore: core,
  };
}

export function completeM0BuildRecord({
  artifactRoot = DEFAULT_ARTIFACT_ROOT,
  platform,
  slot,
  recordCore,
}) {
  platformAndSlot(platform, slot);
  const root = realpathSync(resolve(artifactRoot));
  const recordRoot = `${buildRootFor(platform, slot)}/records`;
  if (!recordCore || typeof recordCore !== 'object'
      || Array.isArray(recordCore)) {
    throw new TypeError('recordCore must be an object');
  }
  return {
    ...recordCore,
    attestations: {
      provenance: descriptor(
        root,
        `${recordRoot}/attestations/provenance.sigstore.json`,
        'provenance Sigstore bundle',
      ),
      sbom: descriptor(
        root,
        `${recordRoot}/attestations/sbom.sigstore.json`,
        'SBOM Sigstore bundle',
      ),
      build: descriptor(
        root,
        `${recordRoot}/attestations/build.sigstore.json`,
        'build Sigstore bundle',
      ),
    },
  };
}

export function aggregateM0BuildRecords({
  artifactRoot = DEFAULT_ARTIFACT_ROOT,
  sourceDigest,
  signerDigest = sourceDigest,
}) {
  const root = realpathSync(resolve(artifactRoot));
  const { trustContract } = readAndValidateM0BuildContract();
  const platforms = {};
  for (const platform of M0_PLATFORM_IDS) {
    platforms[platform] = {};
    for (const slot of SLOTS) {
      const relativePath =
        `${buildRootFor(platform, slot)}/records/build-record.json`;
      platforms[platform][slot] = parseStrictJson(
        readStableBytes(
          artifactPath(root, relativePath, `${platform}/${slot} build record`),
          `${platform}/${slot} build record`,
        ),
        `${platform}/${slot} build record`,
      );
    }
  }
  return {
    schemaVersion: M0_EVIDENCE_V2_SCHEMA_VERSION,
    assuranceLevel: M0_EVIDENCE_V2_ASSURANCE_LEVEL,
    repository: {
      nameWithOwner: trustContract.repository.nameWithOwner,
      repositoryId: trustContract.repository.repositoryId,
      ownerId: trustContract.repository.ownerId,
      visibility: trustContract.repository.visibility,
    },
    source: {
      digest: gitCommit(sourceDigest, 'sourceDigest'),
      ref: trustContract.sourceRef,
    },
    signer: {
      workflow: trustContract.workflows.builder,
      digest: gitCommit(signerDigest, 'signerDigest'),
    },
    platforms,
  };
}

function parseOptions(args, allowed) {
  const values = Object.create(null);
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (!allowed.has(option)) {
      throw new TypeError(`unknown argument ${option}`);
    }
    if (Object.hasOwn(values, option)) {
      throw new TypeError(`${option} may only be supplied once`);
    }
    const value = args[index + 1];
    if (!value || value.startsWith('--')) {
      throw new TypeError(`${option} requires a value`);
    }
    values[option] = value;
    index += 1;
  }
  return values;
}

function requireOptions(values, keys) {
  for (const key of keys) {
    if (!Object.hasOwn(values, key)) {
      throw new TypeError(`${key} is required`);
    }
  }
}

function writePreparedFiles(materials, artifactRoot, platform, slot) {
  const recordRoot = artifactPath(
    artifactRoot,
    `${buildRootFor(platform, slot)}/records`,
    'record root',
  );
  mkdirSync(join(recordRoot, 'attestations'), { recursive: true });
  writeFreshAtomic(
    join(recordRoot, 'build-predicate.json'),
    canonicalJson(materials.buildPredicate),
    'build predicate',
  );
  writeFreshAtomic(
    join(recordRoot, 'provenance-predicate.json'),
    canonicalJson(materials.provenancePredicate),
    'provenance predicate',
  );
  writeFreshAtomic(
    join(recordRoot, 'build-record-core.json'),
    canonicalJson(materials.recordCore),
    'build record core',
  );
}

function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!['prepare', 'complete', 'aggregate'].includes(command)) {
    throw new TypeError(
      'usage: m0-build-record.mjs prepare|complete|aggregate [options]',
    );
  }
  if (command === 'prepare') {
    const values = parseOptions(args, new Set([
      '--artifact-root',
      '--platform',
      '--slot',
      '--run-id',
      '--run-attempt',
      '--check-run-id',
      '--artifact-binding',
      '--runner-kind',
      '--source-digest',
      '--signer-digest',
    ]));
    requireOptions(values, [
      '--artifact-root',
      '--platform',
      '--slot',
      '--run-id',
      '--run-attempt',
      '--check-run-id',
      '--artifact-binding',
      '--runner-kind',
      '--source-digest',
    ]);
    const artifactRoot = resolve(values['--artifact-root']);
    const binding = parseStrictJson(
      readStableBytes(
        resolve(values['--artifact-binding']),
        'payload artifact binding',
      ),
      'payload artifact binding',
    );
    const materials = prepareM0BuildRecord({
      artifactRoot,
      platform: values['--platform'],
      slot: values['--slot'],
      runId: values['--run-id'],
      runAttempt: values['--run-attempt'],
      checkRunId: values['--check-run-id'],
      ...binding,
      runnerKind: values['--runner-kind'],
      sourceDigest: values['--source-digest'],
      signerDigest: values['--signer-digest'],
    });
    writePreparedFiles(
      materials,
      artifactRoot,
      values['--platform'],
      values['--slot'],
    );
    writeSync(process.stdout.fd, `${JSON.stringify({
      ok: true,
      platform: values['--platform'],
      slot: values['--slot'],
      outputs: materials.buildFacts.outputs,
    })}\n`);
    return;
  }
  if (command === 'complete') {
    const values = parseOptions(args, new Set([
      '--artifact-root',
      '--platform',
      '--slot',
    ]));
    requireOptions(values, ['--artifact-root', '--platform', '--slot']);
    const artifactRoot = resolve(values['--artifact-root']);
    const recordRoot =
      `${buildRootFor(values['--platform'], values['--slot'])}/records`;
    const core = parseStrictJson(
      readStableBytes(
        artifactPath(
          artifactRoot,
          `${recordRoot}/build-record-core.json`,
          'build record core',
        ),
        'build record core',
      ),
      'build record core',
    );
    const record = completeM0BuildRecord({
      artifactRoot,
      platform: values['--platform'],
      slot: values['--slot'],
      recordCore: core,
    });
    writeFreshAtomic(
      freshArtifactPath(
        artifactRoot,
        `${recordRoot}/build-record.json`,
        'build record',
      ),
      canonicalJson(record),
      'build record',
    );
    writeSync(process.stdout.fd, `${JSON.stringify({
      ok: true,
      platform: values['--platform'],
      slot: values['--slot'],
    })}\n`);
    return;
  }
  const values = parseOptions(args, new Set([
    '--artifact-root',
    '--source-digest',
    '--signer-digest',
    '--output',
  ]));
  requireOptions(values, [
    '--artifact-root',
    '--source-digest',
    '--output',
  ]);
  const evidence = aggregateM0BuildRecords({
    artifactRoot: values['--artifact-root'],
    sourceDigest: values['--source-digest'],
    signerDigest: values['--signer-digest'],
  });
  writeFreshAtomic(
    resolve(values['--output']),
    canonicalJson(evidence),
    'M0 v2 aggregate evidence',
  );
  writeSync(process.stdout.fd, `${JSON.stringify({
    ok: true,
    builds: M0_PLATFORM_IDS.length * SLOTS.length,
  })}\n`);
}

const isDirect = import.meta.main ?? (
  process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
);
if (isDirect) {
  try {
    main();
  } catch (error) {
    writeSync(process.stderr.fd, `ERROR: ${error.message}\n`);
    process.exitCode = 2;
  }
}
