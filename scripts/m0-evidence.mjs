import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import {
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { normalize } from '../verify-lab/src/normalize.mjs';
import { RULES_VERSION } from '../verify-lab/src/rules.mjs';
import { score } from '../verify-lab/src/score.mjs';
import { buildControlledProbeBinding } from '../verify-lab/src/controlled-probe.mjs';
import { parseStrictJson } from './strict-json.mjs';

export const M0_EVIDENCE_SCHEMA_VERSION = '1.0.0';
export const M0_ARTIFACT_REPORT_SCHEMA_VERSION = '1.1.0';
export const M0_EVIDENCE_ASSURANCE_LEVEL =
  'entrypoint-release-signed-scaffold/v1';
export const M0_HARD_ASSURANCE_LEVEL =
  'full-bundle-builder-attested/v1';
export const M0_EXTERNAL_EXECUTION_ISOLATION = Object.freeze({
  runner: 'external-ephemeral-claimed',
  attestation: 'none',
  localProcessCleanup: 'best-effort',
});
export const M0_EVIDENCE_DOMAIN = Buffer.from(
  'PROTEUS-M0-BUILD-EVIDENCE\0v1\0',
  'utf8',
);
export const M0_PLATFORMS = ['windows-x64', 'macos-universal', 'linux-x64'];
export const M0_RUNNERS = {
  'windows-x64': 'windows-latest',
  'macos-universal': 'macos-latest',
  'linux-x64': 'ubuntu-latest',
};
export const M0_RUN_ID_RE = /^[A-Za-z0-9._:-]{1,160}$/;
export const M0_TOOLCHAINS = {
  'windows-x64': { platform: 'win32', arches: ['x64'] },
  'macos-universal': { platform: 'darwin', arches: ['x64', 'arm64'] },
  'linux-x64': { platform: 'linux', arches: ['x64'] },
};
export const M0_ARTIFACT_INSPECTIONS = {
  'windows-x64': {
    tool: 'proteus-executable-header-inspector/v1',
    architectures: ['x86_64'],
  },
  'macos-universal': {
    tool: 'proteus-executable-header-inspector/v1',
    architectures: ['x86_64', 'arm64'],
  },
  'linux-x64': {
    tool: 'proteus-executable-header-inspector/v1',
    architectures: ['x86_64'],
  },
};

const MAX_PROVENANCE_BYTES = 4 * 1024 * 1024;
const MAX_REPORT_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024;
const FILE_READ_BUFFER_BYTES = 1024 * 1024;

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function sha256File(path) {
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  const fd = openSync(path, 'r');
  try {
    for (;;) {
      const count = readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest('hex');
}

function ordinaryFileState(path, label) {
  const stat = lstatSync(path, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} is not an ordinary non-symlink file`);
  }
  return stat;
}

function sameFileIdentity(left, right) {
  if (left.ino !== 0n && right.ino !== 0n) {
    return left.dev === right.dev && left.ino === right.ino;
  }
  return left.dev === right.dev
    && left.ino === right.ino
    && left.birthtimeNs === right.birthtimeNs;
}

function sameStableFileState(left, right) {
  return sameFileIdentity(left, right)
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function withStableOrdinaryFile(
  path,
  label,
  expectedState,
  maxBytes,
  consume,
) {
  const pathBefore = ordinaryFileState(path, label);
  if (expectedState && !sameStableFileState(expectedState, pathBefore)) {
    throw new TypeError(`${label} path was rebound or changed after resolution`);
  }
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const fd = openSync(path, constants.O_RDONLY | noFollow);
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!opened.isFile()
        || !sameStableFileState(pathBefore, opened)) {
      throw new TypeError(`${label} changed while it was being opened`);
    }
    if (opened.size < 0n || opened.size > BigInt(maxBytes)) {
      throw new TypeError(`${label} exceeds ${maxBytes} bytes`);
    }
    const size = Number(opened.size);
    const result = consume(fd, size);
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = ordinaryFileState(path, label);
    if (!sameStableFileState(opened, after)
        || !sameStableFileState(after, pathAfter)) {
      throw new TypeError(`${label} changed or was rebound while it was being read`);
    }
    return result;
  } finally {
    closeSync(fd);
  }
}

function readExactlyFromStart(fd, size, label) {
  const bytes = Buffer.allocUnsafe(size);
  let offset = 0;
  while (offset < size) {
    const count = readSync(fd, bytes, offset, size - offset, offset);
    if (count === 0) {
      throw new TypeError(`${label} changed while it was being read`);
    }
    offset += count;
  }
  const extra = Buffer.allocUnsafe(1);
  if (readSync(fd, extra, 0, 1, size) !== 0) {
    throw new TypeError(`${label} grew while it was being read`);
  }
  return bytes;
}

function assertDescriptorBytesStable(fd, expected, label) {
  const buffer = Buffer.allocUnsafe(
    Math.min(FILE_READ_BUFFER_BYTES, Math.max(expected.length, 1)),
  );
  let offset = 0;
  while (offset < expected.length) {
    const length = Math.min(buffer.length, expected.length - offset);
    const count = readSync(fd, buffer, 0, length, offset);
    if (count !== length
        || !buffer.subarray(0, count).equals(expected.subarray(offset, offset + count))) {
      throw new TypeError(`${label} changed while it was being read`);
    }
    offset += count;
  }
  if (readSync(fd, buffer, 0, 1, expected.length) !== 0) {
    throw new TypeError(`${label} grew while it was being read`);
  }
}

function readStableJsonSnapshot(path, label, expectedState, maxBytes) {
  return withStableOrdinaryFile(
    path,
    label,
    expectedState,
    maxBytes,
    (fd, size) => {
      const bytes = readExactlyFromStart(fd, size, label);
      assertDescriptorBytesStable(fd, bytes, label);
      return { bytes, sha256: sha256(bytes) };
    },
  );
}

function hashStableArtifactSnapshot(
  path,
  label,
  expectedState,
  platform = null,
) {
  return withStableOrdinaryFile(
    path,
    label,
    expectedState,
    MAX_ARTIFACT_BYTES,
    (fd, size) => {
      const hash = createHash('sha256');
      const buffer = Buffer.allocUnsafe(FILE_READ_BUFFER_BYTES);
      let offset = 0;
      while (offset < size) {
        const length = Math.min(buffer.length, size - offset);
        const count = readSync(fd, buffer, 0, length, offset);
        if (count === 0) {
          throw new TypeError(`${label} changed while it was being read`);
        }
        hash.update(buffer.subarray(0, count));
        offset += count;
      }
      if (readSync(fd, buffer, 0, 1, size) !== 0) {
        throw new TypeError(`${label} grew while it was being read`);
      }
      let architectures = null;
      let inspectionError = null;
      if (platform !== null) {
        try {
          architectures = inspectArtifactArchitecturesFromFd(fd, size, platform);
        } catch (error) {
          inspectionError = error;
        }
      }
      return {
        architectures,
        inspectionError,
        sha256: hash.digest('hex'),
      };
    },
  );
}

export function patchSeriesSha256(repo) {
  const root = join(repo, 'engine-chromium');
  const entries = readFileSync(join(root, 'patches', 'series'), 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
  const hash = createHash('sha256');
  for (const entry of entries) {
    hash.update(entry);
    hash.update('\0');
    hash.update(readFileSync(join(root, 'patches', entry)));
  }
  return hash.digest('hex');
}

export function evidenceSigningInput(record) {
  const signed = {
    schemaVersion: M0_EVIDENCE_SCHEMA_VERSION,
    platform: record.platform,
    chromiumCommit: record.chromiumCommit,
    patchSeriesSha256: record.patchSeriesSha256,
    artifactSha256: record.artifactSha256,
    verificationReportSha256: record.verificationReportSha256,
    buildA: {
      runId: record.buildA.runId,
      runner: record.buildA.runner,
      artifactSha256: record.buildA.artifactSha256,
      provenanceSha256: record.buildA.provenanceSha256,
    },
    buildB: {
      runId: record.buildB.runId,
      runner: record.buildB.runner,
      artifactSha256: record.buildB.artifactSha256,
      provenanceSha256: record.buildB.provenanceSha256,
    },
  };
  return Buffer.concat([
    M0_EVIDENCE_DOMAIN,
    Buffer.from(JSON.stringify(signed), 'utf8'),
  ]);
}

export function verifyM0BuildEvidence(repo) {
  const evidencePath = join(
    repo,
    'engine-chromium',
    'artifacts',
    'm0-build-evidence.json',
  );
  const keyPath = join(repo, '.github', 'keys', 'm0-release-ed25519.pub');
  if (!existsSync(evidencePath)) {
    return {
      ok: false,
      assuranceLevel: M0_EVIDENCE_ASSURANCE_LEVEL,
      failures: ['missing engine-chromium/artifacts/m0-build-evidence.json'],
    };
  }
  if (!existsSync(keyPath)) {
    return {
      ok: false,
      assuranceLevel: M0_EVIDENCE_ASSURANCE_LEVEL,
      failures: ['missing pinned .github/keys/m0-release-ed25519.pub'],
    };
  }

  let evidence;
  let publicKey;
  const failures = [];
  try {
    evidence = parseStrictJson(
      readFileSync(evidencePath),
      'M0 evidence document',
    );
  } catch (error) {
    return {
      ok: false,
      assuranceLevel: M0_EVIDENCE_ASSURANCE_LEVEL,
      failures: [`invalid evidence JSON: ${error.message}`],
    };
  }
  try {
    publicKey = createPublicKey(readFileSync(keyPath));
    if (publicKey.asymmetricKeyType !== 'ed25519') {
      failures.push('pinned M0 release key is not Ed25519');
    }
  } catch (error) {
    failures.push(`invalid pinned M0 release key: ${error.message}`);
  }

  return auditM0BuildEvidenceDocument(
    repo,
    evidence,
    publicKey,
    failures,
  );
}

export function verifyM0BuildEvidenceDocument(repo, evidence, publicKey) {
  const failures = [];
  if (!publicKey || publicKey.asymmetricKeyType !== 'ed25519') {
    failures.push('M0 release public key is not Ed25519');
  }
  return auditM0BuildEvidenceDocument(
    repo,
    evidence,
    publicKey,
    failures,
  );
}

function auditM0BuildEvidenceDocument(
  repo,
  evidence,
  publicKey,
  failures,
) {
  if (!evidence
      || typeof evidence !== 'object'
      || Array.isArray(evidence)) {
    failures.push('evidence document must be an object');
    return {
      ok: false,
      assuranceLevel: M0_EVIDENCE_ASSURANCE_LEVEL,
      failures,
    };
  }
  if (!hasExactKeys(
    evidence,
    ['schemaVersion', 'chromiumCommit', 'patchSeriesSha256', 'platforms'],
  )) {
    failures.push(
      'evidence document must contain only schemaVersion, chromiumCommit, patchSeriesSha256, and platforms',
    );
  }
  if (evidence.schemaVersion !== M0_EVIDENCE_SCHEMA_VERSION) {
    failures.push(
      `unsupported evidence schema ${String(evidence.schemaVersion)}`,
    );
  }
  const currentPatchHash = patchSeriesSha256(repo);
  if (evidence.patchSeriesSha256 !== currentPatchHash) {
    failures.push('evidence patchSeriesSha256 does not match current patch bytes');
  }
  if (!/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(evidence.chromiumCommit ?? '')) {
    failures.push('chromiumCommit must be a full 40- or 64-hex commit digest');
  }

  const platforms = evidence.platforms;
  if (!platforms || typeof platforms !== 'object' || Array.isArray(platforms)) {
    failures.push('platforms must be an object');
    return {
      ok: false,
      assuranceLevel: M0_EVIDENCE_ASSURANCE_LEVEL,
      failures,
    };
  }
  if (!hasExactKeys(platforms, M0_PLATFORMS)) {
    failures.push('platforms must contain exactly the three supported platform records');
  }
  const unexpected = Object.keys(platforms)
    .filter((platform) => !M0_PLATFORMS.includes(platform));
  if (unexpected.length) {
    failures.push(`unexpected platform records: ${unexpected.join(', ')}`);
  }

  const artifactDigests = new Map();
  const buildRunIds = new Map();
  const provenanceFiles = new Map();
  for (const platform of M0_PLATFORMS) {
    const item = platforms[platform];
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      failures.push(`${platform}: missing evidence record`);
      continue;
    }
    if (!hasExactKeys(
      item,
      [
        'buildA',
        'buildB',
        'artifact',
        'verificationReport',
        'releaseSignature',
      ],
    )) {
      failures.push(`${platform}: evidence record contains missing or unknown fields`);
    }
    for (const label of ['buildA', 'buildB']) {
      const build = item[label];
      if (!M0_RUN_ID_RE.test(build?.runId ?? '')) {
        failures.push(`${platform}: ${label} runId is not a safe build identity`);
      } else {
        const previous = buildRunIds.get(build.runId);
        if (previous) {
          failures.push(
            `${platform}: ${label} runId is reused from ${previous}`,
          );
        } else {
          buildRunIds.set(build.runId, `${platform}/${label}`);
        }
      }
      try {
        const provenancePath = resolveArtifactFile(
          repo,
          build?.provenance?.path,
        );
        const identity = physicalFileIdentity(provenancePath);
        const previous = provenanceFiles.get(identity);
        if (previous) {
          failures.push(
            `${platform}: ${label} provenance file is reused from ${previous}`,
          );
        } else {
          provenanceFiles.set(identity, `${platform}/${label}`);
        }
      } catch {
        // verifyPlatform reports the path-specific failure with its full label.
      }
    }
    const artifactHash = verifyPlatform({
      repo,
      platform,
      item,
      evidence,
      publicKey,
      failures,
    });
    if (artifactHash) {
      const previous = artifactDigests.get(artifactHash);
      if (previous) {
        failures.push(
          `${platform}: artifact digest duplicates ${previous}; platform builds must be distinct`,
        );
      } else {
        artifactDigests.set(artifactHash, platform);
      }
    }
  }

  return {
    ok: failures.length === 0,
    assuranceLevel: M0_EVIDENCE_ASSURANCE_LEVEL,
    failures,
    chromiumCommit: evidence.chromiumCommit,
    patchSeriesSha256: evidence.patchSeriesSha256,
  };
}

function verifyPlatform({
  repo,
  platform,
  item,
  evidence,
  publicKey,
  failures,
}) {
  const prefix = `${platform}:`;
  const buildA = item.buildA;
  const buildB = item.buildB;
  if (!validBuildRecord(buildA) || !validBuildRecord(buildB)) {
    failures.push(
      `${prefix} buildA/buildB require artifact path, provenance record, runner, and runId`,
    );
    return;
  }
  if (!hasExactKeys(item.artifact, ['path', 'sha256'])
      || !hasExactKeys(item.verificationReport, ['path', 'sha256'])) {
    failures.push(
      `${prefix} artifact and verificationReport must contain only path and sha256`,
    );
  }
  if (buildA.runner !== M0_RUNNERS[platform]
      || buildB.runner !== M0_RUNNERS[platform]) {
    failures.push(`${prefix} build runners do not match the platform contract`);
  }
  if (buildA.runId === buildB.runId || buildA.path === buildB.path) {
    failures.push(`${prefix} reproducibility inputs must be distinct builds`);
  }

  const paths = {};
  const pathStates = {};
  for (const [label, path] of [
    ['buildA', buildA.path],
    ['buildB', buildB.path],
    ['artifact', item.artifact?.path],
    ['buildAProvenance', buildA.provenance?.path],
    ['buildBProvenance', buildB.provenance?.path],
    ['verificationReport', item.verificationReport?.path],
  ]) {
    try {
      const resolved = resolveArtifactFile(repo, path);
      paths[label] = resolved;
      pathStates[label] = ordinaryFileState(
        resolved,
        `${prefix} ${label}`,
      );
    } catch (error) {
      failures.push(`${prefix} ${label}: ${error.message}`);
    }
  }
  if (!paths.buildA || !paths.buildB || !paths.artifact) return undefined;
  if (filesSharePhysicalIdentity(paths.buildA, paths.buildB)) {
    failures.push(
      `${prefix} reproducibility inputs resolve to the same physical file`,
    );
  }
  if (paths.buildAProvenance
      && paths.buildBProvenance
      && filesSharePhysicalIdentity(
        paths.buildAProvenance,
        paths.buildBProvenance,
      )) {
    failures.push(
      `${prefix} reproducibility provenance resolves to the same physical file`,
    );
  }

  const artifactSnapshots = {};
  for (const label of ['buildA', 'buildB', 'artifact']) {
    try {
      artifactSnapshots[label] = hashStableArtifactSnapshot(
        paths[label],
        `${prefix} ${label}`,
        pathStates[label],
        label === 'artifact' ? platform : null,
      );
    } catch (error) {
      failures.push(`${prefix} ${label} stable snapshot failed: ${error.message}`);
    }
  }
  if (!artifactSnapshots.buildA
      || !artifactSnapshots.buildB
      || !artifactSnapshots.artifact) {
    return undefined;
  }
  const buildAHash = artifactSnapshots.buildA.sha256;
  const buildBHash = artifactSnapshots.buildB.sha256;
  const artifactHash = artifactSnapshots.artifact.sha256;
  if (buildAHash !== buildBHash || buildAHash !== artifactHash) {
    failures.push(`${prefix} independent build/artifact digests do not match`);
  }
  if (item.artifact?.sha256 !== artifactHash) {
    failures.push(`${prefix} artifact sha256 was not recomputed correctly`);
  }
  if (artifactSnapshots.artifact.inspectionError) {
    failures.push(
      `${prefix} artifact executable inspection failed: `
      + artifactSnapshots.artifact.inspectionError.message,
    );
  } else {
    const actualArchitectures = artifactSnapshots.artifact.architectures;
    if (!arraysEqual(
      actualArchitectures,
      M0_ARTIFACT_INSPECTIONS[platform].architectures,
    )) {
      failures.push(
        `${prefix} executable bytes do not contain the required platform architectures`,
      );
    }
  }

  const provenanceHashes = { buildA: '', buildB: '' };
  for (const [label, build, path] of [
    ['buildA', buildA, paths.buildAProvenance],
    ['buildB', buildB, paths.buildBProvenance],
  ]) {
    if (path) {
      let snapshot;
      try {
        snapshot = readStableJsonSnapshot(
          path,
          `${prefix} ${label} provenance`,
          pathStates[`${label}Provenance`],
          MAX_PROVENANCE_BYTES,
        );
      } catch (error) {
        failures.push(
          `${prefix} ${label} provenance stable snapshot failed: ${error.message}`,
        );
      }
      if (!snapshot) continue;
      provenanceHashes[label] = snapshot.sha256;
      if (build.provenance?.sha256 !== snapshot.sha256) {
        failures.push(
          `${prefix} ${label} provenance sha256 was not recomputed correctly`,
        );
      }
      verifyProvenance(
        snapshot.bytes,
        label === 'buildA' ? buildAHash : buildBHash,
        evidence,
        prefix,
        failures,
        { platform, repo, runId: build.runId },
      );
    }
  }

  let reportHash = '';
  if (paths.verificationReport) {
    let snapshot;
    try {
      snapshot = readStableJsonSnapshot(
        paths.verificationReport,
        `${prefix} verification report`,
        pathStates.verificationReport,
        MAX_REPORT_BYTES,
      );
    } catch (error) {
      failures.push(
        `${prefix} verification report stable snapshot failed: ${error.message}`,
      );
    }
    if (snapshot) {
      reportHash = snapshot.sha256;
      if (item.verificationReport?.sha256 !== reportHash) {
        failures.push(
          `${prefix} verification report sha256 was not recomputed correctly`,
        );
      }
      verifyReport(
        snapshot.bytes,
        artifactHash,
        platform,
        prefix,
        failures,
        repo,
      );
    }
  }

  const signatureBytes = decodeSignature(item.releaseSignature, prefix, failures);
  if (!publicKey || publicKey.asymmetricKeyType !== 'ed25519' || !signatureBytes) {
    return artifactHash;
  }
  const record = {
    platform,
    chromiumCommit: evidence.chromiumCommit,
    patchSeriesSha256: evidence.patchSeriesSha256,
    artifactSha256: artifactHash,
    verificationReportSha256: reportHash,
    buildA: {
      runId: buildA.runId,
      runner: buildA.runner,
      artifactSha256: buildAHash,
      provenanceSha256: provenanceHashes.buildA,
    },
    buildB: {
      runId: buildB.runId,
      runner: buildB.runner,
      artifactSha256: buildBHash,
      provenanceSha256: provenanceHashes.buildB,
    },
  };
  if (!verifySignature(null, evidenceSigningInput(record), publicKey, signatureBytes)) {
    failures.push(`${prefix} release evidence signature is invalid`);
  }
  return artifactHash;
}

function verifyProvenance(
  bytes,
  artifactHash,
  evidence,
  prefix,
  failures,
  { platform, repo, runId },
) {
  let provenance;
  try {
    provenance = parseStrictJson(
      bytes,
      `${prefix} provenance`,
    );
  } catch (error) {
    failures.push(`${prefix} invalid provenance JSON: ${error.message}`);
    return;
  }
  const subjectMatches = Array.isArray(provenance.subject)
    && provenance.subject.some(
      (subject) => subject?.digest?.sha256 === artifactHash,
    );
  const patchHash = provenance.predicate?.buildDefinition
    ?.internalParameters?.patchSeriesHash;
  const dependencies = provenance.predicate?.buildDefinition
    ?.resolvedDependencies;
  const commitMatches = Array.isArray(dependencies)
    && dependencies.some(
      (dependency) =>
        dependency?.uri === 'https://chromium.googlesource.com/chromium/src'
        && dependency?.digest?.gitCommit === evidence.chromiumCommit,
    );
  const buildDefinition = provenance.predicate?.buildDefinition;
  const externalParameters = buildDefinition?.externalParameters;
  const baselineTag = readFileSync(
    join(repo, 'engine-chromium', 'CHROMIUM_BASELINE'),
    'utf8',
  ).match(/^CHROMIUM_STABLE=(.+)$/m)?.[1];
  const buildDefinitionMatches =
    buildDefinition?.buildType
      === 'https://proteus.example/buildtypes/chromium-engine/v1'
    && externalParameters?.chromiumTag === baselineTag
    && externalParameters?.gnArgs === 'engine-chromium/build/args.gn'
    && externalParameters?.gnArgsSha256
      === `sha256:${sha256File(join(repo, 'engine-chromium', 'build', 'args.gn'))}`;
  const runMatches =
    provenance.predicate?.runDetails?.metadata?.invocationId === runId;
  const builderMatches =
    provenance.predicate?.runDetails?.builder?.id
      === `https://proteus.example/builders/${platform}/v1`;
  const toolchain = provenance.predicate?.buildDefinition
    ?.internalParameters?.toolchain;
  const expectedToolchain = M0_TOOLCHAINS[platform];
  const toolchainMatches = toolchain?.platform === expectedToolchain.platform
    && expectedToolchain.arches.includes(toolchain?.arch);
  const targetArchitectures =
    buildDefinition?.internalParameters?.targetArchitectures;
  const targetArchitecturesMatch = arraysEqual(
    targetArchitectures,
    M0_ARTIFACT_INSPECTIONS[platform].architectures,
  );
  if (provenance._type !== 'https://in-toto.io/Statement/v1'
      || provenance.predicateType !== 'https://slsa.dev/provenance/v1'
      || !subjectMatches
      || patchHash !== `sha256:${evidence.patchSeriesSha256}`
      || !commitMatches
      || !buildDefinitionMatches
      || !runMatches
      || !builderMatches
      || !toolchainMatches
      || !targetArchitecturesMatch) {
    failures.push(
      `${prefix} provenance does not bind artifact, source, platform, and build invocation`,
    );
  }
}

function verifyReport(bytes, artifactHash, platform, prefix, failures, repo) {
  let report;
  try {
    report = parseStrictJson(
      bytes,
      `${prefix} verification report`,
    );
  } catch (error) {
    failures.push(`${prefix} invalid verification report JSON: ${error.message}`);
    return;
  }
  const suite = Array.isArray(report.suites)
    ? report.suites.find((candidate) =>
      candidate?.name === 'proteus-verify-lab-v1-v5')
    : null;
  const reportShapeMatches = hasExactKeys(report, [
    'schemaVersion',
    'platform',
    'browserArtifactSha256',
    'artifactDriven',
    'executionIsolation',
    'probe',
    'observation',
    'context',
    'artifactInspection',
    'completed',
    'suites',
  ]);
  const suiteShapeMatches = hasExactKeys(suite, [
    'name',
    'scope',
    'rulesVersion',
    'completed',
    'coverageComplete',
    'verdict',
    'gated',
    'aggregate',
    'inconsistencies',
    'vectors',
  ]);
  const vectorNames = ['V1', 'V2', 'V3', 'V4', 'V5'];
  const expectedInspection = M0_ARTIFACT_INSPECTIONS[platform];
  const inspection = report.artifactInspection;
  const inspectionMatches =
    hasExactKeys(inspection, ['artifactSha256', 'tool', 'architectures'])
    && inspection?.artifactSha256 === artifactHash
    && inspection?.tool === expectedInspection.tool
    && arraysEqual(inspection?.architectures, expectedInspection.architectures);
  const isolationMatches = isDeepStrictEqual(
    report.executionIsolation,
    M0_EXTERNAL_EXECUTION_ISOLATION,
  );
  const vectorsComplete = suite
    && vectorNames.every((name) => {
      const vector = suite.vectors?.[name];
      const scoreValid = vector?.score === null
        || (
          typeof vector?.score === 'number'
          && Number.isFinite(vector.score)
          && vector.score >= 0
          && vector.score <= 1
        );
      return scoreValid
        && Number.isSafeInteger(vector?.passed)
        && vector.passed >= 0
        && Number.isSafeInteger(vector?.failed)
        && vector.failed >= 0
        && Number.isSafeInteger(vector?.na)
        && vector.na >= 0
        && vector.passed + vector.failed + vector.na > 0
        && (vector.score === null) === (vector.passed + vector.failed === 0)
        && (
          vector.score === null
          || (
            (vector.failed > 0 || vector.score === 1)
            && (vector.passed > 0 || vector.score === 0)
            && (vector.passed === 0 || vector.failed === 0
              || (vector.score > 0 && vector.score < 1))
          )
        );
    });
  const hasMeasuredVector = suite
    && vectorNames.some((name) => suite.vectors?.[name]?.score !== null);
  const inconsistenciesValid = Array.isArray(suite?.inconsistencies)
    && suite.inconsistencies.every((item) =>
      item
      && typeof item === 'object'
      && typeof item.id === 'string'
      && /^V[1-5]$/.test(item.vector)
      && ['fatal', 'soft'].includes(item.severity)
      && Array.isArray(item.fields)
      && item.fields.every((field) => typeof field === 'string')
      && typeof item.reason === 'string'
      && item.reason.length > 0
      && Number.isSafeInteger(item.weight)
      && item.weight > 0);
  const verdicts = new Set([
    'blends-in',
    'borderline',
    'detectable',
    'detectable-incoherent',
    'insufficient-data',
  ]);
  const failedCountsMatch = suite
    && vectorNames.every((name) =>
      suite.vectors?.[name]?.failed
        === suite.inconsistencies?.filter((item) => item.vector === name).length);
  let recomputed = null;
  let probeMatches = false;
  try {
    if (!report.observation
        || typeof report.observation !== 'object'
        || Array.isArray(report.observation)
        || !report.context
        || typeof report.context !== 'object'
        || Array.isArray(report.context)) {
      throw new TypeError('observation/context must be objects');
    }
    const reference = JSON.parse(
      readFileSync(join(repo, 'verify-lab', 'data', 'reference.json'), 'utf8'),
    );
    if (reference._rulesVersion !== RULES_VERSION) {
      throw new TypeError('reference data and rule catalog versions differ');
    }
    recomputed = score(normalize(report.observation, report.context), reference);
    probeMatches = isDeepStrictEqual(
      report.probe,
      buildControlledProbeBinding(join(repo, 'verify-lab')),
    );
  } catch {
    recomputed = null;
    probeMatches = false;
  }
  const summaryMatches = recomputed?.scope === 'runtime'
    && suite?.coverageComplete === recomputed.coverage.complete
    && suite?.gated === recomputed.gated
    && suite?.aggregate === recomputed.aggregate
    && suite?.verdict === recomputed.verdict
    && isDeepStrictEqual(suite?.vectors, recomputed.vectors)
    && isDeepStrictEqual(suite?.inconsistencies, recomputed.inconsistencies);
  if (!reportShapeMatches
      || !suiteShapeMatches
      || report.schemaVersion !== M0_ARTIFACT_REPORT_SCHEMA_VERSION
      || report.platform !== platform
      || report.browserArtifactSha256 !== artifactHash
      || report.artifactDriven !== true
      || !isolationMatches
      || !probeMatches
      || !inspectionMatches
      || report.completed !== true
      || report.suites?.length !== 1
      || suite?.completed !== true
      || suite?.scope !== 'artifact-runtime'
      || suite?.rulesVersion !== RULES_VERSION
      || !verdicts.has(suite?.verdict)
      || typeof suite?.gated !== 'boolean'
      || typeof suite?.aggregate !== 'number'
      || !Number.isFinite(suite?.aggregate)
      || suite.aggregate < 0
      || suite.aggregate > 1
      || !inconsistenciesValid
      || !vectorsComplete
      || !hasMeasuredVector
      || !failedCountsMatch
      || !summaryMatches) {
    failures.push(
      `${prefix} verification report is not a complete artifact-driven baseline report`,
    );
  }
}

function arraysEqual(actual, expected) {
  return Array.isArray(actual)
    && actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

export function inspectArtifactArchitectures(path, platform) {
  const fd = openSync(path, 'r');
  try {
    const size = fstatSync(fd).size;
    return inspectArtifactArchitecturesFromFd(fd, size, platform);
  } finally {
    closeSync(fd);
  }
}

function inspectArtifactArchitecturesFromFd(fd, size, platform) {
  if (platform === 'windows-x64') return inspectPe(fd, size);
  if (platform === 'linux-x64') return inspectElf(fd, size);
  if (platform === 'macos-universal') return inspectMachOFat(fd, size);
  throw new TypeError(`unsupported artifact platform ${platform}`);
}

function inspectPe(fd, size) {
  const dos = readExactly(fd, 0, 64, size);
  if (dos.toString('ascii', 0, 2) !== 'MZ') {
    throw new TypeError('Windows artifact is not a PE file (missing MZ)');
  }
  const peOffset = dos.readUInt32LE(0x3c);
  const header = readExactly(fd, peOffset, 26, size);
  if (!header.subarray(0, 4).equals(Buffer.from('PE\0\0', 'binary'))
      || header.readUInt16LE(4) !== 0x8664
      || header.readUInt16LE(24) !== 0x20b) {
    throw new TypeError('Windows artifact is not a PE32+ x86_64 executable');
  }
  return ['x86_64'];
}

function inspectElf(fd, size) {
  const header = readExactly(fd, 0, 64, size);
  const executableType = header.readUInt16LE(16);
  if (!header.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
      || header[4] !== 2
      || header[5] !== 1
      || header[6] !== 1
      || ![2, 3].includes(executableType)
      || header.readUInt16LE(18) !== 0x3e) {
    throw new TypeError('Linux artifact is not an ELF64 x86_64 executable');
  }
  return ['x86_64'];
}

function inspectMachOFat(fd, size) {
  const header = readExactly(fd, 0, 8, size);
  const magic = header.readUInt32BE(0);
  const fat64 = magic === 0xcafebabf;
  if (magic !== 0xcafebabe && !fat64) {
    throw new TypeError('macOS artifact is not a big-endian Mach-O fat binary');
  }
  const count = header.readUInt32BE(4);
  if (count !== 2) {
    throw new TypeError(`macOS universal artifact has ${count} slices instead of 2`);
  }

  const entrySize = fat64 ? 32 : 20;
  const architectures = [];
  for (let index = 0; index < count; index += 1) {
    const entry = readExactly(fd, 8 + index * entrySize, entrySize, size);
    const cpuType = entry.readInt32BE(0);
    const offset = fat64
      ? safeBigInt(entry.readBigUInt64BE(8), 'Mach-O slice offset')
      : entry.readUInt32BE(8);
    const sliceSize = fat64
      ? safeBigInt(entry.readBigUInt64BE(16), 'Mach-O slice size')
      : entry.readUInt32BE(12);
    if (sliceSize < 8) throw new TypeError('Mach-O slice is too small');
    const slice = readExactly(fd, offset, 8, size, sliceSize);
    if (slice.readUInt32LE(0) !== 0xfeedfacf
        || slice.readInt32LE(4) !== cpuType) {
      throw new TypeError('Mach-O fat entry does not match its 64-bit slice');
    }
    if (cpuType === 0x01000007) architectures.push('x86_64');
    else if (cpuType === 0x0100000c) architectures.push('arm64');
    else throw new TypeError(`unexpected Mach-O CPU type 0x${cpuType.toString(16)}`);
  }
  return M0_ARTIFACT_INSPECTIONS['macos-universal'].architectures
    .filter((architecture) => architectures.includes(architecture));
}

function readExactly(fd, offset, length, fileSize, containingSize = length) {
  if (!Number.isSafeInteger(offset)
      || !Number.isSafeInteger(length)
      || offset < 0
      || length < 0
      || containingSize < length
      || offset + containingSize > fileSize) {
    throw new TypeError('executable header points outside the artifact');
  }
  const buffer = Buffer.allocUnsafe(length);
  let cursor = 0;
  while (cursor < length) {
    const count = readSync(fd, buffer, cursor, length - cursor, offset + cursor);
    if (count === 0) throw new TypeError('unexpected end of executable header');
    cursor += count;
  }
  return buffer;
}

function safeBigInt(value, label) {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new TypeError(`${label} exceeds the safe file-offset range`);
  }
  return Number(value);
}

export function resolveArtifactFile(repo, path) {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0')) {
    throw new TypeError('path must be a non-empty string');
  }
  if (isAbsolute(path)) throw new TypeError('absolute paths are forbidden');
  const root = realpathSync(join(repo, 'engine-chromium', 'artifacts'));
  const candidate = resolve(root, path);
  const lexical = relative(root, candidate);
  if (lexical === '..' || lexical.startsWith(`..${sep}`)
      || isAbsolute(lexical)) {
    throw new TypeError('path escapes the artifacts directory');
  }
  if (!existsSync(candidate)) throw new TypeError(`file does not exist: ${path}`);
  const stat = lstatSync(candidate);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new TypeError(`not an ordinary non-symlink file: ${path}`);
  }
  const real = realpathSync(candidate);
  const physical = relative(root, real);
  if (physical === '..'
      || physical.startsWith(`..${sep}`)
      || isAbsolute(physical)) {
    throw new TypeError('real path escapes the artifacts directory');
  }
  return real;
}

function physicalFileIdentity(path) {
  const stat = lstatSync(path);
  return stat.ino === 0
    ? `path:${path}`
    : `inode:${stat.dev}:${stat.ino}`;
}

export function filesSharePhysicalIdentity(first, second) {
  return first === second
    || physicalFileIdentity(first) === physicalFileIdentity(second);
}

function validBuildRecord(record) {
  return record
    && typeof record === 'object'
    && hasExactKeys(record, ['path', 'runId', 'runner', 'provenance'])
    && typeof record.path === 'string'
    && record.path.length > 0
    && typeof record.runId === 'string'
    && record.runId.length > 0
    && typeof record.runner === 'string'
    && record.runner.length > 0
    && record.provenance
    && hasExactKeys(record.provenance, ['path', 'sha256'])
    && typeof record.provenance.path === 'string'
    && typeof record.provenance.sha256 === 'string';
}

function hasExactKeys(value, expectedKeys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function decodeSignature(value, prefix, failures) {
  if (typeof value !== 'string') {
    failures.push(`${prefix} releaseSignature must be standard base64`);
    return null;
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== value) {
    failures.push(`${prefix} releaseSignature must encode exactly 64 bytes`);
    return null;
  }
  return bytes;
}
