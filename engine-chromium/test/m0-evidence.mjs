#!/usr/bin/env node

import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import {
  closeSync,
  cpSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import {
  M0_EXTERNAL_EXECUTION_ISOLATION,
  M0_EVIDENCE_ASSURANCE_LEVEL,
  M0_EVIDENCE_SCHEMA_VERSION,
  M0_HARD_ASSURANCE_LEVEL,
  M0_PLATFORMS,
  M0_RUNNERS,
  M0_TOOLCHAINS,
  evidenceSigningInput,
  inspectArtifactArchitectures,
  patchSeriesSha256,
  sha256File,
  verifyM0BuildEvidence,
  verifyM0BuildEvidenceDocument,
} from '../../scripts/m0-evidence.mjs';
import {
  assembleM0BuildEvidence,
  runAssemblerCli,
} from '../scripts/assemble-m0-evidence.mjs';
import { buildArtifactBaselineReport } from '../../verify-lab/src/artifact-report.mjs';
import { buildControlledProbeBinding } from '../../verify-lab/src/controlled-probe.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, '..', '..');
const PROVENANCE = join(REPO, 'engine-chromium', 'scripts', 'provenance.mjs');

let failures = 0;
function check(condition, message) {
  console.log(`  ${condition ? '✅' : '❌'} ${message}`);
  if (!condition) failures += 1;
}

function withFixture(run) {
  const fixture = createFixture();
  try {
    run(fixture);
  } finally {
    rmSync(fixture.repo, { recursive: true, force: true });
  }
}

function createFixture() {
  const repo = mkdtempSync(join(tmpdir(), 'proteus-m0-evidence-'));
  const artifacts = join(repo, 'engine-chromium', 'artifacts');
  const keys = join(repo, '.github', 'keys');
  mkdirSync(artifacts, { recursive: true });
  mkdirSync(keys, { recursive: true });
  cpSync(
    join(REPO, 'engine-chromium', 'patches'),
    join(repo, 'engine-chromium', 'patches'),
    { recursive: true },
  );
  mkdirSync(join(repo, 'verify-lab', 'data'), { recursive: true });
  cpSync(
    join(REPO, 'verify-lab', 'data', 'reference.json'),
    join(repo, 'verify-lab', 'data', 'reference.json'),
  );
  mkdirSync(join(repo, 'verify-lab', 'probe-page'), { recursive: true });
  for (const name of ['headless.html', 'collect.js']) {
    cpSync(
      join(REPO, 'verify-lab', 'probe-page', name),
      join(repo, 'verify-lab', 'probe-page', name),
    );
  }
  cpSync(
    join(REPO, 'engine-chromium', 'CHROMIUM_BASELINE'),
    join(repo, 'engine-chromium', 'CHROMIUM_BASELINE'),
  );
  mkdirSync(join(repo, 'engine-chromium', 'build'), { recursive: true });
  cpSync(
    join(REPO, 'engine-chromium', 'build', 'args.gn'),
    join(repo, 'engine-chromium', 'build', 'args.gn'),
  );

  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateKeyPath = join(repo, 'external-m0-release-private.key');
  writeFileSync(
    privateKeyPath,
    privateKey.export({ format: 'pem', type: 'pkcs8' }),
  );
  writeFileSync(
    join(keys, 'm0-release-ed25519.pub'),
    publicKey.export({ format: 'pem', type: 'spki' }),
  );
  const evidence = {
    schemaVersion: M0_EVIDENCE_SCHEMA_VERSION,
    chromiumCommit: 'a'.repeat(40),
    patchSeriesSha256: patchSeriesSha256(repo),
    platforms: {},
  };

  for (const platform of M0_PLATFORMS) {
    const bytes = executableFixture(platform);
    const buildAPath = `${platform}.build-a.bin`;
    const buildBPath = `${platform}.build-b.bin`;
    const artifactPath = `${platform}.release.bin`;
    const buildAProvenancePath = `${platform}.build-a.provenance.json`;
    const buildBProvenancePath = `${platform}.build-b.provenance.json`;
    const reportPath = `${platform}.verification.json`;
    for (const path of [buildAPath, buildBPath, artifactPath]) {
      writeFileSync(join(artifacts, path), bytes);
    }
    const artifactHash = digest(bytes);
    for (const [artifact, provenancePath, runId] of [
      [buildAPath, buildAProvenancePath, `${platform}-run-a`],
      [buildBPath, buildBProvenancePath, `${platform}-run-b`],
    ]) {
      const output = openSync(join(artifacts, provenancePath), 'w');
      try {
        execFileSync(
          process.execPath,
          [
            PROVENANCE,
            '--artifact',
            join(artifacts, artifact),
            '--chromium-commit',
            evidence.chromiumCommit,
            '--platform',
            platform,
            '--invocation-id',
            runId,
          ],
          { cwd: REPO, stdio: ['ignore', output, 'ignore'] },
        );
      } finally {
        closeSync(output);
      }
      const provenanceFile = join(artifacts, provenancePath);
      const provenance = JSON.parse(readFileSync(provenanceFile, 'utf8'));
      provenance.predicate.buildDefinition.internalParameters.toolchain.platform =
        M0_TOOLCHAINS[platform].platform;
      provenance.predicate.buildDefinition.internalParameters.toolchain.arch =
        M0_TOOLCHAINS[platform].arches[0];
      writeFileSync(provenanceFile, JSON.stringify(provenance));
    }
    const report = buildArtifactBaselineReport({
      artifactPath: join(artifacts, artifactPath),
      executionIsolation: M0_EXTERNAL_EXECUTION_ISOLATION,
      observation: JSON.parse(readFileSync(
        join(REPO, 'verify-lab', 'fixtures', 'bad-v5-automation-tells.json'),
        'utf8',
      )),
      platform,
      probe: buildControlledProbeBinding(join(repo, 'verify-lab')),
    });
    writeFileSync(join(artifacts, reportPath), JSON.stringify(report));

    const item = {
      buildA: {
        path: buildAPath,
        runId: `${platform}-run-a`,
        runner: M0_RUNNERS[platform],
        provenance: {
          path: buildAProvenancePath,
          sha256: sha256File(join(artifacts, buildAProvenancePath)),
        },
      },
      buildB: {
        path: buildBPath,
        runId: `${platform}-run-b`,
        runner: M0_RUNNERS[platform],
        provenance: {
          path: buildBProvenancePath,
          sha256: sha256File(join(artifacts, buildBProvenancePath)),
        },
      },
      artifact: { path: artifactPath, sha256: artifactHash },
      verificationReport: {
        path: reportPath,
        sha256: sha256File(join(artifacts, reportPath)),
      },
      releaseSignature: '',
    };
    evidence.platforms[platform] = item;
    resignPlatform(evidence, platform, privateKey, artifacts);
  }
  writeEvidence(repo, evidence);
  return {
    repo,
    artifacts,
    evidence,
    privateKey,
    privateKeyPath,
    draft: draftFromEvidence(evidence),
  };
}

function draftFromEvidence(evidence) {
  return {
    schemaVersion: evidence.schemaVersion,
    chromiumCommit: evidence.chromiumCommit,
    platforms: Object.fromEntries(M0_PLATFORMS.map((platform) => {
      const item = evidence.platforms[platform];
      return [platform, {
        buildA: {
          path: item.buildA.path,
          runId: item.buildA.runId,
          runner: item.buildA.runner,
          provenance: { path: item.buildA.provenance.path },
        },
        buildB: {
          path: item.buildB.path,
          runId: item.buildB.runId,
          runner: item.buildB.runner,
          provenance: { path: item.buildB.provenance.path },
        },
        artifact: { path: item.artifact.path },
        verificationReport: { path: item.verificationReport.path },
      }];
    })),
  };
}

function throwsMessage(body, pattern) {
  try {
    body();
    return false;
  } catch (error) {
    return pattern.test(error.message);
  }
}

function resignPlatform(evidence, platform, privateKey, artifacts) {
  const item = evidence.platforms[platform];
  const buildAHash = sha256File(join(artifacts, item.buildA.path));
  const buildBHash = sha256File(join(artifacts, item.buildB.path));
  const artifactHash = sha256File(join(artifacts, item.artifact.path));
  const buildAProvenanceHash =
    sha256File(join(artifacts, item.buildA.provenance.path));
  const buildBProvenanceHash =
    sha256File(join(artifacts, item.buildB.provenance.path));
  const reportHash = sha256File(join(artifacts, item.verificationReport.path));
  item.releaseSignature = sign(
    null,
    evidenceSigningInput({
      platform,
      chromiumCommit: evidence.chromiumCommit,
      patchSeriesSha256: evidence.patchSeriesSha256,
      artifactSha256: artifactHash,
      verificationReportSha256: reportHash,
      buildA: {
        runId: item.buildA.runId,
        runner: item.buildA.runner,
        artifactSha256: buildAHash,
        provenanceSha256: buildAProvenanceHash,
      },
      buildB: {
        runId: item.buildB.runId,
        runner: item.buildB.runner,
        artifactSha256: buildBHash,
        provenanceSha256: buildBProvenanceHash,
      },
    }),
    privateKey,
  ).toString('base64');
}

function writeEvidence(repo, evidence) {
  writeFileSync(
    join(repo, 'engine-chromium', 'artifacts', 'm0-build-evidence.json'),
    JSON.stringify(evidence),
  );
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
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
    bytes.write('proteus-windows-fixture', 0x120, 'ascii');
    return bytes;
  }
  if (platform === 'linux-x64') {
    const bytes = Buffer.alloc(256);
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(bytes);
    bytes.writeUInt16LE(3, 16);
    bytes.writeUInt16LE(0x3e, 18);
    bytes.writeUInt32LE(1, 20);
    bytes.write('proteus-linux-fixture', 0x80, 'ascii');
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
    bytes.write('proteus-macos-universal-fixture', 256, 'ascii');
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

console.log('\n  M0 cryptographic evidence verifier tests');
console.log('  ' + '─'.repeat(58));

withFixture(({ repo }) => {
  const audit = verifyM0BuildEvidence(repo);
  check(
    audit.ok,
    'valid three-platform entrypoint evidence passes its bounded verifier',
  );
  check(
    audit.assuranceLevel === M0_EVIDENCE_ASSURANCE_LEVEL
      && audit.assuranceLevel !== M0_HARD_ASSURANCE_LEVEL,
    'bounded entrypoint evidence cannot satisfy the hard M0 assurance level',
  );
});

withFixture(({ repo, evidence }) => {
  const path = join(
    repo,
    'engine-chromium',
    'artifacts',
    'm0-build-evidence.json',
  );
  const duplicated = JSON.stringify(evidence).replace(
    '{"schemaVersion":"1.0.0"',
    '{"schemaVersion":"ignored","schemaVersion":"1.0.0"',
  );
  writeFileSync(path, duplicated);
  const audit = verifyM0BuildEvidence(repo);
  check(
    !audit.ok
      && audit.failures.some((failure) =>
        failure.includes('duplicate object key $.schemaVersion')),
    'hard verifier rejects ambiguous duplicate keys in signed evidence JSON',
  );
});

withFixture(({ repo, evidence }) => {
  evidence.assuranceLevel = M0_HARD_ASSURANCE_LEVEL;
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(
    !audit.ok
      && audit.failures.some((failure) =>
        failure.includes('evidence document must contain only')),
    'unsigned unknown fields cannot inject a higher assurance claim',
  );
});

withFixture(({ repo, draft, privateKeyPath }) => {
  const outputPath = join(
    repo,
    'engine-chromium',
    'artifacts',
    'm0-build-evidence.json',
  );
  const draftPath = join(repo, 'm0-evidence-draft.json');
  writeFileSync(draftPath, JSON.stringify(draft));
  unlinkSync(outputPath);
  const assembled = JSON.parse(runAssemblerCli([
    '--draft',
    draftPath,
    '--private-key',
    privateKeyPath,
    '--repo',
    repo,
  ]));
  check(
    !existsSync(outputPath)
      && M0_PLATFORMS.every((platform) =>
        assembled.platforms[platform].releaseSignature.length === 88),
    'assembler emits signed evidence without persisting its output',
  );
});

withFixture(({ repo, draft, privateKeyPath, artifacts }) => {
  const assembled = assembleM0BuildEvidence(repo, draft, privateKeyPath);
  const linux = assembled.platforms['linux-x64'];
  check(
    assembled.patchSeriesSha256 === patchSeriesSha256(repo)
      && linux.artifact.sha256
        === sha256File(join(artifacts, linux.artifact.path))
      && linux.buildA.provenance.sha256
        === sha256File(join(artifacts, linux.buildA.provenance.path))
      && linux.verificationReport.sha256
        === sha256File(join(artifacts, linux.verificationReport.path)),
    'assembler recomputes patch, artifact, provenance, and report hashes',
  );
});

withFixture(({ repo, draft }) => {
  const { privateKey } = generateKeyPairSync('ed25519');
  const wrongKeyPath = join(repo, 'wrong-m0-release-private.key');
  writeFileSync(
    wrongKeyPath,
    privateKey.export({ format: 'pem', type: 'pkcs8' }),
  );
  check(
    throwsMessage(
      () => assembleM0BuildEvidence(repo, draft, wrongKeyPath),
      /does not match the pinned public key/,
    ),
    'assembler rejects a private key that does not match the pinned public key',
  );
});

withFixture(({ repo, draft, privateKeyPath }) => {
  draft.platforms['linux-x64'].artifact.sha256 = '0'.repeat(64);
  check(
    throwsMessage(
      () => assembleM0BuildEvidence(repo, draft, privateKeyPath),
      /artifact must contain exactly: path/,
    ),
    'strict draft rejects caller-supplied hashes and unknown fields',
  );
});

withFixture(({ repo, draft, privateKeyPath }) => {
  draft.platforms['windows-x64'].buildB.runId = 'different-but-unbound-run';
  check(
    throwsMessage(
      () => assembleM0BuildEvidence(repo, draft, privateKeyPath),
      /failed verification[\s\S]*build invocation/,
    ),
    'assembler requires build identities to match signed provenance',
  );
});

withFixture(({ repo, draft, privateKeyPath }) => {
  draft.platforms['windows-x64'].buildA.runner = 'ubuntu-latest';
  check(
    throwsMessage(
      () => assembleM0BuildEvidence(repo, draft, privateKeyPath),
      /runner must be windows-latest/,
    ),
    'assembler requires the exact runner for every platform',
  );
});

withFixture(({ repo, draft, privateKeyPath }) => {
  const platform = 'linux-x64';
  draft.platforms[platform].buildB.path =
    `./${draft.platforms[platform].buildA.path}`;
  check(
    throwsMessage(
      () => assembleM0BuildEvidence(repo, draft, privateKeyPath),
      /resolve to the same physical file/,
    ),
    'path aliases cannot claim that one artifact is two independent builds',
  );
});

withFixture(({
  repo,
  artifacts,
  draft,
  evidence,
  privateKeyPath,
}) => {
  const platform = 'linux-x64';
  const buildAPath = join(
    artifacts,
    evidence.platforms[platform].buildA.path,
  );
  const buildBPath = join(
    artifacts,
    evidence.platforms[platform].buildB.path,
  );
  try {
    unlinkSync(buildBPath);
    linkSync(buildAPath, buildBPath);
  } catch (error) {
    check(true, `artifact hardlink test skipped where unavailable (${error.code})`);
    return;
  }
  const audit = verifyM0BuildEvidence(repo);
  check(
    !audit.ok
      && audit.failures.some((failure) =>
        failure.includes('same physical file'))
      && throwsMessage(
        () => assembleM0BuildEvidence(repo, draft, privateKeyPath),
        /same physical file/,
      ),
    'hardlinks cannot claim that one artifact is two independent builds',
  );
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'linux-x64';
  const item = evidence.platforms[platform];
  const provenancePath = join(artifacts, item.buildA.provenance.path);
  const reportPath = join(artifacts, item.verificationReport.path);
  const provenanceReplacement = join(
    artifacts,
    `${platform}.build-a.provenance.replacement.json`,
  );
  const reportReplacement = join(
    artifacts,
    `${platform}.verification.replacement.json`,
  );
  writeFileSync(provenanceReplacement, readFileSync(provenancePath));
  writeFileSync(reportReplacement, readFileSync(reportPath));

  const artifactHash = item.artifact.sha256;
  let rebound = false;
  Object.defineProperty(item.artifact, 'sha256', {
    configurable: true,
    enumerable: true,
    get() {
      if (!rebound) {
        rebound = true;
        unlinkSync(provenancePath);
        renameSync(provenanceReplacement, provenancePath);
        unlinkSync(reportPath);
        renameSync(reportReplacement, reportPath);
      }
      return artifactHash;
    },
  });

  const audit = verifyM0BuildEvidenceDocument(
    repo,
    evidence,
    createPublicKey(privateKey),
  );
  check(
    !audit.ok
      && audit.failures.some((failure) =>
        failure.includes('buildA provenance path was rebound or changed'))
      && audit.failures.some((failure) =>
        failure.includes('verification report path was rebound or changed')),
    'same-byte path rebinding cannot swap provenance or report files after resolution',
  );
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'windows-x64';
  const item = evidence.platforms[platform];
  const provenancePath = join(artifacts, item.buildA.provenance.path);
  const reportPath = join(artifacts, item.verificationReport.path);
  const validProvenance = readFileSync(provenancePath);
  const validReport = readFileSync(reportPath);
  const provenanceReplacement = join(
    artifacts,
    `${platform}.build-a.provenance.valid.json`,
  );
  const reportReplacement = join(
    artifacts,
    `${platform}.verification.valid.json`,
  );
  writeFileSync(provenanceReplacement, validProvenance);
  writeFileSync(reportReplacement, validReport);

  const invalidProvenance = JSON.parse(validProvenance);
  invalidProvenance.predicate.buildDefinition
    .resolvedDependencies[0].digest.gitCommit = 'b'.repeat(40);
  const invalidReport = JSON.parse(validReport);
  invalidReport.completed = 'true';
  writeFileSync(provenancePath, JSON.stringify(invalidProvenance));
  writeFileSync(reportPath, JSON.stringify(invalidReport));
  const provenanceHash = sha256File(provenancePath);
  const reportHash = sha256File(reportPath);
  item.buildA.provenance.sha256 = provenanceHash;
  item.verificationReport.sha256 = reportHash;
  resignPlatform(evidence, platform, privateKey, artifacts);

  let provenanceHashReads = 0;
  Object.defineProperty(item.buildA.provenance, 'sha256', {
    configurable: true,
    enumerable: true,
    get() {
      provenanceHashReads += 1;
      if (provenanceHashReads === 2) {
        unlinkSync(provenancePath);
        renameSync(provenanceReplacement, provenancePath);
      }
      return provenanceHash;
    },
  });
  let reportHashRead = false;
  Object.defineProperty(item.verificationReport, 'sha256', {
    configurable: true,
    enumerable: true,
    get() {
      if (!reportHashRead) {
        reportHashRead = true;
        unlinkSync(reportPath);
        renameSync(reportReplacement, reportPath);
      }
      return reportHash;
    },
  });

  const audit = verifyM0BuildEvidenceDocument(
    repo,
    evidence,
    createPublicKey(privateKey),
  );
  check(
    !audit.ok
      && audit.failures.some((failure) =>
        failure.includes('provenance does not bind artifact, source'))
      && audit.failures.some((failure) => failure.includes('baseline report')),
    'digest checks and strict parsing consume the same provenance/report snapshots',
  );
});

withFixture(({ repo, draft, privateKeyPath }) => {
  const draftPath = join(repo, 'duplicate-key-draft.json');
  const json = JSON.stringify(draft);
  writeFileSync(
    draftPath,
    json.replace(
      '{"schemaVersion":"1.0.0",',
      '{"schemaVersion":"1.0.0","schemaVersion":"1.0.0",',
    ),
  );
  check(
    throwsMessage(
      () => runAssemblerCli([
        '--draft',
        draftPath,
        '--private-key',
        privateKeyPath,
        '--repo',
        repo,
      ]),
      /duplicate object key \$\.schemaVersion/,
    ),
    'assembler rejects duplicate JSON object keys before signing',
  );
});

withFixture(({ artifacts }) => {
  const bytes = executableFixture('macos-universal');
  bytes.writeInt32BE(0x01000007, 28);
  bytes.writeInt32LE(0x01000007, 164);
  const path = join(artifacts, 'macos-single-architecture.bin');
  writeFileSync(path, bytes);
  check(
    inspectArtifactArchitectures(path, 'macos-universal').join(',') === 'x86_64',
    'Mach-O byte inspection detects a missing arm64 slice',
  );
});

withFixture(({ repo, artifacts }) => {
  writeFileSync(join(artifacts, 'linux-x64.release.bin'), 'tampered artifact\n');
  const audit = verifyM0BuildEvidence(repo);
  check(
    !audit.ok
      && audit.failures.some((failure) => failure.includes('digests do not match'))
      && audit.failures.some((failure) => failure.includes('executable inspection failed')),
    'artifact-byte tampering is detected by digests and executable inspection',
  );
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'windows-x64';
  const reportPath = join(
    artifacts,
    evidence.platforms[platform].verificationReport.path,
  );
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  report.completed = 'true';
  writeFileSync(reportPath, JSON.stringify(report));
  evidence.platforms[platform].verificationReport.sha256 = sha256File(reportPath);
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('baseline report')),
    'truthy string claims cannot replace strict boolean evidence');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'windows-x64';
  const reportPath = join(
    artifacts,
    evidence.platforms[platform].verificationReport.path,
  );
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  report.executionIsolation.attestation = 'builder-attested';
  writeFileSync(reportPath, JSON.stringify(report));
  evidence.platforms[platform].verificationReport.sha256 = sha256File(reportPath);
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('baseline report')),
    'a caller-claimed runner cannot self-upgrade to attested containment');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'windows-x64';
  const reportPath = join(
    artifacts,
    evidence.platforms[platform].verificationReport.path,
  );
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  report.suites[0].name = 'noop';
  writeFileSync(reportPath, JSON.stringify(report));
  evidence.platforms[platform].verificationReport.sha256 = sha256File(reportPath);
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('baseline report')),
    'a signed noop suite cannot replace the V1-V5 artifact runtime report');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'windows-x64';
  const reportPath = join(
    artifacts,
    evidence.platforms[platform].verificationReport.path,
  );
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  report.suites[0].vectors.V1.score = 2;
  writeFileSync(reportPath, JSON.stringify(report));
  evidence.platforms[platform].verificationReport.sha256 = sha256File(reportPath);
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('baseline report')),
    'a re-signed out-of-range vector score cannot bypass report validation');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'windows-x64';
  const reportPath = join(
    artifacts,
    evidence.platforms[platform].verificationReport.path,
  );
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  report.suites[0].vectors.V1.score = 0.5;
  writeFileSync(reportPath, JSON.stringify(report));
  evidence.platforms[platform].verificationReport.sha256 = sha256File(reportPath);
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('baseline report')),
    'a re-signed score contradicting pass/fail counts is rejected');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'windows-x64';
  const reportPath = join(
    artifacts,
    evidence.platforms[platform].verificationReport.path,
  );
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  report.observation.automation = {
    webdriver: false,
    cdcArtifacts: 0,
    runtimeEnableLeak: false,
    untrustedInput: false,
    headlessTells: 0,
  };
  writeFileSync(reportPath, JSON.stringify(report));
  evidence.platforms[platform].verificationReport.sha256 = sha256File(reportPath);
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('baseline report')),
    'a re-signed observation with a stale score summary is re-scored and rejected');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'macos-universal';
  evidence.platforms[platform].buildB.runId =
    evidence.platforms[platform].buildA.runId;
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('distinct builds')),
    'duplicate build identities cannot claim reproducibility');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'linux-x64';
  evidence.platforms[platform].buildA.runId =
    evidence.platforms['windows-x64'].buildA.runId;
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(
    !audit.ok
      && audit.failures.some((failure) => failure.includes('runId is reused')),
    'build identities must be globally unique across platforms',
  );
});

withFixture(({ repo, evidence }) => {
  evidence.platforms['linux-x64'].artifact.path = '../outside.bin';
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('escapes')),
    'artifact path traversal is rejected');
});

withFixture(({ repo, artifacts, evidence }) => {
  const platform = 'linux-x64';
  const link = `${platform}.symlink.bin`;
  try {
    symlinkSync(
      join(artifacts, evidence.platforms[platform].artifact.path),
      join(artifacts, link),
    );
  } catch (error) {
    check(true, `artifact symlink test skipped where creation is unavailable (${error.code})`);
    return;
  }
  evidence.platforms[platform].artifact.path = link;
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('non-symlink')),
    'artifact symlinks are rejected');
});

withFixture(({ repo, evidence }) => {
  const signature = evidence.platforms['windows-x64'].releaseSignature;
  evidence.platforms['windows-x64'].releaseSignature =
    `${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`;
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('signature is invalid')),
    'wrong release evidence signatures are rejected');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'windows-x64';
  const path =
    join(artifacts, evidence.platforms[platform].buildA.provenance.path);
  const provenance = JSON.parse(readFileSync(path, 'utf8'));
  provenance.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit =
    'b'.repeat(40);
  writeFileSync(path, JSON.stringify(provenance));
  evidence.platforms[platform].buildA.provenance.sha256 = sha256File(path);
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('artifact, source')),
    'provenance must bind the declared Chromium commit');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'windows-x64';
  const path =
    join(artifacts, evidence.platforms[platform].buildA.provenance.path);
  const provenance = JSON.parse(readFileSync(path, 'utf8'));
  provenance.predicate.buildDefinition.resolvedDependencies[0].uri =
    'https://example.invalid/not-chromium';
  writeFileSync(path, JSON.stringify(provenance));
  evidence.platforms[platform].buildA.provenance.sha256 = sha256File(path);
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('artifact, source')),
    'a matching commit attached to a different source URI is rejected');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'linux-x64';
  const path =
    join(artifacts, evidence.platforms[platform].buildA.provenance.path);
  const provenance = JSON.parse(readFileSync(path, 'utf8'));
  provenance.predicate.buildDefinition.externalParameters.gnArgsSha256 =
    `sha256:${'0'.repeat(64)}`;
  writeFileSync(path, JSON.stringify(provenance));
  evidence.platforms[platform].buildA.provenance.sha256 = sha256File(path);
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('artifact, source')),
    'provenance must bind the exact checked-in GN argument bytes');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'macos-universal';
  const reportPath = join(
    artifacts,
    evidence.platforms[platform].verificationReport.path,
  );
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  report.artifactInspection.architectures = ['arm64'];
  writeFileSync(reportPath, JSON.stringify(report));
  evidence.platforms[platform].verificationReport.sha256 = sha256File(reportPath);
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('baseline report')),
    'macOS universal evidence requires x86_64 and arm64 inspection results');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  const platform = 'linux-x64';
  const reportPath = join(
    artifacts,
    evidence.platforms[platform].verificationReport.path,
  );
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  report.probe.bundleSha256 = '0'.repeat(64);
  writeFileSync(reportPath, JSON.stringify(report));
  evidence.platforms[platform].verificationReport.sha256 = sha256File(reportPath);
  resignPlatform(evidence, platform, privateKey, artifacts);
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('baseline report')),
    'artifact report must bind the exact controlled collector bytes');
});

withFixture(({ repo, artifacts, evidence }) => {
  const source = 'windows-x64';
  const target = 'linux-x64';
  for (const label of ['buildA', 'buildB']) {
    writeFileSync(
      join(artifacts, evidence.platforms[target][label].path),
      readFileSync(join(artifacts, evidence.platforms[source][label].path)),
    );
  }
  writeFileSync(
    join(artifacts, evidence.platforms[target].artifact.path),
    readFileSync(join(artifacts, evidence.platforms[source].artifact.path)),
  );
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('digest duplicates')),
    'one copied binary cannot stand in for two platform builds');
});

withFixture(({ repo, artifacts, evidence, privateKey }) => {
  evidence.patchSeriesSha256 = '0'.repeat(64);
  for (const platform of M0_PLATFORMS) {
    resignPlatform(evidence, platform, privateKey, artifacts);
  }
  writeEvidence(repo, evidence);
  const audit = verifyM0BuildEvidence(repo);
  check(!audit.ok && audit.failures.some((failure) => failure.includes('current patch bytes')),
    'signed evidence cannot claim a different patch series');
});

console.log('  ' + '─'.repeat(58));
console.log(`  ${failures === 0 ? 'all evidence tests passed' : `${failures} FAILED`}\n`);
process.exit(failures === 0 ? 0 : 1);
