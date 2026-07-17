#!/usr/bin/env node
// Assemble and sign the final M0 build-evidence document from a path-only draft.
// Private key bytes are read from an external ordinary file, cleared after
// import, and never written by this process. The completed document is emitted
// only to stdout.

import {
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
} from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  writeSync,
} from 'node:fs';
import {
  basename,
  dirname,
  join,
  resolve,
} from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  M0_EVIDENCE_SCHEMA_VERSION,
  M0_PLATFORMS,
  M0_RUN_ID_RE,
  M0_RUNNERS,
  evidenceSigningInput,
  filesSharePhysicalIdentity,
  patchSeriesSha256,
  resolveArtifactFile,
  sha256File,
  verifyM0BuildEvidenceDocument,
} from '../../scripts/m0-evidence.mjs';
import { parseStrictJson } from '../../scripts/strict-json.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = join(HERE, '..', '..');
const COMMIT_RE = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const MAX_DRAFT_BYTES = 1024 * 1024;
const MAX_KEY_BYTES = 64 * 1024;

function usage(argv1 = process.argv[1]) {
  return `usage: ${basename(argv1)} --draft <json> --private-key <pkcs8-pem> [--repo <root>]`;
}

function exactObject(value, expectedKeys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(
      `${label} must contain exactly: ${expectedKeys.join(', ')}`,
    );
  }
  return value;
}

function nonEmptyString(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  return value;
}

function readOrdinaryFile(path, label, maxBytes = null) {
  const pathStat = lstatSync(path);
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }

  const noFollow = constants.O_NOFOLLOW ?? 0;
  const fd = openSync(path, constants.O_RDONLY | noFollow);
  try {
    const openedStat = fstatSync(fd);
    if (!openedStat.isFile()
        || (
          pathStat.ino !== 0
          && (
            pathStat.dev !== openedStat.dev
            || pathStat.ino !== openedStat.ino
          )
        )) {
      throw new TypeError(`${label} changed while it was being opened`);
    }
    if (maxBytes !== null && openedStat.size > maxBytes) {
      throw new TypeError(`${label} exceeds ${maxBytes} bytes`);
    }

    const bytes = Buffer.allocUnsafe(openedStat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, null);
      if (count === 0) {
        throw new TypeError(`${label} changed while it was being read`);
      }
      offset += count;
    }
    const extra = Buffer.allocUnsafe(1);
    if (readSync(fd, extra, 0, 1, null) !== 0
        || fstatSync(fd).size !== openedStat.size) {
      throw new TypeError(`${label} changed while it was being read`);
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function validateDraft(draft) {
  exactObject(
    draft,
    ['schemaVersion', 'chromiumCommit', 'platforms'],
    'draft',
  );
  if (draft.schemaVersion !== M0_EVIDENCE_SCHEMA_VERSION) {
    throw new TypeError(
      `unsupported draft schema ${String(draft.schemaVersion)}`,
    );
  }
  if (!COMMIT_RE.test(draft.chromiumCommit)) {
    throw new TypeError(
      'draft.chromiumCommit must be a lowercase 40- or 64-hex digest',
    );
  }
  exactObject(draft.platforms, M0_PLATFORMS, 'draft.platforms');

  const runIds = new Set();
  const provenancePaths = new Set();
  for (const platform of M0_PLATFORMS) {
    const item = exactObject(
      draft.platforms[platform],
      ['buildA', 'buildB', 'artifact', 'verificationReport'],
      `draft.platforms.${platform}`,
    );
    for (const label of ['buildA', 'buildB']) {
      const build = exactObject(
        item[label],
        ['path', 'runId', 'runner', 'provenance'],
        `draft.platforms.${platform}.${label}`,
      );
      nonEmptyString(build.path, `${platform}.${label}.path`);
      if (!M0_RUN_ID_RE.test(build.runId)) {
        throw new TypeError(
          `${platform}.${label}.runId must match ${M0_RUN_ID_RE}`,
        );
      }
      if (runIds.has(build.runId)) {
        throw new TypeError(`duplicate build runId: ${build.runId}`);
      }
      runIds.add(build.runId);
      if (build.runner !== M0_RUNNERS[platform]) {
        throw new TypeError(
          `${platform}.${label}.runner must be ${M0_RUNNERS[platform]}`,
        );
      }
      const provenance = exactObject(
        build.provenance,
        ['path'],
        `draft.platforms.${platform}.${label}.provenance`,
      );
      nonEmptyString(
        provenance.path,
        `${platform}.${label}.provenance.path`,
      );
      if (provenancePaths.has(provenance.path)) {
        throw new TypeError(`duplicate provenance path: ${provenance.path}`);
      }
      provenancePaths.add(provenance.path);
    }
    if (item.buildA.path === item.buildB.path) {
      throw new TypeError(`${platform} buildA/buildB paths must be distinct`);
    }
    for (const label of ['artifact', 'verificationReport']) {
      const record = exactObject(
        item[label],
        ['path'],
        `draft.platforms.${platform}.${label}`,
      );
      nonEmptyString(record.path, `${platform}.${label}.path`);
    }
  }
}

function importSigningKey(repo, privateKeyPath) {
  const pinnedPath = join(
    repo,
    '.github',
    'keys',
    'm0-release-ed25519.pub',
  );
  const privateBytes = readOrdinaryFile(
    privateKeyPath,
    'M0 release private key',
    MAX_KEY_BYTES,
  );
  let privateKey;
  try {
    privateKey = createPrivateKey(privateBytes);
  } finally {
    privateBytes.fill(0);
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('M0 release private key is not Ed25519');
  }

  const publicKey = createPublicKey(
    readOrdinaryFile(
      pinnedPath,
      'pinned M0 release public key',
      MAX_KEY_BYTES,
    ),
  );
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('pinned M0 release public key is not Ed25519');
  }
  const derived = createPublicKey(privateKey).export({
    format: 'der',
    type: 'spki',
  });
  const pinned = publicKey.export({ format: 'der', type: 'spki' });
  if (derived.length !== pinned.length || !timingSafeEqual(derived, pinned)) {
    throw new TypeError(
      'M0 release private key does not match the pinned public key',
    );
  }
  return { privateKey, publicKey };
}

export function assembleM0BuildEvidence(repo, draft, privateKeyPath) {
  validateDraft(draft);
  const { privateKey, publicKey } = importSigningKey(repo, privateKeyPath);
  const evidence = {
    schemaVersion: M0_EVIDENCE_SCHEMA_VERSION,
    chromiumCommit: draft.chromiumCommit,
    patchSeriesSha256: patchSeriesSha256(repo),
    platforms: {},
  };

  for (const platform of M0_PLATFORMS) {
    const source = draft.platforms[platform];
    const paths = {
      buildA: resolveArtifactFile(repo, source.buildA.path),
      buildB: resolveArtifactFile(repo, source.buildB.path),
      artifact: resolveArtifactFile(repo, source.artifact.path),
      buildAProvenance: resolveArtifactFile(
        repo,
        source.buildA.provenance.path,
      ),
      buildBProvenance: resolveArtifactFile(
        repo,
        source.buildB.provenance.path,
      ),
      verificationReport: resolveArtifactFile(
        repo,
        source.verificationReport.path,
      ),
    };
    if (filesSharePhysicalIdentity(paths.buildA, paths.buildB)) {
      throw new TypeError(
        `${platform} buildA/buildB resolve to the same physical file`,
      );
    }
    if (filesSharePhysicalIdentity(
      paths.buildAProvenance,
      paths.buildBProvenance,
    )) {
      throw new TypeError(
        `${platform} buildA/buildB provenance resolves to the same physical file`,
      );
    }
    const hashes = Object.fromEntries(
      Object.entries(paths).map(([label, path]) => [label, sha256File(path)]),
    );
    const item = {
      buildA: {
        path: source.buildA.path,
        runId: source.buildA.runId,
        runner: source.buildA.runner,
        provenance: {
          path: source.buildA.provenance.path,
          sha256: hashes.buildAProvenance,
        },
      },
      buildB: {
        path: source.buildB.path,
        runId: source.buildB.runId,
        runner: source.buildB.runner,
        provenance: {
          path: source.buildB.provenance.path,
          sha256: hashes.buildBProvenance,
        },
      },
      artifact: {
        path: source.artifact.path,
        sha256: hashes.artifact,
      },
      verificationReport: {
        path: source.verificationReport.path,
        sha256: hashes.verificationReport,
      },
      releaseSignature: '',
    };
    item.releaseSignature = sign(
      null,
      evidenceSigningInput({
        platform,
        chromiumCommit: evidence.chromiumCommit,
        patchSeriesSha256: evidence.patchSeriesSha256,
        artifactSha256: hashes.artifact,
        verificationReportSha256: hashes.verificationReport,
        buildA: {
          runId: item.buildA.runId,
          runner: item.buildA.runner,
          artifactSha256: hashes.buildA,
          provenanceSha256: hashes.buildAProvenance,
        },
        buildB: {
          runId: item.buildB.runId,
          runner: item.buildB.runner,
          artifactSha256: hashes.buildB,
          provenanceSha256: hashes.buildBProvenance,
        },
      }),
      privateKey,
    ).toString('base64');
    evidence.platforms[platform] = item;
  }

  const audit = verifyM0BuildEvidenceDocument(repo, evidence, publicKey);
  if (!audit.ok) {
    throw new TypeError(
      `assembled M0 evidence failed verification:\n- ${audit.failures.join('\n- ')}`,
    );
  }
  return evidence;
}

function parseArgs(args) {
  const parsed = { draft: null, privateKey: null, repo: DEFAULT_REPO };
  const options = new Map([
    ['--draft', 'draft'],
    ['--private-key', 'privateKey'],
    ['--repo', 'repo'],
  ]);
  const seen = new Set();
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    const key = options.get(option);
    if (!key) throw new TypeError(`unknown argument: ${option}`);
    if (seen.has(option)) {
      throw new TypeError(`${option} may only be supplied once`);
    }
    const value = args[index + 1];
    if (!value || value.startsWith('--')) {
      throw new TypeError(`${option} requires a value`);
    }
    parsed[key] = value;
    seen.add(option);
    index += 1;
  }
  if (!parsed.draft || !parsed.privateKey) {
    throw new TypeError('--draft and --private-key are required');
  }
  parsed.repo = resolve(parsed.repo);
  parsed.draft = resolve(parsed.draft);
  parsed.privateKey = resolve(parsed.privateKey);
  return parsed;
}

export function runAssemblerCli(args) {
  const paths = parseArgs(args);
  const draftBytes = readOrdinaryFile(
    paths.draft,
    'M0 evidence draft',
    MAX_DRAFT_BYTES,
  );
  const draft = parseStrictJson(draftBytes, 'M0 evidence draft');
  const evidence = assembleM0BuildEvidence(
    paths.repo,
    draft,
    paths.privateKey,
  );
  return `${JSON.stringify(evidence, null, 2)}\n`;
}

function writeAllSync(fd, value) {
  const bytes = Buffer.from(value, 'utf8');
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset);
    if (written <= 0) throw new Error('output stream stopped accepting bytes');
    offset += written;
  }
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    writeAllSync(process.stdout.fd, runAssemblerCli(process.argv.slice(2)));
  } catch (error) {
    writeAllSync(
      process.stderr.fd,
      `ERROR: ${error.message}\n${usage()}\n`,
    );
    process.exitCode = 2;
  }
}
