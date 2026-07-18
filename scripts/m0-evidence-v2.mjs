#!/usr/bin/env node
// Offline policy core for hard-M0 evidence.
//
// The originating workflow is allowed to choose an attestation predicate, so
// a successful Sigstore verification is not by itself an M0 proof. This module
// recomputes every local digest, validates the complete bundle tree, checks the
// predicate against those recomputed facts, and cross-checks GitHub identities
// through a digest-pinned GitHub CLI API verifier (with explicit injection only
// for tests). The versioned verification-result envelope, matched certificate
// identity, certificate summary, and verified timestamps returned by
// `gh attestation verify` are treated as cryptographic verification results.

import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

import { parseStrictJson } from './strict-json.mjs';
import {
  M0_HARD_ASSURANCE_LEVEL,
  M0_PLATFORM_IDS,
  validateM0BuildContract,
} from '../engine-chromium/scripts/build-contract.mjs';
import {
  verifyBundleManifest,
} from '../engine-chromium/scripts/bundle-manifest.mjs';
import {
  verifyArtifactLicenseBundle,
} from '../engine-chromium/scripts/artifact-licenses.mjs';
import {
  validateEffectiveGnArgsRecord,
} from '../engine-chromium/scripts/effective-gn-args.mjs';
import {
  validatePackageRecord,
} from '../engine-chromium/scripts/package-record.mjs';
import {
  validateBuildDerivedSbom,
} from '../engine-chromium/scripts/build-sbom.mjs';
import {
  validateToolchainLockDocument,
} from '../engine-chromium/scripts/toolchain-lock.mjs';
import {
  sanitizedGitEnvironment,
} from '../engine-chromium/scripts/git-env.mjs';
import {
  createM0BuildPredicate,
  createM0ProvenancePredicate,
} from '../engine-chromium/scripts/m0-predicates.mjs';
import {
  inspectArtifactArchitectures,
  validateM0ArtifactBaselineReport,
} from './m0-evidence.mjs';

export const M0_EVIDENCE_V2_SCHEMA_VERSION = '2.0.0';
export const M0_EVIDENCE_V2_ASSURANCE_LEVEL =
  'full-bundle-builder-attested/v2';
export const M0_EVIDENCE_V2_BUILD_SLOTS = Object.freeze(['A', 'B']);
export const M0_EVIDENCE_V2_STATEMENT_TYPE =
  'https://in-toto.io/Statement/v1';
const SIGSTORE_VERIFICATION_RESULT_MEDIA_TYPE =
  'application/vnd.dev.sigstore.verificationresult+json;version=0.1';

const SHA256_RE = /^[0-9a-f]{64}$/u;
const GIT_COMMIT_RE = /^[0-9a-f]{40}$/u;
const GITHUB_ID_RE = /^[1-9][0-9]{0,19}$/u;
const ARTIFACT_NAME_RE =
  /^m0-payload-(?:windows-x64|macos-universal|linux-x64)-[AB]-attempt-[1-9][0-9]{0,8}$/u;
const SAFE_INSTANCE_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u;
const BASE64_RE =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const MAX_JSON_BYTES = 64 * 1024 * 1024;
const MAX_TEXT_BYTES = 16 * 1024 * 1024;
const MAX_SIGSTORE_BUNDLE_BYTES = 64 * 1024 * 1024;
const MAX_BUNDLE_FILE_BYTES = 8 * 1024 * 1024 * 1024;
const MAX_GH_EXECUTABLE_BYTES = 256 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 42 * 1024 * 1024 * 1024;
const MAX_INNER_TAR_BYTES = 40 * 1024 * 1024 * 1024;
const HASH_BUFFER_BYTES = 1024 * 1024;
const DEFAULT_GH_PATH = process.platform === 'win32'
  ? 'C:\\Program Files\\GitHub CLI\\gh.exe'
  : '/usr/bin/gh';
const GITHUB_API_HOST = 'github.com';
const GITHUB_API_VERSION = '2022-11-28';
const GITHUB_API_ACCEPT = 'application/vnd.github+json';
const RECEIPT_SIGNATURE_DOMAIN = Buffer.from(
  'PROTEUS-M0-EXTERNAL-RUNNER-RECEIPT\0v1\0',
  'utf8',
);

const RECORD_FIELDS = Object.freeze([
  'bundleManifest',
  'dependencyLock',
  'toolchainLock',
  'effectiveGnArgs',
  'sbom',
  'licenseBundle',
  'liveReport',
]);
const OUTPUT_FIELDS = Object.freeze([
  'bundleTreeSha256',
  'bundleManifestSha256',
  'dependencyLockSha256',
  'toolchainLockSha256',
  'effectiveGnArgsSha256',
  'sbomSha256',
  'licenseBundleSha256',
  'liveReportSha256',
]);
const ATTESTATION_TYPES = Object.freeze([
  'provenance',
  'sbom',
  'build',
]);
export function runnerReceiptSigningInput(receipt) {
  const unsigned = canonicalRunnerReceipt(receipt);
  return Buffer.concat([
    RECEIPT_SIGNATURE_DOMAIN,
    Buffer.from(JSON.stringify(unsigned), 'utf8'),
  ]);
}

export function buildGhAttestationVerifyInvocation({
  artifactPath,
  bundlePath,
  repository,
  signerWorkflow,
  signerDigest,
  sourceDigest,
  sourceRef,
  predicateType,
  oidcIssuer,
  denySelfHosted,
}) {
  for (const [label, value] of [
    ['artifactPath', artifactPath],
    ['bundlePath', bundlePath],
    ['repository', repository],
    ['signerWorkflow', signerWorkflow],
    ['sourceRef', sourceRef],
    ['predicateType', predicateType],
    ['oidcIssuer', oidcIssuer],
  ]) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new TypeError(`${label} must be a non-empty string`);
    }
  }
  if (!isAbsolute(artifactPath) || !isAbsolute(bundlePath)) {
    throw new TypeError('attestation artifact and bundle paths must be absolute');
  }
  assertGitCommit(signerDigest, 'signerDigest');
  assertGitCommit(sourceDigest, 'sourceDigest');
  if (typeof denySelfHosted !== 'boolean') {
    throw new TypeError('denySelfHosted must be boolean');
  }
  const args = [
    'attestation',
    'verify',
    artifactPath,
    '--bundle',
    bundlePath,
    '--repo',
    repository,
    '--signer-workflow',
    signerWorkflow,
    '--signer-digest',
    signerDigest,
    '--source-digest',
    sourceDigest,
    '--source-ref',
    sourceRef,
    '--predicate-type',
    predicateType,
    '--cert-oidc-issuer',
    oidcIssuer,
    '--format',
    'json',
  ];
  if (denySelfHosted) args.push('--deny-self-hosted-runners');
  return Object.freeze({ command: 'gh', args: Object.freeze(args) });
}

function controlledGhEnvironment(privateRoot, executablePath) {
  const environment = {
    GH_CONFIG_DIR: privateRoot,
    GH_HOST: GITHUB_API_HOST,
    GH_PROMPT_DISABLED: '1',
    HOME: privateRoot,
    LANG: 'C',
    LC_ALL: 'C',
    NO_COLOR: '1',
    PATH: dirname(executablePath),
    TMPDIR: privateRoot,
  };
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  if (token) environment.GH_TOKEN = token;
  if (process.platform === 'win32') {
    environment.TEMP = privateRoot;
    environment.TMP = privateRoot;
    for (const name of ['ComSpec', 'PATHEXT', 'SystemRoot', 'WINDIR']) {
      if (process.env[name]) environment[name] = process.env[name];
    }
  }
  return environment;
}

function withTrustedGhExecutable({
  ghPath = DEFAULT_GH_PATH,
  expectedGhSha256,
}, body) {
  if (typeof ghPath !== 'string' || !isAbsolute(ghPath)) {
    throw new TypeError('trusted gh executable path must be absolute');
  }
  if (typeof body !== 'function') {
    throw new TypeError('trusted gh operation must be a function');
  }
  assertSha256(expectedGhSha256, 'trusted gh executable SHA-256');
  const sourceBefore = readStableBytes(
    ghPath,
    'trusted gh executable',
    MAX_GH_EXECUTABLE_BYTES,
  );
  if (sourceBefore.sha256 !== expectedGhSha256) {
    throw new TypeError('gh executable does not match its trusted SHA-256');
  }

  const privateRoot = mkdtempSync(
    join(realpathSync(tmpdir()), 'proteus-m0-gh-'),
    { encoding: 'utf8' },
  );
  let result;
  let operationError = null;
  try {
    // Execute an immutable-by-construction private snapshot instead of
    // re-resolving the caller-controlled path after it has been authenticated.
    // The original path is still checked around every invocation so rebinding
    // or mutation is reported even though it cannot change the bytes executed.
    const snapshotPath = join(
      privateRoot,
      process.platform === 'win32' ? 'gh.exe' : 'gh',
    );
    writeFileSync(snapshotPath, sourceBefore.bytes, {
      flag: 'wx',
      mode: 0o500,
    });
    const snapshotBefore = readStableBytes(
      snapshotPath,
      'private gh executable snapshot',
      MAX_GH_EXECUTABLE_BYTES,
    );
    if (snapshotBefore.sha256 !== expectedGhSha256) {
      throw new TypeError('private gh executable snapshot digest is inconsistent');
    }

    const invoke = (args, label) => {
      if (!Array.isArray(args)
          || args.some((value) =>
            typeof value !== 'string' || value.includes('\0'))) {
        throw new TypeError(`${label} gh arguments must be NUL-free strings`);
      }
      const before = readStableBytes(
        ghPath,
        'trusted gh executable',
        MAX_GH_EXECUTABLE_BYTES,
      );
      if (before.sha256 !== expectedGhSha256
          || before.identity !== sourceBefore.identity) {
        throw new TypeError('trusted gh executable changed before execution');
      }
      const snapshotAtInvocation = readStableBytes(
        snapshotPath,
        'private gh executable snapshot',
        MAX_GH_EXECUTABLE_BYTES,
      );
      if (snapshotAtInvocation.sha256 !== expectedGhSha256
          || snapshotAtInvocation.identity !== snapshotBefore.identity) {
        throw new TypeError('private gh executable snapshot changed before execution');
      }
      let output;
      let commandError = null;
      try {
        output = execFileSync(snapshotPath, args, {
          encoding: null,
          env: controlledGhEnvironment(privateRoot, snapshotPath),
          maxBuffer: MAX_JSON_BYTES,
          stdio: ['ignore', 'pipe', 'pipe'],
          windowsHide: true,
        });
      } catch (error) {
        commandError = error;
      }
      const after = readStableBytes(
        ghPath,
        'trusted gh executable',
        MAX_GH_EXECUTABLE_BYTES,
      );
      if (after.sha256 !== expectedGhSha256
          || after.identity !== sourceBefore.identity) {
        throw new TypeError('trusted gh executable changed during execution');
      }
      const snapshotAfter = readStableBytes(
        snapshotPath,
        'private gh executable snapshot',
        MAX_GH_EXECUTABLE_BYTES,
      );
      if (snapshotAfter.sha256 !== expectedGhSha256
          || snapshotAfter.identity !== snapshotBefore.identity) {
        throw new TypeError('private gh executable snapshot changed during execution');
      }
      if (commandError) throw commandError;
      return output;
    };

    try {
      result = body({ executablePath: snapshotPath, invoke, privateRoot });
      if (result && typeof result.then === 'function') {
        throw new TypeError('trusted gh operation must be synchronous');
      }
    } catch (error) {
      operationError = error;
    }

    let integrityError = null;
    try {
      const sourceAfter = readStableBytes(
        ghPath,
        'trusted gh executable',
        MAX_GH_EXECUTABLE_BYTES,
      );
      if (sourceAfter.sha256 !== sourceBefore.sha256
          || sourceAfter.identity !== sourceBefore.identity) {
        throw new TypeError('trusted gh executable changed during verification');
      }
      const snapshotAfter = readStableBytes(
        snapshotPath,
        'private gh executable snapshot',
        MAX_GH_EXECUTABLE_BYTES,
      );
      if (snapshotAfter.sha256 !== snapshotBefore.sha256
          || snapshotAfter.identity !== snapshotBefore.identity) {
        throw new TypeError(
          'private gh executable snapshot changed during verification',
        );
      }
    } catch (error) {
      integrityError = error;
    }
    if (integrityError) {
      throw new TypeError(
        `trusted gh integrity check failed: ${integrityError.message}`,
        { cause: operationError ?? integrityError },
      );
    }
    if (operationError) throw operationError;
    return result;
  } finally {
    rmSync(privateRoot, { force: true, recursive: true });
  }
}

export function defaultGhAttestationVerifier({
  invocation,
  subjectBytes,
  bundleBytes,
  ghPath = DEFAULT_GH_PATH,
  expectedGhSha256,
}) {
  if (!Buffer.isBuffer(subjectBytes) || !Buffer.isBuffer(bundleBytes)) {
    throw new TypeError('default gh verifier requires snapshotted subject and bundle bytes');
  }
  if (!isPlainObject(invocation)
      || invocation.command !== 'gh'
      || !Array.isArray(invocation.args)) {
    throw new TypeError('default gh verifier requires a trusted gh invocation');
  }
  return withTrustedGhExecutable(
    { expectedGhSha256, ghPath },
    ({ invoke, privateRoot }) => {
      const artifactPath = join(privateRoot, 'subject.bin');
      const bundlePath = join(privateRoot, 'bundle.sigstore.json');
      writeFileSync(artifactPath, subjectBytes, {
        flag: 'wx',
        mode: 0o600,
      });
      writeFileSync(bundlePath, bundleBytes, {
        flag: 'wx',
        mode: 0o600,
      });
      const args = [...invocation.args];
      const bundleOption = args.indexOf('--bundle');
      if (args.length < 3
          || bundleOption < 0
          || bundleOption + 1 >= args.length) {
        throw new TypeError('gh attestation invocation is missing subject or bundle');
      }
      args[2] = artifactPath;
      args[bundleOption + 1] = bundlePath;
      const output = invoke(args, 'attestation verification');
      return parseStrictJson(output, 'gh attestation verification output');
    },
  );
}

function githubApiResponse(invoke, endpoint, label, { paginate = false } = {}) {
  if (typeof endpoint !== 'string'
      || !endpoint.startsWith('repos/')
      || endpoint.includes('\\')
      || /[\u0000-\u001f\u007f]/u.test(endpoint)) {
    throw new TypeError(`${label} endpoint is unsafe`);
  }
  const args = [
    'api',
    endpoint,
    '--hostname',
    GITHUB_API_HOST,
    '--method',
    'GET',
    '--header',
    `Accept: ${GITHUB_API_ACCEPT}`,
    '--header',
    `X-GitHub-Api-Version: ${GITHUB_API_VERSION}`,
  ];
  if (paginate) args.push('--paginate', '--slurp');
  return parseStrictJson(invoke(args, label), `${label} response`);
}

function apiGithubId(value, label) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new TypeError(`${label} must be a positive safe integer`);
    }
    return String(value);
  }
  assertGithubId(value, label);
  return value;
}

function apiPositiveInteger(
  value,
  label,
  maximum = Number.MAX_SAFE_INTEGER,
) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new TypeError(`${label} must be a bounded positive safe integer`);
  }
  return value;
}

function apiString(value, label, maximum = 1024) {
  if (typeof value !== 'string'
      || value.length === 0
      || value.length > maximum
      || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError(`${label} must be bounded printable text`);
  }
  return value;
}

function parseRepositoryName(value) {
  apiString(value, 'GitHub repository', 150);
  const parts = value.split('/');
  if (parts.length !== 2
      || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/u.test(parts[0])
      || !/^[A-Za-z0-9_.-]{1,100}$/u.test(parts[1])) {
    throw new TypeError('GitHub repository must be canonical owner/name');
  }
  return value;
}

function apiRepositoryFacts(document, label) {
  if (!isPlainObject(document) || !isPlainObject(document.owner)) {
    throw new TypeError(`${label} is missing repository or owner metadata`);
  }
  const visibility = apiString(document.visibility, `${label} visibility`, 16);
  if (!['public', 'private', 'internal'].includes(visibility)) {
    throw new TypeError(`${label} visibility is unsupported`);
  }
  return {
    nameWithOwner: parseRepositoryName(document.full_name),
    repositoryId: apiGithubId(document.id, `${label} id`),
    ownerId: apiGithubId(document.owner.id, `${label} owner id`),
    visibility,
  };
}

function assertApiRepositoryMatches(document, facts, label) {
  if (!isPlainObject(document) || !isPlainObject(document.owner)) {
    throw new TypeError(`${label} is missing repository or owner metadata`);
  }
  const actual = {
    nameWithOwner: parseRepositoryName(document.full_name),
    repositoryId: apiGithubId(document.id, `${label} id`),
    ownerId: apiGithubId(document.owner.id, `${label} owner id`),
  };
  const expected = {
    nameWithOwner: facts.nameWithOwner,
    repositoryId: facts.repositoryId,
    ownerId: facts.ownerId,
  };
  if (!isDeepStrictEqual(actual, expected)) {
    throw new TypeError(`${label} does not match the repository response`);
  }
}

function canonicalBranchRef(value) {
  const branch = apiString(value, 'workflow run head branch', 255);
  const components = branch.split('/');
  if (branch.startsWith('refs/')
      || branch.startsWith('/')
      || branch.endsWith('/')
      || branch.endsWith('.')
      || branch.includes('..')
      || branch.includes('@{')
      || branch.includes('//')
      || branch.includes('[')
      || /[\\ ~^:?*]/u.test(branch)
      || components.some((component) =>
        component.startsWith('.') || component.endsWith('.lock'))) {
    throw new TypeError('workflow run head branch is not a canonical branch');
  }
  return `refs/heads/${branch}`;
}

function workflowPathFromRun(value, branch) {
  let path = apiString(value, 'workflow run path', 1024);
  for (const suffix of [`@refs/heads/${branch}`, `@${branch}`]) {
    if (path.endsWith(suffix)) {
      path = path.slice(0, -suffix.length);
      break;
    }
  }
  if (!path.startsWith('.github/workflows/')
      || path.includes('@')
      || path.includes('\\')
      || !/\.ya?ml$/u.test(path)
      || path.split('/').some((part) =>
        part === '' || part === '.' || part === '..')) {
    throw new TypeError('workflow run path is not a canonical workflow file');
  }
  return path;
}

function completedConclusion(document, label) {
  if (document.status !== 'completed') {
    throw new TypeError(`${label} is not completed`);
  }
  return apiString(document.conclusion, `${label} conclusion`, 32);
}

function jobsFromPaginatedResponse(document) {
  if (!Array.isArray(document) || document.length === 0) {
    throw new TypeError('workflow jobs response must contain paginated pages');
  }
  const jobs = [];
  let totalCount = null;
  for (const [index, page] of document.entries()) {
    if (!isPlainObject(page)
        || !Number.isSafeInteger(page.total_count)
        || page.total_count < 0
        || !Array.isArray(page.jobs)) {
      throw new TypeError(`workflow jobs page ${index} is malformed`);
    }
    if (totalCount === null) totalCount = page.total_count;
    if (page.total_count !== totalCount) {
      throw new TypeError('workflow jobs pages disagree on total_count');
    }
    jobs.push(...page.jobs);
    if (jobs.length > 10_000) {
      throw new TypeError('workflow jobs response is unexpectedly large');
    }
  }
  if (jobs.length !== totalCount) {
    throw new TypeError('workflow jobs pagination is incomplete');
  }
  return jobs;
}

function runnerFactsFromJob(job) {
  apiString(job.runner_name, 'workflow job runner name', 256);
  if (!Array.isArray(job.labels)
      || job.labels.length === 0
      || job.labels.length > 64) {
    throw new TypeError('workflow job runner labels are missing or excessive');
  }
  const labels = job.labels.map((label, index) =>
    apiString(label, `workflow job runner label ${index}`, 128));
  const folded = labels.map((label) => label.toLowerCase());
  if (new Set(folded).size !== folded.length) {
    throw new TypeError('workflow job runner labels are duplicated');
  }
  const osFamilies = new Set();
  for (const label of folded) {
    if (/^(?:linux|ubuntu)(?:$|[-_.])/u.test(label)) osFamilies.add('linux');
    if (/^windows(?:$|[-_.])/u.test(label)) osFamilies.add('win32');
    if (/^(?:darwin|macos)(?:$|[-_.])/u.test(label)) osFamilies.add('darwin');
  }
  if (osFamilies.size !== 1) {
    throw new TypeError('workflow job runner labels do not identify exactly one OS');
  }
  return {
    environment: folded.includes('self-hosted')
      ? 'self-hosted'
      : 'github-hosted',
    os: [...osFamilies][0],
  };
}

function artifactExpired(document) {
  if (typeof document.expired !== 'boolean') {
    throw new TypeError('artifact expired flag must be boolean');
  }
  const expiresAt = apiString(document.expires_at, 'artifact expires_at', 64);
  if (!/^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?Z$/u
    .test(expiresAt)) {
    throw new TypeError('artifact expires_at must be canonical RFC 3339 UTC');
  }
  const expiresAtMillis = Date.parse(expiresAt);
  if (!Number.isFinite(expiresAtMillis)
      || new Date(expiresAtMillis).toISOString().slice(0, 19)
        !== expiresAt.slice(0, 19)) {
    throw new TypeError('artifact expires_at must be a real calendar timestamp');
  }
  return document.expired || expiresAtMillis <= Date.now();
}

function apiArtifactIdentity(document, label) {
  if (!isPlainObject(document)) {
    throw new TypeError(`${label} is incomplete`);
  }
  const name = apiString(document.name, `${label} name`, 220);
  if (!ARTIFACT_NAME_RE.test(name)) {
    throw new TypeError(`${label} name is not a canonical M0 payload name`);
  }
  const digest = apiString(document.digest, `${label} digest`, 71);
  if (!/^sha256:[0-9a-f]{64}$/u.test(digest)) {
    throw new TypeError(`${label} digest is not SHA-256`);
  }
  return {
    id: apiGithubId(document.id, `${label} id`),
    name,
    digest: digest.slice(7),
    size: apiPositiveInteger(
      document.size_in_bytes,
      `${label} size`,
      MAX_ARTIFACT_BYTES,
    ),
  };
}

export function defaultGithubApiVerifier({
  artifactId,
  artifactName: expectedArtifactName,
  artifactDigest: expectedArtifactDigest,
  artifactSize: expectedArtifactSize,
  checkRunId,
  repository,
  runId,
  ghPath = DEFAULT_GH_PATH,
  expectedGhSha256,
  apiInvoker,
}) {
  parseRepositoryName(repository);
  assertGithubId(runId, 'workflow run id');
  assertGithubId(checkRunId, 'check run id');
  assertGithubId(artifactId, 'artifact id');
  if (!ARTIFACT_NAME_RE.test(expectedArtifactName ?? '')) {
    throw new TypeError('expected artifact name is invalid');
  }
  assertSha256(expectedArtifactDigest, 'expected artifact digest');
  apiPositiveInteger(
    expectedArtifactSize,
    'expected artifact size',
    MAX_ARTIFACT_BYTES,
  );
  const repositoryEndpoint = `repos/${repository}`;
  const verifyApiFacts = ({ invoke }) => {
      const repositoryDocument = githubApiResponse(
        invoke,
        repositoryEndpoint,
        'GitHub repository API',
      );
      const repositoryFacts = apiRepositoryFacts(
        repositoryDocument,
        'GitHub repository API response',
      );

      const runDocument = githubApiResponse(
        invoke,
        `${repositoryEndpoint}/actions/runs/${runId}`,
        'GitHub workflow run API',
      );
      if (!isPlainObject(runDocument)
          || !isPlainObject(runDocument.repository)
          || !isPlainObject(runDocument.head_repository)) {
        throw new TypeError('GitHub workflow run API response is incomplete');
      }
      const actualRunId = apiGithubId(
        runDocument.id,
        'GitHub workflow run API id',
      );
      const runAttempt = apiPositiveInteger(
        runDocument.run_attempt,
        'GitHub workflow run attempt',
      );
      const headSha = apiString(
        runDocument.head_sha,
        'GitHub workflow run head SHA',
        40,
      );
      assertGitCommit(headSha, 'GitHub workflow run head SHA');
      const headBranch = apiString(
        runDocument.head_branch,
        'GitHub workflow run head branch',
        255,
      );
      assertApiRepositoryMatches(
        runDocument.repository,
        repositoryFacts,
        'workflow run repository',
      );
      assertApiRepositoryMatches(
        runDocument.head_repository,
        repositoryFacts,
        'workflow run head repository',
      );

      const jobsDocument = githubApiResponse(
        invoke,
        `${repositoryEndpoint}/actions/runs/${actualRunId}`
          + `/attempts/${runAttempt}/jobs?per_page=100`,
        'GitHub workflow jobs API',
        { paginate: true },
      );
      const jobs = jobsFromPaginatedResponse(jobsDocument);
      const checkRunUrl =
        `https://api.github.com/${repositoryEndpoint}/check-runs/${checkRunId}`;
      const matchingJobs = jobs.filter((job) =>
        isPlainObject(job) && job.check_run_url === checkRunUrl);
      if (matchingJobs.length !== 1) {
        throw new TypeError(
          'check run is not uniquely bound to the workflow run attempt jobs',
        );
      }
      const job = matchingJobs[0];
      const jobRunId = apiGithubId(job.run_id, 'workflow job run id');
      const jobHeadSha = apiString(job.head_sha, 'workflow job head SHA', 40);
      assertGitCommit(jobHeadSha, 'workflow job head SHA');
      const jobConclusion = completedConclusion(job, 'workflow job');
      if (jobRunId !== actualRunId || jobHeadSha !== headSha) {
        throw new TypeError('workflow job does not belong to the workflow run');
      }

      const checkRunDocument = githubApiResponse(
        invoke,
        `${repositoryEndpoint}/check-runs/${checkRunId}`,
        'GitHub check run API',
      );
      if (!isPlainObject(checkRunDocument)) {
        throw new TypeError('GitHub check run API response is incomplete');
      }
      const actualCheckRunId = apiGithubId(
        checkRunDocument.id,
        'GitHub check run API id',
      );
      const checkHeadSha = apiString(
        checkRunDocument.head_sha,
        'GitHub check run head SHA',
        40,
      );
      assertGitCommit(checkHeadSha, 'GitHub check run head SHA');
      const checkConclusion = completedConclusion(
        checkRunDocument,
        'GitHub check run',
      );
      if (actualCheckRunId !== checkRunId
          || checkHeadSha !== headSha
          || checkConclusion !== jobConclusion) {
        throw new TypeError('check run does not match its workflow job');
      }

      const runArtifactsDocument = githubApiResponse(
        invoke,
        `${repositoryEndpoint}/actions/runs/${actualRunId}/artifacts`
          + `?name=${encodeURIComponent(expectedArtifactName)}&per_page=100`,
        'GitHub workflow run artifacts API',
      );
      if (!isPlainObject(runArtifactsDocument)
          || runArtifactsDocument.total_count !== 1
          || !Array.isArray(runArtifactsDocument.artifacts)
          || runArtifactsDocument.artifacts.length !== 1) {
        throw new TypeError(
          'workflow run does not contain exactly one expected payload artifact',
        );
      }
      const listedArtifact = apiArtifactIdentity(
        runArtifactsDocument.artifacts[0],
        'GitHub run-scoped artifact',
      );
      const artifactDocument = githubApiResponse(
        invoke,
        `${repositoryEndpoint}/actions/artifacts/${artifactId}`,
        'GitHub artifact API',
      );
      const fetchedArtifact = apiArtifactIdentity(
        artifactDocument,
        'GitHub artifact API',
      );
      const expectedArtifact = {
        id: artifactId,
        name: expectedArtifactName,
        digest: expectedArtifactDigest,
        size: expectedArtifactSize,
      };
      if (!isDeepStrictEqual(listedArtifact, expectedArtifact)
          || !isDeepStrictEqual(fetchedArtifact, expectedArtifact)) {
        throw new TypeError('artifact does not match its run-scoped signed identity');
      }
      if (artifactDocument.workflow_run !== undefined
          && artifactDocument.workflow_run !== null) {
        if (!isPlainObject(artifactDocument.workflow_run)) {
          throw new TypeError('GitHub artifact workflow_run is malformed');
        }
        const artifactRunId = apiGithubId(
          artifactDocument.workflow_run.id,
          'GitHub artifact workflow run id',
        );
        const artifactRepositoryId = apiGithubId(
          artifactDocument.workflow_run.repository_id,
          'GitHub artifact repository id',
        );
        const artifactHeadRepositoryId = apiGithubId(
          artifactDocument.workflow_run.head_repository_id,
          'GitHub artifact head repository id',
        );
        const artifactHeadSha = apiString(
          artifactDocument.workflow_run.head_sha,
          'GitHub artifact head SHA',
          40,
        );
        assertGitCommit(artifactHeadSha, 'GitHub artifact head SHA');
        if (artifactRunId !== actualRunId
            || artifactRepositoryId !== repositoryFacts.repositoryId
            || artifactHeadRepositoryId !== repositoryFacts.repositoryId
            || artifactHeadSha !== headSha) {
          throw new TypeError('optional artifact workflow_run metadata is inconsistent');
        }
      }

      return {
        repository: repositoryFacts,
        workflowRun: {
          id: actualRunId,
          attempt: runAttempt,
          headSha,
          sourceRef: canonicalBranchRef(headBranch),
          workflowPath: workflowPathFromRun(runDocument.path, headBranch),
          event: apiString(runDocument.event, 'workflow run event', 64),
          conclusion: completedConclusion(runDocument, 'workflow run'),
        },
        checkRun: {
          id: actualCheckRunId,
          workflowRunId: jobRunId,
          headSha: checkHeadSha,
          conclusion: checkConclusion,
        },
        artifact: {
          id: fetchedArtifact.id,
          workflowRunId: actualRunId,
          name: fetchedArtifact.name,
          digest: fetchedArtifact.digest,
          size: fetchedArtifact.size,
          expired: artifactExpired(artifactDocument),
        },
        runner: runnerFactsFromJob(job),
      };
  };
  if (apiInvoker !== undefined) {
    if (typeof apiInvoker !== 'function') {
      throw new TypeError('injected GitHub API invoker must be a function');
    }
    const invoke = (args, label) => {
      const raw = apiInvoker(args, label);
      if (raw && typeof raw.then === 'function') {
        throw new TypeError('injected GitHub API invoker must be synchronous');
      }
      const output = Buffer.isBuffer(raw)
        ? raw
        : typeof raw === 'string'
          ? Buffer.from(raw, 'utf8')
          : null;
      if (!output || output.length > MAX_JSON_BYTES) {
        throw new TypeError(
          'injected GitHub API invoker must return bounded JSON bytes',
        );
      }
      return output;
    };
    return verifyApiFacts({ invoke });
  }
  return withTrustedGhExecutable(
    { expectedGhSha256, ghPath },
    verifyApiFacts,
  );
}

export function verifyM0EvidenceV2(repo, options = {}) {
  const evidencePath = options.evidencePath ?? join(
    resolve(repo),
    'engine-chromium',
    'artifacts',
    'm0-build-evidence-v2.json',
  );
  if (!existsSync(evidencePath)) {
    return failedAudit([
      'missing engine-chromium/artifacts/m0-build-evidence-v2.json',
    ]);
  }
  let evidence;
  try {
    evidence = parseStrictJson(
      readStableBytes(
        evidencePath,
        'M0 v2 evidence document',
        MAX_JSON_BYTES,
      ).bytes,
      'M0 v2 evidence document',
    );
  } catch (error) {
    return failedAudit([`invalid M0 v2 evidence JSON: ${error.message}`]);
  }
  return verifyM0EvidenceV2Document(repo, evidence, options);
}

export function verifyM0EvidenceV2Document(repo, evidence, options = {}) {
  const repoRoot = resolve(repo);
  const failures = [];
  const expectedSourceDigest = options.expectedSourceDigest;
  const expectedSignerDigest =
    options.expectedSignerDigest ?? expectedSourceDigest;
  if (!GIT_COMMIT_RE.test(expectedSourceDigest ?? '')) {
    failures.push('a trusted expectedSourceDigest is required');
  }
  if (!GIT_COMMIT_RE.test(expectedSignerDigest ?? '')) {
    failures.push('a trusted expectedSignerDigest is required');
  }
  if (failures.length > 0) return failedAudit(failures);

  try {
    const policyVerifier =
      options.policyCheckoutVerifier ?? verifySourcePolicyCheckout;
    const audit = policyVerifier({
      expectedSourceDigest,
      repoRoot,
    });
    if (audit && typeof audit.then === 'function') {
      throw new TypeError('source policy checkout verifier must be synchronous');
    }
    if (!audit || audit.ok !== true) {
      throw new TypeError('source policy checkout verifier did not return ok=true');
    }
  } catch (error) {
    return failedAudit([
      `source policy checkout is not bound to the trusted commit: ${error.message}`,
    ]);
  }

  let contracts;
  try {
    contracts = loadContracts(repoRoot);
  } catch (error) {
    return failedAudit([`invalid M0 contracts: ${error.message}`]);
  }
  const {
    audit: contractAudit,
    buildContract,
    buildContractSha256,
    trustContract,
    trustContractSha256,
  } = contracts;
  if (contractAudit.assuranceLevel !== M0_EVIDENCE_V2_ASSURANCE_LEVEL
      || contractAudit.assuranceLevel !== M0_HARD_ASSURANCE_LEVEL) {
    failures.push('M0 build contract does not require hard evidence v2');
  }

  if (!isPlainObject(evidence)) {
    failures.push('M0 v2 evidence document must be an object');
    return failedAudit(failures);
  }
  if (!hasExactKeys(evidence, [
    'schemaVersion',
    'assuranceLevel',
    'repository',
    'source',
    'signer',
    'platforms',
  ])) {
    failures.push('M0 v2 evidence document contains missing or unknown fields');
  }
  if (evidence.schemaVersion !== M0_EVIDENCE_V2_SCHEMA_VERSION) {
    failures.push(`unsupported M0 v2 evidence schema ${String(evidence.schemaVersion)}`);
  }
  if (evidence.assuranceLevel !== M0_EVIDENCE_V2_ASSURANCE_LEVEL) {
    failures.push('evidence assuranceLevel is not hard-M0 v2');
  }

  validateEvidenceRepository(
    evidence.repository,
    trustContract.repository,
    failures,
  );
  if (!hasExactKeys(evidence.source, ['digest', 'ref'])) {
    failures.push('evidence source must contain only digest and ref');
  }
  if (evidence.source?.digest !== expectedSourceDigest) {
    failures.push('evidence source digest does not match the trusted source digest');
  }
  if (evidence.source?.ref !== trustContract.sourceRef) {
    failures.push('evidence source ref does not match the trust contract');
  }
  if (!hasExactKeys(evidence.signer, ['workflow', 'digest'])) {
    failures.push('evidence signer must contain only workflow and digest');
  }
  if (evidence.signer?.workflow !== trustContract.workflows.builder) {
    failures.push('evidence signer workflow does not match the trust contract');
  }
  if (evidence.signer?.digest !== expectedSignerDigest) {
    failures.push('evidence signer digest does not match the trusted workflow digest');
  }

  if (!isPlainObject(evidence.platforms)
      || !hasExactKeys(evidence.platforms, M0_PLATFORM_IDS)) {
    failures.push('platforms must contain exactly the three M0 platform records');
  }

  const context = {
    artifactRoot: join(repoRoot, 'engine-chromium', 'artifacts'),
    attestationVerifier:
      options.attestationVerifier ?? defaultGhAttestationVerifier,
    buildContract,
    buildContractSha256,
    failures,
    githubVerifier: options.githubVerifier ?? defaultGithubApiVerifier,
    ghPath: options.ghPath,
    expectedGhSha256: options.expectedGhSha256,
    patchSeriesSha256: contractAudit.patchSeriesSha256,
    global: {
      artifactIds: new Map(),
      attestationBundleHashes: new Map(),
      bundleFileIdentities: new Map(),
      checkRunIds: new Map(),
      fileIdentities: new Map(),
      instanceIds: new Map(),
      runIds: new Map(),
      treeDigests: new Map(),
      bundleRoots: new Map(),
    },
    repoRoot,
    expectedRunnerControllerKeySha256:
      options.expectedRunnerControllerKeySha256
      ?? trustContract.runnerTrust.externalEphemeral.publicKeySpkiSha256
      ?? null,
    sourceDigest: expectedSourceDigest,
    signerDigest: expectedSignerDigest,
    trustContract,
    trustContractSha256,
  };

  for (const platform of M0_PLATFORM_IDS) {
    const pair = evidence.platforms?.[platform];
    if (!isPlainObject(pair)
        || !hasExactKeys(pair, M0_EVIDENCE_V2_BUILD_SLOTS)) {
      failures.push(`${platform}: must contain exactly builds A and B`);
      continue;
    }
    const verified = {};
    for (const slot of M0_EVIDENCE_V2_BUILD_SLOTS) {
      try {
        verified[slot] = verifyBuildRecord(
          platform,
          slot,
          pair[slot],
          context,
        );
      } catch (error) {
        failures.push(`${platform}/${slot}: ${error.message}`);
      }
    }
    if (verified.A && verified.B) {
      compareIndependentBuilds(platform, verified.A, verified.B, failures);
      const existing = context.global.treeDigests.get(verified.A.outputs.bundleTreeSha256);
      if (existing && existing !== platform) {
        failures.push(`${platform}: complete bundle tree duplicates ${existing}`);
      } else {
        context.global.treeDigests.set(
          verified.A.outputs.bundleTreeSha256,
          platform,
        );
      }
    }
  }

  return {
    ok: failures.length === 0,
    assuranceLevel: M0_EVIDENCE_V2_ASSURANCE_LEVEL,
    failures,
    chromiumCommit: contractAudit.chromiumCommit,
    patchSeriesSha256: contractAudit.patchSeriesSha256,
    sourceDigest: expectedSourceDigest,
    verifiedBuilds: failures.length === 0 ? 6 : 0,
  };
}

function verifyBuildRecord(platform, slot, record, context) {
  const label = `${platform}/${slot}`;
  exactKeys(record, [
    'runId',
    'runAttempt',
    'checkRunId',
    'artifactId',
    'artifactName',
    'artifactDigest',
    'artifactSize',
    'artifactInnerSha256',
    'artifactInnerSize',
    'runner',
    'bundleRoot',
    ...RECORD_FIELDS,
    'attestations',
  ], `${label} build record`);
  assertGithubId(record.runId, `${label} runId`);
  if (!Number.isSafeInteger(record.runAttempt) || record.runAttempt < 1) {
    throw new TypeError('runAttempt must be a positive safe integer');
  }
  assertGithubId(record.checkRunId, `${label} checkRunId`);
  assertGithubId(record.artifactId, `${label} artifactId`);
  const expectedArtifactName =
    `m0-payload-${platform}-${slot}-attempt-${record.runAttempt}`;
  if (record.artifactName !== expectedArtifactName
      || !ARTIFACT_NAME_RE.test(record.artifactName)) {
    throw new TypeError(`${label} artifactName is wrong`);
  }
  assertSha256(record.artifactDigest, `${label} artifactDigest`);
  if (!Number.isSafeInteger(record.artifactSize)
      || record.artifactSize < 1
      || record.artifactSize > MAX_ARTIFACT_BYTES) {
    throw new TypeError(`${label} artifactSize is unsafe`);
  }
  assertSha256(record.artifactInnerSha256, `${label} artifactInnerSha256`);
  if (!Number.isSafeInteger(record.artifactInnerSize)
      || record.artifactInnerSize < 1
      || record.artifactInnerSize > MAX_INNER_TAR_BYTES) {
    throw new TypeError(`${label} artifactInnerSize is unsafe`);
  }
  registerUnique(context.global.runIds, record.runId, label, 'runId');
  registerUnique(
    context.global.checkRunIds,
    record.checkRunId,
    label,
    'checkRunId',
  );
  registerUnique(
    context.global.artifactIds,
    record.artifactId,
    label,
    'artifactId',
  );

  const runner = validateRunner(record.runner, label);
  const root = resolveArtifactDirectory(
    context.artifactRoot,
    record.bundleRoot,
    `${label} bundleRoot`,
  );
  registerUnique(
    context.global.bundleRoots,
    root.identity,
    label,
    'bundle root identity',
  );

  const snapshots = {};
  for (const field of RECORD_FIELDS) {
    snapshots[field] = verifyFileDescriptor(
      context,
      record[field],
      `${label} ${field}`,
      field === 'licenseBundle' ? MAX_TEXT_BYTES : MAX_JSON_BYTES,
      field === 'bundleManifest' ? ['treeSha256'] : [],
    );
  }
  exactKeys(
    record.bundleManifest,
    ['path', 'sha256', 'treeSha256'],
    `${label} bundleManifest`,
  );
  assertSha256(
    record.bundleManifest.treeSha256,
    `${label} bundleManifest treeSha256`,
  );

  const manifest = parseStrictJson(
    snapshots.bundleManifest.bytes,
    `${label} complete bundle manifest`,
  );
  const tree = validateCompleteBundleManifest({
    buildContract: context.buildContract,
    label,
    manifest,
    platform,
    root: root.path,
  });
  if (tree.treeSha256 !== record.bundleManifest.treeSha256) {
    throw new TypeError('declared treeSha256 does not match the complete bundle');
  }
  for (const { identity, path } of tree.fileIdentities) {
    registerUnique(
      context.global.bundleFileIdentities,
      identity,
      `${label}/${path}`,
      'complete bundle file identity',
    );
  }

  const dependencyLock = validateDependencyLock(
    snapshots.dependencyLock.bytes,
    `${label} resolved dependency lock`,
    context.buildContract,
  );
  const effectiveGnArgs = parseStrictJson(
    snapshots.effectiveGnArgs.bytes,
    `${label} effective GN args record`,
  );
  validateEffectiveGnArgsRecord(effectiveGnArgs, { platform });
  const toolchainLock = parseStrictJson(
    snapshots.toolchainLock.bytes,
    `${label} complete toolchain lock`,
  );
  validateToolchainLockDocument(toolchainLock, {
    platform,
    buildContract: context.buildContract,
    buildContractSha256: context.buildContractSha256,
    trustContractSha256: context.trustContractSha256,
    dependencyLockSha256: snapshots.dependencyLock.sha256,
    effectiveGnArgs,
    effectiveGnArgsSha256: snapshots.effectiveGnArgs.sha256,
    repository: context.trustContract.repository.nameWithOwner,
  });

  const expectedLicensePath =
    `${record.bundleRoot}/LICENSES/artifact-license-manifest.json`;
  if (record.licenseBundle.path !== expectedLicensePath) {
    throw new TypeError(
      'artifact license descriptor must point to the manifest inside bundleRoot',
    );
  }
  const licenseTreeEntry = tree.entries.find((entry) =>
    entry.type === 'file'
    && entry.path === 'LICENSES/artifact-license-manifest.json');
  if (!licenseTreeEntry
      || licenseTreeEntry.sha256 !== snapshots.licenseBundle.sha256) {
    throw new TypeError(
      'artifact license manifest is not exactly covered by the complete bundle tree',
    );
  }
  verifyArtifactLicenseBundle({
    bundleDir: root.path,
    manifest: snapshots.licenseBundle.bytes,
    platform,
  });
  validateBundlePackageRecord({
    context,
    dependencyLockBytes: snapshots.dependencyLock.bytes,
    effectiveGnArgsBytes: snapshots.effectiveGnArgs.bytes,
    label,
    licenseManifestBytes: snapshots.licenseBundle.bytes,
    platform,
    root: root.path,
    toolchainLockBytes: snapshots.toolchainLock.bytes,
    tree,
  });
  const sbom = parseStrictJson(
    snapshots.sbom.bytes,
    `${label} build-derived CycloneDX SBOM`,
  );
  const sbomValidation = {
    platform,
    slot,
    bundleManifest: manifest,
    dependencyLock,
    bindings: {
      bundleTreeSha256: tree.treeSha256,
      bundleManifestSha256: snapshots.bundleManifest.sha256,
      dependencyLockSha256: snapshots.dependencyLock.sha256,
      toolchainLockSha256: snapshots.toolchainLock.sha256,
      effectiveGnArgsSha256: snapshots.effectiveGnArgs.sha256,
      licenseBundleSha256: snapshots.licenseBundle.sha256,
      buildContractSha256: context.buildContractSha256,
      trustContractSha256: context.trustContractSha256,
      patchSeriesSha256: context.patchSeriesSha256,
    },
    buildContract: context.buildContract,
  };
  validateBuildDerivedSbom(sbom, sbomValidation);
  validateM0ArtifactBaselineReport(snapshots.liveReport.bytes, {
    artifactSha256: tree.entrypointSha256,
    platform,
    repo: context.repoRoot,
    label: `${label} live report`,
  });

  const outputs = {
    bundleTreeSha256: tree.treeSha256,
    bundleManifestSha256: snapshots.bundleManifest.sha256,
    dependencyLockSha256: snapshots.dependencyLock.sha256,
    toolchainLockSha256: snapshots.toolchainLock.sha256,
    effectiveGnArgsSha256: snapshots.effectiveGnArgs.sha256,
    sbomSha256: snapshots.sbom.sha256,
    licenseBundleSha256: snapshots.licenseBundle.sha256,
    liveReportSha256: snapshots.liveReport.sha256,
  };

  const buildFacts = {
    artifactId: record.artifactId,
    artifactName: record.artifactName,
    artifactDigest: record.artifactDigest,
    artifactSize: record.artifactSize,
    artifactInnerSha256: record.artifactInnerSha256,
    artifactInnerSize: record.artifactInnerSize,
    buildContractSha256: context.buildContractSha256,
    checkRunId: record.checkRunId,
    outputs,
    platform,
    repository: context.trustContract.repository,
    runAttempt: record.runAttempt,
    runId: record.runId,
    signerDigest: context.signerDigest,
    slot,
    sourceDigest: context.sourceDigest,
    trustContractSha256: context.trustContractSha256,
    workflow: context.trustContract.workflows.builder,
  };

  verifyGithubFacts(record, runner, buildFacts, context);
  if (runner.kind === 'external-ephemeral') {
    verifyExternalRunnerReceipt(
      runner.receipt,
      buildFacts,
      context,
      label,
    );
  }

  exactKeys(
    record.attestations,
    ATTESTATION_TYPES,
    `${label} attestations`,
  );
  const attestationSnapshots = {};
  for (const type of ATTESTATION_TYPES) {
    attestationSnapshots[type] = verifyFileDescriptor(
      context,
      record.attestations[type],
      `${label} ${type} Sigstore bundle`,
      MAX_SIGSTORE_BUNDLE_BYTES,
    );
    if (attestationSnapshots[type].bytes.length === 0) {
      throw new TypeError(`${type} Sigstore bundle is empty`);
    }
    registerUnique(
      context.global.attestationBundleHashes,
      attestationSnapshots[type].sha256,
      `${label}/${type}`,
      'raw Sigstore bundle digest',
    );
  }

  for (const type of ATTESTATION_TYPES) {
    verifyAttestation({
      buildFacts,
      bundle: attestationSnapshots[type],
      context,
      denySelfHosted: runner.kind === 'github-hosted',
      sbom,
      subject: snapshots.bundleManifest,
      type,
    });
  }

  return {
    outputs,
    rootIdentity: root.identity,
    runnerKind: runner.kind,
  };
}

function validateRunner(runner, label) {
  if (!isPlainObject(runner)) {
    throw new TypeError(`${label} runner must be an object`);
  }
  if (runner.kind === 'github-hosted') {
    exactKeys(runner, ['kind'], `${label} GitHub-hosted runner`);
    return { kind: runner.kind };
  }
  if (runner.kind === 'external-ephemeral') {
    exactKeys(
      runner,
      ['kind', 'receipt'],
      `${label} external runner`,
    );
    exactKeys(
      runner.receipt,
      ['path', 'sha256'],
      `${label} external runner receipt`,
    );
    return { kind: runner.kind, receipt: runner.receipt };
  }
  throw new TypeError(`${label} runner kind must be github-hosted or external-ephemeral`);
}

function verifyGithubFacts(record, runner, buildFacts, context) {
  const label = `${buildFacts.platform}/${buildFacts.slot}`;
  if (typeof context.githubVerifier !== 'function') {
    throw new TypeError('a trusted GitHub API verifier is required');
  }
  const expected = {
    repository: {
      nameWithOwner: buildFacts.repository.nameWithOwner,
      repositoryId: buildFacts.repository.repositoryId,
      ownerId: buildFacts.repository.ownerId,
      visibility: buildFacts.repository.visibility,
    },
    workflowRun: {
      id: record.runId,
      attempt: record.runAttempt,
      headSha: buildFacts.sourceDigest,
      sourceRef: context.trustContract.sourceRef,
      workflowPath: buildFacts.workflow,
      event: 'workflow_dispatch',
      conclusion: 'success',
    },
    checkRun: {
      id: record.checkRunId,
      workflowRunId: record.runId,
      headSha: buildFacts.sourceDigest,
      conclusion: 'success',
    },
    artifact: {
      id: record.artifactId,
      workflowRunId: record.runId,
      name: record.artifactName,
      digest: record.artifactDigest,
      size: record.artifactSize,
      expired: false,
    },
    runner: {
      environment:
        runner.kind === 'github-hosted' ? 'github-hosted' : 'self-hosted',
      os: context.buildContract.platforms[buildFacts.platform].hostPlatform,
    },
  };
  let actual;
  try {
    actual = context.githubVerifier({
      artifactId: record.artifactId,
      artifactName: record.artifactName,
      artifactDigest: record.artifactDigest,
      artifactSize: record.artifactSize,
      checkRunId: record.checkRunId,
      expected,
      expectedGhSha256: context.expectedGhSha256,
      ghPath: context.ghPath,
      repository: buildFacts.repository.nameWithOwner,
      runId: record.runId,
    });
  } catch (error) {
    throw new TypeError(`GitHub API verification failed: ${error.message}`);
  }
  if (actual && typeof actual.then === 'function') {
    throw new TypeError('GitHub API verifier must be synchronous');
  }
  validateGithubApiResult(actual, expected, label);
}

function validateGithubApiResult(actual, expected, label) {
  exactKeys(
    actual,
    ['repository', 'workflowRun', 'checkRun', 'artifact', 'runner'],
    `${label} GitHub API result`,
  );
  exactKeys(
    actual.repository,
    ['nameWithOwner', 'repositoryId', 'ownerId', 'visibility'],
    `${label} API repository`,
  );
  exactKeys(
    actual.workflowRun,
    [
      'id',
      'attempt',
      'headSha',
      'sourceRef',
      'workflowPath',
      'event',
      'conclusion',
    ],
    `${label} API workflow run`,
  );
  exactKeys(
    actual.checkRun,
    ['id', 'workflowRunId', 'headSha', 'conclusion'],
    `${label} API check run`,
  );
  exactKeys(
    actual.artifact,
    ['id', 'workflowRunId', 'name', 'digest', 'size', 'expired'],
    `${label} API artifact`,
  );
  exactKeys(
    actual.runner,
    ['environment', 'os'],
    `${label} API runner`,
  );
  if (!isDeepStrictEqual(actual, expected)) {
    throw new TypeError('GitHub API facts do not match the evidence contract');
  }
}

function verifyExternalRunnerReceipt(descriptor, buildFacts, context, label) {
  const snapshot = verifyFileDescriptor(
    context,
    descriptor,
    `${label} external runner receipt`,
    MAX_JSON_BYTES,
  );
  const receipt = parseStrictJson(
    snapshot.bytes,
    `${label} external runner receipt`,
  );
  exactKeys(receipt, [
    'schemaVersion',
    'keyId',
    'instanceId',
    'imageDigest',
    'measurementDigest',
    'singleUse',
    'destroyed',
    'startedAt',
    'finishedAt',
    'destroyedAt',
    'repository',
    'source',
    'workflow',
    'build',
    'output',
    'signature',
  ], `${label} external runner receipt`);
  if (receipt.schemaVersion
      !== context.trustContract.runnerTrust.externalEphemeral.receiptSchemaVersion) {
    throw new TypeError('external runner receipt schema is unsupported');
  }
  if (!SAFE_INSTANCE_RE.test(receipt.instanceId ?? '')) {
    throw new TypeError('external runner instanceId is unsafe');
  }
  registerUnique(
    context.global.instanceIds,
    receipt.instanceId,
    label,
    'external runner instanceId',
  );
  assertSha256(receipt.imageDigest, 'external runner imageDigest');
  assertSha256(receipt.measurementDigest, 'external runner measurementDigest');
  if (receipt.singleUse !== true || receipt.destroyed !== true) {
    throw new TypeError('external runner receipt must prove singleUse=true and destroyed=true');
  }
  validateReceiptTimes(receipt);
  const expectedRepository = {
    nameWithOwner: buildFacts.repository.nameWithOwner,
    repositoryId: buildFacts.repository.repositoryId,
    ownerId: buildFacts.repository.ownerId,
    visibility: buildFacts.repository.visibility,
  };
  const expectedSource = {
    digest: buildFacts.sourceDigest,
    ref: context.trustContract.sourceRef,
  };
  const expectedWorkflow = {
    path: buildFacts.workflow,
    digest: buildFacts.signerDigest,
  };
  const expectedBuild = {
    platform: buildFacts.platform,
    slot: buildFacts.slot,
    runId: buildFacts.runId,
    runAttempt: buildFacts.runAttempt,
    checkRunId: buildFacts.checkRunId,
    artifactId: buildFacts.artifactId,
    artifactName: buildFacts.artifactName,
    artifactDigest: buildFacts.artifactDigest,
    artifactSize: buildFacts.artifactSize,
    artifactInnerSha256: buildFacts.artifactInnerSha256,
    artifactInnerSize: buildFacts.artifactInnerSize,
  };
  const expectedOutput = {
    ...buildFacts.outputs,
    buildContractSha256: buildFacts.buildContractSha256,
    trustContractSha256: buildFacts.trustContractSha256,
  };
  for (const [name, actual, expected] of [
    ['repository', receipt.repository, expectedRepository],
    ['source', receipt.source, expectedSource],
    ['workflow', receipt.workflow, expectedWorkflow],
    ['build', receipt.build, expectedBuild],
    ['output', receipt.output, expectedOutput],
  ]) {
    exactKeys(actual, Object.keys(expected), `external receipt ${name}`);
    if (!isDeepStrictEqual(actual, expected)) {
      throw new TypeError(`external runner receipt ${name} binding is wrong`);
    }
  }

  const keyRelative =
    context.trustContract.runnerTrust.externalEphemeral.publicKeyPath;
  const keyPath = resolveRepositoryFile(
    context.repoRoot,
    keyRelative,
    'external runner controller public key',
  );
  const keyBytes = readStableBytes(
    keyPath,
    'external runner controller public key',
    1024 * 1024,
  ).bytes;
  let publicKey;
  try {
    publicKey = createPublicKey(keyBytes);
  } catch (error) {
    throw new TypeError(`invalid external runner controller public key: ${error.message}`);
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('external runner controller public key is not Ed25519');
  }
  const keyId = createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex');
  const expectedKeyId = context.expectedRunnerControllerKeySha256;
  if (!SHA256_RE.test(expectedKeyId ?? '')) {
    throw new TypeError(
      'a trusted external runner controller SPKI SHA-256 is required',
    );
  }
  if (keyId !== expectedKeyId || receipt.keyId !== expectedKeyId) {
    throw new TypeError(
      'external runner receipt keyId does not match the trusted controller key',
    );
  }
  const signature = decodeEd25519Signature(receipt.signature);
  if (!verifySignature(
    null,
    runnerReceiptSigningInput(receipt),
    publicKey,
    signature,
  )) {
    throw new TypeError('external runner receipt signature is invalid');
  }
}

function canonicalRunnerReceipt(receipt) {
  return {
    schemaVersion: receipt.schemaVersion,
    keyId: receipt.keyId,
    instanceId: receipt.instanceId,
    imageDigest: receipt.imageDigest,
    measurementDigest: receipt.measurementDigest,
    singleUse: receipt.singleUse,
    destroyed: receipt.destroyed,
    startedAt: receipt.startedAt,
    finishedAt: receipt.finishedAt,
    destroyedAt: receipt.destroyedAt,
    repository: {
      nameWithOwner: receipt.repository?.nameWithOwner,
      repositoryId: receipt.repository?.repositoryId,
      ownerId: receipt.repository?.ownerId,
      visibility: receipt.repository?.visibility,
    },
    source: {
      digest: receipt.source?.digest,
      ref: receipt.source?.ref,
    },
    workflow: {
      path: receipt.workflow?.path,
      digest: receipt.workflow?.digest,
    },
    build: {
      platform: receipt.build?.platform,
      slot: receipt.build?.slot,
      runId: receipt.build?.runId,
      runAttempt: receipt.build?.runAttempt,
      checkRunId: receipt.build?.checkRunId,
      artifactId: receipt.build?.artifactId,
      artifactName: receipt.build?.artifactName,
      artifactDigest: receipt.build?.artifactDigest,
      artifactSize: receipt.build?.artifactSize,
      artifactInnerSha256: receipt.build?.artifactInnerSha256,
      artifactInnerSize: receipt.build?.artifactInnerSize,
    },
    output: {
      bundleTreeSha256: receipt.output?.bundleTreeSha256,
      bundleManifestSha256: receipt.output?.bundleManifestSha256,
      dependencyLockSha256: receipt.output?.dependencyLockSha256,
      toolchainLockSha256: receipt.output?.toolchainLockSha256,
      effectiveGnArgsSha256: receipt.output?.effectiveGnArgsSha256,
      sbomSha256: receipt.output?.sbomSha256,
      licenseBundleSha256: receipt.output?.licenseBundleSha256,
      liveReportSha256: receipt.output?.liveReportSha256,
      buildContractSha256: receipt.output?.buildContractSha256,
      trustContractSha256: receipt.output?.trustContractSha256,
    },
  };
}

function validateReceiptTimes(receipt) {
  const values = ['startedAt', 'finishedAt', 'destroyedAt'].map((key) => {
    const value = receipt[key];
    if (typeof value !== 'string'
        || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u.test(value)) {
      throw new TypeError(`external runner ${key} must be an RFC 3339 UTC timestamp`);
    }
    const millis = Date.parse(value);
    if (!Number.isFinite(millis) || new Date(millis).toISOString() !== value) {
      throw new TypeError(`external runner ${key} is not a canonical timestamp`);
    }
    return millis;
  });
  if (!(values[0] < values[1] && values[1] <= values[2])) {
    throw new TypeError('external runner timestamps do not prove build then destruction');
  }
}

function verifyAttestation({
  buildFacts,
  bundle,
  context,
  denySelfHosted,
  sbom,
  subject,
  type,
}) {
  const predicateType = context.trustContract.predicateTypes[type];
  const signerWorkflow =
    `${buildFacts.repository.nameWithOwner}/${buildFacts.workflow}`;
  const invocation = buildGhAttestationVerifyInvocation({
    artifactPath: subject.path,
    bundlePath: bundle.path,
    repository: buildFacts.repository.nameWithOwner,
    signerWorkflow,
    signerDigest: buildFacts.signerDigest,
    sourceDigest: buildFacts.sourceDigest,
    sourceRef: context.trustContract.sourceRef,
    predicateType,
    oidcIssuer: context.trustContract.oidcIssuer,
    denySelfHosted,
  });
  const expectedPredicate = type === 'build'
    ? expectedBuildPredicate(buildFacts, context)
    : type === 'provenance'
      ? expectedProvenancePredicate(buildFacts, context)
      : sbom;
  const expectedStatement = {
    _type: M0_EVIDENCE_V2_STATEMENT_TYPE,
    subject: [{
      name: basename(subject.path),
      digest: { sha256: subject.sha256 },
    }],
    predicateType,
    predicate: expectedPredicate,
  };

  let raw;
  try {
    raw = context.attestationVerifier({
      buildFacts,
      bundleBytes: bundle.bytes,
      expectedGhSha256: context.expectedGhSha256,
      expectedStatement,
      ghPath: context.ghPath,
      invocation,
      subjectBytes: subject.bytes,
      type,
    });
  } catch (error) {
    throw new TypeError(`${type} attestation verification failed: ${error.message}`);
  }
  if (raw && typeof raw.then === 'function') {
    throw new TypeError('attestation verifier must be synchronous');
  }
  let result = raw;
  if (Buffer.isBuffer(raw) || typeof raw === 'string') {
    result = parseStrictJson(
      Buffer.isBuffer(raw) ? raw : Buffer.from(raw, 'utf8'),
      `${type} gh attestation verification output`,
    );
  }
  if (!Array.isArray(result) || result.length !== 1) {
    throw new TypeError(`${type} attestation must produce exactly one verification result`);
  }
  const item = result[0];
  exactKeys(
    item,
    ['attestation', 'verificationResult'],
    `${type} attestation result`,
  );
  if (!isPlainObject(item.attestation)) {
    throw new TypeError(`${type} attestation result is missing the raw attestation object`);
  }
  exactKeys(
    item.verificationResult,
    [
      'mediaType',
      'signature',
      'statement',
      'verifiedIdentity',
      'verifiedTimestamps',
    ],
    `${type} verificationResult`,
  );
  if (item.verificationResult.mediaType
      !== SIGSTORE_VERIFICATION_RESULT_MEDIA_TYPE) {
    throw new TypeError(
      `${type} verificationResult has an unsupported Sigstore media type`,
    );
  }
  const expectedVerifiedIdentity = {
    subjectAlternativeName: {
      subjectAlternativeName: '',
      regexp: `^https://github.com/${signerWorkflow}`,
    },
    issuer: {
      issuer: '',
      regexp: '.*',
    },
    ...(denySelfHosted ? { runnerEnvironment: 'github-hosted' } : {}),
  };
  exactKeys(
    item.verificationResult.verifiedIdentity,
    Object.keys(expectedVerifiedIdentity),
    `${type} verified identity`,
  );
  exactKeys(
    item.verificationResult.verifiedIdentity.subjectAlternativeName,
    ['subjectAlternativeName', 'regexp'],
    `${type} verified identity subject alternative name`,
  );
  exactKeys(
    item.verificationResult.verifiedIdentity.issuer,
    ['issuer', 'regexp'],
    `${type} verified identity issuer`,
  );
  if (!isDeepStrictEqual(
    item.verificationResult.verifiedIdentity,
    expectedVerifiedIdentity,
  )) {
    throw new TypeError(
      `${type} verified identity does not match the pinned gh policy`,
    );
  }
  exactKeys(
    item.verificationResult.signature,
    ['certificate'],
    `${type} verified signature`,
  );
  if (!isPlainObject(item.verificationResult.signature.certificate)
      || Object.keys(item.verificationResult.signature.certificate).length === 0) {
    throw new TypeError(`${type} verification result lacks a verified certificate`);
  }
  const certificate = item.verificationResult.signature.certificate;
  const repositoryUri =
    `https://github.com/${buildFacts.repository.nameWithOwner}`;
  const signerUri =
    `${repositoryUri}/${buildFacts.workflow}@${context.trustContract.sourceRef}`;
  const owner = buildFacts.repository.nameWithOwner.split('/')[0];
  const expectedCertificate = {
    issuer: context.trustContract.oidcIssuer,
    subjectAlternativeName: signerUri,
    githubWorkflowSHA: buildFacts.signerDigest,
    githubWorkflowRepository: buildFacts.repository.nameWithOwner,
    githubWorkflowRef: context.trustContract.sourceRef,
    buildSignerURI: signerUri,
    buildSignerDigest: buildFacts.signerDigest,
    runnerEnvironment: denySelfHosted ? 'github-hosted' : 'self-hosted',
    sourceRepositoryURI: repositoryUri,
    sourceRepositoryDigest: buildFacts.sourceDigest,
    sourceRepositoryRef: context.trustContract.sourceRef,
    sourceRepositoryIdentifier: buildFacts.repository.repositoryId,
    sourceRepositoryOwnerURI: `https://github.com/${owner}`,
    sourceRepositoryOwnerIdentifier: buildFacts.repository.ownerId,
    buildConfigURI: signerUri,
    buildConfigDigest: buildFacts.signerDigest,
    buildTrigger: 'workflow_dispatch',
    runInvocationURI:
      `${repositoryUri}/actions/runs/${buildFacts.runId}`
      + `/attempts/${buildFacts.runAttempt}`,
    sourceRepositoryVisibilityAtSigning: buildFacts.repository.visibility,
  };
  if (Object.entries(expectedCertificate).some(([key, expected]) =>
    certificate[key] !== expected)) {
    throw new TypeError(
      `${type} verified certificate identity does not match the trusted workflow`,
    );
  }
  const timestamps = item.verificationResult.verifiedTimestamps;
  if (!Array.isArray(timestamps)
      || timestamps.length === 0) {
    throw new TypeError(`${type} verification result lacks verified timestamps`);
  }
  for (const [index, timestamp] of timestamps.entries()) {
    const label = `${type} verified timestamp ${index}`;
    exactKeys(timestamp, ['type', 'uri', 'timestamp'], label);
    apiString(timestamp.type, `${label} type`, 128);
    const uri = apiString(timestamp.uri, `${label} URI`, 2048);
    let parsedUri;
    try {
      parsedUri = new URL(uri);
    } catch {
      throw new TypeError(`${label} URI must be a valid HTTPS URL`);
    }
    if (parsedUri.protocol !== 'https:'
        || parsedUri.hostname.length === 0
        || parsedUri.username.length > 0
        || parsedUri.password.length > 0) {
      throw new TypeError(`${label} URI must be a valid HTTPS URL`);
    }
    if (!isCanonicalRfc3339(timestamp.timestamp)) {
      throw new TypeError(`${type} verified timestamp is not valid RFC 3339`);
    }
  }
  validateAttestationStatement(
    item.verificationResult.statement,
    expectedStatement,
    `${buildFacts.platform}/${buildFacts.slot} ${type}`,
  );
}

function isCanonicalRfc3339(value) {
  if (typeof value !== 'string') return false;
  const match = value.match(
    /^(?<year>[0-9]{4})-(?<month>0[1-9]|1[0-2])-(?<day>0[1-9]|[12][0-9]|3[01])T(?<hour>[01][0-9]|2[0-3]):(?<minute>[0-5][0-9]):(?<second>[0-5][0-9])(?:\.[0-9]{0,8}[1-9])?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$/u,
  );
  if (!match || Number(match.groups.year) === 0) return false;
  const year = Number(match.groups.year);
  const month = Number(match.groups.month);
  const day = Number(match.groups.day);
  const daysInMonth = [
    31,
    year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ][month - 1];
  return day <= daysInMonth && Number.isFinite(Date.parse(value));
}

function validateAttestationStatement(actual, expected, label) {
  exactKeys(
    actual,
    ['_type', 'subject', 'predicateType', 'predicate'],
    `${label} statement`,
  );
  if (!isDeepStrictEqual(actual, expected)) {
    throw new TypeError(`${label} predicate or subject does not match recomputed build facts`);
  }
}

function expectedBuildPredicate(buildFacts, context) {
  return createM0BuildPredicate(buildFacts, {
    buildContract: context.buildContract,
    predicateTypes: context.trustContract.predicateTypes,
    sourceRef: context.trustContract.sourceRef,
  });
}

function expectedProvenancePredicate(buildFacts, context) {
  return createM0ProvenancePredicate(buildFacts, {
    buildContract: context.buildContract,
    predicateTypes: context.trustContract.predicateTypes,
    sourceRef: context.trustContract.sourceRef,
  });
}

function compareIndependentBuilds(platform, left, right, failures) {
  const equalFields = [
    'bundleTreeSha256',
    'bundleManifestSha256',
    'dependencyLockSha256',
    'toolchainLockSha256',
    'effectiveGnArgsSha256',
    'licenseBundleSha256',
  ];
  for (const field of equalFields) {
    if (left.outputs[field] !== right.outputs[field]) {
      failures.push(`${platform}: independent A/B ${field} values do not match`);
    }
  }
  if (left.rootIdentity === right.rootIdentity) {
    failures.push(`${platform}: A/B builds reuse the same complete bundle root`);
  }
}

function validateCompleteBundleManifest({
  buildContract,
  label,
  manifest,
  platform,
  root,
}) {
  if (manifest.schemaVersion !== buildContract.bundle.manifestSchemaVersion) {
    throw new TypeError('bundle manifest schema does not match the build contract');
  }
  if (manifest.platform !== platform) {
    throw new TypeError('bundle manifest platform is wrong');
  }
  const expectedEntrypoint = buildContract.platforms[platform].entrypoint;
  if (manifest.entrypoint !== expectedEntrypoint) {
    throw new TypeError('bundle manifest entrypoint is wrong');
  }
  const actual = verifyBundleManifest(root, manifest);
  const entrypoint = expectedEntrypoint;
  const entrypointRecord =
    actual.entries.find((entry) =>
      entry.type === 'file' && entry.path === entrypoint);
  if (!entrypointRecord) {
    throw new TypeError(`bundle manifest is missing required entrypoint ${entrypoint}`);
  }
  const entrypointPath = join(root, ...entrypoint.split('/'));
  const architectures = inspectArtifactArchitectures(entrypointPath, platform);
  if (!isDeepStrictEqual(
    architectures,
    buildContract.platforms[platform].architectures,
  )) {
    throw new TypeError('bundle entrypoint architectures do not match the platform contract');
  }
  const entrypointAfterInspection = hashStableFile(
    entrypointPath,
    `${label} inspected entrypoint`,
    MAX_BUNDLE_FILE_BYTES,
  ).sha256;
  if (entrypointAfterInspection !== entrypointRecord.sha256) {
    throw new TypeError('bundle entrypoint changed during architecture inspection');
  }
  const fileIdentities = actual.entries
    .filter((entry) => entry.type === 'file')
    .map((entry) => {
      const path = join(root, ...entry.path.split('/'));
      const stat = lstatSync(path, { bigint: true });
      if (!stat.isFile() || stat.isSymbolicLink()) {
        throw new TypeError(`${label}/${entry.path} changed after manifest verification`);
      }
      return {
        identity: physicalIdentity(stat, realpathSync(path)),
        path: entry.path,
      };
    });
  return {
    entries: actual.entries,
    entrypointSha256: entrypointRecord.sha256,
    fileIdentities,
    treeSha256: actual.treeSha256,
  };
}

function validateDependencyLock(bytes, label, buildContract) {
  const document = parseStrictJson(bytes, label);
  exactKeys(document, [
    'architecture',
    'chromium',
    'dependencies',
    'depotTools',
    'gclientConfigSha256',
    'gclientRevinfoSha256',
    'platform',
    'schemaVersion',
  ], label);
  if (document.schemaVersion !== 1
      || typeof document.architecture !== 'string'
      || document.architecture.length === 0
      || !['win32', 'darwin', 'linux'].includes(document.platform)
      || !Array.isArray(document.dependencies)
      || document.dependencies.length === 0) {
    throw new TypeError(`${label} does not describe a resolved dependency graph`);
  }
  exactKeys(
    document.chromium,
    ['commit', 'repository', 'stable'],
    `${label} Chromium source`,
  );
  if (document.chromium.commit !== buildContract.source.chromiumCommit
      || document.chromium.repository !== buildContract.source.chromiumRepository
      || document.chromium.stable !== buildContract.source.chromiumVersion) {
    throw new TypeError(`${label} does not bind the M0 Chromium source`);
  }
  if (!isPlainObject(document.depotTools)
      || document.depotTools.commit !== buildContract.source.depotToolsCommit
      || document.depotTools.repository
        !== buildContract.source.depotToolsRepository) {
    throw new TypeError(`${label} does not bind pinned depot_tools`);
  }
  assertSha256(document.gclientConfigSha256, `${label} gclientConfigSha256`);
  assertSha256(document.gclientRevinfoSha256, `${label} gclientRevinfoSha256`);
  for (const [index, dependency] of document.dependencies.entries()) {
    if (!isPlainObject(dependency) || Object.keys(dependency).length === 0) {
      throw new TypeError(`${label} dependency ${index} is empty`);
    }
  }
  return document;
}

function validateBundlePackageRecord({
  context,
  dependencyLockBytes,
  effectiveGnArgsBytes,
  label,
  licenseManifestBytes,
  platform,
  root,
  toolchainLockBytes,
  tree,
}) {
  const entry = tree.entries.find((candidate) =>
    candidate.type === 'file' && candidate.path === 'PACKAGE-RECORD.json');
  if (!entry) {
    throw new TypeError('complete bundle is missing PACKAGE-RECORD.json');
  }
  const snapshot = readStableBytes(
    join(root, 'PACKAGE-RECORD.json'),
    `${label} package record`,
    MAX_JSON_BYTES,
  );
  if (snapshot.sha256 !== entry.sha256) {
    throw new TypeError('PACKAGE-RECORD.json is not exactly covered by the bundle tree');
  }
  const document = parseStrictJson(
    snapshot.bytes,
    `${label} package record`,
  );
  validatePackageRecord(document, {
    platform,
    outDirRelative: document.outputDirectory,
    runtimeDependencies: document.runtimeDependencies?.entries,
    dependencyLockBytes,
    effectiveGnArgsBytes,
    toolchainLockBytes,
    licenseManifestBytes,
    repoRoot: context.repoRoot,
  });
  const bundledPaths = new Set(tree.entries.map(({ path }) => path));
  for (const dependency of document.runtimeDependencies.entries) {
    if (!bundledPaths.has(dependency)) {
      throw new TypeError(
        `package runtime dependency is absent from the bundle tree: ${dependency}`,
      );
    }
  }
}

function verifyFileDescriptor(
  context,
  descriptor,
  label,
  maxBytes,
  extraKeys = [],
) {
  exactKeys(descriptor, ['path', 'sha256', ...extraKeys], label);
  assertSha256(descriptor.sha256, `${label} sha256`);
  const path = resolveArtifactFile(
    context.artifactRoot,
    descriptor.path,
    label,
  );
  const snapshot = readStableBytes(path, label, maxBytes);
  if (snapshot.sha256 !== descriptor.sha256) {
    throw new TypeError(`${label} sha256 does not match local bytes`);
  }
  registerUnique(
    context.global.fileIdentities,
    snapshot.identity,
    label,
    'evidence file identity',
  );
  return { ...snapshot, path };
}

function resolveArtifactFile(root, relativePath, label) {
  assertCanonicalRelativePath(relativePath, `${label} path`);
  assertNoSymlinkSegments(root, relativePath, label);
  const rootReal = realpathSync(root);
  const candidate = resolve(root, ...relativePath.split('/'));
  const real = realpathSync(candidate);
  assertContained(rootReal, real, label);
  const stat = lstatSync(real, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  return real;
}

function resolveArtifactDirectory(root, relativePath, label) {
  assertCanonicalRelativePath(relativePath, `${label} path`);
  assertNoSymlinkSegments(root, relativePath, label);
  const rootReal = realpathSync(root);
  const candidate = resolve(root, ...relativePath.split('/'));
  const real = realpathSync(candidate);
  assertContained(rootReal, real, label);
  const stat = lstatSync(real, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink directory`);
  }
  return {
    identity: physicalIdentity(stat, real),
    path: real,
  };
}

function resolveRepositoryFile(repoRoot, relativePath, label) {
  assertCanonicalRelativePath(relativePath, label);
  assertNoSymlinkSegments(repoRoot, relativePath, label);
  const repoReal = realpathSync(repoRoot);
  const real = realpathSync(resolve(repoRoot, ...relativePath.split('/')));
  assertContained(repoReal, real, label);
  const stat = lstatSync(real, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  return real;
}

function assertNoSymlinkSegments(root, relativePath, label) {
  let current = root;
  const rootStat = lstatSync(root, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new TypeError(`${label} root must be an ordinary directory`);
  }
  for (const segment of relativePath.split('/')) {
    current = join(current, segment);
    const stat = lstatSync(current, { bigint: true });
    if (stat.isSymbolicLink()) {
      throw new TypeError(`${label} traverses a symlink`);
    }
  }
}

function assertContained(root, candidate, label) {
  const rel = relative(root, candidate);
  if (rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel))) {
    return;
  }
  throw new TypeError(`${label} escapes the evidence root`);
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
  const parts = value.split('/');
  if (parts.some((part) =>
    part === ''
    || part === '.'
    || part === '..'
    || part.length > 255
    || /[. ]$/u.test(part)
    || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu.test(part))) {
    throw new TypeError(`${label} must be a canonical relative POSIX path`);
  }
}

function readStableBytes(path, label, maxBytes) {
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
    return {
      bytes,
      identity: physicalIdentity(opened, realpathSync(path)),
      sha256: createHash('sha256').update(bytes).digest('hex'),
    };
  } finally {
    closeSync(fd);
  }
}

function hashStableFile(path, label, maxBytes, expectedState = null) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  if (expectedState && !sameStableFile(before, expectedState)) {
    throw new TypeError(`${label} changed before hashing`);
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
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(HASH_BUFFER_BYTES);
    let position = 0;
    const size = safeFileSize(opened.size, label);
    while (position < size) {
      const count = readSync(
        fd,
        buffer,
        0,
        Math.min(buffer.length, size - position),
        position,
      );
      if (count === 0) throw new TypeError(`${label} shrank while hashing`);
      hash.update(buffer.subarray(0, count));
      position += count;
    }
    if (readSync(fd, buffer, 0, 1, size) !== 0) {
      throw new TypeError(`${label} grew while hashing`);
    }
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    if (!sameStableFile(opened, after) || !sameStableFile(after, pathAfter)) {
      throw new TypeError(`${label} changed or was rebound while hashing`);
    }
    return { sha256: hash.digest('hex') };
  } finally {
    closeSync(fd);
  }
}

const SOURCE_POLICY_PATHS = Object.freeze([
  '.gitattributes',
  '.github/workflows/m0-builder.yml',
  '.github/workflows/m0-aggregate.yml',
  '.github/workflows/m0-hard-gate.yml',
  'package.json',
  'package-lock.json',
  'engine-chromium/CHROMIUM_BASELINE',
  'engine-chromium/build/args.gn',
  'engine-chromium/build/m0-build-contract.json',
  'engine-chromium/build/m0-trust.json',
  'engine-chromium/patches/series',
  'engine-chromium/patches/layer0-degoogle/0001-disable-google-network-time.patch',
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
  'scripts/license-policy.mjs',
  'scripts/m0-exit-criteria.mjs',
  'scripts/m0-evidence-v2.mjs',
  'scripts/m0-evidence.mjs',
  'scripts/strict-json.mjs',
  'verify-lab/data/reference.json',
  'verify-lab/probe-page/collect.js',
  'verify-lab/probe-page/context-frame.html',
  'verify-lab/probe-page/context-worker.js',
  'verify-lab/probe-page/headless.html',
  'verify-lab/src/controlled-probe.mjs',
  'verify-lab/src/network-time-audit.mjs',
  'verify-lab/src/normalize.mjs',
  'verify-lab/src/reference-util.mjs',
  'verify-lab/src/rules.mjs',
  'verify-lab/src/score.mjs',
  'verify-lab/src/static-path.mjs',
]);
const SOURCE_POLICY_PREFIXES = Object.freeze([
  '.github/workflows',
  'engine-chromium/build',
  'engine-chromium/patches',
  'engine-chromium/scripts',
  'engine-chromium/tracking-bot',
  'scripts',
  'verify-lab',
]);
const SOURCE_POLICY_ORIGINS = new Set([
  'https://github.com/jiyujie2006/proteus-browser',
  'https://github.com/jiyujie2006/proteus-browser.git',
]);

/**
 * Prove that every byte which defines the hard-M0 policy is the byte stored in
 * the externally trusted source commit. Evidence artifacts are intentionally
 * outside these pathspecs, so a downloaded/untracked evidence directory does
 * not weaken or block the source audit.
 */
export function verifySourcePolicyCheckout({
  expectedSourceDigest,
  repoRoot,
  gitPath = process.platform === 'win32'
    ? 'C:\\Program Files\\Git\\cmd\\git.exe'
    : '/usr/bin/git',
}) {
  assertGitCommit(expectedSourceDigest, 'trusted source digest');
  if (typeof gitPath !== 'string' || !isAbsolute(gitPath)) {
    throw new TypeError('source policy Git executable must be an absolute path');
  }
  const root = resolve(repoRoot);
  if (realpathSync(root) !== root) {
    throw new TypeError('source policy repository path must already be canonical');
  }
  const git = (args, label, maximum = MAX_JSON_BYTES) => {
    let output;
    try {
      output = execFileSync(gitPath, ['-C', root, ...args], {
        encoding: null,
        env: sanitizedGitEnvironment(),
        maxBuffer: maximum,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
    } catch (error) {
      throw new TypeError(`${label} failed: ${error.message}`);
    }
    return Buffer.from(output);
  };
  const text = (args, label) => {
    const value = git(args, label).toString('utf8').trim();
    if (value.includes('\0')) {
      throw new TypeError(`${label} returned unsafe text`);
    }
    return value;
  };

  const insideWorkTree = text(
    ['rev-parse', '--is-inside-work-tree'],
    'Git worktree check',
  );
  const repositoryPrefix = text(
    ['rev-parse', '--show-prefix'],
    'Git repository prefix',
  );
  if (insideWorkTree !== 'true' || repositoryPrefix !== '') {
    throw new TypeError('source policy checkout is not the Git worktree root');
  }
  if (text(['rev-parse', 'HEAD'], 'Git HEAD') !== expectedSourceDigest) {
    throw new TypeError('source policy checkout HEAD differs from trusted source');
  }
  if (!SOURCE_POLICY_ORIGINS.has(text(
    ['config', '--get', 'remote.origin.url'],
    'Git origin',
  ))) {
    throw new TypeError('source policy checkout has an untrusted Git origin');
  }

  const pathspecs = [...SOURCE_POLICY_PREFIXES, ...SOURCE_POLICY_PATHS];
  const namesBytes = git([
    'ls-tree',
    '-r',
    '-z',
    '--name-only',
    expectedSourceDigest,
    '--',
    ...pathspecs,
  ], 'trusted policy tree enumeration');
  const names = namesBytes.subarray(0, Math.max(0, namesBytes.length - 1))
    .toString('utf8')
    .split('\0')
    .filter(Boolean);
  const nameSet = new Set(names);
  for (const path of SOURCE_POLICY_PATHS) {
    if (!nameSet.has(path)) {
      throw new TypeError(`trusted source commit omits policy file ${path}`);
    }
  }
  if (names.length === 0 || nameSet.size !== names.length) {
    throw new TypeError('trusted policy tree enumeration is empty or ambiguous');
  }
  for (const path of names) {
    if (path !== path.normalize('NFC')
        || path.includes('\\')
        || path.includes(':')
        || path.split('/').some((part) =>
          part === '' || part === '.' || part === '..'
          || /[\u0000-\u001f\u007f]/u.test(part))) {
      throw new TypeError(`trusted policy tree contains unsafe path ${path}`);
    }
    const expected = git(
      ['show', `${expectedSourceDigest}:${path}`],
      `trusted policy blob ${path}`,
      MAX_TEXT_BYTES,
    );
    const current = readStableBytes(
      join(root, ...path.split('/')),
      `source policy file ${path}`,
      MAX_TEXT_BYTES,
    ).bytes;
    if (!current.equals(expected)) {
      throw new TypeError(`source policy file differs from trusted commit: ${path}`);
    }
  }
  const status = git([
    'status',
    '--porcelain=v1',
    '-z',
    '--untracked-files=all',
    '--',
    ...pathspecs,
  ], 'source policy worktree status');
  if (status.length !== 0) {
    throw new TypeError(
      'source policy paths contain modified, staged, or untracked bytes',
    );
  }
  return Object.freeze({
    ok: true,
    sourceDigest: expectedSourceDigest,
    policyFiles: names.length,
  });
}

function loadContracts(repoRoot) {
  const engineRoot = join(repoRoot, 'engine-chromium');
  const buildPath = join(engineRoot, 'build', 'm0-build-contract.json');
  const trustPath = join(engineRoot, 'build', 'm0-trust.json');
  const buildSnapshot = readStableBytes(
    buildPath,
    'M0 build contract',
    MAX_JSON_BYTES,
  );
  const trustSnapshot = readStableBytes(
    trustPath,
    'M0 trust contract',
    MAX_JSON_BYTES,
  );
  const buildContract = parseStrictJson(
    buildSnapshot.bytes,
    'M0 build contract',
  );
  const trustContract = parseStrictJson(
    trustSnapshot.bytes,
    'M0 trust contract',
  );
  const audit = validateM0BuildContract(buildContract, trustContract, {
    engineRoot,
    repoRoot,
  });
  return {
    audit,
    buildContract,
    buildContractSha256: buildSnapshot.sha256,
    trustContract,
    trustContractSha256: trustSnapshot.sha256,
  };
}

function validateEvidenceRepository(actual, expected, failures) {
  const keys = ['nameWithOwner', 'repositoryId', 'ownerId', 'visibility'];
  if (!hasExactKeys(actual, keys)) {
    failures.push('evidence repository identity contains missing or unknown fields');
    return;
  }
  const trusted = {
    nameWithOwner: expected.nameWithOwner,
    repositoryId: expected.repositoryId,
    ownerId: expected.ownerId,
    visibility: expected.visibility,
  };
  if (!isDeepStrictEqual(actual, trusted)) {
    failures.push('evidence repository identity does not match the trust contract');
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

function physicalIdentity(stat, realPath) {
  return stat.ino !== 0n
    ? `${stat.dev}:${stat.ino}`
    : `path:${realPath}:${stat.size}:${stat.birthtimeNs}`;
}

function safeFileSize(size, label) {
  if (size < 0n || size > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new TypeError(`${label} has an unsafe file size`);
  }
  return Number(size);
}

function exactKeys(value, keys, label) {
  if (!isPlainObject(value) || !hasExactKeys(value, keys)) {
    throw new TypeError(`${label} must contain exactly: ${keys.join(', ')}`);
  }
  return value;
}

function hasExactKeys(value, keys) {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort(compareText);
  const expected = [...keys].sort(compareText);
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertSha256(value, label) {
  if (!SHA256_RE.test(value ?? '')) {
    throw new TypeError(`${label} must be lowercase SHA-256`);
  }
}

function assertGitCommit(value, label) {
  if (!GIT_COMMIT_RE.test(value ?? '')) {
    throw new TypeError(`${label} must be a lowercase 40-hex Git commit`);
  }
}

function assertGithubId(value, label) {
  if (!GITHUB_ID_RE.test(value ?? '')) {
    throw new TypeError(`${label} must be a positive decimal GitHub ID string`);
  }
}

function registerUnique(map, value, label, kind) {
  const previous = map.get(value);
  if (previous) {
    throw new TypeError(`${kind} is reused from ${previous}`);
  }
  map.set(value, label);
}

function decodeEd25519Signature(value) {
  if (typeof value !== 'string'
      || !BASE64_RE.test(value)
      || value.length === 0) {
    throw new TypeError('external runner receipt signature is not canonical base64');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== value) {
    throw new TypeError('external runner receipt signature is not a 64-byte Ed25519 signature');
  }
  return bytes;
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function failedAudit(failures) {
  return {
    ok: false,
    assuranceLevel: M0_EVIDENCE_V2_ASSURANCE_LEVEL,
    failures,
    verifiedBuilds: 0,
  };
}

function main() {
  const args = process.argv.slice(2);
  if (args.length > 2
      || (args.length > 0
        && (args[0] !== '--repo' || args.length !== 2))) {
    process.stderr.write('usage: m0-evidence-v2.mjs [--repo <path>]\n');
    process.exitCode = 64;
    return;
  }
  const repo = args[0] === '--repo' ? args[1] : resolve(
    dirname(fileURLToPath(import.meta.url)),
    '..',
  );
  const sourceDigest = process.env.PROTEUS_EXPECTED_SOURCE_DIGEST;
  const signerDigest =
    process.env.PROTEUS_EXPECTED_SIGNER_DIGEST ?? sourceDigest;
  const audit = verifyM0EvidenceV2(repo, {
    expectedSourceDigest: sourceDigest,
    expectedSignerDigest: signerDigest,
    expectedRunnerControllerKeySha256:
      process.env.PROTEUS_EXPECTED_RUNNER_KEY_SHA256,
    expectedGhSha256: process.env.PROTEUS_EXPECTED_GH_SHA256,
    ghPath: process.env.PROTEUS_GH_PATH,
  });
  process.stdout.write(`${JSON.stringify(audit, null, 2)}\n`);
  process.exitCode = audit.ok ? 0 : 1;
}

const isDirect = import.meta.main ?? (
  process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
);
if (isDirect) main();
