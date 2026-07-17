#!/usr/bin/env node
// Capture and verify the complete dependency state resolved by the pinned
// depot_tools checkout.
//
// This command is intentionally read-only with respect to Chromium, nested Git
// repositories, CIPD installations, and first-class GCS objects. CIPD
// verification uses its dry-run command with both CheckIntegrity and network
// access disabled. GCS metadata is exported by the pinned gclient parser and
// every retained object is re-hashed locally without contacting GCS.

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import {
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { arch as hostArchitecture, tmpdir } from 'node:os';
import {
  delimiter,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { TextDecoder } from 'node:util';
import { readChromiumBaseline } from './baseline.mjs';
import { assertPinnedChromiumCheckout } from './chromium-checkout.mjs';
import { assertPinnedDepotTools } from './depot-tools-checkout.mjs';
import { sanitizedGitEnvironment } from './git-env.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = resolve(HERE, '..');
const MAX_JSON_BYTES = 32 * 1024 * 1024;
const MAX_TEXT_BYTES = 64 * 1024 * 1024;
const MAX_JSON_DEPTH = 64;
const CIPD_SERVICE_URL = 'https://chrome-infra-packages.appspot.com';
const HEX_COMMIT = /^[0-9a-f]{40}$/u;
const HEX_SHA256 = /^[0-9a-f]{64}$/u;
const CIPD_INSTANCE = /^(?:[0-9a-f]{40}|[A-Za-z0-9_-]{44})$/u;
const PACKAGE_SEGMENT = /^[a-z0-9][a-z0-9._-]*$/u;

export function parseJsonWithoutDuplicateKeys(raw, label = 'JSON') {
  if (typeof raw !== 'string') throw new TypeError(`${label} must be UTF-8 text`);
  if (Buffer.byteLength(raw, 'utf8') > MAX_JSON_BYTES) {
    throw new TypeError(`${label} exceeds ${MAX_JSON_BYTES} bytes`);
  }

  let offset = 0;

  function fail(message) {
    throw new TypeError(`${label}: ${message} at byte ${offset}`);
  }

  function whitespace() {
    while (
      raw[offset] === ' '
      || raw[offset] === '\n'
      || raw[offset] === '\r'
      || raw[offset] === '\t'
    ) {
      offset += 1;
    }
  }

  function string() {
    if (raw[offset] !== '"') fail('expected a JSON string');
    const start = offset;
    offset += 1;
    while (offset < raw.length) {
      const character = raw[offset];
      if (character === '"') {
        offset += 1;
        try {
          return JSON.parse(raw.slice(start, offset));
        } catch (error) {
          fail(`invalid JSON string (${error.message})`);
        }
      }
      if (character === '\\') {
        offset += 1;
        if (offset >= raw.length) fail('unterminated JSON escape');
        if (raw[offset] === 'u') {
          const digits = raw.slice(offset + 1, offset + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(digits)) fail('invalid Unicode escape');
          offset += 5;
        } else {
          if (!/["\\/bfnrt]/u.test(raw[offset])) fail('invalid JSON escape');
          offset += 1;
        }
        continue;
      }
      if (character.charCodeAt(0) <= 0x1f) fail('unescaped control character');
      offset += 1;
    }
    fail('unterminated JSON string');
  }

  function value(depth) {
    if (depth > MAX_JSON_DEPTH) fail(`nesting exceeds ${MAX_JSON_DEPTH}`);
    whitespace();
    const character = raw[offset];
    if (character === '"') return string();
    if (character === '{') return object(depth + 1);
    if (character === '[') return array(depth + 1);
    for (const [token, parsed] of [
      ['true', true],
      ['false', false],
      ['null', null],
    ]) {
      if (raw.startsWith(token, offset)) {
        offset += token.length;
        return parsed;
      }
    }
    const match = raw.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (match) {
      offset += match[0].length;
      const parsed = Number(match[0]);
      if (!Number.isFinite(parsed)) fail('number is not finite');
      return parsed;
    }
    fail('expected a JSON value');
  }

  function object(depth) {
    offset += 1;
    whitespace();
    const output = Object.create(null);
    const keys = new Set();
    if (raw[offset] === '}') {
      offset += 1;
      return output;
    }
    while (offset < raw.length) {
      whitespace();
      const key = string();
      if (keys.has(key)) fail(`duplicate object key ${JSON.stringify(key)}`);
      keys.add(key);
      whitespace();
      if (raw[offset] !== ':') fail('expected ":" after object key');
      offset += 1;
      output[key] = value(depth);
      whitespace();
      if (raw[offset] === '}') {
        offset += 1;
        return output;
      }
      if (raw[offset] !== ',') fail('expected "," or "}" in object');
      offset += 1;
    }
    fail('unterminated JSON object');
  }

  function array(depth) {
    offset += 1;
    whitespace();
    const output = [];
    if (raw[offset] === ']') {
      offset += 1;
      return output;
    }
    while (offset < raw.length) {
      output.push(value(depth));
      whitespace();
      if (raw[offset] === ']') {
        offset += 1;
        return output;
      }
      if (raw[offset] !== ',') fail('expected "," or "]" in array');
      offset += 1;
    }
    fail('unterminated JSON array');
  }

  const parsed = value(0);
  whitespace();
  if (offset !== raw.length) fail('trailing data');
  return parsed;
}

export function detectDependencyRuntime({
  platform = process.platform,
  architecture = hostArchitecture(),
} = {}) {
  const platformMap = {
    darwin: 'mac',
    linux: 'linux',
    win32: 'windows',
  };
  const architectureMap = {
    arm: 'armv6l',
    arm64: 'arm64',
    ia32: '386',
    x64: 'amd64',
  };
  const cipdOs = platformMap[platform];
  const cipdArch = architectureMap[architecture];
  if (!cipdOs) throw new TypeError(`unsupported dependency-lock platform ${platform}`);
  if (!cipdArch) {
    throw new TypeError(`unsupported dependency-lock architecture ${architecture}`);
  }
  return Object.freeze({
    architecture,
    cipdArchitecture: cipdArch,
    cipdOs,
    cipdPlatform: `${cipdOs}-${cipdArch}`,
    platform,
  });
}

export function parseGclientRevinfo(raw, baseline, runtime = detectDependencyRuntime()) {
  const document = parseJsonWithoutDuplicateKeys(raw, 'gclient revinfo JSON');
  if (!isRecord(document) || Array.isArray(document)) {
    throw new TypeError('gclient revinfo JSON must be an object');
  }

  const dependencies = [];
  for (const name of Object.keys(document).sort(compareText)) {
    const entry = document[name];
    if (!isRecord(entry) || Array.isArray(entry)) {
      throw new TypeError(`gclient revinfo entry ${name} must be an object`);
    }
    assertExactKeys(entry, ['rev', 'url'], `gclient revinfo entry ${name}`);
    const { rev, url } = entry;
    if (typeof url !== 'string' || url === '' || hasControl(url)) {
      throw new TypeError(`gclient revinfo entry ${name} has an invalid URL`);
    }

    if (url.startsWith('gs://')) {
      if (rev !== null) {
        throw new TypeError(`GCS entry ${name} must have a null rev`);
      }
      dependencies.push(parseGcsEntry(name, url));
      continue;
    }

    if (url.startsWith(`${CIPD_SERVICE_URL}/p/`)) {
      if (rev !== null) {
        throw new TypeError(`CIPD entry ${name} must have a null rev`);
      }
      dependencies.push(parseCipdEntry(name, url, runtime));
      continue;
    }

    dependencies.push(parseGitEntry(name, url, rev));
  }

  if (dependencies.length === 0) {
    throw new TypeError('gclient revinfo returned no dependencies');
  }
  const solution = dependencies.find((entry) => entry.path === 'src');
  if (!solution || solution.type !== 'git') {
    throw new TypeError('gclient revinfo is missing the src Git solution');
  }
  if (solution.url !== baseline.CHROMIUM_REPOSITORY) {
    throw new TypeError('gclient src solution URL differs from CHROMIUM_BASELINE');
  }
  if (solution.commit !== baseline.CHROMIUM_COMMIT) {
    throw new TypeError('gclient src solution commit differs from CHROMIUM_BASELINE');
  }

  dependencies.sort(compareDependencies);
  return Object.freeze({
    dependencies: Object.freeze(dependencies.map((entry) => Object.freeze(entry))),
    revinfoSha256: sha256(canonicalJson(document, false)),
  });
}

function parseGitEntry(name, url, rev) {
  const path = parseRelativePath(name, 'Git dependency path');
  if (path.includes(':')) throw new TypeError(`Git dependency path ${path} contains ":"`);
  if (typeof rev !== 'string' || !HEX_COMMIT.test(rev)) {
    throw new TypeError(`Git dependency ${path} does not have a full lowercase commit`);
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new TypeError(`Git dependency ${path} has an invalid URL`);
  }
  if (
    parsed.protocol !== 'https:'
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.search !== ''
    || parsed.hash !== ''
  ) {
    throw new TypeError(`Git dependency ${path} must use a credential-free HTTPS URL`);
  }
  if (parsed.href !== url) {
    throw new TypeError(`Git dependency ${path} URL is not canonical`);
  }
  return { commit: rev, path, type: 'git', url };
}

function parseCipdEntry(name, url, runtime) {
  const separator = name.indexOf(':');
  if (separator <= 0 || separator === name.length - 1) {
    throw new TypeError(`CIPD entry ${name} does not identify path and package`);
  }
  const path = parseRelativePath(name.slice(0, separator), 'CIPD dependency path');
  const declaredPackage = name.slice(separator + 1);
  const expandedDeclaredPackage = expandCipdPackage(declaredPackage, runtime);
  const match = url.match(
    /^https:\/\/chrome-infra-packages\.appspot\.com\/p\/([^?#]+)\/\+\/([^/?#]+)$/u,
  );
  if (!match) throw new TypeError(`CIPD entry ${name} has an invalid instance URL`);
  const [, packageName, instanceId] = match;
  assertCipdPackage(packageName, `CIPD entry ${name} package`);
  if (packageName !== expandedDeclaredPackage) {
    throw new TypeError(`CIPD entry ${name} package does not match its resolved URL`);
  }
  if (!CIPD_INSTANCE.test(instanceId)) {
    throw new TypeError(`CIPD entry ${name} does not have a content-addressed instance ID`);
  }
  return {
    declaredPackage,
    instanceId,
    package: packageName,
    path,
    serviceUrl: CIPD_SERVICE_URL,
    type: 'cipd',
  };
}

function parseGcsEntry(name, url) {
  const separator = name.indexOf(':');
  if (separator <= 0 || separator === name.length - 1) {
    throw new TypeError(`GCS entry ${name} does not identify path and object`);
  }
  const path = parseRelativePath(name.slice(0, separator), 'GCS dependency path');
  const declaredObject = name.slice(separator + 1);
  if (
    hasControl(declaredObject)
    || declaredObject.includes('\\')
    || declaredObject.includes(':')
  ) {
    throw new TypeError(`GCS entry ${name} has an invalid object name`);
  }
  const match = url.match(/^gs:\/\/([a-z0-9][a-z0-9._-]*[a-z0-9])\/(.+)$/u);
  if (!match) throw new TypeError(`GCS entry ${name} has an invalid URL`);
  const [, bucket, object] = match;
  if (
    object !== declaredObject
    || object.includes('?')
    || object.includes('#')
    || object.startsWith('/')
    || hasControl(object)
  ) {
    throw new TypeError(`GCS entry ${name} object does not match its URL`);
  }
  return { bucket, object, path, type: 'gcs', url };
}

function expandCipdPackage(packageTemplate, runtime) {
  if (
    packageTemplate === ''
    || hasControl(packageTemplate)
    || /[\s\\:?#]/u.test(packageTemplate)
  ) {
    throw new TypeError(`invalid CIPD package template ${packageTemplate}`);
  }
  const expanded = packageTemplate.replace(/\$\{([^}]+)\}/gu, (_match, variable) => {
    if (variable === 'platform') return runtime.cipdPlatform;
    if (variable === 'os') return runtime.cipdOs;
    if (variable === 'arch') return runtime.cipdArchitecture;
    throw new TypeError(`unsupported CIPD package expansion \${${variable}}`);
  });
  if (expanded.includes('${') || expanded.includes('}')) {
    throw new TypeError(`invalid CIPD package template ${packageTemplate}`);
  }
  assertCipdPackage(expanded, 'expanded CIPD package');
  return expanded;
}

function assertCipdPackage(packageName, label) {
  const segments = packageName.split('/');
  if (
    segments.length === 0
    || segments.some((segment) => !PACKAGE_SEGMENT.test(segment))
  ) {
    throw new TypeError(`${label} is invalid`);
  }
}

export function bindGcsDependencyMetadata(raw, dependencies) {
  const document = parseJsonWithoutDuplicateKeys(raw, 'gclient GCS metadata JSON');
  if (!isRecord(document) || Array.isArray(document)) {
    throw new TypeError('gclient GCS metadata JSON must be an object');
  }
  assertExactKeys(
    document,
    ['dependencies', 'schemaVersion'],
    'gclient GCS metadata JSON',
  );
  if (document.schemaVersion !== 1 || !Array.isArray(document.dependencies)) {
    throw new TypeError('gclient GCS metadata JSON has an unsupported schema');
  }

  const metadata = new Map();
  for (const [index, entry] of document.dependencies.entries()) {
    if (!isRecord(entry) || Array.isArray(entry)) {
      throw new TypeError(`gclient GCS metadata entry ${index} must be an object`);
    }
    assertExactKeys(
      entry,
      ['bucket', 'generation', 'object', 'output', 'path', 'sha256', 'size'],
      `gclient GCS metadata entry ${index}`,
    );
    const candidate = {
      ...entry,
      type: 'gcs',
      url: `gs://${entry.bucket}/${entry.object}`,
    };
    assertGcsDependenciesLockable([candidate]);
    const identity = gcsIdentity(candidate);
    if (metadata.has(identity)) {
      throw new TypeError(
        `gclient GCS metadata duplicates ${candidate.path}:${candidate.object}`,
      );
    }
    metadata.set(identity, candidate);
  }

  const expected = dependencies.filter((entry) => entry.type === 'gcs');
  if (metadata.size !== expected.length) {
    throw new TypeError(
      'gclient GCS metadata does not describe exactly the active revinfo GCS dependencies',
    );
  }
  const resolved = dependencies.map((dependency) => {
    if (dependency.type !== 'gcs') return { ...dependency };
    const entry = metadata.get(gcsIdentity(dependency));
    if (!entry) {
      throw new TypeError(
        `gclient GCS metadata is missing ${dependency.path}:${dependency.object}`,
      );
    }
    if (
      entry.bucket !== dependency.bucket
      || entry.path !== dependency.path
      || entry.object !== dependency.object
      || entry.url !== dependency.url
    ) {
      throw new TypeError(
        `gclient GCS metadata differs from revinfo for ${dependency.path}:${dependency.object}`,
      );
    }
    return entry;
  });
  resolved.sort(compareDependencies);
  assertGcsDependenciesLockable(resolved);
  return Object.freeze(resolved.map((entry) => Object.freeze(entry)));
}

export function assertGcsDependenciesLockable(dependencies) {
  const identities = new Set();
  const outputs = new Set();
  const markers = new Set();
  for (const entry of dependencies.filter((dependency) => dependency.type === 'gcs')) {
    if (!isRecord(entry) || Array.isArray(entry)) {
      throw new TypeError('GCS dependency must be an object');
    }
    assertExactKeys(
      entry,
      [
        'bucket',
        'generation',
        'object',
        'output',
        'path',
        'sha256',
        'size',
        'type',
        'url',
      ],
      `GCS dependency ${entry.path || '<unknown>'}`,
    );
    const parsed = parseGcsEntry(`${entry.path}:${entry.object}`, entry.url);
    if (entry.bucket !== parsed.bucket) {
      throw new TypeError(
        `GCS dependency ${entry.path}:${entry.object} bucket differs from its URL`,
      );
    }
    parseRelativePath(entry.output, 'GCS dependency output');
    if (entry.output.includes(':')) {
      throw new TypeError(
        `GCS dependency ${entry.path}:${entry.object} output is not portable`,
      );
    }
    if (!HEX_SHA256.test(entry.sha256)) {
      throw new TypeError(
        `GCS dependency ${entry.path}:${entry.object} has an invalid SHA-256`,
      );
    }
    if (!Number.isSafeInteger(entry.size) || entry.size < 0) {
      throw new TypeError(
        `GCS dependency ${entry.path}:${entry.object} has an invalid byte size`,
      );
    }
    if (!Number.isSafeInteger(entry.generation) || entry.generation <= 0) {
      throw new TypeError(
        `GCS dependency ${entry.path}:${entry.object} has an invalid generation`,
      );
    }

    const identity = gcsIdentity(entry);
    const output = `${entry.path}\0${entry.output}`;
    const marker = `${entry.path}\0${gcsFilePrefix(entry.object)}`;
    if (identities.has(identity)) {
      throw new TypeError(`duplicate GCS dependency ${entry.path}:${entry.object}`);
    }
    if (outputs.has(output)) {
      throw new TypeError(`duplicate GCS output ${entry.path}/${entry.output}`);
    }
    if (markers.has(marker)) {
      throw new TypeError(
        `GCS dependencies in ${entry.path} have colliding depot_tools markers`,
      );
    }
    identities.add(identity);
    outputs.add(output);
    markers.add(marker);
  }
}

export function auditGcsDependencies(clientRoot, dependencies) {
  assertGcsDependenciesLockable(dependencies);
  const root = realpathSync(clientRoot);
  const audited = [];
  for (const dependency of dependencies.filter((entry) => entry.type === 'gcs')) {
    const dependencyRoot = containedDependencyPath(root, dependency.path);
    let dependencyStat;
    try {
      dependencyStat = lstatSync(dependencyRoot);
    } catch (error) {
      throw new TypeError(
        `cannot inspect GCS dependency root ${dependency.path}: ${error.message}`,
      );
    }
    if (!dependencyStat.isDirectory() || dependencyStat.isSymbolicLink()) {
      throw new TypeError(
        `GCS dependency root ${dependency.path} must be an ordinary directory`,
      );
    }
    const realDependencyRoot = realpathSync(dependencyRoot);
    assertContained(root, realDependencyRoot, dependency.path);

    const output = containedDependencyPath(realDependencyRoot, dependency.output);
    let realOutput;
    try {
      realOutput = realpathSync(output);
    } catch (error) {
      throw new TypeError(
        `GCS dependency output ${dependency.path}/${dependency.output} is unavailable: `
        + error.message,
      );
    }
    assertContained(
      realDependencyRoot,
      realOutput,
      `${dependency.path}/${dependency.output}`,
    );
    const content = digestStableFile(
      output,
      `GCS dependency output ${dependency.path}/${dependency.output}`,
    );
    if (content.size !== BigInt(dependency.size)) {
      throw new TypeError(
        `GCS dependency ${dependency.path}:${dependency.object} byte size differs from DEPS`,
      );
    }
    if (content.sha256 !== dependency.sha256) {
      throw new TypeError(
        `GCS dependency ${dependency.path}:${dependency.object} SHA-256 differs from DEPS`,
      );
    }

    const prefix = gcsFilePrefix(dependency.object);
    const hashMarker = readStableUtf8(
      join(realDependencyRoot, `.${prefix}_hash`),
      1024,
      `GCS dependency ${dependency.path}:${dependency.object} hash marker`,
    );
    if (hashMarker !== `${dependency.sha256}\n`) {
      throw new TypeError(
        `GCS dependency ${dependency.path}:${dependency.object} hash marker is stale`,
      );
    }
    const migrationMarker = readStableUtf8(
      join(realDependencyRoot, `.${prefix}_is_first_class_gcs`),
      1024,
      `GCS dependency ${dependency.path}:${dependency.object} completion marker`,
    );
    if (migrationMarker !== '1\n') {
      throw new TypeError(
        `GCS dependency ${dependency.path}:${dependency.object} completion marker is stale`,
      );
    }
    audited.push(`${dependency.path}:${dependency.object}`);
  }
  return Object.freeze(audited);
}

export function auditNestedGitDependencies(
  clientRoot,
  dependencies,
  {
    environment = process.env,
    git = process.env.PROTEUS_GIT_BIN || 'git',
  } = {},
) {
  const root = realpathSync(clientRoot);
  const gitEnvironment = sanitizedGitEnvironment(environment);
  const audited = [];
  for (const dependency of dependencies) {
    if (dependency.type !== 'git' || dependency.path === 'src') continue;
    const checkout = containedDependencyPath(root, dependency.path);
    let stat;
    try {
      stat = lstatSync(checkout);
    } catch (error) {
      throw new TypeError(
        `cannot inspect nested Git dependency ${dependency.path}: ${error.message}`,
      );
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new TypeError(
        `nested Git dependency ${dependency.path} must be an ordinary directory`,
      );
    }
    const realCheckout = realpathSync(checkout);
    assertContained(root, realCheckout, dependency.path);

    let topLevel;
    let origin;
    let head;
    let actualTree;
    let expectedTree;
    try {
      topLevel = gitOutput(git, checkout, ['rev-parse', '--show-toplevel'], gitEnvironment);
      origin = gitOutput(git, checkout, ['remote', 'get-url', 'origin'], gitEnvironment);
      head = gitOutput(git, checkout, ['rev-parse', '--verify', 'HEAD'], gitEnvironment);
      actualTree = gitOutput(git, checkout, ['write-tree'], gitEnvironment);
      expectedTree = gitOutput(
        git,
        checkout,
        ['rev-parse', '--verify', `${dependency.commit}^{tree}`],
        gitEnvironment,
      );
    } catch (error) {
      throw new TypeError(
        `nested Git dependency ${dependency.path} is unusable: ${firstLine(error)}`,
      );
    }

    if (relative(realCheckout, realpathSync(topLevel)) !== '') {
      throw new TypeError(`nested Git dependency ${dependency.path} is not a repository root`);
    }
    if (origin !== dependency.url) {
      throw new TypeError(`nested Git dependency ${dependency.path} origin differs from revinfo`);
    }
    if (head !== dependency.commit) {
      throw new TypeError(`nested Git dependency ${dependency.path} HEAD differs from revinfo`);
    }
    if (actualTree !== expectedTree) {
      throw new TypeError(`nested Git dependency ${dependency.path} index tree is modified`);
    }

    const flagged = gitOutput(git, checkout, ['ls-files', '-v'], gitEnvironment)
      .split('\n')
      .filter((line) => line !== '' && !line.startsWith('H '));
    if (flagged.length > 0) {
      throw new TypeError(
        `nested Git dependency ${dependency.path} has non-default index flags`,
      );
    }
    if (!gitSucceeds(git, checkout, ['diff-files', '--quiet', '--'], gitEnvironment)) {
      throw new TypeError(
        `nested Git dependency ${dependency.path} worktree differs from its index`,
      );
    }
    const untracked = gitOutput(
      git,
      checkout,
      ['ls-files', '--others', '--exclude-standard'],
      gitEnvironment,
    );
    if (untracked !== '') {
      throw new TypeError(
        `nested Git dependency ${dependency.path} has untracked non-ignored files`,
      );
    }
    audited.push(dependency.path);
  }
  return Object.freeze(audited);
}

export function renderCipdEnsureFile(dependencies) {
  const cipd = dependencies
    .filter((entry) => entry.type === 'cipd')
    .slice()
    .sort(compareDependencies);
  const seen = new Set();
  const lines = [
    `$ServiceURL ${CIPD_SERVICE_URL}`,
    '$ParanoidMode CheckIntegrity',
    '$OverrideInstallMode copy',
    '',
  ];
  let currentPath = null;
  for (const dependency of cipd) {
    const identity = `${dependency.path}\0${dependency.package}`;
    if (seen.has(identity)) {
      throw new TypeError(
        `duplicate CIPD package ${dependency.package} in ${dependency.path}`,
      );
    }
    seen.add(identity);
    if (dependency.path !== currentPath) {
      if (currentPath !== null) lines.push('');
      lines.push(`@Subdir ${dependency.path}`);
      currentPath = dependency.path;
    }
    lines.push(`${dependency.package} ${dependency.instanceId}`);
  }
  lines.push('');
  return `${lines.join('\n')}\n`;
}

export function assertCipdDryRunResult(raw, status) {
  const document = parseJsonWithoutDuplicateKeys(raw, 'CIPD dry-run JSON');
  if (!isRecord(document) || Array.isArray(document)) {
    throw new TypeError('CIPD dry-run JSON must be an object');
  }
  const allowed = new Set(['error', 'result']);
  for (const key of Object.keys(document)) {
    if (!allowed.has(key)) throw new TypeError(`CIPD dry-run JSON has unknown key ${key}`);
  }
  if (typeof document.error === 'string' && document.error !== '') {
    throw new TypeError(`CIPD dry-run failed: ${document.error}`);
  }
  if (document.error !== undefined && document.error !== '') {
    throw new TypeError('CIPD dry-run JSON has an invalid error field');
  }
  const result = document.result;
  const noActions = result === null
    || (isRecord(result) && !Array.isArray(result) && Object.keys(result).length === 0);
  if (!noActions) {
    throw new TypeError('CIPD dry-run planned one or more install, update, remove, or repair actions');
  }
  if (status !== 5) {
    throw new TypeError(`CIPD no-action dry-run returned unexpected exit status ${status}`);
  }
  return Object.freeze({ actions: 0, status });
}

export function runCipdIntegrityAudit(
  clientRoot,
  dependencies,
  cipdClient,
  {
    environment = process.env,
    invoke = defaultCipdInvoke,
  } = {},
) {
  const cipd = dependencies.filter((entry) => entry.type === 'cipd');
  if (cipd.length === 0) return Object.freeze({ actions: 0, packages: 0, skipped: true });
  auditCipdDependencyPaths(clientRoot, cipd);

  const temp = mkdtempSync(join(tmpdir(), 'proteus-cipd-audit-'));
  const ensurePath = join(temp, 'dependencies.ensure');
  const resultPath = join(temp, 'result.json');
  const configPath = join(temp, 'empty-cipd-config.textproto');
  try {
    writeFileSync(ensurePath, renderCipdEnsureFile(cipd), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    writeFileSync(configPath, '', { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    const audit = executeCipdDryRun({
      cipdClient,
      configPath,
      ensurePath,
      environment,
      invoke,
      label: 'Chromium dependency CIPD',
      resultPath,
      root: clientRoot,
    });
    return Object.freeze({ ...audit, packages: cipd.length, skipped: false });
  } finally {
    rmSync(temp, { force: true, recursive: true });
  }
}

export function auditCipdDependencyPaths(clientRoot, dependencies) {
  const root = realpathSync(clientRoot);
  const audited = [];
  for (const path of [...new Set(
    dependencies
      .filter((entry) => entry.type === 'cipd')
      .map((entry) => entry.path),
  )].sort(compareText)) {
    const candidate = containedDependencyPath(root, path);
    const stat = lstatSync(candidate);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new TypeError(`CIPD dependency root ${path} must be an ordinary directory`);
    }
    assertContained(root, realpathSync(candidate), path);
    audited.push(path);
  }
  return Object.freeze(audited);
}

export function renderDepotToolsIntegrityEnsure(raw) {
  if (typeof raw !== 'string') {
    throw new TypeError('depot_tools cipd_manifest.txt must be UTF-8 text');
  }
  const lines = raw.split(/\r?\n/u);
  let paranoidMode = 0;
  let resolvedVersions = 0;
  let serviceUrl = 0;
  const output = [];
  for (const [index, line] of lines.entries()) {
    if (line.startsWith('$ParanoidMode')) {
      if (!/^\$ParanoidMode[ \t]+\S+$/u.test(line)) {
        throw new TypeError(`cipd_manifest.txt:${index + 1}: invalid ParanoidMode`);
      }
      paranoidMode += 1;
      output.push('$ParanoidMode CheckIntegrity');
      continue;
    }
    if (line.startsWith('$ResolvedVersions')) {
      if (line !== '$ResolvedVersions cipd_manifest.versions') {
        throw new TypeError(
          `cipd_manifest.txt:${index + 1}: ResolvedVersions must name cipd_manifest.versions`,
        );
      }
      resolvedVersions += 1;
    }
    if (line.startsWith('$ServiceURL')) {
      if (line !== `$ServiceURL ${CIPD_SERVICE_URL}`) {
        throw new TypeError(
          `cipd_manifest.txt:${index + 1}: ServiceURL must be ${CIPD_SERVICE_URL}`,
        );
      }
      serviceUrl += 1;
    }
    output.push(line);
  }
  if (resolvedVersions !== 1) {
    throw new TypeError('cipd_manifest.txt must have exactly one ResolvedVersions setting');
  }
  if (paranoidMode > 1 || serviceUrl > 1) {
    throw new TypeError('cipd_manifest.txt contains duplicate global settings');
  }
  const settings = [];
  if (serviceUrl === 0) settings.push(`$ServiceURL ${CIPD_SERVICE_URL}`);
  if (paranoidMode === 0) settings.push('$ParanoidMode CheckIntegrity');
  return `${settings.join('\n')}${settings.length > 0 ? '\n' : ''}${output.join('\n')}`;
}

export function runDepotToolsBootstrapIntegrityAudit(
  depotTools,
  cipdClient,
  {
    environment = process.env,
    invoke = defaultCipdInvoke,
  } = {},
) {
  const bootstrap = assertDepotToolsBootstrapReady(depotTools);
  const manifestBytes = readStableFile(
    join(depotTools, 'cipd_manifest.txt'),
    MAX_TEXT_BYTES,
    'depot_tools cipd_manifest.txt',
  );
  const manifest = decodeUtf8(
    manifestBytes,
    'depot_tools cipd_manifest.txt',
  );
  const versions = readStableFile(
    join(depotTools, 'cipd_manifest.versions'),
    MAX_TEXT_BYTES,
    'depot_tools cipd_manifest.versions',
  );
  if (versions.length === 0) {
    throw new TypeError('depot_tools cipd_manifest.versions is empty');
  }

  const temp = mkdtempSync(join(tmpdir(), 'proteus-depot-cipd-audit-'));
  const ensurePath = join(temp, 'cipd_manifest.txt');
  const versionsPath = join(temp, 'cipd_manifest.versions');
  const resultPath = join(temp, 'result.json');
  const configPath = join(temp, 'empty-cipd-config.textproto');
  try {
    writeFileSync(ensurePath, renderDepotToolsIntegrityEnsure(manifest), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    writeFileSync(versionsPath, versions, { flag: 'wx', mode: 0o600 });
    writeFileSync(configPath, '', { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    const audit = executeCipdDryRun({
      cipdClient,
      configPath,
      ensurePath,
      environment,
      invoke,
      label: 'depot_tools bootstrap CIPD',
      resultPath,
      root: bootstrap.root,
    });
    return Object.freeze({
      ...audit,
      manifestSha256: sha256(manifestBytes),
      vpythonSha256: bootstrap.vpythonSha256,
      versionsSha256: sha256(versions),
    });
  } finally {
    rmSync(temp, { force: true, recursive: true });
  }
}

function executeCipdDryRun({
  cipdClient,
  configPath,
  ensurePath,
  environment,
  invoke,
  label,
  resultPath,
  root,
}) {
  const cipdEnvironment = sanitizedDependencyEnvironment(environment, {
    CIPD_CONFIG_FILE: configPath,
    CIPD_DISABLE_NETWORK: '1',
  });
  const result = invoke(
    cipdClient.path,
    [
      'puppet-check-updates',
      '-disable-network',
      '-log-level',
      'error',
      '-root',
      root,
      '-ensure-file',
      ensurePath,
      '-json-output',
      resultPath,
    ],
    cipdEnvironment,
  );
  if (result.error) {
    throw new TypeError(`cannot run pinned CIPD client for ${label}: ${result.error.message}`);
  }
  if (result.signal) throw new TypeError(`pinned CIPD client for ${label} terminated by ${result.signal}`);
  if (!existsSync(resultPath)) {
    throw new TypeError(`pinned CIPD client did not write the ${label} dry-run result`);
  }
  const raw = readStableUtf8(resultPath, MAX_JSON_BYTES, `${label} dry-run JSON`);
  try {
    return assertCipdDryRunResult(raw, result.status);
  } catch (error) {
    throw new TypeError(`${label} integrity audit failed: ${error.message}`);
  }
}

function defaultCipdInvoke(executable, args, env) {
  return spawnSync(executable, args, {
    env,
    stdio: ['ignore', 'ignore', 'pipe'],
    windowsHide: true,
  });
}

export function validatePinnedCipdClient(
  depotTools,
  runtime = detectDependencyRuntime(),
) {
  const versionPath = join(depotTools, 'cipd_client_version');
  const digestsPath = `${versionPath}.digests`;
  const version = readStableUtf8(versionPath, 4096, 'cipd_client_version').trim();
  if (!/^git_revision:[0-9a-f]{40}$/u.test(version)) {
    throw new TypeError('cipd_client_version is not a pinned Git revision');
  }
  const digests = parseCipdDigests(
    readStableUtf8(digestsPath, 256 * 1024, 'cipd_client_version.digests'),
  );
  const expectedSha256 = digests.get(runtime.cipdPlatform);
  if (!expectedSha256) {
    throw new TypeError(`no pinned CIPD client digest for ${runtime.cipdPlatform}`);
  }
  const path = join(
    depotTools,
    process.platform === 'win32' ? '.cipd_client.exe' : '.cipd_client',
  );
  let stat;
  try {
    stat = lstatSync(path);
  } catch (error) {
    throw new TypeError(
      `pinned CIPD client is unavailable; gclient sync must bootstrap it first: ${error.message}`,
    );
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new TypeError('pinned CIPD client must be an ordinary non-symlink file');
  }
  const actualSha256 = sha256StableFile(path, MAX_TEXT_BYTES, 'pinned CIPD client');
  if (actualSha256 !== expectedSha256) {
    throw new TypeError('CIPD client bytes differ from the pinned depot_tools digest');
  }
  return Object.freeze({
    path,
    platform: runtime.cipdPlatform,
    sha256: actualSha256,
    version,
  });
}

function parseCipdDigests(raw) {
  const values = new Map();
  for (const [index, line] of raw.split(/\r?\n/u).entries()) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    const match = trimmed.match(/^([a-z0-9-]+)[ \t]+sha256[ \t]+([0-9a-f]{64})$/u);
    if (!match) {
      throw new TypeError(`cipd_client_version.digests:${index + 1}: invalid line`);
    }
    if (values.has(match[1])) {
      throw new TypeError(
        `cipd_client_version.digests:${index + 1}: duplicate ${match[1]}`,
      );
    }
    values.set(match[1], match[2]);
  }
  if (values.size === 0) throw new TypeError('cipd_client_version.digests is empty');
  return values;
}

export function runPinnedGclientRevinfo(
  clientRoot,
  depotTools,
  cipdClient,
  {
    environment = process.env,
    invoke = defaultGclientInvoke,
  } = {},
) {
  const gclient = join(
    depotTools,
    process.platform === 'win32' ? 'gclient.bat' : 'gclient',
  );
  let cipdCommandDirectory = null;
  try {
    let pathPrefix = depotTools;
    const explicit = {
      DEPOT_TOOLS_METRICS: '0',
      DEPOT_TOOLS_UPDATE: '0',
    };
    if (process.platform === 'win32') {
      // cipd.bat has no CUSTOM_CIPD_CLIENT fast path. Put a byte-for-byte
      // verified copy of the pinned client first on PATH so gclient's internal
      // `cipd` calls cannot self-update or bootstrap from the network.
      cipdCommandDirectory = mkdtempSync(join(tmpdir(), 'proteus-cipd-command-'));
      const command = join(cipdCommandDirectory, 'cipd.exe');
      copyFileSync(cipdClient.path, command);
      if (
        sha256StableFile(command, MAX_TEXT_BYTES, 'temporary CIPD command')
        !== cipdClient.sha256
      ) {
        throw new TypeError('temporary CIPD command differs from the pinned client');
      }
      pathPrefix = `${cipdCommandDirectory}${delimiter}${depotTools}`;
    } else {
      explicit.CUSTOM_CIPD_CLIENT = cipdClient.path;
    }
    explicit.PATH = `${pathPrefix}${delimiter}${environment.PATH || ''}`;
    const gclientEnvironment = sanitizedDependencyEnvironment(environment, explicit);
    const output = invoke(
      gclient,
      ['revinfo', '--actual', '--output-json=-'],
      clientRoot,
      gclientEnvironment,
    );
    if (typeof output !== 'string') {
      throw new TypeError('pinned gclient invoker did not return text');
    }
    if (Buffer.byteLength(output, 'utf8') > MAX_JSON_BYTES) {
      throw new TypeError(`gclient revinfo JSON exceeds ${MAX_JSON_BYTES} bytes`);
    }
    return output;
  } finally {
    if (cipdCommandDirectory) {
      rmSync(cipdCommandDirectory, { force: true, recursive: true });
    }
  }
}

const GCLIENT_GCS_EXPORTER = String.raw`#!/usr/bin/env python3
import json
import os
import sys
import threading

depot_tools = os.path.realpath(sys.argv[1])
revinfo_path = sys.argv[2]
metadata_path = sys.argv[3]
sys.path.insert(0, depot_tools)

import gclient

records = []
records_lock = threading.Lock()
original_deps_to_objects = gclient.Dependency._deps_to_objects

# gclient's parser otherwise removes a GCS output directory when its local
# completion markers are stale. Resolution capture is an audit, not a repair;
# the Node-side verifier reports that state without mutating the checkout.
gclient.GcsDependency.IsDownloadNeeded = lambda self: False

def deps_to_objects_with_gcs_metadata(self, deps, use_relative_paths):
    resolved = original_deps_to_objects(self, deps, use_relative_paths)
    captured = []
    for dependency in resolved:
        if not isinstance(dependency, gclient.GcsDependency):
            continue
        if not dependency.should_process:
            continue
        candidates = []
        for path, value in deps.items():
            if not value or value.get('dep_type') != 'gcs':
                continue
            for obj in value.get('objects', []):
                if dependency.name != f"{path}:{obj.get('object_name')}":
                    continue
                if dependency.bucket != value.get('bucket'):
                    continue
                if dependency.sha256sum != obj.get('sha256sum'):
                    continue
                if dependency.size_bytes != obj.get('size_bytes'):
                    continue
                if dependency.output_file != obj.get('output_file'):
                    continue
                candidates.append((path, value, obj))
        if len(candidates) != 1:
            raise RuntimeError(
                f"could not uniquely bind active GCS dependency {dependency.name}"
            )
        path, value, obj = candidates[0]
        output = dependency.output_file or f".{dependency.gcs_file_name}"
        captured.append({
            "bucket": value["bucket"],
            "generation": obj["generation"],
            "object": obj["object_name"],
            "output": output,
            "path": path,
            "sha256": obj["sha256sum"],
            "size": obj["size_bytes"],
        })
    if captured:
        with records_lock:
            records.extend(captured)
    return resolved

gclient.Dependency._deps_to_objects = deps_to_objects_with_gcs_metadata
status = gclient.main([
    "revinfo",
    "--actual",
    f"--output-json={revinfo_path}",
])
if status:
    raise SystemExit(status)
records.sort(
    key=lambda entry: (
        entry["path"],
        entry["object"],
        entry["bucket"],
        entry["generation"],
    )
)
with open(metadata_path, "x", encoding="utf-8", newline="\n") as output:
    json.dump(
        {"dependencies": records, "schemaVersion": 1},
        output,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    output.write("\n")
`;

export function runPinnedGclientResolution(
  clientRoot,
  depotTools,
  cipdClient,
  {
    environment = process.env,
    invoke = defaultGclientResolutionInvoke,
  } = {},
) {
  const bootstrap = assertDepotToolsBootstrapReady(depotTools);
  const vpythonSpec = join(depotTools, '.vpython3');
  readStableFile(
    vpythonSpec,
    MAX_TEXT_BYTES,
    'depot_tools .vpython3 specification',
  );
  const temp = mkdtempSync(join(tmpdir(), 'proteus-gclient-resolution-'));
  const exporter = join(temp, 'export_gclient_resolution.py');
  const revinfoPath = join(temp, 'revinfo.json');
  const metadataPath = join(temp, 'gcs-metadata.json');
  let cipdCommandDirectory = null;
  try {
    writeFileSync(exporter, GCLIENT_GCS_EXPORTER, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    let pathPrefix = depotTools;
    const explicit = {
      DEPOT_TOOLS_METRICS: '0',
      DEPOT_TOOLS_UPDATE: '0',
      PYTHONDONTWRITEBYTECODE: '1',
    };
    if (process.platform === 'win32') {
      cipdCommandDirectory = mkdtempSync(join(tmpdir(), 'proteus-cipd-command-'));
      const command = join(cipdCommandDirectory, 'cipd.exe');
      copyFileSync(cipdClient.path, command);
      if (
        sha256StableFile(command, MAX_TEXT_BYTES, 'temporary CIPD command')
        !== cipdClient.sha256
      ) {
        throw new TypeError('temporary CIPD command differs from the pinned client');
      }
      pathPrefix = `${cipdCommandDirectory}${delimiter}${depotTools}`;
    } else {
      explicit.CUSTOM_CIPD_CLIENT = cipdClient.path;
    }
    explicit.PATH = `${pathPrefix}${delimiter}${environment.PATH || ''}`;
    const gclientEnvironment = sanitizedDependencyEnvironment(environment, explicit);
    const result = invoke(
      bootstrap.vpython,
      [
        '-vpython-spec',
        vpythonSpec,
        '--',
        exporter,
        depotTools,
        revinfoPath,
        metadataPath,
      ],
      clientRoot,
      gclientEnvironment,
    );
    if (result?.error) {
      throw new TypeError(
        `cannot run pinned gclient resolution exporter: ${result.error.message}`,
      );
    }
    if (result?.signal) {
      throw new TypeError(
        `pinned gclient resolution exporter terminated by ${result.signal}`,
      );
    }
    if (result?.status !== undefined && result.status !== 0) {
      const detail = result.stderr?.toString().trim().split('\n')[0];
      throw new TypeError(
        `pinned gclient resolution exporter exited with ${result.status}`
        + (detail ? `: ${detail}` : ''),
      );
    }
    if (!existsSync(revinfoPath) || !existsSync(metadataPath)) {
      throw new TypeError(
        'pinned gclient resolution exporter did not write both required records',
      );
    }
    return Object.freeze({
      gcsMetadataRaw: readStableUtf8(
        metadataPath,
        MAX_JSON_BYTES,
        'gclient GCS metadata JSON',
      ),
      revinfoRaw: readStableUtf8(
        revinfoPath,
        MAX_JSON_BYTES,
        'gclient revinfo JSON',
      ),
    });
  } finally {
    rmSync(temp, { force: true, recursive: true });
    if (cipdCommandDirectory) {
      rmSync(cipdCommandDirectory, { force: true, recursive: true });
    }
  }
}

function defaultGclientResolutionInvoke(executable, args, cwd, env) {
  return spawnSync(executable, args, {
    cwd,
    env,
    maxBuffer: MAX_JSON_BYTES,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
}

function defaultGclientInvoke(executable, args, cwd, env) {
  if (process.platform !== 'win32') {
    return execFileSync(executable, args, {
      cwd,
      env,
      maxBuffer: MAX_JSON_BYTES,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).toString();
  }
  const systemRoot = process.env.SystemRoot;
  if (!systemRoot || /["&|<>^%\r\n]/u.test(executable)) {
    throw new TypeError('cannot safely invoke pinned gclient.bat on Windows');
  }
  const command = `"${executable}" ${args.join(' ')}`;
  return execFileSync(join(systemRoot, 'System32', 'cmd.exe'), ['/d', '/s', '/c', command], {
    cwd,
    env,
    maxBuffer: MAX_JSON_BYTES,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).toString();
}

export function assembleDependencyLock({
  baseline,
  depotBootstrap,
  cipdClient,
  dependencies,
  gclientConfigSha256,
  revinfoSha256,
  runtime,
}) {
  assertGcsDependenciesLockable(dependencies);
  return Object.freeze({
    architecture: runtime.architecture,
    chromium: Object.freeze({
      commit: baseline.CHROMIUM_COMMIT,
      repository: baseline.CHROMIUM_REPOSITORY,
      stable: baseline.CHROMIUM_STABLE,
    }),
    dependencies: Object.freeze(
      dependencies.map((entry) => Object.freeze({ ...entry })),
    ),
    depotTools: Object.freeze({
      cipdBootstrap: Object.freeze({
        manifestSha256: depotBootstrap.manifestSha256,
        resolvedVersionsSha256: depotBootstrap.versionsSha256,
      }),
      cipdClient: Object.freeze({
        platform: cipdClient.platform,
        sha256: cipdClient.sha256,
        version: cipdClient.version,
      }),
      commit: baseline.DEPOT_TOOLS_COMMIT,
      repository: baseline.DEPOT_TOOLS_REPOSITORY,
      vpython3: Object.freeze({
        platform: runtime.cipdPlatform,
        sha256: depotBootstrap.vpythonSha256,
      }),
    }),
    gclientConfigSha256,
    gclientRevinfoSha256: revinfoSha256,
    platform: runtime.platform,
    schemaVersion: 1,
  });
}

export function collectDependencyLock({
  chromiumState,
  clientRoot,
  depotTools,
  environment = process.env,
  gclientResolutionInvoke = defaultGclientResolutionInvoke,
  git = process.env.PROTEUS_GIT_BIN || 'git',
  cipdInvoke = defaultCipdInvoke,
  runtime = detectDependencyRuntime(),
} = {}) {
  if (!['clean', 'patched'].includes(chromiumState)) {
    throw new TypeError('chromiumState must be clean or patched');
  }
  assertOrdinaryDirectory(clientRoot, 'gclient root');
  assertOrdinaryDirectory(depotTools, 'depot_tools root');
  const baseline = readChromiumBaseline(join(ENGINE_ROOT, 'CHROMIUM_BASELINE'));
  assertPinnedDepotTools(depotTools, baseline, { environment, git });
  assertPinnedChromiumCheckout(join(clientRoot, 'src'), baseline, {
    environment,
    git,
    state: chromiumState,
  });
  const gclientConfig = readStableUtf8(
    join(clientRoot, '.gclient'),
    256 * 1024,
    '.gclient',
  );
  const expectedConfig = expectedGclientConfig(baseline);
  if (gclientConfig !== expectedConfig) {
    throw new TypeError(
      '.gclient differs from the single canonical unmanaged Chromium solution',
    );
  }
  const cipdClient = validatePinnedCipdClient(depotTools, runtime);
  const depotBootstrap = runDepotToolsBootstrapIntegrityAudit(
    depotTools,
    cipdClient,
    { environment, invoke: cipdInvoke },
  );
  const resolution = runPinnedGclientResolution(
    clientRoot,
    depotTools,
    cipdClient,
    { environment, invoke: gclientResolutionInvoke },
  );
  const postGclientCipdClient = validatePinnedCipdClient(depotTools, runtime);
  if (postGclientCipdClient.sha256 !== cipdClient.sha256) {
    throw new TypeError('pinned CIPD client changed while gclient revinfo ran');
  }
  const postGclientBootstrap = runDepotToolsBootstrapIntegrityAudit(
    depotTools,
    postGclientCipdClient,
    { environment, invoke: cipdInvoke },
  );
  if (
    postGclientBootstrap.manifestSha256 !== depotBootstrap.manifestSha256
    || postGclientBootstrap.versionsSha256 !== depotBootstrap.versionsSha256
  ) {
    throw new TypeError('depot_tools CIPD manifest changed while gclient revinfo ran');
  }
  if (postGclientBootstrap.vpythonSha256 !== depotBootstrap.vpythonSha256) {
    throw new TypeError('pinned depot_tools vpython3 changed while gclient revinfo ran');
  }
  const { dependencies, revinfoSha256 } = parseGclientRevinfo(
    resolution.revinfoRaw,
    baseline,
    runtime,
  );
  const lockedDependencies = bindGcsDependencyMetadata(
    resolution.gcsMetadataRaw,
    dependencies,
  );
  auditNestedGitDependencies(clientRoot, lockedDependencies, { environment, git });
  runCipdIntegrityAudit(
    clientRoot,
    lockedDependencies,
    postGclientCipdClient,
    { environment, invoke: cipdInvoke },
  );
  auditGcsDependencies(clientRoot, lockedDependencies);
  const finalCipdClient = validatePinnedCipdClient(depotTools, runtime);
  if (finalCipdClient.sha256 !== cipdClient.sha256) {
    throw new TypeError('pinned CIPD client changed during dependency audit');
  }
  const finalBootstrap = assertDepotToolsBootstrapReady(depotTools);
  if (finalBootstrap.vpythonSha256 !== postGclientBootstrap.vpythonSha256) {
    throw new TypeError('pinned depot_tools vpython3 changed during dependency audit');
  }
  assertPinnedDepotTools(depotTools, baseline, { environment, git });
  return assembleDependencyLock({
    baseline,
    depotBootstrap,
    cipdClient,
    dependencies: lockedDependencies,
    gclientConfigSha256: sha256(gclientConfig),
    revinfoSha256,
    runtime,
  });
}

export function assertDepotToolsBootstrapReady(depotTools) {
  for (const override of ['.cipd_client_platform', '.cipd_client_root']) {
    if (existsSync(join(depotTools, override))) {
      throw new TypeError(`depot_tools ${override} override is forbidden`);
    }
  }
  const root = join(depotTools, '.cipd_bin');
  assertOrdinaryDirectory(root, 'depot_tools CIPD bootstrap root');
  for (const [sourceName, cachedName] of [
    ['cipd_manifest.txt', '.cipd_manifest.txt'],
    ['cipd_manifest.versions', '.cipd_manifest.versions'],
    ['cipd_client_version', '.cipd_client_version'],
  ]) {
    const source = readStableFile(
      join(depotTools, sourceName),
      MAX_TEXT_BYTES,
      `depot_tools ${sourceName}`,
    );
    const cached = readStableFile(
      join(root, cachedName),
      MAX_TEXT_BYTES,
      `depot_tools ${cachedName}`,
    );
    if (
      source.length !== cached.length
      || !timingSafeEqual(source, cached)
    ) {
      throw new TypeError(
        `depot_tools bootstrap cache ${cachedName} is stale; refusing an implicit repair`,
      );
    }
  }
  const vpython = join(
    root,
    process.platform === 'win32' ? 'vpython3.exe' : 'vpython3',
  );
  const stat = lstatSync(vpython);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new TypeError('depot_tools pinned vpython3 must be an ordinary file');
  }
  const vpythonSha256 = sha256StableFile(
    vpython,
    MAX_TEXT_BYTES,
    'depot_tools pinned vpython3',
  );
  return Object.freeze({ root, vpython, vpythonSha256 });
}

export function canonicalDependencyLock(lock) {
  return canonicalJson(lock, true);
}

export function captureDependencyLock(options) {
  const lock = collectDependencyLock(options);
  const bytes = canonicalDependencyLock(lock);
  writeAtomic(options.lockPath, bytes);
  return Object.freeze({
    dependencies: lock.dependencies.length,
    lockPath: options.lockPath,
    sha256: sha256(bytes),
  });
}

export function verifyDependencyLock(options) {
  const actual = readStableUtf8(
    options.lockPath,
    MAX_JSON_BYTES,
    'dependency lock',
  );
  const parsed = parseJsonWithoutDuplicateKeys(actual, 'dependency lock');
  const canonicalActual = canonicalDependencyLock(parsed);
  if (canonicalActual !== actual) {
    throw new TypeError('dependency lock is not canonical sorted JSON');
  }
  const expected = canonicalDependencyLock(collectDependencyLock(options));
  const actualBytes = Buffer.from(actual);
  const expectedBytes = Buffer.from(expected);
  if (
    actualBytes.length !== expectedBytes.length
    || !timingSafeEqual(actualBytes, expectedBytes)
  ) {
    throw new TypeError('dependency lock differs from the live resolved dependency state');
  }
  return Object.freeze({
    dependencies: parsed.dependencies.length,
    lockPath: options.lockPath,
    sha256: sha256(actual),
  });
}

function canonicalJson(value, pretty) {
  const sorted = sortJson(value);
  return pretty
    ? `${JSON.stringify(sorted, null, 2)}\n`
    : JSON.stringify(sorted);
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isRecord(value)) return value;
  const output = Object.create(null);
  for (const key of Object.keys(value).sort(compareText)) {
    output[key] = sortJson(value[key]);
  }
  return output;
}

function compareDependencies(left, right) {
  return compareText(left.path, right.path)
    || compareText(left.type, right.type)
    || compareText(left.package || left.url || '', right.package || right.url || '')
    || compareText(left.commit || left.instanceId || left.object || '', right.commit || right.instanceId || right.object || '');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function gcsIdentity(entry) {
  return `${entry.path}\0${entry.object}`;
}

function gcsFilePrefix(object) {
  return object.replace(/[/.]/gu, '_');
}

function parseRelativePath(value, label) {
  if (
    typeof value !== 'string'
    || value === ''
    || value.length > 4096
    || value.startsWith('/')
    || value.endsWith('/')
    || value.includes('\\')
    || hasControl(value)
  ) {
    throw new TypeError(`${label} is not a canonical POSIX-relative path`);
  }
  const segments = value.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new TypeError(`${label} contains an unsafe segment`);
  }
  return value;
}

function containedDependencyPath(root, posixPath) {
  const candidate = resolve(root, ...posixPath.split('/'));
  assertContained(root, candidate, posixPath);
  return candidate;
}

function assertContained(root, candidate, label) {
  const rel = relative(root, candidate);
  if (rel === '' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    throw new TypeError(`dependency path ${label} escapes or aliases the gclient root`);
  }
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort(compareText);
  const wanted = expected.slice().sort(compareText);
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    throw new TypeError(`${label} must contain exactly ${wanted.join(', ')}`);
  }
}

function sanitizedDependencyEnvironment(source, explicit = {}) {
  const gitSafe = sanitizedGitEnvironment(source);
  const environment = {};
  for (const [key, value] of Object.entries(gitSafe)) {
    if (
      !key.startsWith('CIPD_')
      && !key.startsWith('DEPOT_TOOLS_')
      && !key.startsWith('GCLIENT_')
      && !key.startsWith('VPYTHON_')
      && !key.startsWith('PYTHON')
      && key !== 'CUSTOM_CIPD_CLIENT'
      && key !== 'BASH_ENV'
      && key !== 'CDPATH'
      && key !== 'ENV'
      && key !== 'IFS'
      && key !== 'VIRTUAL_ENV'
    ) {
      environment[key] = value;
    }
  }
  Object.assign(environment, explicit);
  return environment;
}

function expectedGclientConfig(baseline) {
  return `solutions = [
  { "name"        : 'src',
    "url"         : '${baseline.CHROMIUM_REPOSITORY}',
    "deps_file"   : 'DEPS',
    "managed"     : False,
    "custom_deps" : {
    },
    "custom_vars": {},
  },
]
`;
}

function gitOutput(git, root, args, env) {
  return execFileSync(git, ['-C', root, ...args], {
    env,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).toString().trim();
}

function gitSucceeds(git, root, args, env) {
  try {
    execFileSync(git, ['-C', root, ...args], {
      env,
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    return true;
  } catch {
    return false;
  }
}

function readStableUtf8(path, maximum, label) {
  return decodeUtf8(readStableFile(path, maximum, label), label);
}

function decodeUtf8(bytes, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new TypeError(`${label} is not valid UTF-8`);
  }
}

function readStableFile(path, maximum, label) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  if (before.size > BigInt(maximum)) throw new TypeError(`${label} exceeds ${maximum} bytes`);
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameStableFile(before, opened)) throw new TypeError(`${label} changed while opened`);
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const rebound = lstatSync(path, { bigint: true });
    if (!sameStableFile(opened, after) || !sameStableFile(after, rebound)) {
      throw new TypeError(`${label} changed or was rebound while read`);
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function sha256StableFile(path, maximum, label) {
  return sha256(readStableFile(path, maximum, label));
}

function digestStableFile(path, label) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink file`);
  }
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameStableFile(before, opened)) {
      throw new TypeError(`${label} changed while opened`);
    }
    const digest = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytesRead;
    do {
      bytesRead = readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead > 0) digest.update(buffer.subarray(0, bytesRead));
    } while (bytesRead > 0);
    const after = fstatSync(fd, { bigint: true });
    const rebound = lstatSync(path, { bigint: true });
    if (!sameStableFile(opened, after) || !sameStableFile(after, rebound)) {
      throw new TypeError(`${label} changed or was rebound while read`);
    }
    return Object.freeze({
      sha256: digest.digest('hex'),
      size: after.size,
    });
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

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function writeAtomic(path, contents) {
  const parent = dirname(path);
  assertOrdinaryDirectory(parent, 'dependency lock parent');
  if (existsSync(path)) {
    throw new TypeError('dependency lock already exists; capture requires a fresh path');
  }
  const temp = join(
    parent,
    `.proteus-dependency-lock-${process.pid}-${createHash('sha256')
      .update(`${path}\0${Date.now()}\0${Math.random()}`)
      .digest('hex')
      .slice(0, 16)}.tmp`,
  );
  try {
    writeFileSync(temp, contents, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o644,
    });
    renameSync(temp, path);
  } finally {
    rmSync(temp, { force: true });
  }
}

function assertOrdinaryDirectory(path, label) {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} must be an ordinary non-symlink directory`);
  }
}

function isRecord(value) {
  return value !== null && typeof value === 'object';
}

function hasControl(value) {
  return /[\u0000-\u001f\u007f]/u.test(value);
}

function firstLine(error) {
  return (error.stderr?.toString() || error.message).split('\n')[0];
}

function parseCli(args) {
  if (args.length === 0 || !['capture', 'verify'].includes(args[0])) {
    throw new TypeError(
      'usage: dependency-lock.mjs capture|verify '
      + '--client-root <absolute-path> --depot-tools <absolute-path> '
      + '--chromium-state clean|patched [--lock <absolute-path>]',
    );
  }
  const command = args[0];
  const values = Object.create(null);
  const allowed = new Set(['--chromium-state', '--client-root', '--depot-tools', '--lock']);
  for (let index = 1; index < args.length; index += 1) {
    const key = args[index];
    if (!allowed.has(key)) throw new TypeError(`unknown argument ${key}`);
    if (Object.hasOwn(values, key)) throw new TypeError(`${key} may only be supplied once`);
    const value = args[index + 1];
    if (!value || value.startsWith('--')) throw new TypeError(`${key} requires a value`);
    values[key] = value;
    index += 1;
  }
  for (const key of ['--chromium-state', '--client-root', '--depot-tools']) {
    if (!Object.hasOwn(values, key)) throw new TypeError(`${key} is required`);
  }
  const chromiumState = values['--chromium-state'];
  if (!['clean', 'patched'].includes(chromiumState)) {
    throw new TypeError('--chromium-state must be clean or patched');
  }
  const clientRoot = values['--client-root'];
  const depotTools = values['--depot-tools'];
  if (!isAbsolute(clientRoot) || !isAbsolute(depotTools)) {
    throw new TypeError('--client-root and --depot-tools must be absolute paths');
  }
  const lockPath = values['--lock'] || join(clientRoot, '.proteus-dependencies.json');
  if (!isAbsolute(lockPath)) throw new TypeError('--lock must be an absolute path');
  return Object.freeze({
    chromiumState,
    clientRoot: resolve(clientRoot),
    command,
    depotTools: resolve(depotTools),
    lockPath: resolve(lockPath),
  });
}

function main() {
  try {
    const options = parseCli(process.argv.slice(2));
    const result = options.command === 'capture'
      ? captureDependencyLock(options)
      : verifyDependencyLock(options);
    writeSync(process.stdout.fd, `${JSON.stringify(result, null, 2)}\n`);
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
