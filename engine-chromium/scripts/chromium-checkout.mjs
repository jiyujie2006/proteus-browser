#!/usr/bin/env node
// Verify that a Chromium checkout is the canonical pinned source, either clean
// at the baseline or carrying exactly the active patch result in its index and
// worktree.

import { execFileSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readChromiumBaseline } from './baseline.mjs';
import {
  auditActivePatchSeries,
  patchHasPayload,
} from './patch-series.mjs';
import { sanitizedGitEnvironment } from './git-env.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = resolve(HERE, '..');

export function auditPinnedChromiumCheckout(
  source,
  baseline,
  {
    engineRoot = ENGINE_ROOT,
    state = 'clean',
    git = process.env.PROTEUS_GIT_BIN || 'git',
    environment = process.env,
  } = {},
) {
  const errors = [];
  const gitEnvironment = sanitizedGitEnvironment(environment);
  if (!['clean', 'patched'].includes(state)) {
    return { errors: [`unsupported checkout state ${state}`] };
  }

  let stat;
  try {
    stat = lstatSync(source);
  } catch (error) {
    return { errors: [`cannot inspect Chromium checkout: ${error.message}`] };
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    return { errors: ['Chromium checkout must be an ordinary non-symlink directory'] };
  }

  let origin;
  let head;
  let tagCommit;
  let actualTree;
  try {
    origin = gitOutput(git, source, ['remote', 'get-url', 'origin'], gitEnvironment);
    head = gitOutput(git, source, ['rev-parse', '--verify', 'HEAD'], gitEnvironment);
    tagCommit = gitOutput(
      git,
      source,
      ['rev-parse', '--verify', `refs/tags/${baseline.CHROMIUM_STABLE}^{commit}`],
      gitEnvironment,
    );
    actualTree = gitOutput(git, source, ['write-tree'], gitEnvironment);
  } catch (error) {
    return { errors: [`Chromium checkout is not a usable Git worktree: ${firstLine(error)}`] };
  }

  if (origin !== baseline.CHROMIUM_REPOSITORY) {
    errors.push('Chromium origin is not the canonical pinned repository');
  }
  if (head !== baseline.CHROMIUM_COMMIT) {
    errors.push(`Chromium HEAD ${head} does not match ${baseline.CHROMIUM_COMMIT}`);
  }
  if (tagCommit !== baseline.CHROMIUM_COMMIT) {
    errors.push(`Chromium tag ${baseline.CHROMIUM_STABLE} does not resolve to the pin`);
  }

  const flagged = gitOutput(git, source, ['ls-files', '-v'], gitEnvironment)
    .split('\n')
    .filter((line) => line !== '' && !line.startsWith('H '));
  if (flagged.length > 0) {
    errors.push('Chromium index contains non-default tracked-file flags');
  }
  const untracked = gitOutput(
    git,
    source,
    ['ls-files', '--others', '--exclude-standard'],
    gitEnvironment,
  );
  if (untracked !== '') {
    errors.push('Chromium checkout contains untracked non-ignored files');
  }

  let expectedTree = '';
  if (state === 'clean') {
    expectedTree = gitOutput(
      git,
      source,
      ['rev-parse', '--verify', `${baseline.CHROMIUM_COMMIT}^{tree}`],
      gitEnvironment,
    );
  } else {
    const activeAudit = auditActivePatchSeries(
      join(engineRoot, 'patches'),
      baseline.PATCH_PROFILE,
    );
    if (activeAudit.errors.length > 0) {
      errors.push(`active patch contract is invalid: ${activeAudit.errors[0]}`);
    } else {
      const patchPaths = activeAudit.active.map((entry) =>
        join(engineRoot, 'patches', entry));
      const placeholders = patchPaths.filter((path) => !patchHasPayload(path));
      if (placeholders.length > 0) {
        errors.push('active patch series still contains placeholder payloads');
      } else {
        try {
          expectedTree = computeExpectedPatchedTree(
            git,
            source,
            baseline.CHROMIUM_COMMIT,
            patchPaths,
            gitEnvironment,
          );
        } catch (error) {
          errors.push(`cannot derive expected active-patch tree: ${firstLine(error)}`);
        }
      }
    }
  }

  if (expectedTree && actualTree !== expectedTree) {
    errors.push(`Chromium index tree ${actualTree} does not match expected ${expectedTree}`);
  }
  if (!gitSucceeds(
    git,
    source,
    ['diff-files', '--quiet', '--'],
    gitEnvironment,
  )) {
    errors.push('Chromium worktree bytes do not match its index');
  }

  return {
    actualTree,
    errors,
    expectedTree,
    head,
    origin,
    state,
    tagCommit,
  };
}

export function assertPinnedChromiumCheckout(source, baseline, options = {}) {
  const audit = auditPinnedChromiumCheckout(source, baseline, options);
  if (audit.errors.length > 0) {
    throw new TypeError(audit.errors.join('; '));
  }
  return audit;
}

function computeExpectedPatchedTree(
  git,
  source,
  commit,
  patchPaths,
  gitEnvironment,
) {
  const temp = mkdtempSync(join(tmpdir(), 'proteus-patch-index-'));
  const index = join(temp, 'index');
  const env = sanitizedGitEnvironment(gitEnvironment, {
    GIT_INDEX_FILE: index,
  });
  try {
    execFileSync(git, ['-C', source, 'read-tree', commit], {
      env,
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    execFileSync(
      git,
      ['-C', source, 'apply', '--cached', '--whitespace=nowarn', ...patchPaths],
      { env, stdio: ['ignore', 'ignore', 'pipe'] },
    );
    return execFileSync(git, ['-C', source, 'write-tree'], {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).toString().trim();
  } finally {
    rmSync(temp, { force: true, recursive: true });
  }
}

function gitOutput(git, source, args, env) {
  return execFileSync(git, ['-C', source, ...args], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).toString().trim();
}

function gitSucceeds(git, source, args, env) {
  try {
    execFileSync(git, ['-C', source, ...args], {
      env,
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    return true;
  } catch {
    return false;
  }
}

function firstLine(error) {
  return (error.stderr?.toString() || error.message).split('\n')[0];
}

function parseCli(args) {
  let source = process.env.PROTEUS_CHROMIUM_SRC
    ? join(process.env.PROTEUS_CHROMIUM_SRC, 'src')
    : join(ENGINE_ROOT, 'src', 'src');
  let state = null;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--source') {
      const value = args[index + 1];
      if (!value || value.startsWith('--')) throw new TypeError('--source requires a path');
      source = resolve(value);
      index += 1;
    } else if (arg === '--state') {
      const value = args[index + 1];
      if (!value || value.startsWith('--')) throw new TypeError('--state requires a value');
      state = value;
      index += 1;
    } else {
      throw new TypeError(`unknown argument ${arg}`);
    }
  }
  if (!state) throw new TypeError('--state clean|patched is required');
  return { source, state };
}

function main() {
  try {
    const { source, state } = parseCli(process.argv.slice(2));
    if (!existsSync(source)) throw new TypeError(`Chromium checkout does not exist: ${source}`);
    const baseline = readChromiumBaseline(join(ENGINE_ROOT, 'CHROMIUM_BASELINE'));
    const audit = assertPinnedChromiumCheckout(source, baseline, { state });
    writeSync(process.stdout.fd, `${JSON.stringify(audit, null, 2)}\n`);
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
