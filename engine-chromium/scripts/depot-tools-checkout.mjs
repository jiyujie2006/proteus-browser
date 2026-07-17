#!/usr/bin/env node
// Verify the tracked depot_tools checkout before any build tool is invoked.

import { execFileSync } from 'node:child_process';
import { lstatSync, writeSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readChromiumBaseline } from './baseline.mjs';
import { sanitizedGitEnvironment } from './git-env.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = resolve(HERE, '..');

export function auditPinnedDepotTools(
  root,
  baseline,
  {
    git = process.env.PROTEUS_GIT_BIN || 'git',
    environment = process.env,
  } = {},
) {
  const errors = [];
  const gitEnvironment = sanitizedGitEnvironment(environment);
  let stat;
  try {
    stat = lstatSync(root);
  } catch (error) {
    return { errors: [`cannot inspect depot_tools: ${error.message}`] };
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    return { errors: ['depot_tools must be an ordinary non-symlink directory'] };
  }

  let origin;
  let head;
  let actualTree;
  let expectedTree;
  try {
    origin = gitOutput(git, root, ['remote', 'get-url', 'origin'], gitEnvironment);
    head = gitOutput(git, root, ['rev-parse', '--verify', 'HEAD'], gitEnvironment);
    actualTree = gitOutput(git, root, ['write-tree'], gitEnvironment);
    expectedTree = gitOutput(
      git,
      root,
      ['rev-parse', '--verify', `${baseline.DEPOT_TOOLS_COMMIT}^{tree}`],
      gitEnvironment,
    );
  } catch (error) {
    return { errors: [`depot_tools is not a usable Git checkout: ${firstLine(error)}`] };
  }

  if (origin !== baseline.DEPOT_TOOLS_REPOSITORY) {
    errors.push('depot_tools origin is not the canonical pinned repository');
  }
  if (head !== baseline.DEPOT_TOOLS_COMMIT) {
    errors.push(`depot_tools HEAD ${head} does not match ${baseline.DEPOT_TOOLS_COMMIT}`);
  }
  if (actualTree !== expectedTree) {
    errors.push('depot_tools index tree differs from its pinned commit');
  }
  const flagged = gitOutput(git, root, ['ls-files', '-v'], gitEnvironment)
    .split('\n')
    .filter((line) => line !== '' && !line.startsWith('H '));
  if (flagged.length > 0) {
    errors.push('depot_tools index contains non-default tracked-file flags');
  }
  if (!gitSucceeds(
    git,
    root,
    ['diff-files', '--quiet', '--'],
    gitEnvironment,
  )) {
    errors.push('depot_tools tracked worktree bytes differ from its index');
  }
  const untracked = gitOutput(
    git,
    root,
    ['ls-files', '--others', '--exclude-standard'],
    gitEnvironment,
  );
  if (untracked !== '') {
    errors.push('depot_tools contains untracked non-ignored files');
  }
  return { actualTree, errors, expectedTree, head, origin };
}

export function assertPinnedDepotTools(root, baseline, options = {}) {
  const audit = auditPinnedDepotTools(root, baseline, options);
  if (audit.errors.length > 0) throw new TypeError(audit.errors.join('; '));
  return audit;
}

function gitOutput(git, root, args, env) {
  return execFileSync(git, ['-C', root, ...args], {
    env,
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

function firstLine(error) {
  return (error.stderr?.toString() || error.message).split('\n')[0];
}

function main() {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 2 || args[0] !== '--root') {
      throw new TypeError('usage: depot-tools-checkout.mjs --root <directory>');
    }
    const root = resolve(args[1]);
    const baseline = readChromiumBaseline(join(ENGINE_ROOT, 'CHROMIUM_BASELINE'));
    const audit = assertPinnedDepotTools(root, baseline);
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
