#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import {
  existsSync,
  readFileSync,
  writeSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readChromiumBaseline } from './baseline.mjs';
import { assertPinnedChromiumCheckout } from './chromium-checkout.mjs';
import {
  auditActivePatchSeries,
  patchHasPayload,
} from './patch-series.mjs';
import { sanitizedGitEnvironment } from './git-env.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const SOURCE_PARENT = process.env.PROTEUS_CHROMIUM_SRC || join(ROOT, 'src');
const SOURCE = join(SOURCE_PARENT, 'src');
const PATCHES_ROOT = join(ROOT, 'patches');

const args = process.argv.slice(2);
let allowPlaceholders = false;
if (args[0] === '--allow-placeholders') {
  allowPlaceholders = true;
  args.shift();
}
if (args.length > 0) {
  fail(64, 'usage: apply-patches.mjs [--allow-placeholders]');
}
if (!existsSync(SOURCE)) {
  fail(1, `no Chromium tree at ${SOURCE}. Run fetch-chromium.sh first.`);
}
let baseline;
let entries;
try {
  baseline = readChromiumBaseline(join(ROOT, 'CHROMIUM_BASELINE'));
  const audit = auditActivePatchSeries(PATCHES_ROOT, baseline.PATCH_PROFILE);
  if (audit.errors.length > 0) {
    fail(1, `active patch series is invalid: ${audit.errors[0]}`);
  }
  entries = audit.active;
} catch (error) {
  fail(1, error.message);
}

const patches = entries.map((entry) => ({
  entry,
  path: join(PATCHES_ROOT, entry),
}));
for (const patch of patches) {
  if (!existsSync(patch.path)) {
    fail(1, `series lists ${patch.entry} but the file is missing`);
  }
}

const placeholders = patches.filter((patch) => !patchHasPayload(patch.path));
if (allowPlaceholders) {
  stdout(
    `==> inspecting ${patches.length} active ${baseline.PATCH_PROFILE} patch(es); checkout will not be modified\n`,
  );
  stdout('==> future M1/M3 backlog files are excluded and were not read\n');
  for (const patch of patches) {
    stdout(
      `  · ${patch.entry}  (${patchHasPayload(patch.path) ? 'real payload' : 'placeholder, no hunks'})\n`,
    );
  }
  stdout(
    `==> scaffold inspection complete: ${patches.length - placeholders.length} real, ${placeholders.length} placeholder(s)\n`,
  );
  stdout('==> NOT a complete patch application; checkout was not modified and production remains blocked\n');
  process.exit(0);
}

if (placeholders.length > 0 && !allowPlaceholders) {
  stderr(
    `ERROR: active M0 patch series contains ${placeholders.length} placeholder(s) with no diff hunks or valid patch payload:\n`,
  );
  for (const patch of placeholders) stderr(`  - ${patch.entry}\n`);
  stderr(
    'Production apply refused. Fill every active M0 patch, or use --allow-placeholders for scaffold inspection only.\n',
  );
  process.exit(3);
}

try {
  assertPinnedChromiumCheckout(SOURCE, baseline, {
    engineRoot: ROOT,
    state: 'clean',
  });
} catch (error) {
  fail(1, `Chromium preflight failed: ${error.message}`);
}

stdout(
  `==> processing ${patches.length} active ${baseline.PATCH_PROFILE} patch(es) in series order\n`,
);
stdout('==> future M1/M3 backlog files are excluded and were not read\n');
let applied = 0;
for (const patch of patches) {
  stdout(`  · applying ${patch.entry}\n`);
  try {
    execFileSync(
      'git',
      ['-C', SOURCE, 'apply', '--index', '--whitespace=nowarn', patch.path],
      {
        env: sanitizedGitEnvironment(),
        stdio: 'ignore',
      },
    );
  } catch {
    stderr(`\n!!! CONFLICT applying ${patch.entry}\n`);
    const source = readFileSync(patch.path, 'utf8');
    for (const prefix of ['# Upstream-risk:', '# Tests:']) {
      const line = source.split('\n').find((candidate) => candidate.startsWith(prefix));
      if (line) stderr(`${line}\n`);
    }
    stderr('The tracking bot must stop and report this patch surface.\n');
    process.exit(2);
  }
  applied += 1;
}

try {
  const receipt = assertPinnedChromiumCheckout(SOURCE, baseline, {
    engineRoot: ROOT,
    state: 'patched',
  });
  stdout(`==> all ${applied} active patches applied; tree ${receipt.actualTree}\n`);
} catch (error) {
  fail(1, `post-apply checkout verification failed: ${error.message}`);
}

function fail(code, message) {
  stderr(`ERROR: ${message}\n`);
  process.exit(code);
}

function stdout(message) {
  writeSync(process.stdout.fd, message);
}

function stderr(message) {
  writeSync(process.stderr.fd, message);
}
