#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import {
  existsSync,
  readFileSync,
  writeSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const SOURCE_PARENT = process.env.PROTEUS_CHROMIUM_SRC || join(ROOT, 'src');
const SOURCE = join(SOURCE_PARENT, 'src');
const SERIES = join(ROOT, 'patches', 'series');

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
if (!existsSync(SERIES)) {
  fail(1, `patch series file is missing: ${SERIES}`);
}

const entries = readFileSync(SERIES, 'utf8')
  .split('\n')
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith('#'));
if (entries.length === 0) fail(1, 'patch series contains no entries');

const patches = entries.map((entry) => ({
  entry,
  path: join(ROOT, 'patches', entry),
}));
for (const patch of patches) {
  if (!existsSync(patch.path)) {
    fail(1, `series lists ${patch.entry} but the file is missing`);
  }
}

const placeholders = patches.filter((patch) => !hasPayload(patch.path));
if (placeholders.length > 0 && !allowPlaceholders) {
  stderr(
    `ERROR: patch series contains ${placeholders.length} placeholder(s) with no diff hunks or valid patch payload:\n`,
  );
  for (const patch of placeholders) stderr(`  - ${patch.entry}\n`);
  stderr(
    'Production apply refused. Fill every patch, or use --allow-placeholders for scaffold inspection only.\n',
  );
  process.exit(3);
}

stdout(`==> processing ${patches.length} patches in series order\n`);
let applied = 0;
let skipped = 0;
for (const patch of patches) {
  if (!hasPayload(patch.path)) {
    stdout(`  · ${patch.entry}  (placeholder, no hunks — skipped by explicit scaffold mode)\n`);
    skipped += 1;
    continue;
  }
  stdout(`  · applying ${patch.entry}\n`);
  try {
    execFileSync(
      'git',
      ['-C', SOURCE, 'apply', '--index', '--whitespace=nowarn', patch.path],
      { stdio: 'ignore' },
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

if (skipped > 0) {
  stdout(`==> scaffold inspection complete: ${applied} applied, ${skipped} placeholder(s) skipped\n`);
  stdout('==> NOT a complete patch application; production mode remains blocked\n');
} else {
  stdout(`==> all ${patches.length} patches applied cleanly\n`);
}

function hasPayload(path) {
  try {
    execFileSync('git', ['apply', '--numstat', path], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
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
