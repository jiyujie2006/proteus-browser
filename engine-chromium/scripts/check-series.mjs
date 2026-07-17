#!/usr/bin/env node
// check-series.mjs — validate the patch series structure and headers.
// Runs with no Chromium checkout. This is a real CI gate (docs/tdd/05 §3, §8):
// every patch listed in `series` must exist and carry the required rationale
// headers, and every patch file on disk must be listed in `series` (no orphans).

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const PATCHES = join(ROOT, 'patches');

const REQUIRED_HEADERS = ['# Rationale:', '# Surface:', '# Upstream-risk:', '# Tests:'];

function readSeries() {
  const raw = readFileSync(join(PATCHES, 'series'), 'utf8');
  return raw.split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

function allPatchFiles() {
  const out = [];
  for (const layer of readdirSync(PATCHES, { withFileTypes: true })) {
    if (!layer.isDirectory()) continue;
    for (const f of readdirSync(join(PATCHES, layer.name))) {
      if (f.endsWith('.patch')) out.push(`${layer.name}/${f}`);
    }
  }
  return out.sort();
}

let errors = 0;
const fail = (m) => { console.log(`  ❌ ${m}`); errors++; };
const ok = (m) => console.log(`  ✅ ${m}`);

console.log('\n  Proteus patch-series check');
console.log('  ' + '─'.repeat(58));

const series = readSeries();
const onDisk = allPatchFiles();

// 1. Every series entry exists on disk.
for (const entry of series) {
  if (!existsSync(join(PATCHES, entry))) fail(`series lists "${entry}" but it does not exist`);
}

// 2. Every patch on disk is listed in series (no orphans).
const seriesSet = new Set(series);
for (const f of onDisk) {
  if (!seriesSet.has(f)) fail(`patch "${f}" exists but is not in series`);
}

// 3. Series is layered in order (layer0 < layer1 < layer2).
const layerOf = (p) => Number((p.match(/^layer(\d)/) || [])[1] ?? 9);
let lastLayer = -1, ordered = true;
for (const entry of series) {
  const l = layerOf(entry);
  if (l < lastLayer) { ordered = false; fail(`series out of layer order at "${entry}"`); }
  lastLayer = Math.max(lastLayer, l);
}
if (ordered) ok('series is in layer order (0 → 1 → 2)');

// 4. Every patch carries the required headers.
let headerOk = 0;
for (const entry of series) {
  const p = join(PATCHES, entry);
  if (!existsSync(p)) continue;
  const text = readFileSync(p, 'utf8');
  const missing = REQUIRED_HEADERS.filter((h) => !text.includes(h));
  if (missing.length) fail(`"${entry}" missing header(s): ${missing.join(', ')}`);
  else headerOk++;
}
if (headerOk === series.length) ok(`all ${headerOk} patches carry Rationale/Surface/Upstream-risk/Tests headers`);

// 5. Count summary.
console.log('  ' + '─'.repeat(58));
console.log(`  ${series.length} patches in series, ${onDisk.length} on disk`);
console.log(`  ${errors === 0 ? '✅ patch series valid' : '❌ ' + errors + ' problem(s)'}\n`);
process.exit(errors === 0 ? 0 : 1);
