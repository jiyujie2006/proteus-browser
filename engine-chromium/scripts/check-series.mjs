#!/usr/bin/env node
// Validate the complete patch catalog without a Chromium checkout.
//
// `patches/series` is the only production build input. M1/M3 specifications
// live in milestone-labelled backlogs so future work cannot accidentally become
// an M0 exit dependency.

import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readChromiumBaseline } from './baseline.mjs';
import {
  auditActivePatchSeries,
  auditPatchCatalog,
  patchHasPayload,
} from './patch-series.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const PATCHES = join(ROOT, 'patches');

const args = process.argv.slice(2);
const activeOnly = args.length === 1 && args[0] === '--active';
if (args.length > (activeOnly ? 1 : 0)) {
  console.error('usage: check-series.mjs [--active]');
  process.exit(64);
}

let baseline;
try {
  baseline = readChromiumBaseline(join(ROOT, 'CHROMIUM_BASELINE'));
} catch (error) {
  console.error(`\n  ❌ invalid Chromium baseline: ${error.message}\n`);
  process.exit(1);
}

const audit = activeOnly
  ? auditActivePatchSeries(PATCHES, baseline.PATCH_PROFILE)
  : auditPatchCatalog(PATCHES, baseline.PATCH_PROFILE);
const activePayloads = audit.active.filter((entry) =>
  patchHasPayload(join(PATCHES, entry)));

console.log(`\n  Proteus ${activeOnly ? 'active M0 patch-series' : 'patch-catalog'} check`);
console.log('  ' + '─'.repeat(62));

for (const error of audit.errors) console.log(`  ❌ ${error}`);
if (audit.errors.length === 0) {
  if (activeOnly) {
    console.log(
      `  ✅ ${audit.active.length} active M0 layer0 patch satisfies the ${baseline.PATCH_PROFILE} metadata contract`,
    );
    console.log('  ✅ future backlog files were not read and cannot affect this M0 gate');
  } else {
    console.log(
      `  ✅ ${audit.active.length} active M0 patch and ${audit.backlog.length} future specifications are disjoint and complete`,
    );
    console.log('  ✅ every patch has milestone/status/rationale/surface/risk/test metadata');
    console.log(`  ✅ active profile is ${baseline.PATCH_PROFILE}; M1/M3 backlogs are not build inputs`);
  }
}

console.log('  ' + '─'.repeat(62));
if (activeOnly) {
  console.log(`  active: ${activePayloads.length}/${audit.active.length} real payloads`);
} else {
  console.log(
    `  active: ${activePayloads.length}/${audit.active.length} real payloads; backlog: ${audit.backlog.length}; on disk: ${audit.onDisk.length}`,
  );
}
if (activePayloads.length !== audit.active.length) {
  console.log(
    '  ℹ️  active placeholder remains: metadata is valid, but production apply and hard M0 stay closed',
  );
}
console.log(
  `  ${audit.errors.length === 0 ? `✅ ${activeOnly ? 'active M0 series' : 'patch catalog'} valid` : `❌ ${audit.errors.length} problem(s)`}\n`,
);

process.exit(audit.errors.length === 0 ? 0 : 1);
