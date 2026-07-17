#!/usr/bin/env node
// sbom.mjs — emit a CycloneDX-shaped component-manifest stub (docs/tdd/05 §5,8).
// This declared top-level inventory is useful before a build exists, but it is
// NOT the production SBOM. The build farm must generate the full dependency
// inventory from lockfiles and packaged artifacts before a release can ship.

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

function baseline() {
  const raw = readFileSync(join(ROOT, 'CHROMIUM_BASELINE'), 'utf8');
  const m = raw.match(/CHROMIUM_STABLE=(.+)/);
  return m ? m[1].trim() : 'unknown';
}

const components = [
  { type: 'application', name: 'proteus-manager', licenses: ['Apache-2.0'], group: 'proteus', scope: 'required' },
  { type: 'library', name: 'proteus-fingerprint-engine', licenses: ['Apache-2.0'], group: 'proteus', scope: 'required' },
  { type: 'library', name: 'proteus-verify-lab', licenses: ['Apache-2.0'], group: 'proteus', scope: 'required' },
  { type: 'application', name: 'proteus-net-sidecar', licenses: ['Apache-2.0'], group: 'proteus', scope: 'required' },
  { type: 'application', name: 'chromium', version: baseline(), licenses: ['BSD-3-Clause', 'LGPL-2.1', 'MPL-2.0'], group: 'upstream', scope: 'required',
    comment: 'Derivative work; full license set reproduced in release artifacts (about:credits).' },
  { type: 'application', name: 'firefox-camoufox', licenses: ['MPL-2.0'], group: 'upstream', scope: 'optional',
    comment: 'Firefox-family engine via Camoufox; modified MPL files shared upstream.' },
  { type: 'library', name: 'ungoogled-chromium-patches', licenses: ['BSD-3-Clause'], group: 'upstream', scope: 'required',
    comment: 'layer0 de-Google patch methodology.' },
  { type: 'library', name: 'utls', licenses: ['BSD-3-Clause'], group: 'upstream', scope: 'optional',
    comment: 'Optional active-TLS mode only (tdd/03 §6).' },
];

// Produce an RFC 4122 name-based UUID (version 5, RFC variant) from the declared
// component set. It is stable without pretending that raw hash bytes are a UUID.
const UUID_NAMESPACE_URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
function uuidV5(name) {
  const namespace = Buffer.from(UUID_NAMESPACE_URL.replaceAll('-', ''), 'hex');
  const bytes = createHash('sha1')
    .update(namespace)
    .update(name, 'utf8')
    .digest()
    .subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

// License allow-list for redistribution. Anything outside this must be flagged.
const REDISTRIBUTABLE = new Set(['Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause', 'MIT', 'MPL-2.0', 'LGPL-2.1', 'ISC', 'Unlicense', 'CC0-1.0']);

const violations = [];
for (const c of components) {
  for (const lic of c.licenses || []) {
    if (!REDISTRIBUTABLE.has(lic)) violations.push(`${c.name}: license ${lic} is not on the redistributable allow-list`);
  }
}

const serialUuid = uuidV5(
  `https://proteus.example/manifests/component-stub/v1#${JSON.stringify(components)}`,
);

const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${serialUuid}`,
  version: 1,
  metadata: {
    component: { type: 'application', name: 'proteus', group: 'proteus' },
    properties: [
      { name: 'proteus:document-kind', value: 'component-manifest-stub' },
      { name: 'proteus:build-derived', value: 'false' },
      {
        name: 'proteus:scope-note',
        value: 'Declared top-level components only; production release requires a build-derived dependency SBOM.',
      },
    ],
    // timestamp is set by CI; omitted here to keep the doc reproducible.
  },
  components: components.map((c) => ({
    type: c.type, group: c.group, name: c.name, version: c.version,
    scope: c.scope,
    licenses: (c.licenses || []).map((id) => ({ license: { id } })),
    ...(c.comment ? { description: c.comment } : {}),
  })),
};

const asJson = process.argv.includes('--json');
if (asJson) {
  process.stdout.write(JSON.stringify(sbom, null, 2) + '\n');
} else {
  console.log('\n  Proteus component manifest stub (CycloneDX 1.5 shape)');
  console.log('  ⚠ NOT a production SBOM: declared top-level components only');
  console.log('  ' + '─'.repeat(58));
  for (const c of sbom.components) {
    const lic = c.licenses.map((l) => l.license.id).join(', ');
    console.log(`  ${c.group === 'proteus' ? '·' : '↳'} ${c.name.padEnd(30)} ${lic}`);
  }
  console.log('  ' + '─'.repeat(58));
  if (violations.length) {
    console.log('  ❌ DECLARED-MANIFEST LICENSE CHECK FAILED:');
    for (const v of violations) console.log(`     - ${v}`);
  } else {
    console.log('  ✅ declared-manifest license allow-list check passed');
  }
  console.log('  Run with --json for the machine-readable manifest stub.\n');
}

process.exit(violations.length === 0 ? 0 : 1);
