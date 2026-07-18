#!/usr/bin/env node
// sbom.mjs — emit a CycloneDX-shaped repository component-manifest stub.
// This inventory names first-party components plus the narrow third-party
// source context present in this repository. It is NOT a production SBOM or
// redistribution-compliance decision. A release must derive its full inventory
// from sources, build graphs, and packaged bytes.

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const components = [
  {
    type: 'library',
    name: 'proteus-fingerprint',
    licenses: ['Apache-2.0'],
    group: 'proteus',
    scope: 'required',
    comment: 'Implemented deterministic signed-config core.',
  },
  {
    type: 'application',
    name: 'proteus-verify-lab',
    licenses: ['Apache-2.0'],
    group: 'proteus',
    scope: 'required',
    comment: 'Implemented local verification ruler and live-drive harness.',
  },
  {
    type: 'application',
    name: 'proteus-chromium-scaffold',
    licenses: ['Apache-2.0'],
    group: 'proteus',
    scope: 'required',
    comment: 'First-party patch/build/evidence scaffold; no Chromium checkout or binary.',
  },
  {
    type: 'application',
    name: 'proteus-repository-tooling',
    licenses: ['Apache-2.0'],
    group: 'proteus',
    scope: 'required',
    comment: 'Milestone gates, schemas, and repository automation.',
  },
  {
    type: 'library',
    name: 'chromium-network-time-source-context',
    version: '150.0.7871.124',
    licenses: ['BSD-3-Clause'],
    group: 'chromium',
    scope: 'required',
    hashes: [{
      alg: 'SHA-256',
      content: '704ad013d6af61138961ebe95b621c41be93738251ac6e8f5d997fe48881095d',
    }],
    comment: 'Pinned source context in the active M0 Network Time patch; not a Chromium checkout or binary.',
  },
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

const violations = [];
for (const c of components) {
  for (const lic of c.licenses || []) {
    const expected = c.group === 'chromium' ? 'BSD-3-Clause' : 'Apache-2.0';
    if (lic !== expected) {
      violations.push(`${c.name}: expected ${expected}, found ${lic}`);
    }
  }
}

const serialUuid = uuidV5(
  `https://proteus.example/manifests/repository-component-stub/v1#${JSON.stringify(components)}`,
);

const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${serialUuid}`,
  version: 1,
  metadata: {
    component: { type: 'application', name: 'proteus-source-tree', group: 'proteus' },
    properties: [
      { name: 'proteus:document-kind', value: 'repository-component-manifest-stub' },
      { name: 'proteus:build-derived', value: 'false' },
      {
        name: 'proteus:scope-note',
        value: 'Current repository components only, including the pinned Chromium diff context; excludes resolved packages, engine checkouts/binaries, and release artifacts.',
      },
      {
        name: 'proteus:compliance-note',
        value: 'Not redistribution approval; production releases require an artifact-derived SBOM and exact license/notice bundle.',
      },
    ],
    // timestamp is set by CI; omitted here to keep the doc reproducible.
  },
  components: components.map((c) => ({
    type: c.type, group: c.group, name: c.name, version: c.version,
    scope: c.scope,
    licenses: (c.licenses || []).map((id) => ({ license: { id } })),
    ...(c.hashes ? { hashes: c.hashes } : {}),
    ...(c.comment ? { description: c.comment } : {}),
  })),
};

const asJson = process.argv.includes('--json');
if (asJson) {
  process.stdout.write(JSON.stringify(sbom, null, 2) + '\n');
} else {
  console.log('\n  Proteus repository component manifest stub (CycloneDX 1.5 shape)');
  console.log('  ⚠ NOT a production SBOM: repository declarations plus pinned Chromium diff context only');
  console.log('  ' + '─'.repeat(58));
  for (const c of sbom.components) {
    const lic = c.licenses.map((l) => l.license.id).join(', ');
    console.log(`  · ${c.name.padEnd(30)} ${lic}`);
  }
  console.log('  ' + '─'.repeat(58));
  if (violations.length) {
    console.log('  ❌ DECLARED-MANIFEST LICENSE CHECK FAILED:');
    for (const v of violations) console.log(`     - ${v}`);
  } else {
    console.log('  ✅ repository component declarations are internally consistent');
  }
  console.log('  Run with --json for the machine-readable manifest stub.\n');
}

// Let Node drain captured stdout before exiting. Calling process.exit() here can
// truncate the larger JSON form when a parent process reads it through a pipe.
process.exitCode = violations.length === 0 ? 0 : 1;
