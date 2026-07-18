#!/usr/bin/env node
// Authoritative local gate for M1A: deterministic signed Profile Config core.
// This gate deliberately does not claim native Chromium M1 completion.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, '..');
const results = [];

function command(program, args, { capture = false } = {}) {
  try {
    const output = execFileSync(program, args, {
      cwd: REPO,
      stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'ignore',
    });
    return { ok: true, output: output?.toString() || '' };
  } catch (error) {
    return {
      ok: false,
      output: (error.stdout || '').toString() + (error.stderr || '').toString(),
      detail: [error.code, error.status != null ? `status=${error.status}` : null]
        .filter(Boolean).join(', '),
    };
  }
}

function check(label, run) {
  try {
    const result = run();
    results.push({ label, ok: result.ok, detail: result.detail || '' });
  } catch (error) {
    results.push({ label, ok: false, detail: error.message.split('\n')[0] });
  }
}

check('Rust formatting is stable', () => {
  const result = command('cargo', [
    'fmt', '--manifest-path', 'fingerprint/Cargo.toml', '--', '--check',
  ]);
  return { ok: result.ok, detail: result.ok ? 'cargo fmt --check' : result.detail };
});

check('Rust generator/signature/property tests pass', () => {
  const result = command('cargo', [
    'test', '--manifest-path', 'fingerprint/Cargo.toml', '--locked',
  ]);
  return { ok: result.ok, detail: result.ok ? 'Rust integration suite + doc tests' : result.detail };
});

check('Rust Clippy is warning-free', () => {
  const result = command('cargo', [
    'clippy', '--manifest-path', 'fingerprint/Cargo.toml', '--locked',
    '--all-targets', '--', '-D', 'warnings',
  ]);
  return { ok: result.ok, detail: result.ok ? 'all targets, -D warnings' : result.detail };
});

check('normative schema defines the signed M1A contract', () => {
  const schema = JSON.parse(readFileSync(
    join(REPO, 'docs', 'schemas', 'profile-config.schema.json'),
    'utf8',
  ));
  const signature = schema.properties?.signature;
  const required = new Set(schema.required || []);
  const gpuRequired = new Set(schema.properties?.gpu?.required || []);
  const noiseRequired = new Set(schema.properties?.noise?.required || []);
  const provenanceRequired =
    new Set(schema.properties?.provenance?.required || []);
  const ok = schema.properties?.schemaVersion?.const === '1.0.0'
    && signature?.properties?.algorithm?.const === 'Ed25519'
    && signature?.properties?.canonicalization?.const === 'RFC8785'
    && signature?.properties?.domain?.const === 'proteus-profile-config/v1'
    && ['media', 'performance', 'network', 'rarity', 'provenance', 'signature']
      .every((field) => required.has(field))
    && ['webglExtensions', 'webgpuAdapter']
      .every((field) => gpuRequired.has(field))
    && noiseRequired.has('clientRects')
    && provenanceRequired.has('datasetSha256');
  return { ok, detail: ok ? 'strict envelope + complete generated fields' : 'schema contract incomplete' };
});

check('shared dataset and rule versions match golden provenance', () => {
  const datasetBytes = readFileSync(join(REPO, 'verify-lab', 'data', 'reference.json'));
  const dataset = JSON.parse(datasetBytes);
  const golden = JSON.parse(readFileSync(goldenPath(), 'utf8'));
  const datasetSha256 = createHash('sha256').update(datasetBytes).digest('hex');
  const ok = dataset._version === golden.provenance.datasetVersion
    && dataset._rulesVersion === golden.provenance.rulesVersion
    && datasetSha256 === golden.provenance.datasetSha256;
  return {
    ok,
    detail: `${dataset._version} / rules ${dataset._rulesVersion} / sha256:${datasetSha256.slice(0, 12)}…`,
  };
});

check('CLI generation is byte-value deterministic against the golden config', () => {
  const result = command('cargo', [
    'run', '--quiet', '--locked', '--manifest-path', 'fingerprint/Cargo.toml', '--',
    'generate',
    '--request', 'fingerprint/fixtures/request-windows-chrome.json',
    '--dataset', 'verify-lab/data/reference.json',
    '--signing-key', 'fingerprint/fixtures/test-signing-key.json',
  ], { capture: true });
  if (!result.ok) return { ok: false, detail: result.detail || 'CLI generation failed' };
  const actual = JSON.parse(result.output);
  const expected = JSON.parse(readFileSync(goldenPath(), 'utf8'));
  return {
    ok: isDeepStrictEqual(actual, expected),
    detail: isDeepStrictEqual(actual, expected) ? 'generated JSON equals committed golden value' : 'golden drift',
  };
});

check('CLI fail-closed reload verifies signature and semantics', () => {
  const result = command('cargo', [
    'run', '--quiet', '--locked', '--manifest-path', 'fingerprint/Cargo.toml', '--',
    'verify',
    '--config', 'fingerprint/conformance/v2/golden/windows-chrome-us.signed.json',
    '--dataset', 'verify-lab/data/reference.json',
    '--trust-store', 'fingerprint/fixtures/test-trust-store.json',
  ], { capture: true });
  if (!result.ok) return { ok: false, detail: result.detail || 'CLI verification failed' };
  const report = JSON.parse(result.output);
  return { ok: report.valid === true && report.issues?.length === 0, detail: 'signature + strict semantic report' };
});

check('independent Node rules and Ed25519 conformance pass', () => {
  const result = command('node', ['verify-lab/test/run-tests.mjs']);
  return {
    ok: result.ok,
    detail: result.ok ? 'Node canonical hash, signature, tamper, V1/V2 checks' : result.detail,
  };
});

console.log('\n  ══════════════════════════════════════════════════════════════');
console.log('   Proteus — M1A signed-config core exit criteria');
console.log('  ══════════════════════════════════════════════════════════════\n');
for (const result of results) {
  console.log(`   ${result.ok ? '✅' : '❌'} ${result.label}`);
  if (result.detail) console.log(`        ${result.detail}`);
}
const passed = results.filter((result) => result.ok).length;
const allOk = passed === results.length;
console.log('\n  ' + '─'.repeat(62));
console.log(`   ${passed}/${results.length} criteria met`);
console.log(allOk
  ? '   ✅ M1A COMPLETE — deterministic signed-config core is independently verified.'
  : '   ❌ M1A NOT COMPLETE — see failures above.');
console.log('   ℹ️  Native Chromium M1 remains unclaimed: patches/build/runtime contexts are pending.');
console.log('  ' + '─'.repeat(62) + '\n');
process.exit(allOk ? 0 : 1);

function goldenPath() {
  return join(
    REPO,
    'fingerprint',
    'conformance',
    'v2',
    'golden',
    'windows-chrome-us.signed.json',
  );
}
