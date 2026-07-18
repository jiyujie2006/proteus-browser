// Integration tests beyond the fixture self-test:
//  1. Every fixture and the schema example validate against the profile-config
//     JSON Schema (structurally — a tiny built-in validator, no deps), proving the
//     lab and the schema (docs/schemas) agree.
//  2. The reference data is internally consistent (reverse maps line up).
//
// Run: node test/run-tests.mjs

import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { loadReference } from '../src/reference.mjs';
import { runM1AConformanceTests } from './m1a-conformance.mjs';
import { runP0RegressionTests } from './p0-regressions.mjs';
import { runStaticServerSecurityTests } from './static-server-security.mjs';
import { runLiveHarnessSecurityTests } from './live-harness-security.mjs';
import { parseDriveOptions } from '../src/drive-options.mjs';
import {
  assertLinuxSandboxMetadata,
  validateLinuxSandbox,
} from '../src/linux-sandbox.mjs';
import {
  auditNetworkTimeNetLog,
  readNetworkTimeAuditFile,
  validateNetworkTimeAudit,
} from '../src/network-time-audit.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const REPO = join(ROOT, '..');

let failures = 0;
const assert = (cond, msg) => { if (!cond) { console.log(`  ❌ ${msg}`); failures++; } else { console.log(`  ✅ ${msg}`); } };

// Build a schema-conformant profile config from a fixture (strip _meta + runtime-only fields).
function fixtureToConfig(fx) {
  const cfg = {};
  for (const [k, v] of Object.entries(fx)) {
    if (k.startsWith('_')) continue;
    if (['traces', 'network', 'automation', 'context'].includes(k)) continue; // runtime observations, not config
    cfg[k] = v;
  }
  // The schema requires seed/noise/provenance/signature; fixtures omit them for
  // brevity (they're not needed to score). Add schema-valid placeholders so the
  // structural validation is meaningful for the fields fixtures DO carry.
  cfg.seed = cfg.seed || Buffer.alloc(32).toString('base64');
  if (cfg.persona?.device) cfg.persona.device.model ??= null;
  if (cfg.navigator) cfg.navigator.oscpu ??= null;
  if (cfg.clientHints && typeof cfg.clientHints === 'object') {
    cfg.clientHints.platformVersion ??= '0.0.0';
    cfg.clientHints.architecture ??= cfg.persona?.os?.arch === 'arm64' ? 'arm' : 'x86';
    cfg.clientHints.bitness ??= cfg.persona?.os?.arch === 'x86' ? '32' : '64';
    cfg.clientHints.model ??= cfg.persona?.device?.model || '';
  }
  if (cfg.gpu?.webgpuAdapter && typeof cfg.gpu.webgpuAdapter === 'object') {
    cfg.gpu.webgpuAdapter.family ??= cfg.gpu.webgpuAdapter.vendor || 'unknown';
    cfg.gpu.webgpuAdapter.architecture ??= 'fixture-architecture';
    cfg.gpu.webgpuAdapter.device ??= 'fixture-device';
    cfg.gpu.webgpuAdapter.description ??= 'fixture adapter';
  }
  if (cfg.gpu) {
    cfg.gpu.webglExtensions ??= [];
    cfg.gpu.webgpuAdapter ??= null;
  }
  cfg.noise = cfg.noise || {
    canvas: { mode: 'perturb', amplitude: 'hw-natural' },
    webgl: { mode: 'perturb', amplitude: 'hw-natural' },
    audio: { mode: 'perturb', amplitude: 'hw-natural' },
    clientRects: { mode: 'subpixel' },
  };
  cfg.media = cfg.media || {
    profileId: 'fixture-placeholder',
    devices: [{ kind: 'audioinput', label: '', deviceId: 'fixture-device', groupId: 'fixture-group' }],
    speechVoices: [{ name: 'Fixture Voice', lang: 'en-US', localService: true, default: true }],
  };
  cfg.performance = cfg.performance || { timerPrecisionMicros: 100 };
  cfg.network = cfg.network || { quicPolicy: 'match-brand', webrtcPolicy: 'proxy-only' };
  cfg.rarity = cfg.rarity || { score: 1, verdict: 'blends-in', reasons: [] };
  cfg.provenance = cfg.provenance || {
    datasetVersion: '0.3.0',
    datasetSha256: '0'.repeat(64),
    engineVersion: '150.0.7871.124',
    rulesVersion: '1.1.0',
    generatorVersion: '0.2.0',
  };
  cfg.signature = cfg.signature || {
    algorithm: 'Ed25519',
    canonicalization: 'RFC8785',
    domain: 'proteus-profile-config/v1',
    keyId: 'fixture-key',
    value: Buffer.alloc(64).toString('base64'),
  };
  return cfg;
}

console.log('\n  Integration tests');
console.log('  ' + '─'.repeat(58));

const schema = JSON.parse(readFileSync(join(REPO, 'docs', 'schemas', 'profile-config.schema.json'), 'utf8'));
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  validateFormats: true,
});
addFormats(ajv, ['uuid']);
const validateProfileConfig = ajv.compile(schema);

const boundDriveOptions = parseDriveOptions(
  [
    '--json',
    '--external-containment',
    '--chrome',
    '/build/chrome',
    '--platform',
    'linux-x64',
    '--linux-sandbox',
    '/usr/local/lib/proteus-m0/chrome_sandbox',
  ],
  { defaultChrome: '/installed/stock-chrome' },
);
assert(
  boundDriveOptions.chrome === boundDriveOptions.artifactPath,
  'machine report hashes the exact executable launched by the live harness',
);
assert(
  boundDriveOptions.linuxSandbox
    === '/usr/local/lib/proteus-m0/chrome_sandbox',
  'Linux machine report binds an explicit controlled setuid sandbox',
);
let missingExternalContainmentRejected = false;
try {
  parseDriveOptions(
    ['--json', '--chrome', '/build/chrome', '--platform', 'linux-x64'],
    { defaultChrome: '/installed/stock-chrome' },
  );
} catch (error) {
  missingExternalContainmentRejected =
    error.message.includes('--external-containment');
}
assert(
  missingExternalContainmentRejected,
  'machine report requires externally enforced ephemeral-runner containment',
);
let missingLinuxSandboxRejected = false;
try {
  parseDriveOptions(
    [
      '--json',
      '--external-containment',
      '--chrome',
      '/build/chrome',
      '--platform',
      'linux-x64',
    ],
    { defaultChrome: '/installed/stock-chrome' },
  );
} catch (error) {
  missingLinuxSandboxRejected = error.message.includes('--linux-sandbox');
}
assert(
  missingLinuxSandboxRejected,
  'Linux machine report requires an explicit controlled setuid sandbox',
);
let sandboxOnWrongPlatformRejected = false;
try {
  parseDriveOptions(
    [
      '--json',
      '--external-containment',
      '--chrome',
      '/build/chrome',
      '--platform',
      'macos-universal',
      '--linux-sandbox',
      '/usr/local/lib/proteus-m0/chrome_sandbox',
    ],
    { defaultChrome: '/installed/stock-chrome' },
  );
} catch (error) {
  sandboxOnWrongPlatformRejected =
    error.message.includes('only valid with --platform linux-x64');
}
assert(
  sandboxOnWrongPlatformRejected,
  'non-Linux machine reports reject the Linux sandbox claim',
);
const safeSandboxStat = {
  isFile: () => true,
  isSymbolicLink: () => false,
  mode: 0o104755n,
  uid: 0n,
};
let unsafeSandboxOwnerRejected = false;
try {
  assertLinuxSandboxMetadata('/sandbox', {
    ...safeSandboxStat,
    uid: 1000n,
  });
} catch (error) {
  unsafeSandboxOwnerRejected = error.message.includes('owned by uid 0');
}
assert(
  unsafeSandboxOwnerRejected,
  'Linux sandbox validation rejects non-root ownership',
);
let unsafeSandboxModeRejected = false;
try {
  assertLinuxSandboxMetadata('/sandbox', {
    ...safeSandboxStat,
    mode: 0o100755n,
  });
} catch (error) {
  unsafeSandboxModeRejected = error.message.includes('exact mode 4755');
}
assert(
  unsafeSandboxModeRejected,
  'Linux sandbox validation rejects missing or excessive permission bits',
);
assertLinuxSandboxMetadata('/sandbox', safeSandboxStat);
assert(true, 'Linux sandbox validation accepts only root-owned mode-4755 files');
let nonCanonicalSandboxRejected = false;
try {
  validateLinuxSandbox('/sandbox', {
    lstat: () => ({
      ...safeSandboxStat,
      dev: 1n,
      ino: 2n,
    }),
    realpath: () => '/real/sandbox',
  });
} catch (error) {
  nonCanonicalSandboxRejected = error.message.includes('canonical path');
}
assert(
  nonCanonicalSandboxRejected,
  'Linux sandbox validation rejects symlinked path components',
);
let reboundSandboxRejected = false;
let sandboxStatCalls = 0;
try {
  validateLinuxSandbox('/sandbox', {
    lstat: () => ({
      ...safeSandboxStat,
      dev: 1n,
      ino: BigInt(++sandboxStatCalls),
    }),
    realpath: (path) => path,
  });
} catch (error) {
  reboundSandboxRejected = error.message.includes('changed while');
}
assert(
  reboundSandboxRejected,
  'Linux sandbox validation rejects path rebinding during validation',
);
const cleanNetworkTimeAudit = auditNetworkTimeNetLog({
  events: [{
    type: 1,
    params: { url: 'http://127.0.0.1/controlled-probe' },
  }],
});
assert(
  validateNetworkTimeAudit(cleanNetworkTimeAudit).defaultQueryAbsent === true,
  'Network Time audit accepts a non-empty NetLog without the Google time endpoint',
);
const leakingNetworkTimeAudit = auditNetworkTimeNetLog({
  events: [{
    type: 2,
    params: {
      host: 'clients2.google.com',
      path: '/time/1/current?cup2key=fixture',
    },
  }],
});
let networkTimeLeakRejected = false;
try {
  validateNetworkTimeAudit(leakingNetworkTimeAudit);
} catch (error) {
  networkTimeLeakRejected = error.message.includes('endpoint was absent');
}
assert(
  networkTimeLeakRejected,
  'Network Time audit rejects a NetLog containing the Google time endpoint',
);
const networkTimeFixtureRoot = mkdtempSync(join(tmpdir(), 'proteus-netlog-test-'));
try {
  const netLogPath = join(networkTimeFixtureRoot, 'netlog.json');
  writeFileSync(netLogPath, JSON.stringify({
    events: [{
      type: 1,
      params: { url: 'http://127.0.0.1/controlled-probe' },
    }],
  }));
  assert(
    readNetworkTimeAuditFile(netLogPath, { maxBytes: 1024 })
      .defaultQueryAbsent === true,
    'Network Time audit reads one stable bounded NetLog file descriptor',
  );
  writeFileSync(netLogPath, '{"events":[],"events":[]}');
  let duplicateNetLogRejected = false;
  try {
    readNetworkTimeAuditFile(netLogPath, { maxBytes: 1024 });
  } catch (error) {
    duplicateNetLogRejected = error.message.includes('duplicate object key');
  }
  assert(
    duplicateNetLogRejected,
    'Network Time audit rejects ambiguous duplicate NetLog keys',
  );
  writeFileSync(netLogPath, JSON.stringify({
    events: [{ params: { padding: 'x'.repeat(128) } }],
  }));
  let oversizedNetLogRejected = false;
  try {
    readNetworkTimeAuditFile(netLogPath, { maxBytes: 32 });
  } catch (error) {
    oversizedNetLogRejected = error.message.includes('size must be');
  }
  assert(
    oversizedNetLogRejected,
    'Network Time audit rejects a NetLog beyond its byte bound',
  );
  const targetPath = join(networkTimeFixtureRoot, 'target.json');
  const symlinkPath = join(networkTimeFixtureRoot, 'netlog-link.json');
  writeFileSync(targetPath, JSON.stringify({ events: [{ type: 1 }] }));
  try {
    symlinkSync(targetPath, symlinkPath);
    let symlinkNetLogRejected = false;
    try {
      readNetworkTimeAuditFile(symlinkPath, { maxBytes: 1024 });
    } catch (error) {
      symlinkNetLogRejected = error.message.includes('non-symlink');
    }
    assert(
      symlinkNetLogRejected,
      'Network Time audit rejects a symlinked NetLog path',
    );
  } catch (error) {
    assert(
      true,
      `Network Time symlink test skipped where creation is unavailable (${error.code})`,
    );
  }
} finally {
  rmSync(networkTimeFixtureRoot, { recursive: true, force: true });
}
let interactiveContainmentClaimRejected = false;
try {
  parseDriveOptions(
    ['--external-containment'],
    { defaultChrome: '/installed/stock-chrome' },
  );
} catch (error) {
  interactiveContainmentClaimRejected =
    error.message.includes('only valid with --json');
}
assert(
  interactiveContainmentClaimRejected,
  'interactive mode rejects a meaningless external-containment claim',
);
assert(
  parseDriveOptions([], { defaultChrome: '/installed/stock-chrome' }).url
    === 'http://127.0.0.1:8791/probe-page/headless.html',
  'interactive live harness defaults to the same IPv4 loopback host as its server',
);
let customMachineUrlRejected = false;
try {
  parseDriveOptions(
    [
      '--json',
      '--external-containment',
      '--chrome',
      '/build/chrome',
      '--platform',
      'linux-x64',
      '--url',
      'http://127.0.0.1:9999/fake.html',
    ],
    { defaultChrome: '/installed/stock-chrome' },
  );
} catch (error) {
  customMachineUrlRejected = error.message.includes('controlled probe');
}
assert(
  customMachineUrlRejected,
  'machine report rejects caller-selected probe URLs',
);
let splitArtifactRejected = false;
try {
  parseDriveOptions(
    [
      '--json',
      '--chrome',
      '/installed/stock-chrome',
      '--artifact',
      '/build/other-engine',
      '--platform',
      'linux-x64',
    ],
    { defaultChrome: '/installed/stock-chrome' },
  );
} catch (error) {
  splitArtifactRejected = error.message.includes('unknown argument: --artifact');
}
assert(
  splitArtifactRejected,
  'live report CLI rejects a separate unlaunched artifact path',
);
for (const unsafeChrome of ['chrome', './chrome']) {
  let rejected = false;
  try {
    parseDriveOptions(
      [
        '--json',
        '--external-containment',
        '--chrome',
        unsafeChrome,
        '--platform',
        'linux-x64',
      ],
      { defaultChrome: '/installed/stock-chrome' },
    );
  } catch (error) {
    rejected = error.message.includes('absolute engine-executable path');
  }
  assert(
    rejected,
    `machine report rejects non-absolute executable path "${unsafeChrome}"`,
  );
}

// Only the "good" fixtures are guaranteed schema-conformant (bad ones intentionally
// violate coherence, but should still be structurally valid JSON of the right shape).
const fixtureFiles = readdirSync(join(ROOT, 'fixtures')).filter((f) => f.endsWith('.json'));
for (const f of fixtureFiles) {
  const fx = JSON.parse(readFileSync(join(ROOT, 'fixtures', f), 'utf8'));
  const cfg = fixtureToConfig(fx);
  const valid = validateProfileConfig(cfg);
  const errs = validateProfileConfig.errors || [];
  assert(valid, `fixture ${f} is Draft 2020-12 schema-valid`
    + (errs.length
      ? `\n        └─ ${errs.slice(0, 3)
        .map((error) => `${error.instancePath || '$'} ${error.message}`)
        .join('\n        └─ ')}`
      : ''));
}

// Schema mutation corpus exercises deep keywords that the previous dependency-
// free subset validator could not check: const, format, pattern, minimum,
// nested required/$ref/items, additionalProperties, and allOf conditionals.
const golden = JSON.parse(readFileSync(
  join(
    REPO,
    'fingerprint',
    'conformance',
    'v1',
    'golden',
    'windows-chrome-us.signed.json',
  ),
  'utf8',
));
assert(validateProfileConfig(golden), 'golden signed config passes full Draft 2020-12 validation');

const schemaMutations = [
  ['unknown root fields', (value) => { value.unexpected = true; }],
  ['unknown schema revisions', (value) => { value.schemaVersion = '1.1.0'; }],
  ['malformed UUIDs', (value) => { value.profileId = 'not-a-uuid'; }],
  ['URN-prefixed UUIDs outside the Rust contract', (value) => {
    value.profileId = `urn:uuid:${value.profileId}`;
  }],
  ['short seed encodings', (value) => { value.seed = 'AAAA'; }],
  ['zero available screen width', (value) => { value.screen.availWidth = 0; }],
  ['missing WebGL extension arrays', (value) => { delete value.gpu.webglExtensions; }],
  ['missing clientRects policy', (value) => { delete value.noise.clientRects; }],
  ['omitted nullable device model', (value) => { delete value.persona.device.model; }],
  ['omitted nullable navigator oscpu', (value) => { delete value.navigator.oscpu; }],
  ['malformed dataset digests', (value) => { value.provenance.datasetSha256 = 'ABC'; }],
  ['malformed signature encodings', (value) => { value.signature.value = 'AAAA'; }],
  ['invalid key identifiers', (value) => { value.signature.keyId = 'bad key id'; }],
  ['missing nested media fields', (value) => { delete value.media.devices[0].kind; }],
  ['missing $ref brand fields', (value) => { delete value.clientHints.brands[0].version; }],
  ['Firefox/Client-Hints conditional mismatch', (value) => {
    value.engine.family = 'firefox';
    value.engine.brand = 'Firefox';
  }],
];
for (const [name, mutate] of schemaMutations) {
  const candidate = structuredClone(golden);
  mutate(candidate);
  assert(!validateProfileConfig(candidate), `full schema rejects ${name}`);
}

// ---- 2. Reference-data internal consistency ----
const ref = loadReference();

// Every timezone in timezoneToRegion should point to a region that exists in localeByRegion.
let tzOk = true;
for (const [tz, region] of Object.entries(ref.timezoneToRegion)) {
  if (tz.startsWith('_')) continue;
  if (!ref.localeByRegion[region]) { console.log(`        └─ ${tz} → ${region} not in localeByRegion`); tzOk = false; }
}
assert(tzOk, 'every timezoneToRegion entry maps to a known region');

// Every region's timezones should reverse-map back to that region.
let revOk = true;
for (const [region, info] of Object.entries(ref.localeByRegion)) {
  if (region.startsWith('_')) continue;
  for (const tz of info.timezones) {
    if (ref.timezoneToRegion[tz] !== region) { console.log(`        └─ ${tz} does not reverse-map to ${region}`); revOk = false; }
  }
}
assert(revOk, 'localeByRegion timezones reverse-map consistently');

// Every OS in gpuVendorFamiliesByOs has a platform token list.
let osOk = true;
for (const os of Object.keys(ref.gpuVendorFamiliesByOs)) {
  if (os.startsWith('_')) continue;
  if (!ref.platformByOs[os]) { console.log(`        └─ ${os} missing from platformByOs`); osOk = false; }
}
assert(osOk, 'every OS with a GPU-family list has platform tokens');

// ---- 3. P0 scoring/rule/normalization regressions ----
runP0RegressionTests(assert, ref);

// ---- 4. Rust generator ↔ independent Node verifier conformance ----
runM1AConformanceTests(assert, ref);

// ---- 5. Local static-server boundary regressions ----
runStaticServerSecurityTests(assert);

// ---- 6. Process-bound live harness and controlled probe regressions ----
await runLiveHarnessSecurityTests(assert);

console.log('  ' + '─'.repeat(58));
console.log(`  ${failures === 0 ? 'all integration tests passed' : failures + ' FAILED'}\n`);
process.exit(failures === 0 ? 0 : 1);
