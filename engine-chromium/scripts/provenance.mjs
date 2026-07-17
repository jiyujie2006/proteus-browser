#!/usr/bin/env node
// provenance.mjs — generate the reproducible-build manifest + SLSA-style
// provenance document for a Proteus engine artifact (docs/tdd/05 §5, Principle VI).
//
// With an explicit --demo it emits a document for a deterministic placeholder so
// the shape is reviewable without a build. Production use must provide a real,
// ordinary file with --artifact <path>; missing or invalid inputs fail closed.
//
// The provenance answers "can I trust this binary?" with a checkable document,
// not a promise: it records the exact source tag, patch-series hash, toolchain,
// build args, and artifact digest, so an independent rebuilder can reproduce and
// compare.

import { createReadStream, existsSync, lstatSync, readFileSync, writeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { basename, dirname, join } from 'node:path';
import { execSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const REPO = join(ROOT, '..');
const TARGET_ARCHITECTURES = {
  'windows-x64': ['x86_64'],
  'macos-universal': ['x86_64', 'arm64'],
  'linux-x64': ['x86_64'],
};

function usage() {
  return `usage: ${basename(process.argv[1])} (--artifact <file> --chromium-commit <hex> --platform <id> --invocation-id <id> | --demo)`;
}

function fail(message) {
  writeSync(process.stderr.fd, `ERROR: ${message}\n${usage()}\n`);
  process.exit(2);
}

function parseArgs(args) {
  let demo = false;
  let artifactPath = null;
  let chromiumCommit = null;
  let platform = null;
  let invocationId = null;

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--demo') {
      if (demo) fail('--demo may only be supplied once');
      demo = true;
      continue;
    }
    if (arg === '--artifact') {
      if (artifactPath !== null) fail('--artifact may only be supplied once');
      const value = args[i + 1];
      if (!value || value.startsWith('--')) fail('--artifact requires a file path');
      artifactPath = value;
      i += 1;
      continue;
    }
    if (arg === '--chromium-commit') {
      if (chromiumCommit !== null) fail('--chromium-commit may only be supplied once');
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        fail('--chromium-commit requires a full commit digest');
      }
      chromiumCommit = value;
      i += 1;
      continue;
    }
    if (arg === '--platform' || arg === '--invocation-id') {
      const current = arg === '--platform' ? platform : invocationId;
      if (current !== null) fail(`${arg} may only be supplied once`);
      const value = args[i + 1];
      if (!value || value.startsWith('--')) fail(`${arg} requires a value`);
      if (arg === '--platform') platform = value;
      else invocationId = value;
      i += 1;
      continue;
    }
    fail(`unknown argument: ${arg}`);
  }

  if (demo && (
    artifactPath !== null
    || chromiumCommit !== null
    || platform !== null
    || invocationId !== null
  )) {
    fail('--demo is mutually exclusive with artifact/commit inputs');
  }
  if (!demo && artifactPath === null) {
    fail('no artifact supplied; use --artifact <file>, or opt into scaffold output with --demo');
  }
  if (!demo && chromiumCommit === null) {
    fail('production provenance requires --chromium-commit <full-hex-digest>');
  }
  if (!demo && !['windows-x64', 'macos-universal', 'linux-x64'].includes(platform)) {
    fail('production provenance requires a supported --platform id');
  }
  if (!demo && (invocationId === null || !/^[A-Za-z0-9._:-]{1,160}$/.test(invocationId))) {
    fail('production provenance requires a safe --invocation-id');
  }
  if (chromiumCommit !== null
      && !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(chromiumCommit)) {
    fail('--chromium-commit must be a lowercase 40- or 64-hex digest');
  }

  return { demo, artifactPath, chromiumCommit, platform, invocationId };
}

function readBaseline() {
  const raw = readFileSync(join(ROOT, 'CHROMIUM_BASELINE'), 'utf8');
  const out = {};
  for (const line of raw.split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

// Hash the patch series deterministically: concat sorted patch file contents.
function patchSeriesHash() {
  const series = readFileSync(join(ROOT, 'patches', 'series'), 'utf8')
    .split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  const h = createHash('sha256');
  for (const rel of series) {
    const p = join(ROOT, 'patches', rel);
    h.update(rel + '\0');
    if (existsSync(p)) h.update(readFileSync(p));
  }
  return 'sha256:' + h.digest('hex');
}

function sha256File(path) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const input = createReadStream(path);
    input.on('data', (chunk) => hash.update(chunk));
    input.on('error', reject);
    input.on('end', () => resolve(hash.digest('hex')));
  });
}

function toolchainInfo() {
  // On the farm these are pinned; here we record what we can observe.
  const info = { node: process.version, platform: process.platform, arch: process.arch };
  try { info.git = execSync('git --version', { cwd: REPO }).toString().trim(); } catch (_) {}
  return info;
}

const baseline = readBaseline();
const {
  demo,
  artifactPath,
  chromiumCommit,
  platform,
  invocationId,
} = parseArgs(process.argv.slice(2));

let artifact;
if (artifactPath !== null) {
  if (!existsSync(artifactPath)) {
    fail(`artifact does not exist: ${artifactPath}`);
  }

  let artifactStat;
  try {
    artifactStat = lstatSync(artifactPath);
  } catch (error) {
    fail(`cannot inspect artifact ${artifactPath}: ${error.message}`);
  }
  if (!artifactStat.isFile()) {
    fail(`artifact is not an ordinary file: ${artifactPath}`);
  }

  let digest;
  try {
    digest = await sha256File(artifactPath);
  } catch (error) {
    fail(`cannot read artifact ${artifactPath}: ${error.message}`);
  }
  artifact = {
    name: basename(artifactPath),
    digest: { sha256: digest },
    annotations: {
      'https://proteus.example/artifact-kind': 'file',
      'https://proteus.example/size-bytes': String(artifactStat.size),
    },
    real: true,
  };
} else {
  // Explicit scaffold mode uses a deterministic sentinel, never an invented
  // digest for a binary that was not built.
  const sentinel = Buffer.from('Proteus provenance demo: no artifact\n', 'utf8');
  artifact = {
    name: `proteus-chromium-${baseline.CHROMIUM_STABLE}-${process.platform}-${process.arch}.demo`,
    digest: { sha256: createHash('sha256').update(sentinel).digest('hex') },
    annotations: {
      'https://proteus.example/artifact-kind': 'demo-placeholder',
      'https://proteus.example/size-bytes': String(sentinel.length),
    },
    real: false,
  };
}

// SLSA-provenance-shaped document (in-toto statement style). Not a full SLSA
// generator (that runs in CI on the farm), but the same fields, so it is a real
// skeleton, not a mock.
const provenance = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{
    name: artifact.name,
    digest: artifact.digest,
    annotations: artifact.annotations,
  }],
  predicateType: 'https://slsa.dev/provenance/v1',
  predicate: {
    buildDefinition: {
      buildType: 'https://proteus.example/buildtypes/chromium-engine/v1',
      externalParameters: {
        chromiumTag: baseline.CHROMIUM_STABLE,
        channel: baseline.CHANNEL,
        milestone: baseline.MILESTONE,
        gnArgs: 'engine-chromium/build/args.gn',
        gnArgsSha256: `sha256:${createHash('sha256')
          .update(readFileSync(join(ROOT, 'build', 'args.gn')))
          .digest('hex')}`,
      },
      internalParameters: {
        patchSeriesHash: patchSeriesHash(),
        toolchain: toolchainInfo(),
        targetArchitectures: artifact.real
          ? TARGET_ARCHITECTURES[platform]
          : [process.arch === 'x64' ? 'x86_64' : process.arch],
      },
      resolvedDependencies: [
        {
          uri: 'https://chromium.googlesource.com/chromium/src',
          digest: artifact.real
            ? { gitCommit: chromiumCommit }
            : { gitTag: baseline.CHROMIUM_STABLE },
        },
        { uri: 'https://github.com/ungoogled-software/ungoogled-chromium', comment: 'layer0 patch methodology' },
      ],
    },
    runDetails: {
      builder: {
        id: artifact.real
          ? `https://proteus.example/builders/${platform}/v1`
          : 'https://proteus.example/builders/demo/v1',
      },
      metadata: {
        // On the farm: real invocation id + timestamps. Omitted here (no Date in a
        // reproducible doc) — filled by the CI provenance generator.
        invocationId: artifact.real ? invocationId : 'demo',
      },
      byproducts: [
        { name: 'sbom', comment: 'engine-chromium/scripts/sbom.mjs output attached at release' },
        { name: 'verify-lab-report', comment: 'VERIFY gate result attached at release (tdd/06)' },
      ],
    },
  },
  _proteusNotes: {
    reproducibility: 'bit-for-bit target via build/args.gn (strip paths, no timestamps, pinned toolchain, thin-LTO).',
    verification: 'An independent party rebuilds with the same chromiumTag + patchSeriesHash + gnArgs and compares subject.digest.',
    principle: 'VI — trust the binary, verifiably. This document is the check anyone can run.',
    m0Status: artifact.real
      ? 'real ordinary-file artifact hashed'
      : 'DEMO ONLY — subject hashes a documented sentinel, not a built artifact',
  },
};

writeSync(process.stdout.fd, JSON.stringify(provenance, null, 2) + '\n');
if (demo) {
  writeSync(process.stderr.fd, '\n(demo provenance — subject is a deterministic sentinel, not a built artifact)\n');
}
