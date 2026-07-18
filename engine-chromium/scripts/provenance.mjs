#!/usr/bin/env node
// provenance.mjs — generate the reproducible-build manifest + SLSA-style
// provenance document for a Proteus engine artifact (docs/tdd/05 §5, Principle VI).
//
// With an explicit --demo it emits a document for a deterministic placeholder so
// the shape is reviewable without a build. Production use must provide a real,
// ordinary file with --artifact <path>; missing or invalid inputs fail closed.
//
// The provenance answers "can I trust this binary?" with a checkable document,
// not a promise: it records the exact source tag, active patch-series hash, toolchain,
// build args, and artifact digest, so an independent rebuilder can reproduce and
// compare.

import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  writeSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { basename, dirname, join } from 'node:path';
import { execSync } from 'node:child_process';
import { readChromiumBaseline } from './baseline.mjs';
import { activePatchSeriesSha256 } from './patch-series.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const REPO = join(ROOT, '..');
const TARGET_ARCHITECTURES = {
  'windows-x64': ['x86_64'],
  'macos-universal': ['x86_64', 'arm64'],
  'linux-x64': ['x86_64'],
};

function usage() {
  return `usage: ${basename(process.argv[1])} (--artifact <file> --effective-gn-args <file> --chromium-commit <hex> --platform <id> --invocation-id <id> | --demo)`;
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
  let effectiveGnArgs = null;

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
    if (arg === '--effective-gn-args') {
      if (effectiveGnArgs !== null) {
        fail('--effective-gn-args may only be supplied once');
      }
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        fail('--effective-gn-args requires a file path');
      }
      effectiveGnArgs = value;
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
    || effectiveGnArgs !== null
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
  if (!demo && effectiveGnArgs === null) {
    fail('production provenance requires --effective-gn-args <file>');
  }
  if (!demo && !['windows-x64', 'macos-universal', 'linux-x64'].includes(platform)) {
    fail('production provenance requires a supported --platform id');
  }
  if (!demo && (invocationId === null || !/^[A-Za-z0-9._:-]{1,160}$/.test(invocationId))) {
    fail('production provenance requires a safe --invocation-id');
  }
  if (chromiumCommit !== null
      && !/^[0-9a-f]{40}$/.test(chromiumCommit)) {
    fail('--chromium-commit must be a lowercase 40-hex digest');
  }

  return {
    demo,
    artifactPath,
    chromiumCommit,
    effectiveGnArgs,
    platform,
    invocationId,
  };
}

function hashStableOrdinaryFile(path, label, maxBytes) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new TypeError(`${label} is not an ordinary non-symlink file`);
  }
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  const hash = createHash('sha256');
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameStableFile(before, opened)) {
      throw new TypeError(`${label} changed while it was opened`);
    }
    if (opened.size > BigInt(maxBytes)) {
      throw new TypeError(`${label} exceeds ${maxBytes} bytes`);
    }
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const count = readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
    }
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    if (!sameStableFile(opened, after) || !sameStableFile(after, pathAfter)) {
      throw new TypeError(`${label} changed or was rebound while hashing`);
    }
    return { sha256: hash.digest('hex'), size: opened.size };
  } finally {
    closeSync(fd);
  }
}

function sameStableFile(left, right) {
  return left.isFile()
    && right.isFile()
    && left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function toolchainInfo() {
  // On the farm these are pinned; here we record what we can observe.
  const info = { node: process.version, platform: process.platform, arch: process.arch };
  try { info.git = execSync('git --version', { cwd: REPO }).toString().trim(); } catch (_) {}
  return info;
}

const baseline = readChromiumBaseline(join(ROOT, 'CHROMIUM_BASELINE'));
const gnArgsTemplateSnapshot = hashStableOrdinaryFile(
  join(ROOT, 'build', 'args.gn'),
  'GN args template',
  1024 * 1024,
);
const {
  demo,
  artifactPath,
  chromiumCommit,
  effectiveGnArgs,
  platform,
  invocationId,
} = parseArgs(process.argv.slice(2));
if (!demo && chromiumCommit !== baseline.CHROMIUM_COMMIT) {
  fail(
    `--chromium-commit must equal pinned baseline commit ${baseline.CHROMIUM_COMMIT}`,
  );
}
let effectiveGnArgsSnapshot = gnArgsTemplateSnapshot;
if (!demo) {
  if (!existsSync(effectiveGnArgs)) {
    fail(`effective GN args do not exist: ${effectiveGnArgs}`);
  }
  try {
    effectiveGnArgsSnapshot = hashStableOrdinaryFile(
      effectiveGnArgs,
      'effective GN args',
      1024 * 1024,
    );
  } catch (error) {
    fail(`cannot hash effective GN args ${effectiveGnArgs}: ${error.message}`);
  }
}

let artifact;
if (artifactPath !== null) {
  if (!existsSync(artifactPath)) {
    fail(`artifact does not exist: ${artifactPath}`);
  }

  let artifactSnapshot;
  try {
    artifactSnapshot = hashStableOrdinaryFile(
      artifactPath,
      'artifact',
      16 * 1024 * 1024 * 1024,
    );
  } catch (error) {
    fail(`cannot hash artifact ${artifactPath}: ${error.message}`);
  }
  artifact = {
    name: basename(artifactPath),
    digest: { sha256: artifactSnapshot.sha256 },
    annotations: {
      'https://proteus.example/artifact-kind': 'file',
      'https://proteus.example/size-bytes': String(artifactSnapshot.size),
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
        gnArgsTemplate: 'engine-chromium/build/args.gn',
        gnArgsTemplateSha256: `sha256:${gnArgsTemplateSnapshot.sha256}`,
        effectiveGnArgs: artifact.real
          ? basename(effectiveGnArgs)
          : 'demo:engine-chromium/build/args.gn',
        effectiveGnArgsSha256: `sha256:${effectiveGnArgsSnapshot.sha256}`,
      },
      internalParameters: {
        patchProfile: baseline.PATCH_PROFILE,
        patchSeriesHash:
          `sha256:${activePatchSeriesSha256(ROOT, baseline.PATCH_PROFILE)}`,
        depotToolsCommit: baseline.DEPOT_TOOLS_COMMIT,
        toolchain: toolchainInfo(),
        targetArchitectures: artifact.real
          ? TARGET_ARCHITECTURES[platform]
          : [process.arch === 'x64' ? 'x86_64' : process.arch],
      },
      resolvedDependencies: [
        {
          uri: 'https://chromium.googlesource.com/chromium/src',
          digest: { gitCommit: artifact.real ? chromiumCommit : baseline.CHROMIUM_COMMIT },
        },
        {
          uri: 'https://chromium.googlesource.com/chromium/tools/depot_tools',
          digest: { gitCommit: baseline.DEPOT_TOOLS_COMMIT },
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
