import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { normalize } from '../src/normalize.mjs';
import { RULES_VERSION } from '../src/rules.mjs';
import { score } from '../src/score.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, '..', '..');
const GOLDEN_PATH = join(
  REPO,
  'fingerprint',
  'conformance',
  'v2',
  'golden',
  'windows-chrome-us.signed.json',
);
const VECTOR_PATH = join(
  REPO,
  'fingerprint',
  'conformance',
  'v2',
  'signing-vector.json',
);
const DATASET_PATH = join(REPO, 'verify-lab', 'data', 'reference.json');
const CLI_PATH = join(REPO, 'verify-lab', 'bin', 'verify-lab.mjs');

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Independent Node conformance checks for the Rust-generated golden config.
 * This intentionally does not import Rust implementation details.
 */
export function runM1AConformanceTests(check, ref) {
  const signed = JSON.parse(readFileSync(GOLDEN_PATH, 'utf8'));
  const vector = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));
  const { signature, ...body } = signed;

  const payload = Buffer.from(canonicalJson(body));
  const prefix = Buffer.from(vector.signingPrefixHex, 'hex');
  const protectedKeyId = Buffer.from(vector.keyId, 'utf8');
  const input = Buffer.concat([prefix, protectedKeyId, Buffer.from([0]), payload]);
  const payloadHash = sha256(payload);
  const inputHash = sha256(input);

  check(payloadHash === vector.canonicalPayloadSha256,
    'Node canonical payload matches the Rust golden SHA-256');
  check(inputHash === vector.signingInputSha256,
    'Node domain-separated signing input matches the Rust golden SHA-256');
  check(signature.value === vector.signatureBase64,
    'signed config carries the versioned conformance signature');
  check(signature.keyId === vector.keyId,
    'signed config carries the protected signing-key identifier');

  const rawPublicKey = Buffer.from(vector.publicKeyBase64, 'base64');
  const publicKey = createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, rawPublicKey]),
    format: 'der',
    type: 'spki',
  });
  const signatureBytes = Buffer.from(signature.value, 'base64');
  check(verifySignature(null, input, publicKey, signatureBytes),
    'Node independently verifies the Rust Ed25519 signature');

  const tampered = structuredClone(body);
  tampered.locale.timezone = 'Europe/Berlin';
  const tamperedBodyInput = Buffer.concat([
    prefix,
    protectedKeyId,
    Buffer.from([0]),
    Buffer.from(canonicalJson(tampered)),
  ]);
  check(!verifySignature(null, tamperedBodyInput, publicKey, signatureBytes),
    'Node rejects a tampered signed field');
  const aliasedKeyInput = Buffer.concat([
    prefix,
    Buffer.from('same-key-alias', 'utf8'),
    Buffer.from([0]),
    payload,
  ]);
  check(!verifySignature(null, aliasedKeyInput, publicKey, signatureBytes),
    'Node rejects an unsigned keyId alias substitution');

  const checkSemanticMutation = (label, ruleId, mutate) => {
    const changed = structuredClone(signed);
    mutate(changed);
    const assessment = score(normalize(changed, {}), ref);
    const outcome = assessment.results.find((entry) => entry.id === ruleId);
    check(outcome?.status === 'fail'
        && assessment.gated
        && assessment.verdict !== 'blends-in'
        && assessment.inconsistencies.some((entry) => entry.id === ruleId),
      `current-target config mutation is rejected: ${label} (${ruleId})`);
  };

  const checkMissingContractField = (field, ruleId) => {
    const changed = structuredClone(signed);
    delete changed[field];
    const assessment = score(normalize(changed, {}), ref);
    const outcome = assessment.results.find((entry) => entry.id === ruleId);
    check(outcome?.status === 'na'
        && assessment.verdict !== 'blends-in'
        && assessment.coverage.missingRequiredRules.includes(ruleId),
      `current config cannot downgrade by deleting ${field} (${ruleId})`);
  };

  const checkCombinedContractDowngrade = (label, mutate) => {
    const changed = structuredClone(signed);
    mutate(changed);
    const assessment = score(normalize(changed, {}), ref);
    check(assessment.scope === 'config'
        && assessment.verdict !== 'blends-in'
        && (!assessment.coverage.complete || assessment.gated),
      `current config cannot downgrade through ${label}`);
    return changed;
  };

  // Independent mirrors of Rust validate() for the current engine target.
  // Runtime observations intentionally keep their broader tolerances.
  checkSemanticMutation('persona OS version', 'R-PERSONA-TARGET',
    (value) => { value.persona.os.version = '10'; });
  checkSemanticMutation('non-null desktop model', 'R-PERSONA-TARGET',
    (value) => { value.persona.device.model = 'Synthetic Desktop'; });
  checkSemanticMutation('unreduced full-version UA', 'R-UA-CH',
    (value) => {
      value.navigator.userAgent = value.navigator.userAgent.replace(
        'Chrome/150.0.0.0',
        `Chrome/${value.engine.fullVersion}`,
      );
    });
  checkSemanticMutation('approximately matching DPR', 'R-SCREEN-REAL',
    (value) => { value.screen.devicePixelRatio += 0.0005; });
  checkSemanticMutation('available screen height', 'R-SCREEN-REAL',
    (value) => { value.screen.availHeight -= 1; });
  checkSemanticMutation('screen color depth', 'R-SCREEN-REAL',
    (value) => { value.screen.colorDepth = 30; });
  checkSemanticMutation('non-candidate hardware pair', 'R-HW-PAIR',
    (value) => {
      value.navigator.hardwareConcurrency = 5;
      value.navigator.deviceMemory = 2;
    });
  checkSemanticMutation('timezone-derived locale', 'R-LANG',
    (value) => { value.locale.timezone = 'Europe/Berlin'; });
  checkSemanticMutation('speech-voice shape', 'R-MEDIA-OS',
    (value) => { value.media.speechVoices[0].localService = false; });
  checkSemanticMutation('duplicate media device ID', 'R-MEDIA-OS',
    (value) => {
      value.media.devices[1].deviceId = value.media.devices[0].deviceId;
    });
  checkSemanticMutation('performance policy', 'R-PERF-PRECISION',
    (value) => { value.performance.timerPrecisionMicros = 101; });
  checkSemanticMutation('unbounded noise amplitude', 'R-NOISE-BOUNDS',
    (value) => { value.noise.canvas.amplitude = 'unbounded'; });
  checkSemanticMutation('rarity verdict', 'R-RARITY-RANGE',
    (value) => { value.rarity.verdict = 'too-rare'; });
  checkSemanticMutation('dataset provenance', 'R-PROVENANCE',
    (value) => { value.provenance.datasetVersion = '0.3.0-tampered'; });
  checkSemanticMutation('engine patch outside exact target', 'R-VERSION-LIVE',
    (value) => {
      const changedVersion = '150.0.7871.125';
      value.engine.fullVersion = changedVersion;
      value.provenance.engineVersion = changedVersion;
      for (const entry of value.clientHints.fullVersionList) {
        if (entry.brand === 'Chromium' || entry.brand === 'Google Chrome') {
          entry.version = changedVersion;
        }
      }
    });
  checkSemanticMutation('engine major outside exact target', 'R-VERSION-LIVE',
    (value) => {
      const changedMajor = 149;
      const changedVersion = '149.0.7777.1';
      value.engine.majorVersion = changedMajor;
      value.engine.fullVersion = changedVersion;
      value.provenance.engineVersion = changedVersion;
      value.navigator.userAgent = value.navigator.userAgent.replace(
        'Chrome/150.0.0.0',
        `Chrome/${changedMajor}.0.0.0`,
      );
      for (const entry of value.clientHints.brands) {
        if (entry.brand === 'Chromium' || entry.brand === 'Google Chrome') {
          entry.version = String(changedMajor);
        }
      }
      for (const entry of value.clientHints.fullVersionList) {
        if (entry.brand === 'Chromium' || entry.brand === 'Google Chrome') {
          entry.version = changedVersion;
        }
      }
    });
  checkMissingContractField('noise', 'R-NOISE-BOUNDS');
  checkMissingContractField('media', 'R-MEDIA-OS');
  checkMissingContractField('performance', 'R-PERF-PRECISION');
  checkMissingContractField('provenance', 'R-PROVENANCE');
  const strictContractFields = [
    'provenance',
    'noise',
    'rarity',
    'media',
    'performance',
  ];
  checkCombinedContractDowngrade('combined strict-field deletion', (value) => {
    for (const field of strictContractFields) delete value[field];
  });
  checkCombinedContractDowngrade('combined strict-field nulling', (value) => {
    for (const field of strictContractFields) value[field] = null;
  });
  const cliDowngrade = checkCombinedContractDowngrade(
    'strict fields plus seed/schema deletion',
    (value) => {
      for (const field of strictContractFields) delete value[field];
      delete value.seed;
      delete value.schemaVersion;
    },
  );
  const cliTemp = mkdtempSync(join(tmpdir(), 'proteus-config-downgrade-'));
  try {
    const cliInput = join(cliTemp, 'mutated-config.json');
    writeFileSync(cliInput, JSON.stringify(cliDowngrade));
    const cli = spawnSync(
      process.execPath,
      [CLI_PATH, 'score', cliInput, '--json'],
      { encoding: 'utf8' },
    );
    let cliAssessment;
    try {
      cliAssessment = JSON.parse(cli.stdout);
    } catch {
      cliAssessment = null;
    }
    check(cli.status === 1
        && cliAssessment?.scope === 'config'
        && cliAssessment?.verdict !== 'blends-in'
        && (!cliAssessment?.coverage?.complete || cliAssessment?.gated),
      'score CLI fails closed on combined discriminator deletion');
  } finally {
    rmSync(cliTemp, { recursive: true, force: true });
  }

  const result = score(normalize(signed, {}), ref);
  check(result.scope === 'config' && result.assessment.complete,
    'generated profile is a complete config-scope assessment');
  check(result.vectors.V1.score === 1 && result.inconsistencies.length === 0,
    'generated profile passes the independent Node V1 rule implementation');
  check(result.verdict === 'blends-in',
    'generated profile passes the seed V1/V2 config gate');
  check(result.vectors.V3.score === null && result.vectors.V5.score === null,
    'config conformance does not claim unmeasured runtime V3-V5 coverage');
  check(signed.provenance.datasetVersion === ref._version
      && signed.provenance.rulesVersion === ref._rulesVersion
      && ref._rulesVersion === RULES_VERSION,
    'generated provenance identifies the exact shared rule and dataset versions');
  check(signed.provenance.datasetSha256
      === sha256(readFileSync(DATASET_PATH)),
    'generated provenance binds the exact shared dataset bytes');
}

function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite JSON number');
    const absolute = Math.abs(value);
    if (absolute !== 0 && (absolute < 1e-6 || absolute >= 1e21)) {
      throw new RangeError('number outside the Profile Config canonicalization range');
    }
    return Object.is(value, -0) ? '0' : JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError(`unsupported JSON type ${typeof value}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
