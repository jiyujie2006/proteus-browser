import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { readFileSync } from 'node:fs';
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
  'v1',
  'golden',
  'windows-chrome-us.signed.json',
);
const VECTOR_PATH = join(
  REPO,
  'fingerprint',
  'conformance',
  'v1',
  'signing-vector.json',
);
const DATASET_PATH = join(REPO, 'verify-lab', 'data', 'reference.json');

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
