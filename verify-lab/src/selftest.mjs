// Self-test: run every fixture through the scorer and assert its declared
// expectations (the `_expect` block). This is the "probe self-tests" requirement
// from tdd/06 §8 — a suite that grades itself must be verified against known-good
// and known-bad inputs, or a broken probe that always passes could hide a
// regression. Deterministic (tdd/06 §8: same fixture + rules → same score).

import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadReference } from './reference.mjs';
import { normalize } from './normalize.mjs';
import { score } from './score.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, '..', 'fixtures');

/** Run all fixtures. Returns { passed, failed, cases: [...] }. */
export function runSelfTest() {
  const ref = loadReference();
  const files = readdirSync(FIXTURES).filter((f) => f.endsWith('.json')).sort();
  const cases = [];
  let passed = 0, failed = 0;

  for (const file of files) {
    const raw = JSON.parse(readFileSync(join(FIXTURES, file), 'utf8'));
    const expect = raw._expect || {};
    const obs = normalize(raw, {});
    const scored = score(obs, ref);
    const firedRules = new Set(scored.inconsistencies.map((i) => i.id));

    const failures = [];

    if (expect.verdict && scored.verdict !== expect.verdict) {
      failures.push(`verdict: expected "${expect.verdict}", got "${scored.verdict}"`);
    }
    if (typeof expect.maxInconsistencies === 'number' && scored.inconsistencies.length > expect.maxInconsistencies) {
      failures.push(`inconsistencies: expected ≤${expect.maxInconsistencies}, got ${scored.inconsistencies.length}`);
    }
    if (typeof expect.minInconsistencies === 'number' && scored.inconsistencies.length < expect.minInconsistencies) {
      failures.push(`inconsistencies: expected ≥${expect.minInconsistencies}, got ${scored.inconsistencies.length}`);
    }
    if (Array.isArray(expect.mustFireRules)) {
      for (const rid of expect.mustFireRules) {
        if (!firedRules.has(rid)) failures.push(`rule ${rid} was expected to fire but did not`);
      }
    }
    if (Array.isArray(expect.mustNotFireRules)) {
      for (const rid of expect.mustNotFireRules) {
        if (firedRules.has(rid)) failures.push(`rule ${rid} fired but should not have`);
      }
    }

    const okCase = failures.length === 0;
    if (okCase) passed++; else failed++;
    cases.push({
      file, name: raw._fixture || file, ok: okCase, failures,
      verdict: scored.verdict, aggregate: scored.aggregate,
      inconsistencies: scored.inconsistencies.length,
      firedRules: [...firedRules],
    });
  }

  return { passed, failed, total: files.length, cases };
}

/** Determinism check: score a fixture twice, assert byte-identical JSON. */
export function checkDeterminism() {
  const ref = loadReference();
  const file = join(FIXTURES, 'good-windows-chrome.json');
  const raw = JSON.parse(readFileSync(file, 'utf8'));
  const a = JSON.stringify(score(normalize(raw, {}), ref));
  const b = JSON.stringify(score(normalize(raw, {}), ref));
  return a === b;
}
