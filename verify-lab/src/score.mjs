// Scoring engine (tdd/06 §4). Turns rule results into per-vector scores, a
// coherence-dominant aggregate, and — the actionable part — the inconsistency
// list. Deterministic: same input → same output (tdd/06 §8).
//
// Two ideas from the threat model drive the model:
//
//  1. "No green-washing" (tdd/06 §4): a profile with a real tell must never be
//     shown as good, no matter how clean everything else is. We enforce this with
//     a hard GATE: any *fatal* rule failure (a deterministic tell — webdriver
//     true, Apple GPU on Windows, TLS mismatch, cross-context leak) caps the
//     aggregate below the "blends-in" threshold and forces a "detectable"
//     verdict. Clean vectors cannot average a deterministic tell away, because a
//     real detector doesn't average — it acts on the single signal.
//
//  2. Coherence dominance (Principle I): V1 outranks the rest, so a V1 failure
//     produces the most severe verdict ("detectable-incoherent") and V1 carries
//     the greatest weight in the gradient used to rank non-fatal differences.
//
// `soft` failures (rarity, V2) are matters of degree: they pull the score down a
// gradient but do not by themselves gate the verdict. `na` results never help or
// hurt and are excluded from their vector's score.

import { runRules } from './rules.mjs';

// Vector weights for the aggregate gradient. V1 dominates by Principle I.
export const VECTOR_WEIGHTS = Object.freeze({
  V1: 5,
  V2: 3,
  V3: 3,
  V4: 2,
  V5: 2,
});
const VECTORS = ['V1', 'V2', 'V3', 'V4', 'V5'];
const CONFIG_VECTORS = ['V1', 'V2'];

// These rules describe the minimum evidence needed before a config can be called
// coherent/common. Context-dependent and newly scaffolded rules are added below
// only when their inputs are actually applicable.
const CONFIG_REQUIRED_RULES = [
  'R-PLATFORM-GPU',
  'R-PLATFORM-OS',
  'R-UA-CH',
  'R-VENDOR-FAMILY',
  'R-FONT-OS',
  'R-LANG',
  'R-SCREEN-REAL',
  'R-HW-PAIR',
  'R-VERSION-LIVE',
];

const RUNTIME_REQUIRED_RULES = [
  'R-NATIVE-TOSTRING',
  'R-DESCRIPTOR-SHAPE',
  'R-CROSS-CONTEXT',
  'R-TLS-PARITY',
  'R-H2-PARITY',
  'R-NO-DNS-LEAK',
  'R-NO-WEBRTC-LEAK',
  'R-NO-WEBDRIVER',
  'R-NO-CDP-ARTIFACTS',
  'R-NO-RUNTIME-LEAK',
  'R-ISTRUSTED',
  'R-NO-HEADLESS',
];

const BLENDS_IN = 0.9;
const BORDERLINE = 0.7;
// A fatal tell caps the aggregate here — comfortably in "detectable" territory,
// while still letting the number reflect how much else was clean (so two caught
// profiles can be compared).
const FATAL_CAP = 0.5;

/** Weighted pass-ratio for one vector from its rule results. Returns null if unmeasured. */
function vectorScore(results) {
  const measured = results.filter((r) => r.status !== 'na');
  if (measured.length === 0) return null;
  const total = measured.reduce((s, r) => s + (r.weight || 1), 0);
  const passed = measured.filter((r) => r.status === 'pass').reduce((s, r) => s + (r.weight || 1), 0);
  return total === 0 ? null : passed / total;
}

/**
 * Score a normalized fingerprint observation.
 * @returns {{
 *   aggregate:number, verdict:string, gated:boolean, scope:"config"|"runtime",
 *   vectors:Record<string,{score:number|null,passed:number,failed:number,na:number}>,
 *   inconsistencies:Array<{id,vector,severity,fields,reason,weight}>,
 *   fatalVectors:string[], results:object[], coverage:object, assessment:object
 * }}
 */
export function score(fp, ref) {
  const scope = fp?.scope === 'runtime' ? 'runtime' : fp?.scope === 'config' ? 'config'
    : (fp?.traces !== undefined || fp?.automation !== undefined || fp?.network !== undefined ? 'runtime' : 'config');
  const activeVectors = scope === 'config' ? CONFIG_VECTORS : VECTORS;
  const results = runRules(fp, ref).filter((result) => activeVectors.includes(result.vector));

  const vectors = {};
  for (const v of VECTORS) {
    const rs = results.filter((r) => r.vector === v);
    vectors[v] = {
      score: vectorScore(rs),
      passed: rs.filter((r) => r.status === 'pass').length,
      failed: rs.filter((r) => r.status === 'fail').length,
      na: rs.filter((r) => r.status === 'na').length,
    };
  }

  // Weighted aggregate over measured vectors (the "how clean overall" gradient).
  let num = 0, den = 0;
  for (const v of VECTORS) {
    const s = vectors[v].score;
    if (s == null) continue;
    num += s * VECTOR_WEIGHTS[v];
    den += VECTOR_WEIGHTS[v];
  }
  let aggregate = den === 0 ? 0 : num / den;

  const requiredRuleIds = requiredRulesFor(fp, scope);
  const resultById = new Map(results.map((result) => [result.id, result]));
  const missingRequiredRules = requiredRuleIds.filter((id) => {
    const result = resultById.get(id);
    return !result || result.status === 'na';
  });
  const measured = results.filter((result) => result.status !== 'na').length;
  const requiredMeasured = requiredRuleIds.length - missingRequiredRules.length;
  const coverage = {
    measured,
    total: results.length,
    ratio: round(results.length ? measured / results.length : 0),
    required: requiredRuleIds.length,
    requiredMeasured,
    requiredRatio: round(requiredRuleIds.length ? requiredMeasured / requiredRuleIds.length : 1),
    missingRequiredRules,
    complete: missingRequiredRules.length === 0,
  };

  // Which vectors carry a fatal (deterministic) tell?
  const fatalFailures = results.filter((r) => r.status === 'fail' && r.severity === 'fatal');
  const fatalVectors = [...new Set(fatalFailures.map((r) => r.vector))].sort();
  const v1Fatal = fatalVectors.includes('V1');

  // The gate: any fatal tell caps the aggregate into "detectable".
  const gated = fatalFailures.length > 0;
  if (gated && aggregate > FATAL_CAP) aggregate = FATAL_CAP;

  const inconsistencies = results
    .filter((r) => r.status === 'fail')
    .sort((a, b) => severityRank(b) - severityRank(a) || (b.weight || 1) - (a.weight || 1))
    .map((r) => ({ id: r.id, vector: r.vector, severity: r.severity, fields: r.fields, reason: r.reason, weight: r.weight || 1 }));

  let verdict;
  if (v1Fatal) verdict = 'detectable-incoherent';       // Principle I: coherence failure is worst
  else if (fatalFailures.length > 0) verdict = 'detectable'; // a deterministic tell elsewhere (V3/V4/V5)
  else if (!coverage.complete) verdict = 'insufficient-data';
  else if (aggregate >= BLENDS_IN) verdict = 'blends-in';
  else if (results.some((result) => result.status === 'fail' && result.severity === 'soft')) verdict = 'borderline';
  else if (aggregate >= BORDERLINE) verdict = 'borderline';
  else verdict = 'detectable';

  const assessment = {
    scope,
    status: coverage.complete ? 'complete' : 'insufficient-data',
    complete: coverage.complete,
    activeVectors: [...activeVectors],
    missingRequiredRules: [...missingRequiredRules],
  };

  return {
    aggregate: round(aggregate), verdict, gated, scope,
    vectors: roundVectors(vectors), inconsistencies, fatalVectors, coverage, assessment, results,
  };
}

function requiredRulesFor(fp, scope) {
  const ids = [...CONFIG_REQUIRED_RULES];
  if (fp.context?.proxyGeoCountry) ids.push('R-TZ-GEO');
  if (fp.gpu?.webgpuAdapter != null) ids.push('R-WEBGL-WEBGPU');
  if (fp.media != null) ids.push('R-MEDIA-OS');
  if (fp.performance != null) ids.push('R-PERF-PRECISION');
  if (scope === 'runtime') ids.push(...RUNTIME_REQUIRED_RULES);
  return ids;
}

function severityRank(r) { return r.severity === 'fatal' ? 1 : 0; }
function round(x) { return Math.round(x * 1000) / 1000; }
function roundVectors(vectors) {
  for (const v of Object.values(vectors)) if (v.score != null) v.score = round(v.score);
  return vectors;
}

export const THRESHOLDS = { BLENDS_IN, BORDERLINE, FATAL_CAP };
