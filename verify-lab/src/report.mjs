// Human-readable report rendering. The inconsistency list is the hero element
// (tdd/06 §4) — the actionable output, not a bare number.

const BAR_WIDTH = 20;

function bar(score) {
  if (score == null) return '  n/a               ';
  const filled = Math.round(score * BAR_WIDTH);
  return '█'.repeat(filled) + '░'.repeat(BAR_WIDTH - filled);
}

function pct(score) {
  return score == null ? ' n/a' : `${String(Math.round(score * 100)).padStart(3)}%`;
}

const VECTOR_LABEL = {
  V1: 'V1 coherence   ',
  V2: 'V2 rarity      ',
  V3: 'V3 traces      ',
  V4: 'V4 network     ',
  V5: 'V5 automation  ',
};

const VERDICT_LABEL = {
  'blends-in': '✅ BLENDS IN',
  borderline: '⚠️  BORDERLINE',
  detectable: '❌ DETECTABLE',
  'detectable-incoherent': '❌ DETECTABLE (incoherent — V1 failure)',
};

/** Render a full text report for a scored result. Returns a string. */
export function renderReport(scored, meta = {}) {
  const lines = [];
  const title = meta.title || 'fingerprint';
  lines.push('');
  lines.push(`  Proteus Verification Lab — ${title}`);
  lines.push('  ' + '─'.repeat(58));
  lines.push('');
  lines.push(`  Aggregate: ${String(Math.round(scored.aggregate * 100)).padStart(3)}%   Verdict: ${VERDICT_LABEL[scored.verdict] || scored.verdict}`);
  if (scored.gated) {
    const vecs = (scored.fatalVectors && scored.fatalVectors.length) ? scored.fatalVectors.join('+') : 'a';
    lines.push(`             (aggregate capped: ${vecs} deterministic tell — no green-washing, tdd/06 §4)`);
  }
  lines.push('');
  for (const v of ['V1', 'V2', 'V3', 'V4', 'V5']) {
    const info = scored.vectors[v];
    const detail = info.score == null ? 'not measured' : `${info.passed} pass / ${info.failed} fail`;
    lines.push(`  ${VECTOR_LABEL[v]} ${bar(info.score)} ${pct(info.score)}   ${detail}`);
  }
  lines.push('');

  if (scored.inconsistencies.length === 0) {
    lines.push('  Inconsistencies: none 🎉  (every measured coherence rule passed)');
  } else {
    lines.push(`  Inconsistencies (${scored.inconsistencies.length}) — the actionable output:`);
    lines.push('');
    for (const inc of scored.inconsistencies) {
      lines.push(`   ✗ [${inc.vector} · ${inc.id}] ${inc.reason}`);
      lines.push(`       fields: ${inc.fields.join(', ')}`);
    }
  }
  lines.push('');
  return lines.join('\n');
}

/** Compact one-line summary for CI logs. */
export function renderSummary(scored, meta = {}) {
  const title = meta.title || 'fingerprint';
  return `${title}: ${Math.round(scored.aggregate * 100)}% ${scored.verdict} (${scored.inconsistencies.length} inconsistencies)`;
}
