// Node-only reference loader (uses fs). Re-exports the pure helpers so existing
// imports from './reference.mjs' keep working. Browser code imports the pure
// helpers from './reference-util.mjs' directly and fetches the JSON itself.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export { gpuFamilyOf, normalizeGpuFamilyForOs } from './reference-util.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Load the coherence reference dataset (the shared source of truth, tdd/06 §4). */
export function loadReference() {
  const raw = readFileSync(join(__dirname, '..', 'data', 'reference.json'), 'utf8');
  return JSON.parse(raw);
}
