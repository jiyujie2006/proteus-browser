// Pure reference-data helpers with NO Node dependencies, so both the Node CLI and
// the browser probe page can import them. The fs-based loader lives in
// reference.mjs (Node only); the browser fetches the JSON itself.

/** Classify a WebGL renderer/vendor string into a GPU vendor family, or null. */
export function gpuFamilyOf(str, ref) {
  if (!str) return null;
  const s = String(str).toLowerCase();
  const matches = [];
  for (const [family, markers] of Object.entries(ref.gpuVendorStringMarkers)) {
    if (family.startsWith('_') || !Array.isArray(markers)) continue; // skip _comment meta keys
    if (markers.some((m) => s.includes(String(m).toLowerCase()))) matches.push(family);
  }
  // Some umbrella families intentionally repeat a model-family marker. Adreno,
  // for example, appears in both Qualcomm and Adreno marker lists. Prefer the
  // specific model family so Android's allowed-family check does not turn a real
  // Adreno renderer into an impossible generic Qualcomm result.
  if (matches.includes('Adreno')) return 'Adreno';
  return matches[0] || null;
}

/** Map a GPU family to the umbrella families accepted per-OS (Adreno⊂Qualcomm etc.). */
export function normalizeGpuFamilyForOs(family) {
  if (family === 'Adreno') return ['Adreno', 'Qualcomm'];
  return [family];
}
