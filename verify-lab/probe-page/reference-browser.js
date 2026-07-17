// Browser-side reference loader. The Node loader (src/reference.mjs) uses fs;
// in the browser we fetch the same data file over HTTP from the local server so
// the page and the CLI score against an identical dataset.
export async function loadReferenceBrowser() {
  const res = await fetch('../data/reference.json');
  if (!res.ok) throw new Error('failed to load reference.json: ' + res.status);
  return res.json();
}
