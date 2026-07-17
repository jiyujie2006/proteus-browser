#!/usr/bin/env node
// verify-lab CLI — the entry point for humans and CI.
//
//   verify-lab score <file.json> [--proxy-country XX] [--json]
//   verify-lab selftest [--json]
//   verify-lab serve [--port 8791] [--host 127.0.0.1]
//   verify-lab m0-gate            # local M0 ruler-subset check
//
// Runtime CLI: zero dependencies; Node built-ins only. The separate integration
// test suite uses root-locked Ajv dev dependencies for full JSON Schema checks.

import { readFileSync, realpathSync, writeSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadReference } from '../src/reference.mjs';
import { normalize } from '../src/normalize.mjs';
import { score } from '../src/score.mjs';
import { renderReport, renderSummary } from '../src/report.mjs';
import { runSelfTest, checkDeterminism } from '../src/selftest.mjs';
import {
  DEFAULT_STATIC_HOST,
  isPathInsideRoot,
  resolveStaticPath,
} from '../src/static-path.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const args = process.argv.slice(2);
const cmd = args[0];
const writeStdout = (text) => writeSync(process.stdout.fd, text);

function flag(name, fallback) {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
}
function has(name) { return args.includes(name); }

function cmdScore() {
  const file = args[1];
  if (!file) { console.error('usage: verify-lab score <file.json> [--proxy-country XX] [--json]'); process.exit(2); }
  const ref = loadReference();
  const raw = JSON.parse(readFileSync(file, 'utf8'));
  const context = {};
  const pc = flag('--proxy-country', null);
  if (pc) context.proxyGeoCountry = pc;
  const scored = score(normalize(raw, context), ref);
  if (has('--json')) {
    writeStdout(JSON.stringify({ file, ...scored, results: undefined }, null, 2) + '\n');
  } else {
    writeStdout(renderReport(scored, { title: file }) + '\n');
  }
  // Exit non-zero if the profile is detectable, so scripts can gate on it.
  process.exit(scored.verdict === 'blends-in' ? 0 : 1);
}

function cmdSelfTest() {
  const result = runSelfTest();
  const deterministic = checkDeterminism();
  if (has('--json')) {
    writeStdout(JSON.stringify({ ...result, deterministic }, null, 2) + '\n');
    process.exit(result.failed === 0 && deterministic ? 0 : 1);
  }
  console.log('\n  Proteus Verification Lab — self-test');
  console.log('  ' + '─'.repeat(58));
  for (const c of result.cases) {
    const mark = c.ok ? '✅' : '❌';
    console.log(`  ${mark} ${c.name.padEnd(42)} ${String(Math.round(c.aggregate * 100)).padStart(3)}%  ${c.verdict}`);
    if (!c.ok) for (const f of c.failures) console.log(`        └─ ${f}`);
  }
  console.log('  ' + '─'.repeat(58));
  console.log(`  ${result.passed}/${result.total} fixtures passed · determinism: ${deterministic ? 'ok' : 'FAILED'}`);
  console.log('');
  process.exit(result.failed === 0 && deterministic ? 0 : 1);
}

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.css': 'text/css' };

function cmdServe() {
  const port = Number(flag('--port', '8791'));
  const host = flag('--host', DEFAULT_STATIC_HOST);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error('error: --port must be an integer from 1 to 65535');
    process.exit(2);
  }

  const rootRealPath = realpathSync(ROOT);
  const server = createServer((req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' });
      return res.end('method not allowed');
    }

    const requestedPath = resolveStaticPath(rootRealPath, req.url);
    if (!requestedPath) {
      res.writeHead(403);
      return res.end('forbidden');
    }

    try {
      // Lexical containment is not enough when an in-tree symlink points out of
      // the served root. Resolve it and enforce the boundary a second time.
      const filePath = realpathSync(requestedPath);
      if (!isPathInsideRoot(rootRealPath, filePath)) {
        res.writeHead(403);
        return res.end('forbidden');
      }
      const body = readFileSync(filePath);
      res.writeHead(200, {
        'content-type': MIME[extname(filePath)] || 'application/octet-stream',
        'x-content-type-options': 'nosniff',
      });
      res.end(req.method === 'HEAD' ? undefined : body);
    } catch {
      res.writeHead(404);
      res.end('not found');
    }
  });
  server.listen(port, host, () => {
    console.log(`\n  Proteus Verification Lab serving at http://${host}:${port}/`);
    console.log('  Open it in any browser and click "Test this browser".');
    console.log('  Nothing leaves your machine. Ctrl-C to stop.\n');
  });
}

function cmdM0Gate() {
  // The local M0 ruler subset (docs/06-roadmap.md): the lab runs, scores
  // a profile, lists inconsistencies, is deterministic, and its self-tests pass.
  console.log('\n  Local M0 ruler-subset gate\n');
  const checks = [];

  const st = runSelfTest();
  checks.push(['verification lab self-test passes', st.failed === 0, `${st.passed}/${st.total} fixtures`]);
  checks.push(['scoring is deterministic', checkDeterminism(), 'same input → same output']);

  // Can it produce a score + inconsistency list on a real input?
  const ref = loadReference();
  const good = JSON.parse(readFileSync(join(ROOT, 'fixtures', 'good-windows-chrome.json'), 'utf8'));
  const goodScore = score(normalize(good, {}), ref);
  checks.push(['a coherent profile scores "blends-in"', goodScore.verdict === 'blends-in', `${Math.round(goodScore.aggregate*100)}%`]);
  checks.push(['coherent profile has zero inconsistencies', goodScore.inconsistencies.length === 0, `${goodScore.inconsistencies.length}`]);

  const bad = JSON.parse(readFileSync(join(ROOT, 'fixtures', 'bad-v1-apple-gpu-on-windows.json'), 'utf8'));
  const badScore = score(normalize(bad, {}), ref);
  checks.push(['an incoherent profile is caught + gated', badScore.verdict === 'detectable-incoherent' && badScore.gated, badScore.verdict]);
  checks.push(['incoherent profile lists the exact contradiction', badScore.inconsistencies.some(i => i.id === 'R-PLATFORM-GPU'), 'R-PLATFORM-GPU fired']);

  let allOk = true;
  for (const [label, ok, detail] of checks) {
    console.log(`  ${ok ? '✅' : '❌'} ${label.padEnd(48)} ${detail}`);
    if (!ok) allOk = false;
  }
  console.log('\n  ' + (allOk ? '✅ local M0 ruler subset MET' : '❌ local M0 ruler subset NOT met') + '\n');
  process.exit(allOk ? 0 : 1);
}

switch (cmd) {
  case 'score': cmdScore(); break;
  case 'selftest': cmdSelfTest(); break;
  case 'serve': cmdServe(); break;
  case 'm0-gate': cmdM0Gate(); break;
  default:
    console.log(`Proteus verify-lab

  verify-lab score <file.json> [--proxy-country XX] [--json]   score a fingerprint/config
  verify-lab selftest [--json]                                 run the lab's own tests
  verify-lab serve [--port 8791] [--host 127.0.0.1]            serve the local probe page
  verify-lab m0-gate                                           local M0 ruler-subset check
`);
    process.exit(cmd ? 2 : 0);
}
