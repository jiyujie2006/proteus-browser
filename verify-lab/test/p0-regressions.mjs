import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalize } from '../src/normalize.mjs';
import { gpuFamilyOf } from '../src/reference-util.mjs';
import { score } from '../src/score.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const GOOD = JSON.parse(readFileSync(join(__dirname, '..', 'fixtures', 'good-windows-chrome.json'), 'utf8'));

const clone = (value) => structuredClone(value);

function staticConfig(value = GOOD) {
  const config = clone(value);
  delete config.traces;
  delete config.network;
  delete config.automation;
  delete config.context;
  return config;
}

function setChromeVersion(value, major, fullVersion) {
  value.engine.majorVersion = major;
  value.engine.fullVersion = fullVersion;
  value.navigator.userAgent = value.navigator.userAgent.replace(/Chrome\/\d+(?:\.\d+){3}/, `Chrome/${major}.0.0.0`);
  for (const entry of value.clientHints.brands) {
    if (entry.brand === 'Google Chrome' || entry.brand === 'Chromium') entry.version = String(major);
  }
  for (const entry of value.clientHints.fullVersionList) {
    if (entry.brand === 'Google Chrome') entry.version = fullVersion;
  }
}

function scored(value, ref, context = {}) {
  return score(normalize(value, context), ref);
}

function fires(result, id) {
  return result.inconsistencies.some((entry) => entry.id === id);
}

/**
 * P0 regression cases. The callback matches run-tests.mjs's tiny assertion API so
 * this remains dependency-free and is automatically included by `npm test`.
 */
export function runP0RegressionTests(check, ref) {
  const sparseRaw = scored({
    engine: { family: 'chromium', brand: 'Chrome', majorVersion: 148, fullVersion: '148.0' },
  }, ref);
  check(sparseRaw.scope === 'runtime', 'sparse probe input is assessed in runtime scope');
  check(sparseRaw.verdict === 'insufficient-data', 'one passing rule cannot make a sparse probe blend in');
  check(!sparseRaw.coverage.complete && sparseRaw.coverage.missingRequiredRules.length > 0,
    'sparse probe reports its missing required rules');

  const completeConfig = scored(staticConfig(), ref);
  check(completeConfig.scope === 'config', 'static profile is explicitly assessed in config scope');
  check(completeConfig.assessment.status === 'complete' && completeConfig.verdict === 'blends-in',
    'complete coherent config can blend in');
  check(completeConfig.results.every((result) => result.vector === 'V1' || result.vector === 'V2'),
    'config scope evaluates only V1 and V2');
  check(completeConfig.vectors.V3.score === null && completeConfig.vectors.V5.score === null,
    'config scope leaves runtime vectors unmeasured');

  const missingCh = staticConfig();
  delete missingCh.clientHints;
  const incompleteConfig = scored(missingCh, ref);
  check(incompleteConfig.verdict === 'insufficient-data',
    'config missing a required V1 input cannot blend in');
  check(incompleteConfig.coverage.missingRequiredRules.includes('R-UA-CH'),
    'coverage identifies the missing UA/Client-Hints rule');

  const partialRuntime = clone(GOOD);
  delete partialRuntime.network;
  const incompleteRuntime = scored(partialRuntime, ref);
  check(incompleteRuntime.scope === 'runtime' && incompleteRuntime.verdict === 'insufficient-data',
    'partial runtime observation cannot blend in');
  check(incompleteRuntime.coverage.missingRequiredRules.includes('R-TLS-PARITY'),
    'runtime coverage requires network parity evidence');

  const runtimeGood = scored(clone(GOOD), ref);
  check(runtimeGood.scope === 'runtime' && runtimeGood.assessment.status === 'complete',
    'full fixture is a complete runtime assessment');
  check(!runtimeGood.coverage.missingRequiredRules.includes('R-MEDIA-OS')
      && !runtimeGood.coverage.missingRequiredRules.includes('R-PERF-PRECISION'),
    'inapplicable optional rules do not destabilize required coverage');

  const staleRuntimeInput = clone(GOOD);
  setChromeVersion(staleRuntimeInput, 138, '138.0.7204.150');
  const staleStaticInput = staticConfig(staleRuntimeInput);
  const staleRuntime = scored(staleRuntimeInput, ref);
  const staleStatic = scored(staleStaticInput, ref);
  check(staleRuntime.verdict === 'borderline' && staleStatic.verdict === 'borderline',
    'soft rarity verdict is stable when unrelated runtime vectors are absent');

  const uaVersionMismatch = clone(GOOD);
  uaVersionMismatch.navigator.userAgent = uaVersionMismatch.navigator.userAgent.replace('Chrome/148.0.0.0', 'Chrome/99.0.0.0');
  check(fires(scored(uaVersionMismatch, ref), 'R-UA-CH'),
    'R-UA-CH catches UA versus engine version mismatch');

  const uaOsMismatch = clone(GOOD);
  uaOsMismatch.navigator.userAgent = uaOsMismatch.navigator.userAgent
    .replace('Windows NT 10.0; Win64; x64', 'Macintosh; Intel Mac OS X 10_15_7');
  check(fires(scored(uaOsMismatch, ref), 'R-UA-CH'),
    'R-UA-CH catches UA OS token mismatch');

  const chBrandMismatch = clone(GOOD);
  chBrandMismatch.clientHints.brands = [{ brand: 'Microsoft Edge', version: '148' }];
  check(fires(scored(chBrandMismatch, ref), 'R-UA-CH'),
    'R-UA-CH catches missing claimed brand in Client Hints');

  const chMobileMismatch = clone(GOOD);
  chMobileMismatch.clientHints.mobile = true;
  check(fires(scored(chMobileMismatch, ref), 'R-UA-CH'),
    'R-UA-CH catches Client Hints mobile versus device-class mismatch');

  const intlMismatch = clone(GOOD);
  intlMismatch.locale.intlLocale = 'ja-JP';
  check(fires(scored(intlMismatch, ref), 'R-LANG'),
    'R-LANG catches navigator versus Intl locale mismatch');

  const gpuMismatch = clone(GOOD);
  gpuMismatch.gpu.webgpuAdapter = { vendor: 'intel' };
  check(fires(scored(gpuMismatch, ref), 'R-WEBGL-WEBGPU'),
    'R-WEBGL-WEBGPU catches adapter-family mismatch');

  const mediaMismatch = clone(GOOD);
  mediaMismatch.media = {
    devices: [],
    speechVoices: [{ name: 'Samantha', voiceURI: 'com.apple.speech.synthesis.voice.samantha' }],
  };
  check(fires(scored(mediaMismatch, ref), 'R-MEDIA-OS'),
    'R-MEDIA-OS catches unmistakable Apple voice IDs on Windows');

  const performanceMismatch = clone(GOOD);
  performanceMismatch.performance = { precisionMatches: false, nowResolutionMs: 0.001 };
  check(fires(scored(performanceMismatch, ref), 'R-PERF-PRECISION'),
    'R-PERF-PRECISION catches harness-reported precision mismatch');

  const opera = normalize({
    navigator: {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/150.0.0.0 Safari/537.36 OPR/134.0.0.0',
      platform: 'Win32',
    },
  });
  check(opera.engine.brand === 'Opera' && opera.engine.majorVersion === 134 && opera.engine.fullVersion === '134.0.0.0',
    'Opera inference uses the OPR version instead of the embedded Chrome version');

  check(gpuFamilyOf('ANGLE (Qualcomm, Adreno (TM) 740)', ref) === 'Adreno',
    'GPU marker precedence preserves the specific Adreno family');
}
