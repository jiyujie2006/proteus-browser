import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalize } from '../src/normalize.mjs';
import { gpuFamilyOf } from '../src/reference-util.mjs';
import { score } from '../src/score.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const GOOD = JSON.parse(readFileSync(join(__dirname, '..', 'fixtures', 'good-windows-chrome.json'), 'utf8'));
const GOLDEN = JSON.parse(readFileSync(join(
  __dirname,
  '..',
  '..',
  'fingerprint',
  'conformance',
  'v2',
  'golden',
  'windows-chrome-us.signed.json',
), 'utf8'));

const clone = (value) => structuredClone(value);

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

function ruleResult(result, id) {
  return result.results.find((entry) => entry.id === id);
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

  const completeConfig = scored(clone(GOLDEN), ref);
  check(completeConfig.scope === 'config', 'static profile is explicitly assessed in config scope');
  check(completeConfig.assessment.status === 'complete' && completeConfig.verdict === 'blends-in',
    'complete coherent config can blend in');
  check(completeConfig.results.every((result) => result.vector === 'V1' || result.vector === 'V2'),
    'config scope evaluates only V1 and V2');
  check(completeConfig.vectors.V3.score === null && completeConfig.vectors.V5.score === null,
    'config scope leaves runtime vectors unmeasured');

  const missingCh = clone(GOLDEN);
  delete missingCh.clientHints;
  const incompleteConfig = scored(missingCh, ref);
  check(incompleteConfig.verdict !== 'blends-in'
      && incompleteConfig.assessment.status === 'insufficient-data',
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

  const requiredCrossContexts = [
    'main',
    'same-origin-iframe',
    'cross-origin-iframe',
    'dedicated-worker',
    'shared-worker',
    'service-worker',
  ];
  const consistentContextValues = {
    navigator: {
      userAgent: GOOD.navigator.userAgent,
      platform: GOOD.navigator.platform,
      languages: [...GOOD.navigator.languages],
      hardwareConcurrency: GOOD.navigator.hardwareConcurrency,
      deviceMemory: GOOD.navigator.deviceMemory,
      vendor: GOOD.navigator.vendor,
    },
    locale: {
      timezone: GOOD.locale.timezone,
      intlLocale: GOOD.locale.intlLocale,
    },
    clientHints: clone(GOOD.clientHints),
    gpu: clone(GOOD.gpu),
  };
  const completeCrossContext = () => ({
    schemaVersion: '1.0.0',
    requiredContexts: [...requiredCrossContexts],
    contexts: Object.fromEntries(
      requiredCrossContexts.map((context) => {
        const values = clone(consistentContextValues);
        if (context.endsWith('worker')) delete values.navigator.vendor;
        return [context, { status: 'ok', values }];
      }),
    ),
    mismatches: [],
    complete: true,
  });

  const structuredConsistent = clone(GOOD);
  structuredConsistent.traces.crossContextMismatches = 9;
  structuredConsistent.traces.crossContext = completeCrossContext();
  const structuredConsistentRule = ruleResult(
    scored(structuredConsistent, ref),
    'R-CROSS-CONTEXT',
  );
  check(structuredConsistentRule.status === 'pass',
    'structured six-context evidence accepts worker vendor absence and takes precedence over the legacy count');

  const vendorFrameMismatch = clone(GOOD);
  vendorFrameMismatch.traces.crossContext = completeCrossContext();
  vendorFrameMismatch.traces.crossContext.contexts['same-origin-iframe']
    .values.navigator.vendor = 'Unexpected Vendor';
  const vendorFrameMismatchRule = ruleResult(
    scored(vendorFrameMismatch, ref),
    'R-CROSS-CONTEXT',
  );
  check(vendorFrameMismatchRule.status === 'fail'
      && vendorFrameMismatchRule.reason.includes(
        'same-origin-iframe/navigator.vendor',
      ),
    'navigator.vendor is required to agree in frame contexts');

  const forgedStructuredMain = clone(GOOD);
  forgedStructuredMain.traces.crossContext = completeCrossContext();
  for (const context of [
    'main',
    'same-origin-iframe',
    'cross-origin-iframe',
  ]) {
    forgedStructuredMain.traces.crossContext.contexts[context]
      .values.navigator.vendor = 'Internally Consistent Forgery';
  }
  const forgedStructuredMainRule = ruleResult(
    scored(forgedStructuredMain, ref),
    'R-CROSS-CONTEXT',
  );
  check(forgedStructuredMainRule.status === 'fail'
      && forgedStructuredMainRule.reason.includes('main/navigator.vendor'),
    'structured main-context values are bound to the top-level observation');

  const structuredMismatch = clone(GOOD);
  structuredMismatch.traces.crossContext = completeCrossContext();
  structuredMismatch.traces.crossContext.mismatches.push({
    context: 'shared-worker',
    field: 'navigator.platform',
    expected: 'Win32',
    actual: 'Linux x86_64',
  });
  structuredMismatch.traces.crossContext.contexts['shared-worker']
    .values.navigator.platform = 'Linux x86_64';
  const structuredMismatchRule = ruleResult(
    scored(structuredMismatch, ref),
    'R-CROSS-CONTEXT',
  );
  check(structuredMismatchRule.status === 'fail'
      && structuredMismatchRule.reason.includes('shared-worker/navigator.platform')
      && structuredMismatchRule.fields.includes('traces.crossContext.mismatches.0.context')
      && structuredMismatchRule.fields.includes('traces.crossContext.mismatches.0.field'),
    'structured cross-context mismatch fails with the exact context and field');

  const undeclaredMismatch = clone(GOOD);
  undeclaredMismatch.traces.crossContext = completeCrossContext();
  undeclaredMismatch.traces.crossContext.contexts['dedicated-worker']
    .values.navigator.userAgent = 'forged worker UA';
  const undeclaredMismatchRule = ruleResult(
    scored(undeclaredMismatch, ref),
    'R-CROSS-CONTEXT',
  );
  check(undeclaredMismatchRule.status === 'fail'
      && undeclaredMismatchRule.reason.includes(
        'dedicated-worker/navigator.userAgent',
      ),
    'structured cross-context values are independently compared instead of trusting the mismatch list');

  const undeclaredOptionalMismatch = clone(GOOD);
  undeclaredOptionalMismatch.traces.crossContext = completeCrossContext();
  undeclaredOptionalMismatch.traces.crossContext.contexts['shared-worker']
    .values.clientHints.platform = 'Linux';
  const undeclaredOptionalMismatchRule = ruleResult(
    scored(undeclaredOptionalMismatch, ref),
    'R-CROSS-CONTEXT',
  );
  check(undeclaredOptionalMismatchRule.status === 'fail'
      && undeclaredOptionalMismatchRule.reason.includes(
        'shared-worker/clientHints.platform',
      ),
    'structured optional cross-context values are independently compared instead of trusting the mismatch list');

  for (const [label, path, context] of [
    ['deviceMemory', ['navigator', 'deviceMemory'], 'dedicated-worker'],
    ['UA-CH', ['clientHints', 'fullVersionList'], 'shared-worker'],
    ['WebGL', ['gpu', 'webglRenderer'], 'service-worker'],
  ]) {
    const missingOptional = clone(GOOD);
    missingOptional.traces.crossContext = completeCrossContext();
    const values = missingOptional.traces.crossContext.contexts[context].values;
    delete values[path[0]][path[1]];
    const missingOptionalRule = ruleResult(
      scored(missingOptional, ref),
      'R-CROSS-CONTEXT',
    );
    check(missingOptionalRule.status === 'fail'
        && missingOptionalRule.reason.includes(
          `${context}/${path.join('.')} (missing)`,
        ),
      `structured cross-context evidence fails closed when ${label} is missing`);
  }

  const missingMainOptional = clone(GOOD);
  missingMainOptional.traces.crossContext = completeCrossContext();
  for (const context of requiredCrossContexts) {
    delete missingMainOptional.traces.crossContext.contexts[context]
      .values.navigator.deviceMemory;
  }
  const missingMainOptionalRule = ruleResult(
    scored(missingMainOptional, ref),
    'R-CROSS-CONTEXT',
  );
  check(missingMainOptionalRule.status === 'fail'
      && missingMainOptionalRule.reason.includes(
        'main/navigator.deviceMemory (missing)',
      ),
    'top-level optional values cannot be omitted from every structured context');

  const unexpectedOptionalPresence = clone(GOOD);
  delete unexpectedOptionalPresence.navigator.deviceMemory;
  delete unexpectedOptionalPresence.clientHints;
  delete unexpectedOptionalPresence.gpu;
  unexpectedOptionalPresence.traces.crossContext = completeCrossContext();
  for (const context of requiredCrossContexts) {
    const values = unexpectedOptionalPresence.traces.crossContext
      .contexts[context].values;
    delete values.navigator.deviceMemory;
    delete values.clientHints;
    delete values.gpu;
  }
  unexpectedOptionalPresence.traces.crossContext
    .contexts['same-origin-iframe'].values.navigator.deviceMemory = 8;
  unexpectedOptionalPresence.traces.crossContext
    .contexts['service-worker'].values.clientHints = {
      platform: 'Worker-only platform',
    };
  unexpectedOptionalPresence.traces.crossContext
    .contexts['dedicated-worker'].values.gpu = {
      webglRenderer: 'Worker-only renderer',
    };
  const unexpectedOptionalPresenceRule = ruleResult(
    scored(unexpectedOptionalPresence, ref),
    'R-CROSS-CONTEXT',
  );
  check(unexpectedOptionalPresenceRule.status === 'fail'
      && unexpectedOptionalPresenceRule.reason.includes(
        'same-origin-iframe/navigator.deviceMemory (unexpected presence)',
      )
      && unexpectedOptionalPresenceRule.reason.includes(
        'service-worker/clientHints.platform (unexpected presence)',
      )
      && unexpectedOptionalPresenceRule.reason.includes(
        'dedicated-worker/gpu.webglRenderer (unexpected presence)',
      ),
    'optional surfaces exposed outside main fail as presence mismatches');

  const unexpectedContext = clone(GOOD);
  unexpectedContext.traces.crossContext = completeCrossContext();
  unexpectedContext.traces.crossContext.contexts['unbound-extra-context'] = {
    status: 'ok',
    values: clone(consistentContextValues),
  };
  const unexpectedContextRule = ruleResult(
    scored(unexpectedContext, ref),
    'R-CROSS-CONTEXT',
  );
  check(unexpectedContextRule.status === 'fail'
      && unexpectedContextRule.fields.includes('traces.crossContext.contexts'),
    'structured cross-context evidence rejects unbound extra contexts');

  const structuredTimeout = clone(GOOD);
  structuredTimeout.traces.crossContext = completeCrossContext();
  structuredTimeout.traces.crossContext.contexts['service-worker'] = { status: 'timeout' };
  structuredTimeout.traces.crossContext.complete = false;
  const structuredTimeoutRule = ruleResult(
    scored(structuredTimeout, ref),
    'R-CROSS-CONTEXT',
  );
  check(structuredTimeoutRule.status === 'fail'
      && structuredTimeoutRule.reason.includes('service-worker (timeout)')
      && structuredTimeoutRule.fields.includes(
        'traces.crossContext.contexts.service-worker.status',
      ),
    'structured cross-context timeout fails closed and names the unmeasured context');

  const structuredMissing = clone(GOOD);
  structuredMissing.traces.crossContext = completeCrossContext();
  delete structuredMissing.traces.crossContext.contexts['cross-origin-iframe'];
  structuredMissing.traces.crossContext.complete = false;
  const structuredMissingRule = ruleResult(
    scored(structuredMissing, ref),
    'R-CROSS-CONTEXT',
  );
  check(structuredMissingRule.status === 'fail'
      && structuredMissingRule.reason.includes('cross-origin-iframe (missing)')
      && structuredMissingRule.fields.includes(
        'traces.crossContext.contexts.cross-origin-iframe',
      ),
    'structured cross-context missing observation fails closed and names the context');

  const legacyCrossContextPass = clone(GOOD);
  delete legacyCrossContextPass.traces.crossContext;
  legacyCrossContextPass.traces.crossContextMismatches = 0;
  const legacyCrossContextFail = clone(legacyCrossContextPass);
  legacyCrossContextFail.traces.crossContextMismatches = 1;
  const legacyCrossContextNa = clone(legacyCrossContextPass);
  legacyCrossContextNa.traces.crossContextMismatches = null;
  check(ruleResult(scored(legacyCrossContextPass, ref), 'R-CROSS-CONTEXT').status === 'pass'
      && ruleResult(scored(legacyCrossContextFail, ref), 'R-CROSS-CONTEXT').status === 'fail'
      && ruleResult(scored(legacyCrossContextNa, ref), 'R-CROSS-CONTEXT').status === 'na',
    'legacy crossContextMismatches number/null semantics remain compatible');

  const truthyNetworkStrings = clone(GOOD);
  truthyNetworkStrings.network.ja3Matches = 'false';
  truthyNetworkStrings.network.h2Matches = 'false';
  const truthyNetworkResult = scored(truthyNetworkStrings, ref);
  const malformedTls = ruleResult(truthyNetworkResult, 'R-TLS-PARITY');
  const malformedH2 = ruleResult(truthyNetworkResult, 'R-H2-PARITY');
  check(malformedTls.status === 'fail'
      && malformedTls.severity === 'fatal'
      && malformedTls.fields.includes('network.ja3Matches')
      && malformedH2.status === 'fail'
      && malformedH2.severity === 'fatal'
      && malformedH2.fields.includes('network.h2Matches'),
    'truthy string network parity claims fail closed instead of passing as booleans');

  const highMemoryChrome = clone(GOOD);
  highMemoryChrome.navigator.hardwareConcurrency = 32;
  highMemoryChrome.navigator.deviceMemory = 32;
  check(ruleResult(scored(highMemoryChrome, ref), 'R-HW-PAIR').status === 'pass',
    'Chrome 150-era 32-core/32-GiB desktop buckets are accepted');

  const staleRuntimeInput = clone(GOOD);
  setChromeVersion(staleRuntimeInput, 138, '138.0.7204.150');
  const staleRuntime = scored(staleRuntimeInput, ref);
  check(staleRuntime.verdict === 'borderline'
      && ruleResult(staleRuntime, 'R-VERSION-LIVE').severity === 'soft'
      && !staleRuntime.gated,
    'stale runtime version remains a soft rarity signal');

  const uaVersionMismatch = clone(GOOD);
  uaVersionMismatch.navigator.userAgent = uaVersionMismatch.navigator.userAgent.replace('Chrome/148.0.0.0', 'Chrome/99.0.0.0');
  check(fires(scored(uaVersionMismatch, ref), 'R-UA-CH'),
    'R-UA-CH catches UA versus engine version mismatch');

  const requestUaMismatch = clone(GOOD);
  check(fires(scored(requestUaMismatch, ref, {
    requestUserAgent: requestUaMismatch.navigator.userAgent.replace(
      'Chrome/148.0.0.0',
      'Chrome/147.0.0.0',
    ),
  }), 'R-UA-CH'),
  'R-UA-CH catches HTTP versus navigator User-Agent mismatch');

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

  const target = ref.engineTargets[0];
  const reducedUaRuntime = clone(GOOD);
  delete reducedUaRuntime.engine;
  reducedUaRuntime.navigator.userAgent = reducedUaRuntime.navigator.userAgent
    .replace(/Chrome\/\d+(?:\.\d+){3}/u, `Chrome/${target.majorVersion}.0.0.0`);
  reducedUaRuntime.clientHints = {
    brands: clone(target.clientHintBrands),
    fullVersionList: clone(target.clientHintFullVersionList),
    platform: 'Windows',
    platformVersion: target.platformVersions.Windows,
    architecture: 'x86',
    bitness: '64',
    model: '',
    mobile: false,
  };
  const reducedUaNormalized = normalize(reducedUaRuntime);
  const reducedUaRule = ruleResult(
    score(reducedUaNormalized, ref),
    'R-UA-CH',
  );
  check(reducedUaNormalized.engine.majorVersion === target.majorVersion
      && reducedUaNormalized.engine.fullVersion === target.fullVersion
      && reducedUaRule.status === 'pass',
    'stock reduced Chrome UA recovers the real full version from branded UA-CH without a false R-UA-CH failure');

  const sampledLinuxRuntime = clone(reducedUaRuntime);
  sampledLinuxRuntime.persona = {
    os: { name: 'Linux', version: 'rolling', arch: 'x86_64' },
    device: { class: 'desktop', model: null },
  };
  sampledLinuxRuntime.navigator.userAgent =
    `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/${target.majorVersion}.0.0.0 Safari/537.36`;
  sampledLinuxRuntime.navigator.platform = 'Linux x86_64';
  sampledLinuxRuntime.navigator.hardwareConcurrency = 32;
  sampledLinuxRuntime.navigator.deviceMemory = 32;
  sampledLinuxRuntime.clientHints.platform = 'Linux';
  sampledLinuxRuntime.clientHints.platformVersion = '';
  const sampledLinuxRule = ruleResult(
    scored(sampledLinuxRuntime, ref),
    'R-UA-CH',
  );
  check(sampledLinuxRule.status === 'pass',
    'sampled Chrome 150 Linux reduced UA and empty platformVersion do not produce a false R-UA-CH failure');

  const currentTargetConfig = clone(GOLDEN);
  const currentTargetResult = scored(currentTargetConfig, ref);
  check(ruleResult(currentTargetResult, 'R-UA-CH').status === 'pass'
      && ruleResult(currentTargetResult, 'R-WEBGL-WEBGPU').status === 'pass',
    'current config matches the exact target Client Hints and joint GPU profile');

  for (const [label, mutate, ruleId] of [
    ['extra Client Hints brand', (value) => value.clientHints.brands.push({
      brand: 'Conflicting Browser',
      version: String(target.majorVersion),
    }), 'R-UA-CH'],
    ['Client Hints platformVersion', (value) => {
      value.clientHints.platformVersion = '0.0.0';
    }, 'R-UA-CH'],
    ['Client Hints architecture', (value) => {
      value.clientHints.architecture = 'arm';
    }, 'R-UA-CH'],
    ['WebGL extensions', (value) => {
      value.gpu.webglExtensions = value.gpu.webglExtensions.slice(1);
    }, 'R-WEBGL-WEBGPU'],
    ['WebGPU adapter description', (value) => {
      value.gpu.webgpuAdapter.description = 'mutated adapter';
    }, 'R-WEBGL-WEBGPU'],
    ['GPU device class', (value) => {
      value.persona.device.class = 'phone';
    }, 'R-WEBGL-WEBGPU'],
  ]) {
    const mutation = clone(currentTargetConfig);
    mutate(mutation);
    check(fires(scored(mutation, ref), ruleId),
      `exact target validation rejects mutated ${label}`);
  }

  const opera = normalize({
    navigator: {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/150.0.0.0 Safari/537.36 OPR/134.0.0.0',
      platform: 'Win32',
    },
    clientHints: {
      fullVersionList: [{
        brand: 'Opera',
        version: '134.0.6998.205',
      }],
    },
  });
  const edge = normalize({
    navigator: {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0',
      platform: 'Win32',
    },
    clientHints: {
      fullVersionList: [{
        brand: 'Microsoft Edge',
        version: '150.0.3765.53',
      }],
    },
  });
  check(opera.engine.brand === 'Opera'
      && opera.engine.majorVersion === 134
      && opera.engine.fullVersion === '134.0.6998.205'
      && edge.engine.brand === 'Edge'
      && edge.engine.fullVersion === '150.0.3765.53',
    'Opera and Edge inference use their branded UA-CH full versions instead of embedded or reduced Chrome tokens');

  check(gpuFamilyOf('ANGLE (Qualcomm, Adreno (TM) 740)', ref) === 'Adreno',
    'GPU marker precedence preserves the specific Adreno family');
}
