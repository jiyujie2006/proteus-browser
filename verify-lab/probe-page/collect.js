// probe-page/collect.js
//
// The client-side collector. Runs IN A BROWSER, gathers every fingerprint surface
// the threat model cares about (V1–V5), and returns a plain object that the
// verify-lab scorer (Node side) normalizes and scores. It is deliberately
// framework-free and works when loaded as a classic script (exposes
// window.ProteusCollect) or imported.
//
// Nothing here is transmitted anywhere by itself — the page decides what to do
// with the result (show it, POST it to the local runner, download it). That is
// the Principle-V "test without sending your fingerprint to a third party" model.
//
// NOTE on scope: this collects what a *page* can observe. The V3 trace probes
// (toString/descriptor/cross-context) run real checks here. The V4 network probes
// (JA3/H2/DNS/WebRTC parity) cannot be judged by page JS alone — they require the
// verify-lab's controlled origin / sidecar harness (tdd/06 §3c) — so those fields
// are left for the harness to fill. The collector marks them null, not fake-pass.

(function (root) {
  'use strict';

  function safe(fn, fallback) {
    try { return fn(); } catch (_) { return fallback; }
  }

  // ---- V3: is a function's toString native? -------------------------------
  function isNative(fn) {
    return safe(() => /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn)), false);
  }

  // Count getters on hot surfaces whose toString is NOT native (an injection tell).
  function countNonNativeToString() {
    let count = 0;
    const checks = [
      () => Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent').get,
      () => Object.getOwnPropertyDescriptor(Navigator.prototype, 'platform').get,
      () => Object.getOwnPropertyDescriptor(Navigator.prototype, 'languages').get,
      () => Object.getOwnPropertyDescriptor(Navigator.prototype, 'hardwareConcurrency').get,
      () => Object.getOwnPropertyDescriptor(Screen.prototype, 'width').get,
      () => HTMLCanvasElement.prototype.toDataURL,
      () => WebGLRenderingContext.prototype.getParameter,
    ];
    for (const get of checks) {
      const fn = safe(get, null);
      if (fn && !isNative(fn)) count++;
    }
    return count;
  }

  // Detect descriptor-shape anomalies (a spoofed accessor turned into a data prop, etc.)
  function countDescriptorAnomalies() {
    let count = 0;
    const expectAccessor = [
      [Navigator.prototype, 'userAgent'],
      [Navigator.prototype, 'platform'],
      [Navigator.prototype, 'languages'],
      [Screen.prototype, 'width'],
    ];
    for (const [obj, prop] of expectAccessor) {
      const d = safe(() => Object.getOwnPropertyDescriptor(obj, prop), null);
      if (!d) { count++; continue; }
      // These are accessors on a real engine; a data value is a tell.
      if (typeof d.get !== 'function') count++;
      if (d.enumerable !== true) count++; // these prototype getters are enumerable in Chrome
    }
    return count;
  }

  // ---- V1 surfaces ---------------------------------------------------------
  function getWebGL() {
    return safe(() => {
      let canvas = null;
      if (typeof document !== 'undefined' && typeof document.createElement === 'function') {
        canvas = document.createElement('canvas');
      } else if (typeof OffscreenCanvas !== 'undefined') {
        canvas = new OffscreenCanvas(16, 16);
      }
      if (!canvas) return null;
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return null;
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      const vendor = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
      const renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
      return { webglVendor: vendor, webglRenderer: renderer };
    }, null);
  }

  // Font detection by measurement (offsetWidth of a probe string vs baseline fonts).
  function detectFonts() {
    return safe(() => {
      const baseFonts = ['monospace', 'sans-serif', 'serif'];
      const testString = 'mmmmmmmmmmlli';
      const testSize = '72px';
      const candidates = [
        'Arial', 'Calibri', 'Cambria', 'Consolas', 'Segoe UI', 'Tahoma', 'Times New Roman', 'Verdana', 'Courier New',
        'Georgia', 'Trebuchet MS', 'Helvetica', 'Helvetica Neue', 'Menlo', 'SF Pro', 'Geneva', 'Monaco', 'Lucida Grande',
        'Avenir', 'Optima', 'DejaVu Sans', 'Liberation Sans', 'Ubuntu',
      ];
      const span = document.createElement('span');
      span.style.position = 'absolute';
      span.style.left = '-9999px';
      span.style.fontSize = testSize;
      span.textContent = testString;
      document.body.appendChild(span);
      const baseline = {};
      for (const b of baseFonts) {
        span.style.fontFamily = b;
        baseline[b] = { w: span.offsetWidth, h: span.offsetHeight };
      }
      const detected = [];
      for (const font of candidates) {
        let matched = false;
        for (const b of baseFonts) {
          span.style.fontFamily = `'${font}',${b}`;
          if (span.offsetWidth !== baseline[b].w || span.offsetHeight !== baseline[b].h) { matched = true; break; }
        }
        if (matched) detected.push(font);
      }
      document.body.removeChild(span);
      return detected;
    }, null);
  }

  async function getClientHints() {
    const uaData = safe(() => navigator.userAgentData, null);
    if (!uaData) return null;
    let high = {};
    if (typeof uaData.getHighEntropyValues === 'function') {
      try {
        high = await uaData.getHighEntropyValues([
          'architecture',
          'bitness',
          'fullVersionList',
          'model',
          'platformVersion',
        ]);
      } catch (_) {
        high = {};
      }
    }
    const copyBrands = (value) => Array.isArray(value)
      ? value.map((entry) => ({
        brand: String(entry?.brand ?? ''),
        version: String(entry?.version ?? ''),
      }))
      : null;
    return {
      brands: copyBrands(high.brands ?? uaData.brands) || [],
      fullVersionList: copyBrands(high.fullVersionList),
      platform: String(high.platform ?? uaData.platform ?? ''),
      platformVersion: typeof high.platformVersion === 'string' ? high.platformVersion : null,
      architecture: typeof high.architecture === 'string' ? high.architecture : null,
      bitness: typeof high.bitness === 'string' ? high.bitness : null,
      model: typeof high.model === 'string' ? high.model : null,
      mobile: Boolean(high.mobile ?? uaData.mobile),
    };
  }

  // ---- V3: cross-context consistency --------------------------------------
  const REQUIRED_CONTEXTS = Object.freeze([
    'main',
    'same-origin-iframe',
    'cross-origin-iframe',
    'dedicated-worker',
    'shared-worker',
    'service-worker',
  ]);
  const CORE_CONTEXT_FIELDS = Object.freeze([
    'navigator.userAgent',
    'navigator.platform',
    'navigator.languages',
    'navigator.hardwareConcurrency',
    'locale.timezone',
    'locale.intlLocale',
  ]);
  const OPTIONAL_CONTEXT_FIELDS = Object.freeze([
    'navigator.deviceMemory',
    'clientHints.brands',
    'clientHints.fullVersionList',
    'clientHints.platform',
    'clientHints.platformVersion',
    'clientHints.architecture',
    'clientHints.bitness',
    'clientHints.model',
    'clientHints.mobile',
    'gpu.webglVendor',
    'gpu.webglRenderer',
  ]);
  const CONTEXT_TIMEOUT_MS = 5000;

  async function collectContextValues() {
    const resolved = safe(() => Intl.DateTimeFormat().resolvedOptions(), {});
    return {
      navigator: {
        userAgent: safe(() => navigator.userAgent, null),
        platform: safe(() => navigator.platform, null),
        languages: safe(() => Array.from(navigator.languages || []), null),
        hardwareConcurrency: safe(() => navigator.hardwareConcurrency, null),
        deviceMemory: safe(() => navigator.deviceMemory, null),
        vendor: safe(() => navigator.vendor, null),
      },
      locale: {
        timezone: typeof resolved.timeZone === 'string' ? resolved.timeZone : null,
        intlLocale: typeof resolved.locale === 'string' ? resolved.locale : null,
      },
      clientHints: await getClientHints(),
      gpu: getWebGL(),
    };
  }

  function contextValuesValid(value) {
    return value
      && typeof value === 'object'
      && !Array.isArray(value)
      && typeof value.navigator?.userAgent === 'string'
      && value.navigator.userAgent.length > 0
      && typeof value.navigator?.platform === 'string'
      && Array.isArray(value.navigator?.languages)
      && value.navigator.languages.length > 0
      && typeof value.navigator?.hardwareConcurrency === 'number'
      && Number.isFinite(value.navigator.hardwareConcurrency)
      && value.navigator.hardwareConcurrency > 0
      && typeof value.locale?.timezone === 'string'
      && value.locale.timezone.length > 0
      && typeof value.locale?.intlLocale === 'string'
      && value.locale.intlLocale.length > 0;
  }

  function shortReason(value) {
    return String(value?.message ?? value ?? 'unknown error')
      .replace(/[\r\n\t]+/g, ' ')
      .slice(0, 240);
  }

  function boundedContext(name, setup) {
    return new Promise((resolve) => {
      let finished = false;
      const cleanups = [];
      const runCleanup = (cleanup) => {
        try {
          const result = cleanup();
          if (result && typeof result.catch === 'function') result.catch(() => {});
        } catch (_) {}
      };
      const addCleanup = (cleanup) => {
        if (finished) {
          runCleanup(cleanup);
          return false;
        }
        cleanups.push(cleanup);
        return true;
      };
      const finish = (record) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        for (const cleanup of cleanups.reverse()) {
          runCleanup(cleanup);
        }
        resolve(record);
      };
      const timer = setTimeout(() => {
        finish({ status: 'timeout', reason: `${name} did not answer within ${CONTEXT_TIMEOUT_MS}ms` });
      }, CONTEXT_TIMEOUT_MS);
      Promise.resolve()
        .then(() => setup({
          addCleanup,
          finish,
          isFinished: () => finished,
        }))
        .catch((error) => finish({ status: 'error', reason: shortReason(error) }));
    });
  }

  function requestId() {
    return safe(() => {
      const words = new Uint32Array(4);
      crypto.getRandomValues(words);
      return Array.from(words, (word) => word.toString(16).padStart(8, '0')).join('');
    }, `fallback-${Date.now()}-${Math.random()}`);
  }

  function responseRecord(event, expectedId) {
    const data = event?.data;
    if (!data
        || data.type !== 'proteus-context-result'
        || data.requestId !== expectedId) {
      return null;
    }
    if (data.ok !== true || !contextValuesValid(data.values)) {
      return {
        status: 'error',
        reason: shortReason(data.error || 'context returned malformed values'),
      };
    }
    return { status: 'ok', values: data.values };
  }

  function frameContext(name, href) {
    if (typeof document === 'undefined'
        || typeof window === 'undefined'
        || typeof MessageChannel === 'undefined') {
      return Promise.resolve({ status: 'unsupported', reason: `${name} APIs are unavailable` });
    }
    return boundedContext(name, ({ addCleanup, finish }) => {
      const id = requestId();
      const url = new URL(href, location.href);
      url.hash = id;
      const expectedOrigin = url.origin;
      const frame = document.createElement('iframe');
      frame.hidden = true;
      frame.setAttribute('aria-hidden', 'true');
      frame.src = url.href;
      addCleanup(() => frame.remove());
      let port = null;
      addCleanup(() => port?.close());
      const onWindowMessage = (event) => {
        if (event.source !== frame.contentWindow
            || event.origin !== expectedOrigin
            || event.data?.type !== 'proteus-context-ready'
            || event.data?.requestId !== id) {
          return;
        }
        window.removeEventListener('message', onWindowMessage);
        const channel = new MessageChannel();
        port = channel.port1;
        port.onmessage = (message) => {
          const record = responseRecord(message, id);
          if (record) finish(record);
        };
        port.onmessageerror = () => finish({
          status: 'error',
          reason: `${name} returned an unreadable message`,
        });
        port.start();
        frame.contentWindow.postMessage({
          type: 'proteus-context-collect',
          requestId: id,
        }, expectedOrigin, [channel.port2]);
      };
      window.addEventListener('message', onWindowMessage);
      addCleanup(() => window.removeEventListener('message', onWindowMessage));
      frame.onerror = () => finish({ status: 'error', reason: `${name} failed to load` });
      document.body.appendChild(frame);
    });
  }

  function crossOriginFrameHref() {
    if (typeof location === 'undefined'
        || !['http:', 'https:'].includes(location.protocol)) {
      return null;
    }
    const alternate = location.hostname === '127.0.0.1'
      ? 'localhost'
      : location.hostname === 'localhost'
        ? '127.0.0.1'
        : null;
    if (!alternate) return null;
    const url = new URL('./context-frame.html', location.href);
    url.hostname = alternate;
    return url.origin === location.origin ? null : url.href;
  }

  function dedicatedWorkerContext() {
    if (typeof Worker === 'undefined') {
      return Promise.resolve({ status: 'unsupported', reason: 'Dedicated Worker is unavailable' });
    }
    return boundedContext('dedicated-worker', ({ addCleanup, finish }) => {
      const id = requestId();
      const worker = new Worker('./context-worker.js', { name: 'proteus-context-dedicated' });
      addCleanup(() => worker.terminate());
      worker.onmessage = (event) => {
        const record = responseRecord(event, id);
        if (record) finish(record);
      };
      worker.onmessageerror = () => finish({
        status: 'error',
        reason: 'Dedicated Worker returned an unreadable message',
      });
      worker.onerror = (event) => finish({
        status: 'error',
        reason: shortReason(event.message || 'Dedicated Worker failed'),
      });
      worker.postMessage({ type: 'proteus-context-collect', requestId: id });
    });
  }

  function sharedWorkerContext() {
    if (typeof SharedWorker === 'undefined') {
      return Promise.resolve({ status: 'unsupported', reason: 'Shared Worker is unavailable' });
    }
    return boundedContext('shared-worker', ({ addCleanup, finish }) => {
      const id = requestId();
      const worker = new SharedWorker('./context-worker.js', 'proteus-context-shared');
      const port = worker.port;
      addCleanup(() => port.close());
      port.onmessage = (event) => {
        const record = responseRecord(event, id);
        if (record) finish(record);
      };
      port.onmessageerror = () => finish({
        status: 'error',
        reason: 'Shared Worker returned an unreadable message',
      });
      port.start();
      port.postMessage({ type: 'proteus-context-collect', requestId: id });
    });
  }

  async function waitForActivatedWorker(registration, isFinished) {
    for (let attempt = 0; attempt < 100; attempt++) {
      if (isFinished()) return null;
      const worker = registration.active || registration.waiting || registration.installing;
      if (worker?.state === 'activated') return worker;
      if (worker?.state === 'redundant') throw new Error('Service Worker became redundant');
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    throw new Error('Service Worker did not activate');
  }

  function serviceWorkerContext() {
    if (typeof navigator === 'undefined'
        || !navigator.serviceWorker
        || typeof MessageChannel === 'undefined') {
      return Promise.resolve({ status: 'unsupported', reason: 'Service Worker is unavailable' });
    }
    return boundedContext('service-worker', async ({
      addCleanup,
      finish,
      isFinished,
    }) => {
      const registration = await navigator.serviceWorker.register(
        './context-worker.js',
        { scope: './__proteus_context__/' },
      );
      if (!addCleanup(() => registration.unregister())) return;
      const worker = await waitForActivatedWorker(registration, isFinished);
      if (!worker || isFinished()) return;
      const id = requestId();
      const channel = new MessageChannel();
      if (!addCleanup(() => channel.port1.close())) return;
      channel.port1.onmessage = (event) => {
        const record = responseRecord(event, id);
        if (record) finish(record);
      };
      channel.port1.onmessageerror = () => finish({
        status: 'error',
        reason: 'Service Worker returned an unreadable message',
      });
      channel.port1.start();
      worker.postMessage(
        { type: 'proteus-context-collect', requestId: id },
        [channel.port2],
      );
    });
  }

  function valueAt(object, path) {
    return path.split('.').reduce(
      (value, part) => value == null ? undefined : value[part],
      object,
    );
  }

  function sameValue(left, right) {
    return JSON.stringify(left) === JSON.stringify(right);
  }

  async function collectCrossContext(mainValues) {
    const crossHref = crossOriginFrameHref();
    const tasks = [
      frameContext('same-origin-iframe', './context-frame.html'),
      crossHref
        ? frameContext('cross-origin-iframe', crossHref)
        : Promise.resolve({
          status: 'unsupported',
          reason: 'a distinct loopback origin is unavailable',
        }),
      dedicatedWorkerContext(),
      sharedWorkerContext(),
      serviceWorkerContext(),
    ];
    const records = await Promise.all(tasks);
    const contexts = {
      main: contextValuesValid(mainValues)
        ? { status: 'ok', values: mainValues }
        : { status: 'error', reason: 'main context returned malformed values' },
    };
    REQUIRED_CONTEXTS.slice(1).forEach((name, index) => {
      contexts[name] = records[index];
    });
    const mismatches = [];
    if (contexts.main.status === 'ok') {
      for (const name of REQUIRED_CONTEXTS.slice(1)) {
        const record = contexts[name];
        if (record.status !== 'ok') continue;
        const fields = [...CORE_CONTEXT_FIELDS];
        for (const field of OPTIONAL_CONTEXT_FIELDS) {
          const expected = valueAt(mainValues, field);
          const actual = valueAt(record.values, field);
          if (expected != null || actual != null) fields.push(field);
        }
        for (const field of fields) {
          const expected = valueAt(mainValues, field);
          const actual = valueAt(record.values, field);
          if (!sameValue(expected, actual)) {
            mismatches.push({ context: name, field, expected, actual });
          }
        }
      }
    }
    const complete = REQUIRED_CONTEXTS.every((name) => contexts[name]?.status === 'ok');
    return {
      schemaVersion: '1.0.0',
      requiredContexts: [...REQUIRED_CONTEXTS],
      contexts,
      mismatches,
      complete,
    };
  }

  // ---- V5 automation tells (page-observable subset) -----------------------
  function getAutomation() {
    const webdriver = safe(() => navigator.webdriver === true, null);
    // cdc_ artifacts: ChromeDriver injects window.cdc_* / document.$cdc_*
    let cdc = 0;
    safe(() => {
      for (const k of Object.getOwnPropertyNames(window)) if (/^[$]?cdc_/.test(k)) cdc++;
      for (const k of Object.getOwnPropertyNames(document)) if (/^[$]?cdc_/.test(k)) cdc++;
    });
    // headless tells: no plugins + certain UA markers + missing chrome object
    let headless = 0;
    safe(() => { if (/headless/i.test(navigator.userAgent)) headless++; });
    safe(() => { if (navigator.plugins && navigator.plugins.length === 0 && /chrome/i.test(navigator.userAgent)) headless++; });
    safe(() => { if (window.chrome === undefined && /chrome/i.test(navigator.userAgent)) headless++; });
    return {
      webdriver: webdriver,
      cdcArtifacts: cdc,
      headlessTells: headless,
      // runtimeEnableLeak and untrustedInput require the harness/driver; leave null.
      runtimeEnableLeak: null,
      untrustedInput: null,
    };
  }

  // ---- Assemble ------------------------------------------------------------
  async function collect() {
    const mainValues = await collectContextValues();
    const nav = {
      userAgent: mainValues.navigator.userAgent ?? '',
      platform: mainValues.navigator.platform ?? '',
      languages: mainValues.navigator.languages ?? [],
      hardwareConcurrency: mainValues.navigator.hardwareConcurrency,
      deviceMemory: mainValues.navigator.deviceMemory,
      vendor: mainValues.navigator.vendor ?? '',
    };
    const screenObj = {
      width: safe(() => screen.width, null),
      height: safe(() => screen.height, null),
      availWidth: safe(() => screen.availWidth, null),
      availHeight: safe(() => screen.availHeight, null),
      colorDepth: safe(() => screen.colorDepth, null),
      devicePixelRatio: safe(() => window.devicePixelRatio, null),
    };
    const locale = {
      timezone: mainValues.locale.timezone,
      acceptLanguage: null, // header-only; harness fills from the request it saw
      intlLocale: mainValues.locale.intlLocale,
    };
    const crossContext = await collectCrossContext(mainValues);
    const traces = {
      nonNativeToString: countNonNativeToString(),
      descriptorAnomalies: countDescriptorAnomalies(),
      crossContextMismatches: crossContext.complete
        ? crossContext.mismatches.length
        : null,
      crossContext,
    };

    return {
      _source: 'probe-page',
      _collectedAt: new Date().toISOString(),
      navigator: nav,
      screen: screenObj,
      gpu: mainValues.gpu,
      fonts: (function () { const f = detectFonts(); return f ? { set: f, policy: 'observed' } : null; })(),
      clientHints: mainValues.clientHints,
      locale: locale,
      traces: traces,
      automation: getAutomation(),
      // network (V4) is intentionally absent: it can only be judged by the
      // controlled-origin/sidecar harness, not by page JS. Left undefined so the
      // rules return `na` rather than a fabricated pass.
    };
  }

  const api = { collect, collectContextValues };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ProteusCollect = api;
})(typeof self !== 'undefined' ? self : this);
