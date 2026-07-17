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

  // ---- V3: cross-context consistency (main vs worker) ---------------------
  // Returns a Promise<number> of mismatches. Spins up a worker that reports the
  // same surfaces and compares. Falls back to 0-unmeasured if workers unavailable.
  function crossContextMismatches(mainValues) {
    return new Promise((resolve) => {
      if (typeof Worker === 'undefined' || typeof Blob === 'undefined' || typeof URL === 'undefined') {
        return resolve(null);
      }
      const src = `self.onmessage=function(){try{postMessage({ok:true,v:{` +
        `userAgent:navigator.userAgent,` +
        `platform:navigator.platform,` +
        `hardwareConcurrency:navigator.hardwareConcurrency,` +
        `languages:(navigator.languages||[]).join(',')` +
        `}})}catch(e){postMessage({ok:false})}}`;
      let url;
      try {
        url = URL.createObjectURL(new Blob([src], { type: 'application/javascript' }));
        const w = new Worker(url);
        const timer = setTimeout(() => { safe(() => w.terminate()); cleanup(); resolve(null); }, 1500);
        function cleanup() { safe(() => URL.revokeObjectURL(url)); clearTimeout(timer); }
        w.onmessage = (e) => {
          cleanup(); safe(() => w.terminate());
          if (!e.data || !e.data.ok) return resolve(null);
          const v = e.data.v;
          let m = 0;
          if (v.userAgent !== mainValues.userAgent) m++;
          if (v.platform !== mainValues.platform) m++;
          if (v.hardwareConcurrency !== mainValues.hardwareConcurrency) m++;
          if (v.languages !== (mainValues.languages || []).join(',')) m++;
          resolve(m);
        };
        w.onerror = () => { cleanup(); resolve(null); };
        w.postMessage('go');
      } catch (_) {
        resolve(null);
      }
    });
  }

  // ---- V1 surfaces ---------------------------------------------------------
  function getWebGL() {
    return safe(() => {
      const c = document.createElement('canvas');
      const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
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

  function getClientHints() {
    return safe(() => {
      const uaData = navigator.userAgentData;
      if (!uaData) return null;
      return {
        brands: uaData.brands,
        platform: uaData.platform,
        mobile: uaData.mobile,
      };
    }, null);
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
    const nav = {
      userAgent: safe(() => navigator.userAgent, ''),
      platform: safe(() => navigator.platform, ''),
      languages: safe(() => Array.from(navigator.languages || []), []),
      hardwareConcurrency: safe(() => navigator.hardwareConcurrency, null),
      deviceMemory: safe(() => navigator.deviceMemory, null),
      vendor: safe(() => navigator.vendor, ''),
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
      timezone: safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone, null),
      acceptLanguage: null, // header-only; harness fills from the request it saw
      intlLocale: safe(() => Intl.DateTimeFormat().resolvedOptions().locale, null),
    };
    const traces = {
      nonNativeToString: countNonNativeToString(),
      descriptorAnomalies: countDescriptorAnomalies(),
      crossContextMismatches: await crossContextMismatches(nav),
    };

    return {
      _source: 'probe-page',
      _collectedAt: new Date().toISOString(),
      navigator: nav,
      screen: screenObj,
      gpu: getWebGL(),
      fonts: (function () { const f = detectFonts(); return f ? { set: f, policy: 'observed' } : null; })(),
      clientHints: getClientHints(),
      locale: locale,
      traces: traces,
      automation: getAutomation(),
      // network (V4) is intentionally absent: it can only be judged by the
      // controlled-origin/sidecar harness, not by page JS. Left undefined so the
      // rules return `na` rather than a fabricated pass.
    };
  }

  const api = { collect };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ProteusCollect = api;
})(typeof self !== 'undefined' ? self : this);
