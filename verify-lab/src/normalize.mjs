// Normalize heterogeneous fingerprint inputs into the flat observation shape the
// rules expect. Two input shapes are supported:
//
//  1. A Proteus profile config (docs/schemas/profile-config.schema.json) — the
//     forward-looking case: score an identity we intend to generate, before a
//     browser even exists (M0 can score configs today).
//  2. A raw collection from the probe page (probe-page/collect.js output) — the
//     runtime case for M1+, where a real (or fixture) browser reports what it
//     actually exposes.
//
// Both converge on the same observation so one rule catalog serves both.

/** Detect which input shape we were handed. */
function looksLikeProfileConfig(input) {
  return input && input.schemaVersion && input.persona && input.engine;
}

/** A fixture/config may carry out-of-band runtime observations alongside config fields. */
function hasRuntimeObservation(input) {
  return input?.traces !== undefined
    || input?.automation !== undefined
    || input?.network?._observed === true;
}

/** Map a profile config into the observation. Fields line up nearly 1:1. */
function fromProfileConfig(cfg, context) {
  return {
    scope: hasRuntimeObservation(cfg) ? 'runtime' : 'config',
    engine: cfg.engine,
    persona: cfg.persona,
    navigator: cfg.navigator,
    clientHints: cfg.clientHints,
    screen: cfg.screen,
    gpu: cfg.gpu,
    fonts: cfg.fonts,
    media: cfg.media,
    performance: cfg.performance,
    locale: cfg.locale,
    // traces/network/automation are only observable at runtime; a static config
    // can't fail them, so they stay absent (rules return `na`).
    traces: cfg.traces,
    network: cfg.network && cfg.network._observed ? cfg.network : undefined,
    automation: cfg.automation,
    context: { ...(cfg.context || {}), ...(context || {}) },
  };
}

/** Map a probe-page collection into the observation. */
function fromProbeCollection(raw, context) {
  const nav = raw.navigator || {};
  return {
    scope: 'runtime',
    engine: raw.engine || inferEngine(nav.userAgent),
    persona: raw.persona || inferPersona(nav, raw.screen),
    navigator: {
      userAgent: nav.userAgent,
      platform: nav.platform,
      languages: nav.languages,
      hardwareConcurrency: nav.hardwareConcurrency,
      deviceMemory: nav.deviceMemory,
      vendor: nav.vendor,
    },
    clientHints: raw.clientHints,
    screen: raw.screen,
    gpu: raw.gpu,
    fonts: raw.fonts,
    media: raw.media,
    performance: raw.performance,
    locale: raw.locale,
    traces: raw.traces,
    network: raw.network,
    automation: raw.automation,
    context: { ...(raw.context || {}), ...(context || {}) },
  };
}

/** Best-effort engine inference from a UA string (probe pages may not label it). */
function inferEngine(ua = '') {
  const u = ua.toLowerCase();
  let brand = 'Chrome', family = 'chromium';
  if (u.includes('firefox')) { brand = 'Firefox'; family = 'firefox'; }
  else if (u.includes('edg')) { brand = 'Edge'; }
  else if (u.includes('opr')) { brand = 'Opera'; }
  // Edge and Opera UAs also contain a Chrome token. Parse the token belonging to
  // the inferred brand, otherwise Opera 134 on Chromium 150 is mis-scored as
  // Opera 150.
  const versionToken = brand === 'Firefox' ? 'Firefox'
    : brand === 'Edge' ? 'Edg(?:A|iOS)?'
    : brand === 'Opera' ? 'OPR'
    : 'Chrome';
  const m = ua.match(new RegExp(`${versionToken}/(\\d+)\\.(\\d+)\\.?([\\d]+)?\\.?([\\d]+)?`, 'i'));
  const majorVersion = m ? Number(m[1]) : undefined;
  const fullVersion = m ? m.slice(1).filter(Boolean).join('.') : undefined;
  return { brand, family, majorVersion, fullVersion };
}

/** Best-effort persona inference from navigator + screen. */
function inferPersona(nav = {}, screen = {}) {
  const p = String(nav.platform || '');
  let os = 'Windows';
  if (/mac/i.test(p)) os = 'macOS';
  else if (/linux/i.test(p) && !/android/i.test(p)) os = 'Linux';
  else if (/win/i.test(p)) os = 'Windows';
  const cls = screen && screen.width && screen.width <= 1536 ? 'laptop' : 'desktop';
  return { os: { name: os }, device: { class: cls } };
}

/** Public entry: normalize any supported input into an observation. */
export function normalize(input, context) {
  return looksLikeProfileConfig(input) ? fromProfileConfig(input, context) : fromProbeCollection(input, context);
}
