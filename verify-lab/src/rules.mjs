// The Node verification-lab rule catalog (tdd/02 §5, tdd/06 §4).
//
// Each rule is a pure predicate over a normalized fingerprint observation. It
// returns a Result describing pass/fail, the exact contradicting fields, and a
// human sentence — so a report can say
//   "timezone (America/New_York) contradicts proxy geo (DE)"
// rather than a bare fail. The Rust generator has an independent validator;
// RULES_VERSION, exact dataset bytes, golden vectors, and cross-language tests
// make semantic drift between the two implementations a failing contract.
//
// A rule may return `na` (not-applicable) when the observation lacks the fields
// it needs — e.g. R-TZ-GEO with no proxy attached. `na` never lowers a score.

import { gpuFamilyOf, normalizeGpuFamilyForOs } from './reference-util.mjs';

// Increment whenever the meaning or membership of the normative rule catalog
// changes. Generated configs record this value in provenance, and the
// cross-language conformance gate rejects drift from the shared dataset.
export const RULES_VERSION = '1.1.0';
const CONFIG_GENERATOR_VERSION = '0.2.0';

/**
 * @typedef {Object} RuleResult
 * @property {string} id           Rule id, e.g. "R-PLATFORM-GPU"
 * @property {string} vector       Threat vector, e.g. "V1"
 * @property {"pass"|"fail"|"na"} status
 * @property {string[]} fields     The specific contradicting fields (empty on pass/na)
 * @property {string} [reason]     Human sentence explaining a fail
 * @property {number} weight       Relative severity within its vector (default 1)
 */

const ok = (id, vector, weight = 1) => ({ id, vector, status: 'pass', fields: [], weight });
const na = (id, vector, weight = 1) => ({ id, vector, status: 'na', fields: [], weight });
const bad = (id, vector, fields, reason, weight = 1) => ({ id, vector, status: 'fail', fields, reason, weight });

// ------------------------------------------------------------------ V1 rules

/**
 * R-CONFIG-SCHEMA: the dependency-free score path enforces minimum envelope
 * completeness before semantic rules run. Full types, formats, enums, and
 * conditional shape remain owned by the normative Draft 2020-12 schema gate.
 */
function rConfigSchema(fp) {
  if (fp.scope !== 'config') return na('R-CONFIG-SCHEMA', 'V1', 3);
  const contract = fp.configContract;
  if (!contract || !Array.isArray(contract.presentFields)) {
    return bad('R-CONFIG-SCHEMA', 'V1', ['config'],
      'config input is missing normalized contract metadata', 3);
  }
  const requiredFields = [
    'schemaVersion',
    'profileId',
    'seed',
    'engine',
    'persona',
    'navigator',
    'clientHints',
    'screen',
    'gpu',
    'fonts',
    'media',
    'locale',
    'performance',
    'noise',
    'network',
    'rarity',
    'provenance',
    'signature',
  ];
  const present = new Set(contract.presentFields);
  const missing = requiredFields.filter((field) => !present.has(field));
  const invalid = [];
  if (fp.schemaVersion !== '1.0.0') invalid.push('schemaVersion');
  if (typeof contract.profileId !== 'string') invalid.push('profileId');
  if (typeof contract.seed !== 'string') invalid.push('seed');
  if (contract.network == null || typeof contract.network !== 'object') invalid.push('network');
  if (contract.signature == null || typeof contract.signature !== 'object') invalid.push('signature');
  const fields = [
    ...missing.map((field) => `config.${field}`),
    ...invalid.map((field) => `config.${field}`),
  ];
  return fields.length === 0
    ? ok('R-CONFIG-SCHEMA', 'V1', 3)
    : bad('R-CONFIG-SCHEMA', 'V1', [...new Set(fields)],
      `config is not a complete supported Profile Config envelope: ${[...new Set(fields)].join(', ')}`,
      3);
}

/** R-PLATFORM-GPU: navigator.platform's OS must permit the WebGL GPU vendor family. */
function rPlatformGpu(fp, ref) {
  const os = fp.persona?.os?.name;
  const renderer = fp.gpu?.webglRenderer;
  if (!os || !renderer) return na('R-PLATFORM-GPU', 'V1', 3);
  const family = gpuFamilyOf(renderer, ref) || gpuFamilyOf(fp.gpu?.webglVendor, ref);
  if (!family) return na('R-PLATFORM-GPU', 'V1', 3); // unknown GPU string, can't judge
  const allowed = ref.gpuVendorFamiliesByOs[os] || [];
  const candidates = normalizeGpuFamilyForOs(family);
  const permitted = candidates.some((c) => allowed.includes(c));
  return permitted
    ? ok('R-PLATFORM-GPU', 'V1', 3)
    : bad('R-PLATFORM-GPU', 'V1',
        ['persona.os.name', 'gpu.webglRenderer'],
        `GPU family "${family}" (from "${renderer}") is impossible on ${os}`,
        3);
}

/** R-PLATFORM-OS: navigator.platform token must be valid for the persona OS. */
function rPlatformOs(fp, ref) {
  const os = fp.persona?.os?.name;
  const platform = fp.navigator?.platform;
  if (!os || !platform) return na('R-PLATFORM-OS', 'V1', 2);
  const allowed = ref.platformByOs[os] || [];
  return allowed.includes(platform)
    ? ok('R-PLATFORM-OS', 'V1', 2)
    : bad('R-PLATFORM-OS', 'V1',
        ['persona.os.name', 'navigator.platform'],
        `navigator.platform "${platform}" is not a valid token for ${os} (expected one of ${allowed.join(', ')})`,
        2);
}

/**
 * R-PERSONA-TARGET: a current generated config must stay inside the implemented
 * M1A persona boundary. Runtime observations and non-catalog fixtures retain
 * the broader reference rules below.
 */
function rPersonaTarget(fp, ref) {
  if (!isM1AConfig(fp)) {
    return na('R-PERSONA-TARGET', 'V1', 3);
  }
  const expected = {
    'persona.os.name': 'Windows',
    'persona.os.version': '11',
    'persona.os.arch': 'x86_64',
    'persona.device.model': null,
  };
  const mismatches = Object.entries(expected)
    .filter(([path, value]) => path.split('.').reduce(
      (current, part) => current == null ? undefined : current[part],
      fp,
    ) !== value)
    .map(([path]) => path);
  if (!['desktop', 'laptop'].includes(fp.persona?.device?.class)) {
    mismatches.push('persona.device.class');
  }
  return mismatches.length === 0
    ? ok('R-PERSONA-TARGET', 'V1', 3)
    : bad('R-PERSONA-TARGET', 'V1', mismatches,
      `config persona is outside the implemented Windows 11 x86_64 desktop/laptop target: ${mismatches.join(', ')}`,
      3);
}

function versionMajor(value) {
  const match = String(value ?? '').match(/^(\d+)/);
  return match ? Number(match[1]) : null;
}

function exactValue(actual, expected) {
  if (Object.is(actual, expected)) return true;
  if (Array.isArray(actual) || Array.isArray(expected)) {
    return Array.isArray(actual)
      && Array.isArray(expected)
      && actual.length === expected.length
      && actual.every((value, index) => exactValue(value, expected[index]));
  }
  if (actual === null || expected === null
      || typeof actual !== 'object' || typeof expected !== 'object') {
    return false;
  }
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  return exactValue(actualKeys, expectedKeys)
    && actualKeys.every((key) => exactValue(actual[key], expected[key]));
}

function matchingEngineTarget(fp, ref) {
  if (!Array.isArray(ref?.engineTargets)) return null;
  return ref.engineTargets.find((target) =>
    target?.family === fp.engine?.family
      && target?.brand === fp.engine?.brand
      && Number(target?.majorVersion) === Number(fp.engine?.majorVersion)
      && String(target?.fullVersion) === String(fp.engine?.fullVersion)) || null;
}

/**
 * Every config-scope input uses generation-strict semantics. Completeness is
 * checked separately by R-CONFIG-SCHEMA; no removable body field is allowed to
 * act as an escape hatch into the tolerant runtime path.
 */
export function isM1AConfig(fp) {
  return fp?.scope === 'config';
}

function uaVersionForBrand(ua, brand) {
  const token = brand === 'Firefox' ? 'Firefox'
    : brand === 'Edge' ? 'Edg(?:A|iOS)?'
    : brand === 'Opera' ? 'OPR'
    : 'Chrome';
  const match = String(ua).match(new RegExp(`${token}/(\\d+(?:\\.\\d+){0,3})`, 'i'));
  return match?.[1] || null;
}

function uaMatchesOs(ua, os) {
  const value = String(ua);
  const tests = {
    Windows: /Windows NT/i,
    macOS: /Macintosh|Mac OS X/i,
    Linux: /Linux/i,
    ChromeOS: /CrOS/i,
    Android: /Android/i,
    iOS: /iPhone|iPad|iPod/i,
  };
  const test = tests[os];
  if (!test) return true;
  if (os === 'Linux' && /Android|CrOS/i.test(value)) return false;
  return test.test(value);
}

function clientHintBrandAliases(brand) {
  return {
    Chrome: ['Google Chrome'],
    Edge: ['Microsoft Edge'],
    Brave: ['Brave'],
    Opera: ['Opera', 'Opera GX'],
  }[brand] || [];
}

function findClientHintBrand(entries, aliases) {
  if (!Array.isArray(entries)) return null;
  const wanted = new Set(aliases.map((value) => value.toLowerCase()));
  return entries.find((entry) => wanted.has(String(entry?.brand || '').toLowerCase())) || null;
}

function expectedClientHintCpu(fp) {
  const configured = String(fp.persona?.os?.arch || '').toLowerCase();
  const ua = String(fp.navigator?.userAgent || '').toLowerCase();
  const platform = String(fp.navigator?.platform || '').toLowerCase();
  const source = configured || `${ua} ${platform}`;
  if (/arm64|aarch64/u.test(source)) {
    return { architecture: 'arm', bitness: '64' };
  }
  if (/x86_64|x64|win64|amd64/u.test(source)) {
    return { architecture: 'x86', bitness: '64' };
  }
  if (/x86|i[3-6]86/u.test(source)) {
    return { architecture: 'x86', bitness: '32' };
  }
  return null;
}

/** R-UA-CH: the UA string, the claimed brand, and Client Hints must agree, same family. */
function rUaCh(fp, ref) {
  const ua = fp.navigator?.userAgent;
  const brand = fp.engine?.brand;
  const family = fp.engine?.family;
  if (!ua || !brand) return na('R-UA-CH', 'V1', 3);
  const requestUa = fp.context?.requestUserAgent;
  if (typeof requestUa === 'string' && requestUa !== ua) {
    return bad('R-UA-CH', 'V1',
      ['navigator.userAgent', 'context.requestUserAgent'],
      `HTTP User-Agent differs from navigator.userAgent: "${requestUa}" versus "${ua}"`,
      3);
  }
  const fields = [];
  let reason = '';

  // family/brand consistency (no cross-family impersonation, ADR 0002)
  const expectedFamily = ref.browserFamily[brand];
  if (expectedFamily && family && expectedFamily !== family) {
    fields.push('engine.brand', 'engine.family');
    reason = `brand "${brand}" belongs to family "${expectedFamily}" but engine.family is "${family}"`;
    return bad('R-UA-CH', 'V1', fields, reason, 3);
  }

  // UA should mention the brand (or a known token). Chromium brands all contain "Chrome".
  const uaLc = ua.toLowerCase();
  const chromiumBrandTokens = { Chrome: 'chrome', Edge: 'edg', Brave: 'chrome', Opera: 'opr' };
  if (family === 'chromium') {
    if (!uaLc.includes('chrome')) {
      fields.push('navigator.userAgent', 'engine.brand');
      reason = `Chromium-family UA must contain "Chrome"; got "${ua}"`;
      return bad('R-UA-CH', 'V1', fields, reason, 3);
    }
    const tok = chromiumBrandTokens[brand];
    if (tok && !uaLc.includes(tok)) {
      fields.push('navigator.userAgent', 'engine.brand');
      reason = `brand "${brand}" expects token "${tok}" in the UA; got "${ua}"`;
      return bad('R-UA-CH', 'V1', fields, reason, 2);
    }
    if ((brand === 'Chrome' || brand === 'Brave') && /\b(?:edg|opr)\//i.test(ua)) {
      return bad('R-UA-CH', 'V1',
        ['navigator.userAgent', 'engine.brand'],
        `brand "${brand}" contradicts an Edge/Opera token in the UA`, 3);
    }
  } else if (family === 'firefox') {
    if (!uaLc.includes('firefox') || uaLc.includes('chrome')) {
      fields.push('navigator.userAgent', 'engine.family');
      reason = `Firefox-family UA must contain "Firefox" and not "Chrome"; got "${ua}"`;
      return bad('R-UA-CH', 'V1', fields, reason, 3);
    }
    if (fp.clientHints != null) {
      return bad('R-UA-CH', 'V1',
        ['clientHints', 'engine.family'],
        'Firefox-family profiles must not expose Chromium Client Hints', 3);
    }
  }

  const os = fp.persona?.os?.name;
  if (os && !uaMatchesOs(ua, os)) {
    return bad('R-UA-CH', 'V1',
      ['navigator.userAgent', 'persona.os.name'],
      `UA OS token contradicts persona OS ${os}: "${ua}"`, 3);
  }

  const engineMajor = fp.engine?.majorVersion;
  const fullVersion = fp.engine?.fullVersion;
  const fullMajor = versionMajor(fullVersion);
  if (engineMajor == null || fullMajor == null) return na('R-UA-CH', 'V1', 3);
  if (Number(engineMajor) !== fullMajor) {
    return bad('R-UA-CH', 'V1',
      ['engine.majorVersion', 'engine.fullVersion'],
      `engine.majorVersion ${engineMajor} contradicts fullVersion "${fullVersion}"`, 3);
  }

  const uaVersion = uaVersionForBrand(ua, brand);
  const uaMajor = versionMajor(uaVersion);
  if (uaMajor == null) return na('R-UA-CH', 'V1', 3);
  if (uaMajor !== Number(engineMajor)) {
    return bad('R-UA-CH', 'V1',
      ['navigator.userAgent', 'engine.majorVersion'],
      `UA ${brand} major ${uaMajor} contradicts engine major ${engineMajor}`, 3);
  }

  if (family !== 'chromium') return ok('R-UA-CH', 'V1', 3);

  const ch = fp.clientHints;
  const aliases = clientHintBrandAliases(brand);
  // A missing/partial CH collection is incomplete evidence, not a pass. Returning
  // na lets the scoring coverage gate produce `insufficient-data`.
  if (!ch || !Array.isArray(ch.brands) || !Array.isArray(ch.fullVersionList)
      || !ch.platform || typeof ch.mobile !== 'boolean') {
    return na('R-UA-CH', 'V1', 3);
  }

  // Client Hints platform must match persona OS (only Chromium exposes CH).
  const chPlatform = ch.platform;
  if (os) {
    const map = { Windows: 'Windows', macOS: 'macOS', Linux: 'Linux', ChromeOS: 'Chrome OS', Android: 'Android' };
    const expected = map[os] || os;
    if (chPlatform !== expected) {
      fields.push('clientHints.platform', 'persona.os.name');
      reason = `Sec-CH-UA-Platform "${chPlatform}" contradicts persona OS ${os} (expected "${expected}")`;
      return bad('R-UA-CH', 'V1', fields, reason, 3);
    }
  }

  const expectedMobile = ['phone', 'tablet'].includes(fp.persona?.device?.class)
    || ['Android', 'iOS'].includes(os);
  if (ch.mobile !== expectedMobile) {
    return bad('R-UA-CH', 'V1',
      ['clientHints.mobile', 'persona.device.class'],
      `Client Hints mobile=${ch.mobile} contradicts device class ${fp.persona?.device?.class ?? 'unknown'}`, 2);
  }

  const brandEntry = findClientHintBrand(ch.brands, aliases);
  if (!brandEntry) {
    return bad('R-UA-CH', 'V1',
      ['clientHints.brands', 'engine.brand'],
      `Client Hints brands do not contain the claimed brand "${brand}"`, 3);
  }
  if (versionMajor(brandEntry.version) !== Number(engineMajor)) {
    return bad('R-UA-CH', 'V1',
      ['clientHints.brands', 'engine.majorVersion'],
      `Client Hints ${brand} major ${versionMajor(brandEntry.version)} contradicts engine major ${engineMajor}`, 3);
  }

  const fullEntry = findClientHintBrand(ch.fullVersionList, aliases);
  if (!fullEntry) {
    return bad('R-UA-CH', 'V1',
      ['clientHints.fullVersionList', 'engine.brand'],
      `Client Hints full-version-list does not contain the claimed brand "${brand}"`, 3);
  }
  if (String(fullEntry.version) !== String(fullVersion)) {
    return bad('R-UA-CH', 'V1',
      ['clientHints.fullVersionList', 'engine.fullVersion'],
      `Client Hints full version "${fullEntry.version}" contradicts engine.fullVersion "${fullVersion}"`, 3);
  }

  const target = matchingEngineTarget(fp, ref);
  if (target && Object.hasOwn(target.platformVersions || {}, os)) {
    if (fp.scope === 'config' && brand === 'Chrome' && os === 'Windows') {
      const expectedUa =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        + 'AppleWebKit/537.36 (KHTML, like Gecko) '
        + `Chrome/${engineMajor}.0.0.0 Safari/537.36`;
      if (ua !== expectedUa) {
        return bad('R-UA-CH', 'V1',
          ['navigator.userAgent', 'engine.majorVersion', 'persona.os.name'],
          `config UA differs from the exact reduced Windows Chrome target: "${ua}"`,
          3);
      }
    }
    const targetPlatform = {
      Windows: 'Windows',
      macOS: 'macOS',
      Linux: 'Linux',
      ChromeOS: 'Chrome OS',
      Android: 'Android',
    }[os] || os;
    const cpu = expectedClientHintCpu(fp);
    if (!cpu) {
      return bad('R-UA-CH', 'V1',
        [
          'persona.os.arch',
          'navigator.userAgent',
          'navigator.platform',
          'clientHints.architecture',
          'clientHints.bitness',
        ],
        'Client Hints architecture/bitness cannot be bound to the claimed CPU architecture',
        3);
    }
    const expected = {
      brands: target.clientHintBrands,
      fullVersionList: target.clientHintFullVersionList,
      platform: targetPlatform,
      platformVersion: target.platformVersions?.[os],
      architecture: cpu.architecture,
      bitness: cpu.bitness,
      model: fp.persona?.device?.model ?? '',
      mobile: expectedMobile,
    };
    const mismatches = Object.entries(expected)
      .filter(([, value]) => value !== undefined && value !== null)
      .filter(([field, value]) => !exactValue(ch[field], value))
      .map(([field]) => field);
    if (mismatches.length > 0) {
      return bad('R-UA-CH', 'V1',
        mismatches.map((field) => `clientHints.${field}`),
        `Client Hints fields differ from the exact ${brand} ${fullVersion} dataset target: ${mismatches.join(', ')}`,
        3);
    }
  }

  return ok('R-UA-CH', 'V1', 3);
}

/** R-VENDOR-FAMILY: navigator.vendor must match the engine family. */
function rVendorFamily(fp, ref) {
  const family = fp.engine?.family;
  const vendor = fp.navigator?.vendor;
  if (!family || vendor === undefined) return na('R-VENDOR-FAMILY', 'V1', 1);
  const expected = ref.vendorByFamily[family];
  if (expected === undefined) return na('R-VENDOR-FAMILY', 'V1', 1);
  return vendor === expected
    ? ok('R-VENDOR-FAMILY', 'V1', 1)
    : bad('R-VENDOR-FAMILY', 'V1',
        ['navigator.vendor', 'engine.family'],
        `navigator.vendor "${vendor}" doesn't match ${family} (expected "${expected}")`,
        1);
}

/** R-FONT-OS: presented font set must be a superset of OS core and subset of OS superset. */
function rFontOs(fp, ref) {
  const os = fp.persona?.os?.name;
  const set = fp.fonts?.set;
  if (!os || !Array.isArray(set)) return na('R-FONT-OS', 'V1', 2);
  const table = ref.fontsByOs[os];
  if (!table) return na('R-FONT-OS', 'V1', 2);
  const present = new Set(set);
  const missingCore = table.core.filter((f) => !present.has(f));
  const supersetSet = new Set(table.superset);
  const foreign = set.filter((f) => !supersetSet.has(f));
  if (missingCore.length) {
    return bad('R-FONT-OS', 'V1',
      ['fonts.set', 'persona.os.name'],
      `${os} persona is missing core fonts: ${missingCore.slice(0, 5).join(', ')}${missingCore.length > 5 ? '…' : ''}`,
      2);
  }
  if (foreign.length) {
    return bad('R-FONT-OS', 'V1',
      ['fonts.set', 'persona.os.name'],
      `font set contains fonts foreign to ${os}: ${foreign.slice(0, 5).join(', ')}${foreign.length > 5 ? '…' : ''}`,
      2);
  }
  return ok('R-FONT-OS', 'V1', 2);
}

/** R-TZ-GEO: timezone must match the attached proxy's country (only when a proxy geo is known). */
function rTzGeo(fp, ref) {
  const tz = fp.locale?.timezone;
  const proxyCountry = fp.context?.proxyGeoCountry; // provided by Manager when a proxy is attached
  if (!tz) return na('R-TZ-GEO', 'V1', 3);
  if (!proxyCountry) return na('R-TZ-GEO', 'V1', 3); // no proxy → not applicable
  const tzRegion = ref.timezoneToRegion[tz];
  if (!tzRegion) return na('R-TZ-GEO', 'V1', 3); // unknown tz, can't judge
  return tzRegion === proxyCountry
    ? ok('R-TZ-GEO', 'V1', 3)
    : bad('R-TZ-GEO', 'V1',
        ['locale.timezone', 'context.proxyGeoCountry'],
        `timezone ${tz} (${tzRegion}) contradicts proxy geo (${proxyCountry})`,
        3);
}

function languageHead(value) {
  return String(value)
    .split(',')[0]
    .split(';')[0]
    .trim()
    .replace(/-(?:u|x)-.*$/i, '')
    .toLowerCase();
}

/** R-LANG: navigator, Accept-Language, Intl locale, and known proxy region must agree. */
function rLang(fp, ref) {
  const langs = fp.navigator?.languages;
  const accept = fp.locale?.acceptLanguage;
  const intlLocale = fp.locale?.intlLocale;
  if (!Array.isArray(langs) || !langs.length || !accept || !intlLocale) return na('R-LANG', 'V1', 1);
  const a = languageHead(langs[0]);
  const b = languageHead(accept);
  const c = languageHead(intlLocale);
  if (a !== b) {
    return bad('R-LANG', 'V1',
      ['navigator.languages', 'locale.acceptLanguage'],
      `navigator.languages[0] "${langs[0]}" head differs from Accept-Language "${accept}" head`, 1);
  }
  if (a !== c) {
    return bad('R-LANG', 'V1',
      ['navigator.languages', 'locale.intlLocale'],
      `navigator.languages[0] "${langs[0]}" contradicts Intl locale "${intlLocale}"`, 1);
  }
  if (isM1AConfig(fp)) {
    const timezone = fp.locale?.timezone;
    const timezoneRegion = ref.timezoneToRegion?.[timezone];
    const localeReference = timezoneRegion && ref.localeByRegion?.[timezoneRegion];
    if (!localeReference) {
      return bad('R-LANG', 'V1',
        ['locale.timezone'],
        `config timezone "${timezone}" is not bound to a dataset locale region`,
        1);
    }
    const expected = localeReference.languageHead;
    const acceptHead = String(accept).split(',')[0].trim();
    const mismatches = [];
    if (langs[0] !== expected) mismatches.push('navigator.languages');
    if (acceptHead !== expected) mismatches.push('locale.acceptLanguage');
    if (intlLocale !== expected) mismatches.push('locale.intlLocale');
    if (mismatches.length > 0) {
      return bad('R-LANG', 'V1',
        [...mismatches, 'locale.timezone'],
        `config locale fields do not match timezone region ${timezoneRegion} (expected ${expected})`,
        1);
    }
  }
  const proxyCountry = fp.context?.proxyGeoCountry;
  const regionalHead = proxyCountry && ref.localeByRegion?.[proxyCountry]?.languageHead;
  if (regionalHead && a !== languageHead(regionalHead)) {
    return bad('R-LANG', 'V1',
      ['navigator.languages', 'context.proxyGeoCountry'],
      `language "${langs[0]}" contradicts proxy region ${proxyCountry} (expected ${regionalHead})`, 1);
  }
  return ok('R-LANG', 'V1', 1);
}

/** R-SCREEN-REAL: (width,height,dpr) must be a really-shipped tuple for the device class. */
function rScreenReal(fp, ref) {
  const cls = fp.persona?.device?.class;
  const s = fp.screen;
  if (!cls || !s || s.width == null || s.height == null) return na('R-SCREEN-REAL', 'V1', 2);
  const tuples = ref.screenTuplesByClass[cls];
  if (!tuples) return na('R-SCREEN-REAL', 'V1', 2);
  const dpr = s.devicePixelRatio ?? 1.0;
  const strictConfig = isM1AConfig(fp);
  const match = tuples.some((t) =>
    t.width === s.width
      && t.height === s.height
      && (strictConfig ? t.dpr === dpr : Math.abs(t.dpr - dpr) < 0.01));
  if (match) {
    if (strictConfig
        && (s.availWidth !== s.width
          || s.availHeight !== s.height - 40
          || s.colorDepth !== 24)) {
      return bad('R-SCREEN-REAL', 'V1',
        [
          'screen.availWidth',
          'screen.availHeight',
          'screen.colorDepth',
          'screen.width',
          'screen.height',
        ],
        'config available dimensions and color depth do not exactly match the generated seed mode',
        2);
    }
    // avail must not exceed real, and must leave *some* chrome room on desktop/laptop.
    if (s.availWidth != null && s.availHeight != null) {
      if (s.availWidth > s.width || s.availHeight > s.height) {
        return bad('R-SCREEN-REAL', 'V1',
          ['screen.availWidth', 'screen.availHeight'],
          `avail dimensions (${s.availWidth}×${s.availHeight}) exceed screen (${s.width}×${s.height})`, 2);
      }
    }
    return ok('R-SCREEN-REAL', 'V1', 2);
  }
  return bad('R-SCREEN-REAL', 'V1',
    ['screen.width', 'screen.height', 'screen.devicePixelRatio'],
    `resolution ${s.width}×${s.height}@${dpr} is not a shipped ${cls} mode`,
    2);
}

/** R-HW-PAIR: (hardwareConcurrency, deviceMemory) must be a plausible pair for the class. */
function rHwPair(fp, ref) {
  const cls = fp.persona?.device?.class;
  const cores = fp.navigator?.hardwareConcurrency;
  const mem = fp.navigator?.deviceMemory;
  if (!cls || cores == null || mem == null) return na('R-HW-PAIR', 'V1', 1);
  if (isM1AConfig(fp)) {
    const pairs = ref.hardwarePairsByClass?.[cls];
    const exactPair = Array.isArray(pairs)
      && pairs.some((pair) =>
        pair.hardwareConcurrency === cores && pair.deviceMemory === mem);
    return exactPair
      ? ok('R-HW-PAIR', 'V1', 1)
      : bad('R-HW-PAIR', 'V1',
        [
          'persona.device.class',
          'navigator.hardwareConcurrency',
          'navigator.deviceMemory',
        ],
        `config hardware pair ${cores} cores/${mem}GiB is not an exact ${cls} dataset candidate`,
        1);
  }
  const t = ref.hardwareByClass[cls];
  if (!t) return na('R-HW-PAIR', 'V1', 1);
  const fields = [];
  let reason = '';
  if (cores < t.coresMin || cores > t.coresMax) {
    fields.push('navigator.hardwareConcurrency');
    reason = `hardwareConcurrency ${cores} out of range for ${cls} [${t.coresMin}, ${t.coresMax}]`;
  }
  if (!t.memoryValues.includes(mem)) {
    fields.push('navigator.deviceMemory');
    reason += (reason ? '; ' : '') + `deviceMemory ${mem} is not a standard Chrome bucket (${t.memoryValues.join('/')})`;
  }
  const floor = t.minMemoryForCores?.[String(cores)];
  if (floor && mem < floor) {
    if (!fields.includes('navigator.deviceMemory')) fields.push('navigator.deviceMemory');
    if (!fields.includes('navigator.hardwareConcurrency')) fields.push('navigator.hardwareConcurrency');
    reason += (reason ? '; ' : '') + `${cores} cores with only ${mem}GiB is implausible`;
  }
  return fields.length ? bad('R-HW-PAIR', 'V1', fields, reason, 1) : ok('R-HW-PAIR', 'V1', 1);
}

/** R-WEBGL-WEBGPU: WebGL vendor/renderer and WebGPU adapter families must agree. */
function rWebglWebgpu(fp, ref) {
  const gpu = fp.gpu;
  if (!gpu) return na('R-WEBGL-WEBGPU', 'V1', 3);

  // A current generated config must be one of the dataset's complete, jointly
  // sampled GPU profiles. Runtime observations remain family-checked below:
  // the curated generator profiles are not an exhaustive list of real devices.
  const os = fp.persona?.os?.name;
  const deviceClass = fp.persona?.device?.class;
  const profiles = ref.gpuProfilesByOs?.[os];
  if (isM1AConfig(fp) && Array.isArray(profiles)) {
    const exactProfile = profiles.find((profile) =>
      gpu.webglVendor === profile.webglVendor
        && gpu.webglRenderer === profile.webglRenderer
        && exactValue(gpu.webglExtensions, profile.webglExtensions)
        && exactValue(gpu.webgpuAdapter, profile.webgpuAdapter));
    if (!exactProfile) {
      return bad('R-WEBGL-WEBGPU', 'V1',
        [
          'gpu.webglVendor',
          'gpu.webglRenderer',
          'gpu.webglExtensions',
          'gpu.webgpuAdapter',
        ],
        `GPU fields do not exactly match one ${os} dataset profile`,
        3);
    }
    if (!Array.isArray(exactProfile.allowedDeviceClasses)
        || !exactProfile.allowedDeviceClasses.includes(deviceClass)) {
      return bad('R-WEBGL-WEBGPU', 'V1',
        ['gpu', 'persona.device.class'],
        `GPU profile "${exactProfile.webglRenderer}" is not allowed for device class "${deviceClass}"`,
        3);
    }
    return ok('R-WEBGL-WEBGPU', 'V1', 3);
  }

  const rendererFamily = gpuFamilyOf(gpu.webglRenderer, ref);
  const vendorFamily = gpuFamilyOf(gpu.webglVendor, ref);
  if (rendererFamily && vendorFamily) {
    const rendererCandidates = normalizeGpuFamilyForOs(rendererFamily);
    const vendorCandidates = normalizeGpuFamilyForOs(vendorFamily);
    if (!rendererCandidates.some((family) => vendorCandidates.includes(family))) {
      return bad('R-WEBGL-WEBGPU', 'V1',
        ['gpu.webglVendor', 'gpu.webglRenderer'],
        `WebGL vendor family "${vendorFamily}" contradicts renderer family "${rendererFamily}"`, 3);
    }
  }

  const webglFamily = rendererFamily || vendorFamily;
  const adapter = gpu.webgpuAdapter;
  if (!webglFamily || adapter == null) return na('R-WEBGL-WEBGPU', 'V1', 3);
  const adapterText = typeof adapter === 'string'
    ? adapter
    : [adapter.vendor, adapter.description, adapter.name, adapter.device].filter(Boolean).join(' ');
  const webgpuFamily = gpuFamilyOf(adapterText, ref);
  if (!webgpuFamily) return na('R-WEBGL-WEBGPU', 'V1', 3);
  const webglCandidates = normalizeGpuFamilyForOs(webglFamily);
  const webgpuCandidates = normalizeGpuFamilyForOs(webgpuFamily);
  return webglCandidates.some((family) => webgpuCandidates.includes(family))
    ? ok('R-WEBGL-WEBGPU', 'V1', 3)
    : bad('R-WEBGL-WEBGPU', 'V1',
      ['gpu.webglRenderer', 'gpu.webgpuAdapter'],
      `WebGL family "${webglFamily}" contradicts WebGPU adapter family "${webgpuFamily}"`, 3);
}

/** R-MEDIA-OS: dataset profile, harness conclusions, and OS-specific voice IDs must match. */
function rMediaOs(fp, ref) {
  const media = fp.media;
  const os = fp.persona?.os?.name;
  if (!media || !os) return na('R-MEDIA-OS', 'V1', 2);
  if (typeof media.osMatches === 'boolean') {
    return media.osMatches
      ? ok('R-MEDIA-OS', 'V1', 2)
      : bad('R-MEDIA-OS', 'V1', ['media', 'persona.os.name'],
        `observed media devices or speech voices contradict ${os}`, 2);
  }

  const voices = Array.isArray(media.speechVoices) ? media.speechVoices : null;
  const devices = Array.isArray(media.devices) ? media.devices : null;
  if (!voices && !devices) return na('R-MEDIA-OS', 'V1', 2);
  const profiles = ref.mediaProfilesByOs?.[os];
  if (isM1AConfig(fp) && Array.isArray(profiles)) {
    const expected = profiles.find((profile) => profile.id === media.profileId);
    if (!expected) {
      return bad('R-MEDIA-OS', 'V1',
        ['media.profileId', 'persona.os.name'],
        `config media profile "${media.profileId}" is not valid for ${os}`, 2);
    }
    const deviceShapeMatches = Array.isArray(devices)
      && devices.length === expected.devices.length
      && expected.devices.every((item, index) =>
        devices[index]?.kind === item.kind
          && devices[index]?.label === item.label
          && typeof devices[index]?.deviceId === 'string'
          && devices[index].deviceId.length > 0
          && typeof devices[index]?.groupId === 'string'
          && devices[index].groupId.length > 0);
    const uniqueDeviceIds = Array.isArray(devices)
      && new Set(devices.map((device) => device.deviceId)).size === devices.length;
    if (!deviceShapeMatches
        || !uniqueDeviceIds
        || !exactValue(voices, expected.speechVoices)) {
      return bad('R-MEDIA-OS', 'V1',
        [
          'media.devices',
          'media.speechVoices',
          'media.profileId',
          'persona.os.name',
        ],
        `config media fields do not exactly match dataset profile "${media.profileId}" for ${os}`,
        2);
    }
    return ok('R-MEDIA-OS', 'V1', 2);
  }
  if (media.profileId && Array.isArray(profiles)) {
    const expected = profiles.find((profile) => profile.id === media.profileId);
    if (!expected) {
      return bad('R-MEDIA-OS', 'V1',
        ['media.profileId', 'persona.os.name'],
        `media profile "${media.profileId}" is not valid for ${os}`, 2);
    }
    const deviceShapeMatches = Array.isArray(devices)
      && devices.length === expected.devices.length
      && expected.devices.every((item, index) =>
        devices[index]?.kind === item.kind && devices[index]?.label === item.label);
    const voiceShapeMatches = Array.isArray(voices)
      && voices.length === expected.speechVoices.length
      && expected.speechVoices.every((item, index) =>
        voices[index]?.name === item.name && voices[index]?.lang === item.lang);
    if (!deviceShapeMatches || !voiceShapeMatches) {
      return bad('R-MEDIA-OS', 'V1',
        ['media.devices', 'media.speechVoices', 'media.profileId'],
        `media fields do not match dataset profile "${media.profileId}" for ${os}`, 2);
    }
  }
  const voiceText = (voices || []).map((voice) => typeof voice === 'string'
    ? voice
    : [voice?.name, voice?.voiceURI].filter(Boolean).join(' ')).join(' ');
  if (!['macOS', 'iOS'].includes(os) && /com\.apple\.speech/i.test(voiceText)) {
    return bad('R-MEDIA-OS', 'V1',
      ['media.speechVoices', 'persona.os.name'],
      `Apple speech voice identifiers contradict ${os}`, 2);
  }
  if (os !== 'Windows' && /Microsoft (?:David|Zira|Mark|Hazel)/i.test(voiceText)) {
    return bad('R-MEDIA-OS', 'V1',
      ['media.speechVoices', 'persona.os.name'],
      `Windows speech voices contradict ${os}`, 2);
  }
  return ok('R-MEDIA-OS', 'V1', 2);
}

/** R-PERF-PRECISION: config or measured timer precision must match its reference. */
function rPerfPrecision(fp, ref) {
  const perf = fp.performance;
  if (!perf) return na('R-PERF-PRECISION', 'V1', 2);
  if (typeof perf.precisionMatches === 'boolean') {
    return perf.precisionMatches
      ? ok('R-PERF-PRECISION', 'V1', 2)
      : bad('R-PERF-PRECISION', 'V1',
        ['performance.nowResolutionMs', 'engine.fullVersion'],
        'performance.now precision differs from the claimed browser behavior', 2);
  }
  if (typeof perf.timerPrecisionMicros === 'number') {
    const expectedMicros = ref.performanceByFamily?.[fp.engine?.family]?.timerPrecisionMicros;
    if (typeof expectedMicros !== 'number') return na('R-PERF-PRECISION', 'V1', 2);
    return perf.timerPrecisionMicros === expectedMicros
      ? ok('R-PERF-PRECISION', 'V1', 2)
      : bad('R-PERF-PRECISION', 'V1',
        ['performance.timerPrecisionMicros', 'engine.family'],
        `timer precision ${perf.timerPrecisionMicros}µs contradicts ${fp.engine?.family} reference ${expectedMicros}µs`, 2);
  }
  const observed = perf.nowResolutionMs ?? perf.precisionMs;
  const expected = perf.expectedNowResolutionMs ?? perf.expectedPrecisionMs;
  if (typeof observed !== 'number' || typeof expected !== 'number') {
    return na('R-PERF-PRECISION', 'V1', 2);
  }
  const tolerance = Math.max(1e-9, Math.abs(expected) * 0.01);
  return Math.abs(observed - expected) <= tolerance
    ? ok('R-PERF-PRECISION', 'V1', 2)
    : bad('R-PERF-PRECISION', 'V1',
      ['performance.nowResolutionMs', 'performance.expectedNowResolutionMs'],
      `performance.now resolution ${observed}ms contradicts expected ${expected}ms`, 2);
}

/** R-NOISE-BOUNDS: current generated configs use the bounded M1A amplitude. */
function rNoiseBounds(fp, ref) {
  if (!isM1AConfig(fp)) {
    return na('R-NOISE-BOUNDS', 'V1', 2);
  }
  const noise = fp.noise;
  if (!noise) return na('R-NOISE-BOUNDS', 'V1', 2);
  const mismatches = ['canvas', 'webgl', 'audio']
    .filter((surface) => noise[surface]?.amplitude !== 'hw-natural')
    .map((surface) => `noise.${surface}.amplitude`);
  return mismatches.length === 0
    ? ok('R-NOISE-BOUNDS', 'V1', 2)
    : bad('R-NOISE-BOUNDS', 'V1', mismatches,
      `config noise amplitudes exceed the M1A hw-natural policy: ${mismatches.join(', ')}`,
      2);
}

/**
 * R-PROVENANCE: bind every semantic input available to the independent Node
 * verifier. The exact dataset digest comes from the Node reference loader.
 */
function rProvenance(fp, ref) {
  if (!isM1AConfig(fp)) {
    return na('R-PROVENANCE', 'V1', 3);
  }
  const provenance = fp.provenance;
  if (!provenance || typeof ref?._sha256 !== 'string') {
    return na('R-PROVENANCE', 'V1', 3);
  }
  const expected = {
    datasetVersion: ref._version,
    datasetSha256: ref._sha256,
    engineVersion: fp.engine?.fullVersion,
    rulesVersion: RULES_VERSION,
    generatorVersion: CONFIG_GENERATOR_VERSION,
  };
  const mismatches = Object.entries(expected)
    .filter(([field, value]) => provenance[field] !== value)
    .map(([field]) => `provenance.${field}`);
  return mismatches.length === 0
    ? ok('R-PROVENANCE', 'V1', 3)
    : bad('R-PROVENANCE', 'V1', mismatches,
      `config provenance does not identify the exact dataset/engine/rules/generator inputs: ${mismatches.join(', ')}`,
      3);
}

// ------------------------------------------------------------------ V2 rules

/** R-VERSION-LIVE: engine major version must sit within the live population window. */
function rVersionLive(fp, ref) {
  const brand = fp.engine?.brand;
  const full = fp.engine?.fullVersion;
  const major = fp.engine?.majorVersion ?? (full ? Number(String(full).split('.')[0]) : null);
  if (!brand || major == null) return na('R-VERSION-LIVE', 'V2', 2);
  if (isM1AConfig(fp) && !matchingEngineTarget(fp, ref)) {
    const result = bad('R-VERSION-LIVE', 'V2',
      ['engine.family', 'engine.brand', 'engine.majorVersion', 'engine.fullVersion'],
      `${brand} ${full} is not an exact current dataset engine target`,
      2);
    // A stale runtime observation is probabilistic, but a generated config
    // claiming a target absent from its bound dataset is a deterministic error.
    result.severity = 'fatal';
    return result;
  }
  const win = ref.liveVersionWindow[brand];
  if (!win) return na('R-VERSION-LIVE', 'V2', 2);
  if (major >= win.min && major <= win.max) return ok('R-VERSION-LIVE', 'V2', 2);
  return bad('R-VERSION-LIVE', 'V2',
    ['engine.majorVersion'],
    `${brand} ${major} is outside the live window [${win.min}, ${win.max}] — stale/rare versions are a V2 signal`,
    2);
}

/** R-RARITY-RANGE: informational score and verdict must remain self-consistent. */
function rRarityRange(fp, ref) {
  if (!isM1AConfig(fp)) {
    return na('R-RARITY-RANGE', 'V2', 2);
  }
  const rarity = fp.rarity;
  if (!rarity) return na('R-RARITY-RANGE', 'V2', 2);
  const value = rarity.score;
  if (typeof value !== 'number'
      || !Number.isFinite(value)
      || value < 0
      || value > 1
      || (value !== 0 && value < 0.000001)) {
    return bad('R-RARITY-RANGE', 'V2',
      ['rarity.score'],
      `rarity score ${value} is outside the canonical [0,1] Profile Config range`,
      2);
  }
  const expected = value >= 0.7 ? 'blends-in'
    : value >= 0.5 ? 'borderline'
      : 'too-rare';
  return rarity.verdict === expected
    ? ok('R-RARITY-RANGE', 'V2', 2)
    : bad('R-RARITY-RANGE', 'V2',
      ['rarity.score', 'rarity.verdict'],
      `rarity verdict "${rarity.verdict}" contradicts score ${value} (expected "${expected}")`,
      2);
}

// ------------------------------------------------------------------ V3 rules (trace tells)

/** R-NATIVE-TOSTRING: probed getters must report native code (no injection tell). */
function rNativeToString(fp) {
  const t = fp.traces;
  if (!t || typeof t.nonNativeToString !== 'number') return na('R-NATIVE-TOSTRING', 'V3', 3);
  return t.nonNativeToString === 0
    ? ok('R-NATIVE-TOSTRING', 'V3', 3)
    : bad('R-NATIVE-TOSTRING', 'V3',
        ['traces.nonNativeToString'],
        `${t.nonNativeToString} overridden function(s) do not report [native code] — a JS-injection tell (V3)`,
        3);
}

/** R-DESCRIPTOR-SHAPE: property descriptors must match stock (accessor vs data, flags). */
function rDescriptorShape(fp) {
  const t = fp.traces;
  if (!t || typeof t.descriptorAnomalies !== 'number') return na('R-DESCRIPTOR-SHAPE', 'V3', 2);
  return t.descriptorAnomalies === 0
    ? ok('R-DESCRIPTOR-SHAPE', 'V3', 2)
    : bad('R-DESCRIPTOR-SHAPE', 'V3',
        ['traces.descriptorAnomalies'],
        `${t.descriptorAnomalies} property descriptor anomaly(ies) vs stock shape (V3)`,
        2);
}

const CROSS_CONTEXT_SCHEMA_VERSION = '1.0.0';
const REQUIRED_CROSS_CONTEXTS = Object.freeze([
  'main',
  'same-origin-iframe',
  'cross-origin-iframe',
  'dedicated-worker',
  'shared-worker',
  'service-worker',
]);
const CROSS_CONTEXT_STATUSES = new Set(['ok', 'unsupported', 'timeout', 'error']);
const REQUIRED_CROSS_CONTEXT_VALUES = Object.freeze([
  ['navigator.userAgent', (value) => typeof value === 'string' && value.length > 0],
  ['navigator.platform', (value) => typeof value === 'string'],
  ['navigator.languages', (value) =>
    Array.isArray(value)
      && value.length > 0
      && value.every((entry) => typeof entry === 'string')],
  ['navigator.hardwareConcurrency', (value) =>
    typeof value === 'number' && Number.isFinite(value) && value > 0],
  ['locale.timezone', (value) => typeof value === 'string' && value.length > 0],
  ['locale.intlLocale', (value) => typeof value === 'string' && value.length > 0],
]);
const FRAME_CROSS_CONTEXTS = Object.freeze([
  'main',
  'same-origin-iframe',
  'cross-origin-iframe',
]);
const CONDITIONAL_CROSS_CONTEXT_VALUES = Object.freeze([
  ['navigator.vendor', FRAME_CROSS_CONTEXTS],
  ['navigator.deviceMemory', REQUIRED_CROSS_CONTEXTS],
  ['clientHints.brands', REQUIRED_CROSS_CONTEXTS],
  ['clientHints.fullVersionList', REQUIRED_CROSS_CONTEXTS],
  ['clientHints.platform', REQUIRED_CROSS_CONTEXTS],
  ['clientHints.platformVersion', REQUIRED_CROSS_CONTEXTS],
  ['clientHints.architecture', REQUIRED_CROSS_CONTEXTS],
  ['clientHints.bitness', REQUIRED_CROSS_CONTEXTS],
  ['clientHints.model', REQUIRED_CROSS_CONTEXTS],
  ['clientHints.mobile', REQUIRED_CROSS_CONTEXTS],
  ['gpu.webglVendor', REQUIRED_CROSS_CONTEXTS],
  ['gpu.webglRenderer', REQUIRED_CROSS_CONTEXTS],
]);

function isStructuredCrossContext(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function unique(values) {
  return [...new Set(values)];
}

function crossContextValueAt(value, path) {
  return path.split('.').reduce(
    (current, part) => current == null ? undefined : current[part],
    value,
  );
}

function crossContextValuesAreComplete(values) {
  return isStructuredCrossContext(values)
    && REQUIRED_CROSS_CONTEXT_VALUES.every(
      ([path, validate]) => validate(crossContextValueAt(values, path)),
    );
}

function crossContextValueIsPresent(value) {
  return value !== undefined && value !== null;
}

function sameCrossContextValue(left, right) {
  return exactValue(left, right);
}

/**
 * Artifact baselines must carry the structured report itself, not merely the
 * legacy mismatch counter. Status/value validity remains the rule's job so a
 * complete report can faithfully preserve a measured failure.
 */
export function hasStructuredSixContextEvidence(observation) {
  const report = observation?.traces?.crossContext;
  return isStructuredCrossContext(report)
    && report.schemaVersion === CROSS_CONTEXT_SCHEMA_VERSION
    && Array.isArray(report.requiredContexts)
    && report.requiredContexts.length === REQUIRED_CROSS_CONTEXTS.length
    && REQUIRED_CROSS_CONTEXTS.every(
      (context, index) => report.requiredContexts[index] === context,
    )
    && isStructuredCrossContext(report.contexts)
    && Object.keys(report.contexts).length === REQUIRED_CROSS_CONTEXTS.length
    && REQUIRED_CROSS_CONTEXTS.every(
      (context) => Object.hasOwn(report.contexts, context)
        && isStructuredCrossContext(report.contexts[context]),
    );
}

/**
 * R-CROSS-CONTEXT: every required frame/worker context must be measured and
 * expose the same values. Structured M1 evidence is fail-closed: incomplete
 * coverage is itself a failure, not an unmeasured/pass result.
 */
function rCrossContext(fp) {
  const t = fp.traces;
  const report = t?.crossContext;

  if (isStructuredCrossContext(report)) {
    const fields = [];
    const reasons = [];

    if (report.schemaVersion !== CROSS_CONTEXT_SCHEMA_VERSION) {
      fields.push('traces.crossContext.schemaVersion');
      reasons.push(
        `schemaVersion must be "${CROSS_CONTEXT_SCHEMA_VERSION}"`,
      );
    }

    const requiredContextsAreExact = Array.isArray(report.requiredContexts)
      && report.requiredContexts.length === REQUIRED_CROSS_CONTEXTS.length
      && REQUIRED_CROSS_CONTEXTS.every(
        (context, index) => report.requiredContexts[index] === context,
      );
    if (!requiredContextsAreExact) {
      fields.push('traces.crossContext.requiredContexts');
      reasons.push(
        `requiredContexts must be exactly [${REQUIRED_CROSS_CONTEXTS.join(', ')}]`,
      );
    }

    const contexts = isStructuredCrossContext(report.contexts)
      ? report.contexts
      : null;
    const contextNamesAreExact = contexts
      && Object.keys(contexts).length === REQUIRED_CROSS_CONTEXTS.length
      && REQUIRED_CROSS_CONTEXTS.every((context) =>
        Object.hasOwn(contexts, context));
    if (!contextNamesAreExact) {
      fields.push('traces.crossContext.contexts');
      reasons.push(
        `contexts must contain exactly [${REQUIRED_CROSS_CONTEXTS.join(', ')}]`,
      );
    }
    const unmeasured = [];
    for (const context of REQUIRED_CROSS_CONTEXTS) {
      const observation = contexts && Object.hasOwn(contexts, context)
        ? contexts[context]
        : undefined;
      if (!isStructuredCrossContext(observation)) {
        fields.push(`traces.crossContext.contexts.${context}`);
        unmeasured.push(`${context} (missing)`);
        continue;
      }
      if (!CROSS_CONTEXT_STATUSES.has(observation.status)) {
        fields.push(`traces.crossContext.contexts.${context}.status`);
        unmeasured.push(`${context} (invalid status "${String(observation.status)}")`);
        continue;
      }
      if (observation.status !== 'ok') {
        fields.push(`traces.crossContext.contexts.${context}.status`);
        unmeasured.push(`${context} (${observation.status})`);
      } else if (!crossContextValuesAreComplete(observation.values)) {
        fields.push(`traces.crossContext.contexts.${context}.values`);
        unmeasured.push(`${context} (malformed values)`);
      }
    }
    if (unmeasured.length > 0) {
      reasons.push(`unmeasured required contexts: ${unmeasured.join(', ')}`);
    }

    if (report.complete !== true) {
      fields.push('traces.crossContext.complete');
      reasons.push('complete must be true');
    }

    if (!Array.isArray(report.mismatches)) {
      fields.push('traces.crossContext.mismatches');
      reasons.push('mismatches must be an array');
    } else {
      const mismatchReasons = [];
      report.mismatches.forEach((mismatch, index) => {
        const base = `traces.crossContext.mismatches.${index}`;
        if (!isStructuredCrossContext(mismatch)) {
          fields.push(base);
          mismatchReasons.push(`entry ${index} is malformed`);
          return;
        }
        const context = mismatch.context;
        const field = mismatch.field;
        if (!REQUIRED_CROSS_CONTEXTS.includes(context)) {
          fields.push(`${base}.context`);
          mismatchReasons.push(
            `entry ${index} has invalid context "${String(context)}"`,
          );
          return;
        }
        if (typeof field !== 'string' || field.length === 0) {
          fields.push(`${base}.field`);
          mismatchReasons.push(`entry ${index} in ${context} has no field`);
          return;
        }
        fields.push(`${base}.context`, `${base}.field`);
        mismatchReasons.push(`${context}/${field}`);
      });
      if (mismatchReasons.length > 0) {
        reasons.unshift(`mismatches: ${mismatchReasons.join(', ')}`);
      }
    }

    const mainValues = contexts?.main?.values;
    if (crossContextValuesAreComplete(mainValues)) {
      const undeclared = [];
      for (const [path] of REQUIRED_CROSS_CONTEXT_VALUES) {
        if (!sameCrossContextValue(
          crossContextValueAt(fp, path),
          crossContextValueAt(mainValues, path),
        )) {
          fields.push(
            path,
            `traces.crossContext.contexts.main.values.${path}`,
          );
          undeclared.push(`main/${path}`);
        }
      }
      for (const context of REQUIRED_CROSS_CONTEXTS.slice(1)) {
        const values = contexts?.[context]?.values;
        if (!crossContextValuesAreComplete(values)) continue;
        for (const [path] of REQUIRED_CROSS_CONTEXT_VALUES) {
          if (!sameCrossContextValue(
            crossContextValueAt(mainValues, path),
            crossContextValueAt(values, path),
          )) {
            fields.push(
              `traces.crossContext.contexts.main.values.${path}`,
              `traces.crossContext.contexts.${context}.values.${path}`,
            );
            undeclared.push(`${context}/${path}`);
          }
        }
      }
      for (const [path, applicableContexts] of CONDITIONAL_CROSS_CONTEXT_VALUES) {
        const expected = crossContextValueAt(fp, path);
        const mainValue = crossContextValueAt(mainValues, path);
        const expectedIsPresent = crossContextValueIsPresent(expected);
        const mainIsPresent = crossContextValueIsPresent(mainValue);
        if (expectedIsPresent !== mainIsPresent
            || (expectedIsPresent
              && !sameCrossContextValue(expected, mainValue))) {
          fields.push(
            path,
            `traces.crossContext.contexts.main.values.${path}`,
          );
          undeclared.push(
            `main/${path}${mainIsPresent ? '' : ' (missing)'}`,
          );
        }
        for (const context of applicableContexts.slice(1)) {
          const values = contexts?.[context]?.values;
          if (!crossContextValuesAreComplete(values)) continue;
          const actual = crossContextValueAt(values, path);
          const actualIsPresent = crossContextValueIsPresent(actual);
          if (expectedIsPresent && !actualIsPresent) {
            fields.push(
              `traces.crossContext.contexts.main.values.${path}`,
              `traces.crossContext.contexts.${context}.values.${path}`,
            );
            undeclared.push(`${context}/${path} (missing)`);
          } else if (!expectedIsPresent && actualIsPresent) {
            fields.push(
              `traces.crossContext.contexts.main.values.${path}`,
              `traces.crossContext.contexts.${context}.values.${path}`,
            );
            undeclared.push(`${context}/${path} (unexpected presence)`);
          } else if (expectedIsPresent
              && !sameCrossContextValue(expected, actual)) {
            fields.push(
              `traces.crossContext.contexts.main.values.${path}`,
              `traces.crossContext.contexts.${context}.values.${path}`,
            );
            undeclared.push(`${context}/${path}`);
          }
        }
      }
      if (undeclared.length > 0) {
        reasons.unshift(
          `observed values disagree independently of the declared mismatch list: ${undeclared.join(', ')}`,
        );
      }
    }

    return reasons.length === 0
      ? ok('R-CROSS-CONTEXT', 'V3', 3)
      : bad(
          'R-CROSS-CONTEXT',
          'V3',
          unique(fields),
          `cross-context evidence failed closed — ${reasons.join('; ')}`,
          3,
        );
  }

  // Legacy fixture compatibility. A null/missing legacy value remains
  // unmeasured; a numeric zero/nonzero retains the original pass/fail meaning.
  if (!t || typeof t.crossContextMismatches !== 'number') return na('R-CROSS-CONTEXT', 'V3', 3);
  return t.crossContextMismatches === 0
    ? ok('R-CROSS-CONTEXT', 'V3', 3)
    : bad('R-CROSS-CONTEXT', 'V3',
        ['traces.crossContextMismatches'],
        `${t.crossContextMismatches} value(s) differ between main frame and iframe/worker — injection leak (V3)`,
        3);
}

// ------------------------------------------------------------------ V4 rules (network)

/** R-TLS-PARITY: the JA3/JA4 the origin saw must match the claimed browser family. */
function rTlsParity(fp) {
  const n = fp.network;
  if (!n || n.ja3Matches == null) return na('R-TLS-PARITY', 'V4', 3);
  if (typeof n.ja3Matches !== 'boolean') {
    return bad('R-TLS-PARITY', 'V4',
      ['network.ja3Matches'],
      `network.ja3Matches must be a boolean observation, got ${typeof n.ja3Matches}`,
      3);
  }
  return n.ja3Matches
    ? ok('R-TLS-PARITY', 'V4', 3)
    : bad('R-TLS-PARITY', 'V4',
        ['network.ja3', 'engine.brand'],
        `observed TLS fingerprint does not match a real ${fp.engine?.brand ?? 'browser'} handshake (V4 cross-layer mismatch)`,
        3);
}

/** R-H2-PARITY: the HTTP/2 fingerprint must match the claimed browser. */
function rH2Parity(fp) {
  const n = fp.network;
  if (!n || n.h2Matches == null) return na('R-H2-PARITY', 'V4', 2);
  if (typeof n.h2Matches !== 'boolean') {
    return bad('R-H2-PARITY', 'V4',
      ['network.h2Matches'],
      `network.h2Matches must be a boolean observation, got ${typeof n.h2Matches}`,
      2);
  }
  return n.h2Matches
    ? ok('R-H2-PARITY', 'V4', 2)
    : bad('R-H2-PARITY', 'V4',
        ['network.h2', 'engine.brand'],
        `observed HTTP/2 fingerprint does not match a real ${fp.engine?.brand ?? 'browser'} (V4)`,
        2);
}

/** R-NO-DNS-LEAK / R-NO-WEBRTC-LEAK: no real-IP / DNS leakage. */
function rNoDnsLeak(fp) {
  const n = fp.network;
  if (!n || n.dnsLeak == null) return na('R-NO-DNS-LEAK', 'V4', 3);
  return n.dnsLeak === false
    ? ok('R-NO-DNS-LEAK', 'V4', 3)
    : bad('R-NO-DNS-LEAK', 'V4', ['network.dnsLeak'], `DNS resolution leaked outside the proxy tunnel (V4)`, 3);
}
function rNoWebrtcLeak(fp) {
  const n = fp.network;
  if (!n || n.webrtcLeak == null) return na('R-NO-WEBRTC-LEAK', 'V4', 3);
  return n.webrtcLeak === false
    ? ok('R-NO-WEBRTC-LEAK', 'V4', 3)
    : bad('R-NO-WEBRTC-LEAK', 'V4', ['network.webrtcLeak'], `WebRTC exposed the real IP outside the proxy (V4)`, 3);
}

// ------------------------------------------------------------------ V5 rules (automation)

/** R-NO-WEBDRIVER: navigator.webdriver must be false/undefined. */
function rNoWebdriver(fp) {
  const a = fp.automation;
  if (!a || a.webdriver == null) return na('R-NO-WEBDRIVER', 'V5', 3);
  return a.webdriver === false
    ? ok('R-NO-WEBDRIVER', 'V5', 3)
    : bad('R-NO-WEBDRIVER', 'V5', ['automation.webdriver'], `navigator.webdriver is true — automation tell (V5)`, 3);
}

/** R-NO-CDP-ARTIFACTS: no cdc_ / driver globals. */
function rNoCdpArtifacts(fp) {
  const a = fp.automation;
  if (!a || a.cdcArtifacts == null) return na('R-NO-CDP-ARTIFACTS', 'V5', 3);
  return a.cdcArtifacts === 0
    ? ok('R-NO-CDP-ARTIFACTS', 'V5', 3)
    : bad('R-NO-CDP-ARTIFACTS', 'V5', ['automation.cdcArtifacts'], `${a.cdcArtifacts} ChromeDriver/Selenium artifact(s) present (V5)`, 3);
}

/** R-NO-RUNTIME-LEAK: the Runtime.enable CDP leak must not be observable. */
function rNoRuntimeLeak(fp) {
  const a = fp.automation;
  if (!a || a.runtimeEnableLeak == null) return na('R-NO-RUNTIME-LEAK', 'V5', 3);
  return a.runtimeEnableLeak === false
    ? ok('R-NO-RUNTIME-LEAK', 'V5', 3)
    : bad('R-NO-RUNTIME-LEAK', 'V5', ['automation.runtimeEnableLeak'], `Runtime.enable side effects are observable — CDP automation leak (V5)`, 3);
}

/** R-ISTRUSTED: synthetic input must not betray isTrusted=false where a human would be true. */
function rIsTrusted(fp) {
  const a = fp.automation;
  if (!a || a.untrustedInput == null) return na('R-ISTRUSTED', 'V5', 2);
  return a.untrustedInput === false
    ? ok('R-ISTRUSTED', 'V5', 2)
    : bad('R-ISTRUSTED', 'V5', ['automation.untrustedInput'], `input events report isTrusted=false — synthetic-event tell (V5)`, 2);
}

/** R-NO-HEADLESS: no headless tells. */
function rNoHeadless(fp) {
  const a = fp.automation;
  if (!a || a.headlessTells == null) return na('R-NO-HEADLESS', 'V5', 2);
  return a.headlessTells === 0
    ? ok('R-NO-HEADLESS', 'V5', 2)
    : bad('R-NO-HEADLESS', 'V5', ['automation.headlessTells'], `${a.headlessTells} headless indicator(s) present (V5)`, 2);
}

/** The ordered catalog. Adding a rule here is the only step needed to extend coverage. */
export const RULES = [
  rConfigSchema, rPlatformGpu, rPlatformOs, rPersonaTarget, rUaCh, rVendorFamily, rFontOs, rTzGeo, rLang,
  rScreenReal, rHwPair, rWebglWebgpu, rMediaOs, rPerfPrecision, rNoiseBounds, rProvenance,       // V1
  rVersionLive, rRarityRange,                                                                    // V2
  rNativeToString, rDescriptorShape, rCrossContext,                                               // V3
  rTlsParity, rH2Parity, rNoDnsLeak, rNoWebrtcLeak,                                               // V4
  rNoWebdriver, rNoCdpArtifacts, rNoRuntimeLeak, rIsTrusted, rNoHeadless,                          // V5
];

// Per-rule severity. `fatal` = a deterministic tell: if it fires, a competent
// detector can flag the session on that signal alone, so it must gate the verdict
// (it cannot be averaged away by clean vectors). `soft` = a matter of degree
// (rarity), which contributes to the score gradient but does not by itself mean
// "caught". This mirrors the threat model: V1/V3/V4/V5 contain deterministic
// tells; V2 rarity is probabilistic. Severity is per-rule (not just per-vector)
// so future soft tells (a mild behavioral hint, a weak rarity signal) can be
// added without gating the verdict.
export const SEVERITY = {
  'R-CONFIG-SCHEMA': 'fatal',
  'R-PLATFORM-GPU': 'fatal', 'R-PLATFORM-OS': 'fatal', 'R-PERSONA-TARGET': 'fatal',
  'R-UA-CH': 'fatal',
  'R-VENDOR-FAMILY': 'fatal', 'R-FONT-OS': 'fatal', 'R-TZ-GEO': 'fatal',
  'R-LANG': 'fatal', 'R-SCREEN-REAL': 'fatal', 'R-HW-PAIR': 'fatal',
  'R-WEBGL-WEBGPU': 'fatal', 'R-MEDIA-OS': 'fatal', 'R-PERF-PRECISION': 'fatal',
  'R-NOISE-BOUNDS': 'fatal', 'R-PROVENANCE': 'fatal',
  'R-VERSION-LIVE': 'soft', 'R-RARITY-RANGE': 'fatal',
  'R-NATIVE-TOSTRING': 'fatal', 'R-DESCRIPTOR-SHAPE': 'fatal', 'R-CROSS-CONTEXT': 'fatal',
  'R-TLS-PARITY': 'fatal', 'R-H2-PARITY': 'fatal', 'R-NO-DNS-LEAK': 'fatal', 'R-NO-WEBRTC-LEAK': 'fatal',
  'R-NO-WEBDRIVER': 'fatal', 'R-NO-CDP-ARTIFACTS': 'fatal', 'R-NO-RUNTIME-LEAK': 'fatal',
  'R-ISTRUSTED': 'fatal', 'R-NO-HEADLESS': 'fatal',
};

/** Run every rule over a normalized fingerprint observation, attaching severity. */
export function runRules(fp, ref) {
  return RULES.map((fn) => {
    const r = fn(fp, ref);
    r.severity ||= SEVERITY[r.id] || 'fatal';
    return r;
  });
}
