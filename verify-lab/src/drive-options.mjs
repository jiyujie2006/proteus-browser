import { isAbsolute } from 'node:path';

const PLATFORMS = new Set([
  'windows-x64',
  'macos-universal',
  'linux-x64',
]);

export function parseDriveOptions(args, {
  defaultChrome,
  defaultUrl = 'http://127.0.0.1:8791/probe-page/headless.html',
} = {}) {
  const values = {
    chrome: defaultChrome,
    externalContainment: false,
    json: false,
    platform: null,
    url: defaultUrl,
  };
  const seen = new Set();
  let chromeExplicit = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (['--json', '--external-containment'].includes(arg)) {
      if (seen.has(arg)) throw new TypeError(`${arg} may only be supplied once`);
      seen.add(arg);
      if (arg === '--json') values.json = true;
      if (arg === '--external-containment') values.externalContainment = true;
      continue;
    }
    if (!['--url', '--chrome', '--platform'].includes(arg)) {
      throw new TypeError(`unknown argument: ${arg}`);
    }
    if (seen.has(arg)) throw new TypeError(`${arg} may only be supplied once`);
    seen.add(arg);
    const value = args[index + 1];
    if (!value || value.startsWith('--')) {
      throw new TypeError(`${arg} requires a value`);
    }
    index += 1;
    if (arg === '--url') values.url = value;
    if (arg === '--chrome') {
      values.chrome = value;
      chromeExplicit = true;
    }
    if (arg === '--platform') values.platform = value;
  }

  if (values.platform !== null && !PLATFORMS.has(values.platform)) {
    throw new TypeError(`unsupported --platform ${values.platform}`);
  }
  if (values.json && (!chromeExplicit || values.platform === null)) {
    throw new TypeError(
      '--json requires an explicit --chrome <engine-executable> and --platform',
    );
  }
  if (values.json && !isAbsolute(values.chrome)) {
    throw new TypeError(
      '--json requires --chrome to be an absolute engine-executable path',
    );
  }
  if (values.json && seen.has('--url')) {
    throw new TypeError(
      '--json uses the internally hosted controlled probe and rejects --url',
    );
  }
  if (values.json && !values.externalContainment) {
    throw new TypeError(
      '--json requires --external-containment on an externally enforced ephemeral runner',
    );
  }
  if (!values.json && values.externalContainment) {
    throw new TypeError('--external-containment is only valid with --json');
  }
  return {
    ...values,
    artifactPath: values.json ? values.chrome : null,
  };
}
