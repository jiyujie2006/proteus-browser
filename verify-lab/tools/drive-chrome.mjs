// tools/drive-chrome.mjs — drive a real headless Chrome against the probe page,
// collect its LIVE fingerprint, and score it. Zero npm dependencies: uses Node's
// built-in streams to speak CDP over Chromium's process-bound debugging pipe.
//
// This is the M1-style runtime path exercised early: instead of a fixture, we
// score what an actual browser exposes. For stock Chrome (unmodified) we EXPECT
// tells — the point is to prove the ruler measures a real browser end-to-end, and
// to establish the baseline the Proteus engine must improve on.
//
// Usage:
//   node tools/drive-chrome.mjs [--url URL] [--chrome /path]
//   node tools/drive-chrome.mjs --json --external-containment
//     --chrome /path --platform <id> [--linux-sandbox /root-owned/path]

import { execFileSync, spawn } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { loadReference } from '../src/reference.mjs';
import { normalize } from '../src/normalize.mjs';
import { score } from '../src/score.mjs';
import { renderReport } from '../src/report.mjs';
import { buildArtifactBaselineReport } from '../src/artifact-report.mjs';
import { closeBrowserGracefully } from '../src/browser-close.mjs';
import { CdpPipeClient } from '../src/cdp-pipe.mjs';
import { startControlledProbeServer } from '../src/controlled-probe.mjs';
import { parseDriveOptions } from '../src/drive-options.mjs';
import { validateLinuxSandbox } from '../src/linux-sandbox.mjs';
import {
  readNetworkTimeAuditFile,
} from '../src/network-time-audit.mjs';
import {
  M0_EXTERNAL_EXECUTION_ISOLATION,
  sha256File,
} from '../../scripts/m0-evidence.mjs';

function firstExisting(paths) { return paths.find((p) => existsSync(p)) || 'google-chrome'; }
function canonicalExecutable(path) {
  const real = realpathSync(path);
  if (!lstatSync(real).isFile()) {
    throw new TypeError(`--chrome is not an ordinary executable file: ${path}`);
  }
  return real;
}

function artifactStat(path) {
  const stat = statSync(path, { bigint: true });
  return {
    ctimeNs: stat.ctimeNs.toString(),
    dev: stat.dev.toString(),
    ino: stat.ino.toString(),
    mode: stat.mode.toString(),
    mtimeNs: stat.mtimeNs.toString(),
    size: stat.size.toString(),
  };
}

function sameArtifactStat(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function captureArtifactBeforeLaunch(path) {
  const before = artifactStat(path);
  const sha256 = sha256File(path);
  const after = artifactStat(path);
  if (!sameArtifactStat(before, after)) {
    throw new Error('engine executable changed while its pre-launch hash was computed');
  }
  return { sha256, stat: after };
}

const sleep = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

function assertHostPlatform(platform) {
  const expected = {
    'windows-x64': 'win32',
    'macos-universal': 'darwin',
    'linux-x64': 'linux',
  }[platform];
  if (process.platform !== expected) {
    throw new Error(
      `--platform ${platform} requires a ${expected} host, got ${process.platform}`,
    );
  }
}

function assertSameArtifact(expected, actual, label) {
  if (expected.sha256 !== actual.sha256
      || !sameArtifactStat(expected.stat, actual.stat)) {
    throw new Error(`${label} does not match the pre-launch executable bytes`);
  }
}

async function captureLinuxProcessImage(pid) {
  const path = `/proc/${pid}/exe`;
  let lastError = null;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      return captureArtifactBeforeLaunch(path);
    } catch (error) {
      lastError = error;
      await sleep(20);
    }
  }
  throw new Error(
    `cannot inspect the launched Linux process image: ${lastError?.message}`,
  );
}

function macProcessTextIdentity(pid) {
  const output = execFileSync(
    '/usr/sbin/lsof',
    ['-a', '-p', String(pid), '-d', 'txt', '-F0Di'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
  );
  let inTextRecord = false;
  let device = null;
  let inode = null;
  for (const rawField of output.split('\0')) {
    const field = rawField.replace(/^[\r\n]+/, '');
    if (field.startsWith('f')) {
      inTextRecord = field === 'ftxt';
      continue;
    }
    if (!inTextRecord) continue;
    if (field.startsWith('D')) {
      device = BigInt(field.slice(1)).toString();
    } else if (field.startsWith('i')) {
      inode = BigInt(field.slice(1)).toString();
    }
  }
  if (device === null || inode === null) {
    throw new Error('lsof did not return the launched macOS text vnode identity');
  }
  return { dev: device, ino: inode };
}

async function assertRunningProcessImage(
  chrome,
  executablePath,
  expected,
  platform,
) {
  if (!Number.isInteger(chrome.pid)) {
    throw new Error('Chromium did not expose a child process id');
  }
  if (platform === 'linux-x64') {
    assertSameArtifact(
      expected,
      await captureLinuxProcessImage(chrome.pid),
      'launched /proc process image',
    );
    return;
  }
  if (platform === 'macos-universal') {
    let identity = null;
    let lastError = null;
    for (let attempt = 0; attempt < 50 && identity === null; attempt += 1) {
      try {
        identity = macProcessTextIdentity(chrome.pid);
      } catch (error) {
        lastError = error;
        await sleep(20);
      }
    }
    if (!identity) {
      throw new Error(
        `cannot inspect the launched macOS process image: ${lastError?.message}`,
      );
    }
    if (identity.dev !== expected.stat.dev || identity.ino !== expected.stat.ino) {
      throw new Error('launched macOS text vnode is not the declared executable');
    }
  }
  // The Windows launch guard holds the path against writes/rename throughout
  // the run. macOS additionally needs this path-byte recheck after vnode proof.
  assertSameArtifact(
    expected,
    captureArtifactBeforeLaunch(executablePath),
    'running executable path',
  );
}

async function acquireWindowsLaunchGuard(executablePath, expected) {
  if (process.platform !== 'win32') return null;
  const systemRoot = process.env.SystemRoot ?? process.env.WINDIR;
  if (!systemRoot) throw new Error('Windows launch guard requires SystemRoot');
  const powershell = join(
    systemRoot,
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  );
  const script = [
    "$ErrorActionPreference='Stop'",
    '$file=[IO.File]::Open($env:PROTEUS_LOCK_PATH,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)',
    "[Console]::Out.WriteLine('READY')",
    '[Console]::Out.Flush()',
    '[Console]::In.ReadLine() | Out-Null',
    '$file.Dispose()',
  ].join(';');
  const guard = spawn(
    powershell,
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
    {
      env: { ...process.env, PROTEUS_LOCK_PATH: executablePath },
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    },
  );
  let stdout = '';
  let stderr = '';
  let ready = false;
  let releasing = false;
  let terminalError = null;
  let resolveReady;
  let rejectReady;
  let resolveTerminal;
  const readySignal = new Promise((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  const terminal = new Promise((resolve) => {
    resolveTerminal = resolve;
  });
  const fail = (error) => {
    terminalError ??= error;
    rejectReady(terminalError);
  };
  guard.once('error', (error) => {
    fail(new Error(`Windows executable launch guard failed: ${error.message}`));
    resolveTerminal({ code: null, signal: null });
  });
  guard.once('close', (code, signal) => {
    if (!releasing) {
      fail(new Error(
        `Windows executable launch guard exited unexpectedly (${signal ?? code}): ${stderr.slice(-400)}`,
      ));
    } else if (code !== 0) {
      terminalError ??= new Error(
        `Windows executable launch guard exited ${signal ?? code}: ${stderr.slice(-400)}`,
      );
    }
    resolveTerminal({ code, signal });
  });
  guard.stdin.on('error', (error) => {
    fail(new Error(`Windows executable launch guard input failed: ${error.message}`));
  });
  guard.stderr.on('data', (chunk) => {
    stderr = appendTail(stderr, chunk);
  });
  guard.stdout.on('data', (chunk) => {
    stdout = appendTail(stdout, chunk, 4 * 1024);
    if (!ready && stdout.split(/\r?\n/u).includes('READY')) {
      ready = true;
      resolveReady();
    }
  });

  const waitForTerminal = (label) => new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`${label} timed out`)),
      5_000,
    );
    terminal.then((result) => {
      clearTimeout(timeout);
      resolve(result);
    });
  });

  const readyTimeout = setTimeout(
    () => rejectReady(new Error('Windows executable launch guard timed out')),
    5_000,
  );
  try {
    await readySignal;
  } catch (error) {
    releasing = true;
    guard.stdin.destroy();
    guard.kill();
    await waitForTerminal('Windows executable launch guard shutdown')
      .catch(() => {});
    throw error;
  } finally {
    clearTimeout(readyTimeout);
  }

  const assertHeld = () => {
    if (!ready
        || releasing
        || terminalError
        || guard.exitCode !== null
        || guard.signalCode !== null) {
      throw terminalError ?? new Error(
        'Windows executable launch guard is not holding the executable',
      );
    }
  };

  try {
    assertHeld();
    assertSameArtifact(
      expected,
      captureArtifactBeforeLaunch(executablePath),
      'locked Windows executable',
    );
  } catch (error) {
    releasing = true;
    guard.stdin.end('\n');
    await waitForTerminal('Windows executable launch guard release')
      .catch(() => {});
    throw error;
  }
  return {
    assertHeld,
    async release() {
      assertHeld();
      releasing = true;
      guard.stdin.end('\n');
      await waitForTerminal('Windows executable launch guard release');
      if (terminalError) throw terminalError;
    },
  };
}

function machineEnvironment(userDataDir, linuxSandbox) {
  const inherited = process.env;
  const environment = {
    HOME: userDataDir,
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    TEMP: userDataDir,
    TMP: userDataDir,
    TMPDIR: userDataDir,
    USERPROFILE: userDataDir,
    XDG_CACHE_HOME: join(userDataDir, 'cache'),
    XDG_CONFIG_HOME: join(userDataDir, 'config'),
  };
  for (const name of ['ComSpec', 'SystemDrive', 'SystemRoot', 'WINDIR']) {
    if (inherited[name]) environment[name] = inherited[name];
  }
  if (linuxSandbox !== null) {
    environment.CHROME_DEVEL_SANDBOX = linuxSandbox;
  }
  return environment;
}

function appendTail(current, chunk, limit = 64 * 1024) {
  return (current + chunk.toString()).slice(-limit);
}

async function writeStdout(text) {
  await new Promise((resolve, reject) => {
    process.stdout.write(text, 'utf8', (error) => (
      error ? reject(error) : resolve()
    ));
  });
}

// Defense-in-depth teardown only. A hostile descendant can escape a POSIX
// process group or a Windows parent tree, which is why machine mode separately
// requires externally enforced disposable-runner containment.
async function terminateBrowser(chrome) {
  if (!chrome || !Number.isInteger(chrome.pid)) return;
  const active = chrome.exitCode === null && chrome.signalCode === null;
  const closed = active ? once(chrome, 'close') : null;

  if (process.platform === 'win32') {
    const systemRoot = process.env.SystemRoot ?? process.env.WINDIR;
    if (!systemRoot) throw new Error('Windows process-tree cleanup requires SystemRoot');
    try {
      execFileSync(
        join(systemRoot, 'System32', 'taskkill.exe'),
        ['/PID', String(chrome.pid), '/T', '/F'],
        { stdio: 'ignore', windowsHide: true },
      );
    } catch (error) {
      if (active) throw new Error(`failed to terminate Chromium process tree: ${error.message}`);
      return;
    }
  } else {
    try {
      process.kill(-chrome.pid, 'SIGKILL');
    } catch (error) {
      if (error.code !== 'ESRCH') {
        throw new Error(`failed to terminate Chromium process group: ${error.message}`);
      }
      return;
    }
  }
  if (!active) return;
  const timeout = new Promise((_, reject) => {
    const timer = setTimeout(
      () => reject(new Error('Chromium process tree did not close after termination')),
      5_000,
    );
    timer.unref();
  });
  await Promise.race([closed, timeout]);
}

async function main(options) {
  const {
    chrome: requestedChrome,
    externalContainment: EXTERNAL_CONTAINMENT,
    json: JSON_OUTPUT,
    linuxSandbox: requestedLinuxSandbox,
    platform: PLATFORM,
    url: URL,
  } = options;
  const CHROME = JSON_OUTPUT
    ? canonicalExecutable(requestedChrome)
    : requestedChrome;
  if (JSON_OUTPUT) {
    assertHostPlatform(PLATFORM);
    if (EXTERNAL_CONTAINMENT !== true) {
      throw new Error(
        'machine mode requires externally enforced ephemeral-runner containment',
      );
    }
  }
  const linuxSandbox = requestedLinuxSandbox === null
    ? null
    : validateLinuxSandbox(requestedLinuxSandbox);
  const userDataDir = mkdtempSync(join(tmpdir(), 'proteus-chrome-'));
  const netLogPath = join(userDataDir, 'netlog.json');
  let chrome = null;
  let client = null;
  let probeServer = null;
  let launchGuard = null;
  let browserCloseRequested = false;
  let stderr = '';

  try {
    const artifactBefore = JSON_OUTPUT
      ? captureArtifactBeforeLaunch(CHROME)
      : null;
    if (JSON_OUTPUT) {
      launchGuard = await acquireWindowsLaunchGuard(CHROME, artifactBefore);
      probeServer = await startControlledProbeServer();
      launchGuard?.assertHeld();
    }
    const targetUrl = probeServer?.url ?? URL;
    chrome = spawn(CHROME, [
      '--headless=new',
      '--remote-debugging-pipe',
      `--user-data-dir=${userDataDir}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-gpu',
      ...(JSON_OUTPUT ? [
        `--log-net-log=${netLogPath}`,
        '--net-log-capture-mode=Everything',
      ] : []),
      'about:blank',
    ], {
      detached: process.platform !== 'win32',
      env: JSON_OUTPUT
        ? machineEnvironment(userDataDir, linuxSandbox)
        : process.env,
      stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'],
    });
    chrome.stderr.on('data', (chunk) => {
      stderr = appendTail(stderr, chunk);
    });
    client = new CdpPipeClient(chrome.stdio[4], chrome.stdio[3]);
    chrome.once('error', (error) => client.abort(error));
    chrome.once('exit', (code, signal) => {
      if (!browserCloseRequested) {
        client.abort(new Error(
          `Chromium exited before collection completed (${signal ?? code})`,
        ));
      }
    });
    if (JSON_OUTPUT) {
      launchGuard?.assertHeld();
      await assertRunningProcessImage(
        chrome,
        CHROME,
        artifactBefore,
        PLATFORM,
      );
      launchGuard?.assertHeld();
    }

    // Open a tab, navigate, wait, evaluate the collector promise.
    const { targetId } = await client.send(
      'Target.createTarget',
      { url: 'about:blank' },
    );
    if (!targetId) throw new Error('CDP did not return a targetId');
    const { sessionId } = await client.send(
      'Target.attachToTarget',
      { targetId, flatten: true },
    );
    if (!sessionId) throw new Error('CDP did not return a sessionId');

    await client.send('Page.enable', {}, sessionId);
    await client.send('Runtime.enable', {}, sessionId);
    await client.send('Page.setLifecycleEventsEnabled', { enabled: true }, sessionId);
    const navigation = await client.send(
      'Page.navigate',
      { url: targetUrl },
      sessionId,
    );
    if (navigation.errorText) {
      throw new Error(`probe navigation failed: ${navigation.errorText}`);
    }
    if (!navigation.loaderId) {
      throw new Error('probe navigation did not produce a loaderId');
    }
    await client.waitForEvent('Page.lifecycleEvent', {
      predicate: (event) =>
        event.loaderId === navigation.loaderId && event.name === 'load',
      sessionId,
    });

    const evalResult = await client.send('Runtime.evaluate', {
      expression: 'window.__collected.then(r => JSON.stringify(r))',
      awaitPromise: true,
      returnByValue: true,
    }, sessionId);
    if (evalResult.exceptionDetails) {
      throw new Error(
        `probe evaluation failed: ${evalResult.exceptionDetails.text ?? 'unknown exception'}`,
      );
    }
    const serialized = evalResult.result?.value;
    if (typeof serialized !== 'string') {
      throw new Error('probe evaluation did not return serialized observation JSON');
    }
    const raw = JSON.parse(serialized);

    // Score the live collection. No proxy context in this harness → V4 stays n/a.
    const ref = loadReference();
    const scored = score(normalize(raw, {}), ref);
    if (JSON_OUTPUT) {
      launchGuard?.assertHeld();
      await assertRunningProcessImage(
        chrome,
        CHROME,
        artifactBefore,
        PLATFORM,
      );
      launchGuard?.assertHeld();
      await closeBrowserGracefully(chrome, client, {
        onCommandWritten() {
          browserCloseRequested = true;
        },
      });
      client.close();
      client = null;
      launchGuard?.assertHeld();
      const networkTimeAudit = readNetworkTimeAuditFile(netLogPath);
      const report = buildArtifactBaselineReport({
        artifactPath: CHROME,
        executionIsolation: M0_EXTERNAL_EXECUTION_ISOLATION,
        networkTimeAudit,
        observation: raw,
        platform: PLATFORM,
        probe: probeServer.binding,
      });
      const artifactAfter = artifactStat(CHROME);
      if (report.browserArtifactSha256 !== artifactBefore.sha256
          || !sameArtifactStat(artifactBefore.stat, artifactAfter)) {
        throw new Error(
          'engine executable changed between pre-launch hashing and report assembly',
        );
      }
      return `${JSON.stringify(report, null, 2)}\n`;
    } else {
      console.log(renderReport(scored, { title: 'LIVE headless Chrome (stock, unmodified)' }));
      console.log('  Note: this is STOCK Chrome. Tells here are the baseline the Proteus');
      console.log('  engine must eliminate (M1+). The point proven now: the ruler measures');
      console.log('  a real browser end-to-end, not just fixtures.\n');

      // Emit the raw collection for inspection.
      console.log('  Collected surfaces:');
      console.log('   platform  :', raw.navigator?.platform);
      console.log('   UA        :', (raw.navigator?.userAgent || '').slice(0, 70) + '…');
      console.log('   webglRend :', raw.gpu?.webglRenderer);
      console.log('   timezone  :', raw.locale?.timezone);
      console.log('   webdriver :', raw.automation?.webdriver, '(true = automation tell, expected under CDP)');
      console.log('   fonts (#) :', raw.fonts?.set?.length ?? 'none detected');
      console.log('');
    }
  } catch (error) {
    throw new Error(
      `${error.message}${stderr ? `\nChromium stderr tail:\n${stderr.slice(-400)}` : ''}`,
      { cause: error },
    );
  } finally {
    let cleanupError = null;
    try {
      await terminateBrowser(chrome);
    } catch (error) {
      cleanupError = error;
    }
    client?.close();
    try {
      await launchGuard?.release();
    } catch (error) {
      cleanupError ??= error;
    }
    try {
      await probeServer?.close();
    } catch (error) {
      cleanupError ??= error;
    }
    try {
      rmSync(userDataDir, {
        recursive: true,
        force: true,
        maxRetries: process.platform === 'win32' ? 5 : 0,
        retryDelay: process.platform === 'win32' ? 100 : 0,
      });
    } catch (error) {
      cleanupError ??= error;
    }
    if (cleanupError) throw cleanupError;
  }
}

try {
  const options = parseDriveOptions(process.argv.slice(2), {
    defaultChrome: firstExisting([
      '/usr/bin/google-chrome-stable',
      '/usr/bin/google-chrome',
      '/usr/bin/chromium',
      '/usr/bin/chromium-browser',
    ]),
  });
  const output = await main(options);
  if (output) await writeStdout(output);
} catch (error) {
  console.error('drive-chrome failed:', error.message);
  process.exitCode = 1;
}
