import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';

import { CdpPipeClient } from '../src/cdp-pipe.mjs';
import { closeBrowserGracefully } from '../src/browser-close.mjs';
import {
  buildControlledProbeBinding,
  createControlledProbeHandler,
} from '../src/controlled-probe.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

export async function runLiveHarnessSecurityTests(assert) {
  const expectedBinding = buildControlledProbeBinding(ROOT);
  const probe = createControlledProbeHandler(ROOT);
  assert(
    JSON.stringify(probe.binding) === JSON.stringify(expectedBinding),
    'machine probe reports the exact frozen file bundle it serves',
  );

  function request(method, url, headers = {}) {
    const result = { body: undefined, headers: null, status: null };
    probe.handle(
      { headers, method, url },
      {
        end(body) { result.body = body; },
        writeHead(status, headers) {
          result.status = status;
          result.headers = headers ?? null;
        },
      },
    );
    return result;
  }
  const entry = request('GET', '/probe-page/headless.html', {
    'accept-language': 'en-US,en;q=0.9',
    'user-agent': 'Proteus controlled fixture',
  });
  assert(
    entry.status === 200
      && Buffer.from(entry.body).equals(
        readFileSync(join(ROOT, 'probe-page', 'headless.html')),
      ),
    'controlled server serves the bound headless entry bytes',
  );
  const entryHeaders = probe.entryRequestHeaders();
  assert(
    entryHeaders.acceptLanguage === 'en-US,en;q=0.9'
      && entryHeaders.userAgent === 'Proteus controlled fixture',
    'controlled server binds the entry request language and user-agent headers',
  );
  assert(
    request('GET', '/probe-page/headless.html?unbound=1').status === 404,
    'controlled server rejects unbound query variants',
  );
  for (const name of ['context-frame.html', 'context-worker.js']) {
    const resource = request('GET', `/probe-page/${name}`);
    assert(
      resource.status === 200
        && Buffer.from(resource.body).equals(
          readFileSync(join(ROOT, 'probe-page', name)),
        ),
      `controlled server serves the bound ${name} bytes`,
    );
  }
  assert(
    request('GET', '/data/reference.json').status === 404,
    'controlled server exposes no resources outside the four-file probe bundle',
  );
  assert(
    request('POST', '/probe-page/headless.html').status === 405,
    'controlled server rejects state-changing HTTP methods',
  );

  let resolveLateRegistration;
  let registrationCalls = 0;
  let unregisterCalls = 0;
  let messageChannelCalls = 0;
  let workerPostCalls = 0;
  const lateRegistration = new Promise((resolve) => {
    resolveLateRegistration = resolve;
  });
  class MockNavigator {}
  for (const property of [
    'userAgent',
    'platform',
    'languages',
    'hardwareConcurrency',
  ]) {
    Object.defineProperty(MockNavigator.prototype, property, {
      configurable: true,
      enumerable: true,
      get() { return undefined; },
    });
  }
  class MockScreen {}
  Object.defineProperty(MockScreen.prototype, 'width', {
    configurable: true,
    enumerable: true,
    get() { return undefined; },
  });
  class MockCanvas {}
  MockCanvas.prototype.toDataURL = function toDataURL() {};
  class MockWebGl {}
  MockWebGl.prototype.getParameter = function getParameter() {};
  class MockMessageChannel {
    constructor() {
      messageChannelCalls += 1;
      this.port1 = {
        close() {},
        start() {},
      };
      this.port2 = {};
    }
  }
  const collectorSandbox = {
    HTMLCanvasElement: MockCanvas,
    MessageChannel: MockMessageChannel,
    Navigator: MockNavigator,
    Screen: MockScreen,
    WebGLRenderingContext: MockWebGl,
    clearTimeout: globalThis.clearTimeout,
    crypto: {
      getRandomValues(values) {
        values.fill(1);
        return values;
      },
    },
    navigator: {
      hardwareConcurrency: 8,
      languages: ['en-US', 'en'],
      platform: 'Linux x86_64',
      serviceWorker: {
        register() {
          registrationCalls += 1;
          return lateRegistration;
        },
      },
      userAgent: 'Proteus lifecycle fixture',
      vendor: 'Google Inc.',
    },
    setTimeout(callback) {
      return globalThis.setTimeout(callback, 0);
    },
  };
  collectorSandbox.self = collectorSandbox;
  runInNewContext(
    readFileSync(join(ROOT, 'probe-page', 'collect.js'), 'utf8'),
    collectorSandbox,
    { filename: 'probe-page/collect.js' },
  );
  const timedOutCollection = await collectorSandbox.ProteusCollect.collect();
  assert(
    timedOutCollection.traces.crossContext.contexts['service-worker'].status
      === 'timeout',
    'service-worker lifecycle fixture reaches the bounded timeout',
  );
  resolveLateRegistration({
    active: {
      postMessage() {
        workerPostCalls += 1;
      },
      state: 'activated',
    },
    unregister() {
      unregisterCalls += 1;
      return Promise.resolve(true);
    },
  });
  await new Promise((resolve) => globalThis.setTimeout(resolve, 0));
  assert(
    registrationCalls === 1
      && unregisterCalls === 1
      && messageChannelCalls === 0
      && workerPostCalls === 0,
    'late service-worker setup is immediately unregistered and allocates no post-timeout ports',
  );

  const chromeOutput = new PassThrough();
  const chromeInput = new PassThrough();
  const client = new CdpPipeClient(chromeOutput, chromeInput, {
    timeoutMs: 1_000,
  });
  let outbound = Buffer.alloc(0);
  const command = new Promise((resolve) => {
    chromeInput.on('data', (chunk) => {
      outbound = Buffer.concat([outbound, chunk]);
      const delimiter = outbound.indexOf(0);
      if (delimiter === -1) return;
      resolve(JSON.parse(outbound.subarray(0, delimiter).toString('utf8')));
    });
  });
  const responsePromise = client.send('Browser.getVersion');
  const sent = await command;
  assert(
    sent.method === 'Browser.getVersion'
      && Number.isSafeInteger(sent.id)
      && outbound[outbound.indexOf(0)] === 0,
    'CDP pipe commands use NUL-delimited JSON on the process-bound stream',
  );
  const encodedResponse = Buffer.from(
    `${JSON.stringify({ id: sent.id, result: { product: 'Chromium/test' } })}\0`,
  );
  chromeOutput.write(encodedResponse.subarray(0, 7));
  chromeOutput.write(encodedResponse.subarray(7));
  assert(
    (await responsePromise).product === 'Chromium/test',
    'CDP pipe parser accepts a response split across stream chunks',
  );

  const trackedResponse = client.sendWithWriteAck('Browser.getVersion');
  await trackedResponse.written;
  chromeOutput.write(`${JSON.stringify({
    id: sent.id + 1,
    result: { product: 'Chromium/tracked' },
  })}\0`);
  assert(
    (await trackedResponse.response).product === 'Chromium/tracked',
    'CDP pipe exposes a separate successful-write acknowledgement',
  );

  const eventPromise = client.waitForEvent('Page.lifecycleEvent', {
    predicate: (event) => event.loaderId === 'loader' && event.name === 'load',
    sessionId: 'session',
  });
  chromeOutput.write(`${JSON.stringify({
    method: 'Page.lifecycleEvent',
    params: { loaderId: 'loader', name: 'load' },
    sessionId: 'session',
  })}\0`);
  assert(
    (await eventPromise).name === 'load',
    'CDP pipe events stay bound to the expected target session and loader',
  );
  client.close();

  function fakeChrome() {
    const chrome = new EventEmitter();
    chrome.pid = 123;
    chrome.exitCode = null;
    chrome.signalCode = null;
    return chrome;
  }

  async function closeCase({
    afterClose = () => {},
    close = [0, null],
    response = Promise.resolve({}),
    timeoutMs = 100,
    written = Promise.resolve(),
  } = {}) {
    const chrome = fakeChrome();
    let writeObserved = false;
    const closing = closeBrowserGracefully(
      chrome,
      {
        sendWithWriteAck(method) {
          assert(method === 'Browser.close', 'graceful close uses the root Browser.close command');
          return { response, written };
        },
      },
      {
        onCommandWritten() {
          writeObserved = true;
        },
        timeoutMs,
      },
    );
    if (close) {
      setImmediate(() => {
        chrome.emit('close', ...close);
        afterClose();
      });
    }
    await closing;
    return writeObserved;
  }

  assert(
    await closeCase(),
    'graceful close accepts a CDP response followed by a normal child close',
  );
  assert(
    await (() => {
      let rejectResponse;
      const response = new Promise((_, reject) => {
        rejectResponse = reject;
      });
      return closeCase({
        afterClose() {
          rejectResponse(new Error('Chromium closed CDP output pipe'));
        },
        response,
      });
    })(),
    'graceful close accepts expected response loss after a written close command',
  );

  let protocolCloseFailureRejected = false;
  try {
    await closeCase({
      response: Promise.reject(
        new Error('CDP Browser.close failed: method rejected'),
      ),
    });
  } catch (error) {
    protocolCloseFailureRejected = error.message.includes('method rejected');
  }
  assert(
    protocolCloseFailureRejected,
    'graceful close rejects an explicit Browser.close protocol error',
  );

  let closeWriteFailureRejected = false;
  try {
    await closeCase({
      close: null,
      response: Promise.reject(new Error('write EPIPE')),
      written: Promise.reject(new Error('write EPIPE')),
    });
  } catch (error) {
    closeWriteFailureRejected = error.message.includes('EPIPE');
  }
  assert(
    closeWriteFailureRejected,
    'graceful close rejects a Browser.close write failure',
  );

  let abnormalCloseRejected = false;
  try {
    await closeCase({ close: [1, null] });
  } catch (error) {
    abnormalCloseRejected = error.message.includes('graceful close failed');
  }
  assert(
    abnormalCloseRejected,
    'graceful close rejects a nonzero child exit',
  );

  let signaledCloseRejected = false;
  try {
    await closeCase({ close: [null, 'SIGKILL'] });
  } catch (error) {
    signaledCloseRejected = error.message.includes('SIGKILL');
  }
  assert(
    signaledCloseRejected,
    'graceful close rejects a signaled child exit',
  );

  let closeTimeoutRejected = false;
  try {
    await closeCase({
      close: null,
      response: new Promise(() => {}),
      timeoutMs: 5,
    });
  } catch (error) {
    closeTimeoutRejected = error.message.includes('did not close');
  }
  assert(
    closeTimeoutRejected,
    'graceful close has one bounded write-and-exit timeout',
  );
}
