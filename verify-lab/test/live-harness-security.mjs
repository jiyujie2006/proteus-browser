import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';

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

  function request(method, url) {
    const result = { body: undefined, headers: null, status: null };
    probe.handle(
      { method, url },
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
  const entry = request('GET', '/probe-page/headless.html');
  assert(
    entry.status === 200
      && Buffer.from(entry.body).equals(
        readFileSync(join(ROOT, 'probe-page', 'headless.html')),
      ),
    'controlled server serves the bound headless entry bytes',
  );
  assert(
    request('GET', '/probe-page/headless.html?unbound=1').status === 404,
    'controlled server rejects unbound query variants',
  );
  assert(
    request('GET', '/data/reference.json').status === 404,
    'controlled server exposes no resources outside the two-file probe bundle',
  );
  assert(
    request('POST', '/probe-page/headless.html').status === 405,
    'controlled server rejects state-changing HTTP methods',
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
