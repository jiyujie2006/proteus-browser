import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';

import { CdpPipeClient } from '../src/cdp-pipe.mjs';
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
}
