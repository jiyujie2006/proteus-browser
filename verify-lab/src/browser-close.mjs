import { once } from 'node:events';

const DEFAULT_CLOSE_TIMEOUT_MS = 10_000;

export async function closeBrowserGracefully(
  chrome,
  client,
  {
    onCommandWritten = () => {},
    timeoutMs = DEFAULT_CLOSE_TIMEOUT_MS,
  } = {},
) {
  if (!chrome
      || !Number.isInteger(chrome.pid)
      || chrome.exitCode !== null
      || chrome.signalCode !== null) {
    throw new Error('Chromium is not running before the graceful close');
  }
  if (!client || typeof client.sendWithWriteAck !== 'function') {
    throw new TypeError('graceful close requires a tracked CDP client');
  }
  if (typeof onCommandWritten !== 'function') {
    throw new TypeError('graceful close write callback must be a function');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new TypeError('graceful close timeout must be a positive integer');
  }

  const closed = once(chrome, 'close');
  const request = client.sendWithWriteAck('Browser.close');
  let responseError = null;
  void request.response.catch((error) => {
    responseError = error;
  });

  let timer;
  try {
    const [code, signal] = await Promise.race([
      (async () => {
        await request.written;
        onCommandWritten();
        return closed;
      })(),
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error('Chromium did not close after Browser.close')),
          timeoutMs,
        );
      }),
    ]);
    // Let a response/error already queued by the CDP stream settle. A lost
    // response caused by the expected pipe EOF is acceptable after the command
    // write and a normal child close; an explicit protocol rejection is not.
    await Promise.resolve();
    if (responseError?.message?.startsWith('CDP Browser.close failed:')) {
      throw responseError;
    }
    if (code !== 0 || signal !== null) {
      throw new Error(`Chromium graceful close failed (${signal ?? code})`);
    }
  } finally {
    clearTimeout(timer);
  }
}
