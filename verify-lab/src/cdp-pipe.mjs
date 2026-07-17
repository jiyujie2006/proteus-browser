const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024;

/**
 * Minimal Chrome DevTools Protocol client for `--remote-debugging-pipe`.
 *
 * Chromium reads NUL-terminated JSON commands from child fd 3 and writes
 * NUL-terminated JSON responses/events to child fd 4. The caller must pass the
 * parent-side streams corresponding to those descriptors.
 */
export class CdpPipeClient {
  constructor(readable, writable, {
    maxFrameBytes = DEFAULT_MAX_FRAME_BYTES,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  } = {}) {
    if (!readable?.on || !writable?.write) {
      throw new TypeError('CDP pipe requires readable fd 4 and writable fd 3 streams');
    }
    this.readable = readable;
    this.writable = writable;
    this.maxFrameBytes = maxFrameBytes;
    this.timeoutMs = timeoutMs;
    this.buffer = Buffer.alloc(0);
    this.nextId = 1;
    this.pending = new Map();
    this.waiters = new Set();
    this.recentEvents = [];
    this.failure = null;

    readable.on('data', (chunk) => this.onData(chunk));
    readable.on('error', (error) => this.abort(error));
    readable.on('end', () => this.abort(new Error('Chromium closed CDP output pipe')));
    writable.on('error', (error) => this.abort(error));
  }

  send(method, params = {}, sessionId = null) {
    if (this.failure) return Promise.reject(this.failure);
    if (typeof method !== 'string' || method.length === 0) {
      return Promise.reject(new TypeError('CDP method must be a non-empty string'));
    }
    const id = this.nextId;
    this.nextId += 1;
    const message = { id, method, params };
    if (sessionId !== null) message.sessionId = sessionId;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP timeout: ${method}`));
      }, this.timeoutMs);
      this.pending.set(id, {
        method,
        reject,
        resolve,
        timer,
      });
      this.writable.write(
        `${JSON.stringify(message)}\0`,
        'utf8',
        (error) => {
          if (!error) return;
          const pending = this.pending.get(id);
          if (!pending) return;
          clearTimeout(pending.timer);
          this.pending.delete(id);
          reject(error);
        },
      );
    });
  }

  waitForEvent(method, {
    predicate = () => true,
    sessionId = null,
    timeoutMs = this.timeoutMs,
  } = {}) {
    const matches = (message) =>
      message.method === method
      && (sessionId === null || message.sessionId === sessionId)
      && predicate(message.params ?? {});
    const queued = this.recentEvents.find(matches);
    if (queued) return Promise.resolve(queued.params ?? {});
    if (this.failure) return Promise.reject(this.failure);

    return new Promise((resolve, reject) => {
      const waiter = {
        matches,
        reject,
        resolve: (message) => resolve(message.params ?? {}),
        timer: null,
      };
      waiter.timer = setTimeout(() => {
        this.waiters.delete(waiter);
        reject(new Error(`CDP event timeout: ${method}`));
      }, timeoutMs);
      this.waiters.add(waiter);
    });
  }

  onData(chunk) {
    if (this.failure) return;
    this.buffer = Buffer.concat([this.buffer, Buffer.from(chunk)]);
    for (;;) {
      const delimiter = this.buffer.indexOf(0);
      if (delimiter === -1) {
        if (this.buffer.length > this.maxFrameBytes) {
          this.abort(new Error('CDP pipe frame exceeded the configured byte limit'));
        }
        return;
      }
      if (delimiter > this.maxFrameBytes) {
        this.abort(new Error('CDP pipe frame exceeded the configured byte limit'));
        return;
      }
      const frame = this.buffer.subarray(0, delimiter);
      this.buffer = this.buffer.subarray(delimiter + 1);
      if (frame.length === 0) continue;
      let message;
      try {
        message = JSON.parse(frame.toString('utf8'));
      } catch (error) {
        this.abort(new Error(`invalid JSON from Chromium CDP pipe: ${error.message}`));
        return;
      }
      this.onMessage(message);
    }
  }

  onMessage(message) {
    if (!message || typeof message !== 'object' || Array.isArray(message)) {
      this.abort(new Error('Chromium CDP pipe emitted a non-object message'));
      return;
    }
    if (Number.isSafeInteger(message.id)) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pending.delete(message.id);
      if (message.error) {
        pending.reject(new Error(
          `CDP ${pending.method} failed: ${message.error.message ?? 'unknown error'}`,
        ));
      } else {
        pending.resolve(message.result ?? {});
      }
      return;
    }
    if (typeof message.method !== 'string') return;
    this.recentEvents.push(message);
    if (this.recentEvents.length > 128) this.recentEvents.shift();
    for (const waiter of this.waiters) {
      let matches = false;
      try {
        matches = waiter.matches(message);
      } catch (error) {
        clearTimeout(waiter.timer);
        this.waiters.delete(waiter);
        waiter.reject(error);
        continue;
      }
      if (!matches) continue;
      clearTimeout(waiter.timer);
      this.waiters.delete(waiter);
      waiter.resolve(message);
    }
  }

  abort(error) {
    if (this.failure) return;
    this.failure = error instanceof Error ? error : new Error(String(error));
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(this.failure);
    }
    this.pending.clear();
    for (const waiter of this.waiters) {
      clearTimeout(waiter.timer);
      waiter.reject(this.failure);
    }
    this.waiters.clear();
  }

  close() {
    this.abort(new Error('CDP pipe client closed'));
    this.writable.end();
    this.readable.destroy();
  }
}
