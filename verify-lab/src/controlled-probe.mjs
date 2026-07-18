import { createHash } from 'node:crypto';
import {
  lstatSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { DEFAULT_STATIC_HOST, isPathInsideRoot } from './static-path.mjs';

const LAB_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PROBE_DOMAIN = Buffer.from('PROTEUS-CONTROLLED-PROBE\0v1\0', 'utf8');
const PROBE_FILES = Object.freeze([
  Object.freeze({
    contentType: 'text/html; charset=utf-8',
    path: 'probe-page/headless.html',
    requestPath: '/probe-page/headless.html',
  }),
  Object.freeze({
    contentType: 'text/javascript; charset=utf-8',
    path: 'probe-page/collect.js',
    requestPath: '/probe-page/collect.js',
  }),
  Object.freeze({
    contentType: 'text/html; charset=utf-8',
    path: 'probe-page/context-frame.html',
    requestPath: '/probe-page/context-frame.html',
  }),
  Object.freeze({
    contentType: 'text/javascript; charset=utf-8',
    path: 'probe-page/context-worker.js',
    requestPath: '/probe-page/context-worker.js',
  }),
]);

function loadProbeBundle(root) {
  const rootRealPath = realpathSync(root);
  const resources = new Map();
  const files = [];
  const bundleHash = createHash('sha256').update(PROBE_DOMAIN);

  for (const descriptor of PROBE_FILES) {
    const candidate = realpathSync(join(rootRealPath, descriptor.path));
    if (!isPathInsideRoot(rootRealPath, candidate) || !lstatSync(candidate).isFile()) {
      throw new TypeError(
        `controlled probe resource is not an ordinary in-root file: ${descriptor.path}`,
      );
    }
    const bytes = readFileSync(candidate);
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    bundleHash
      .update(descriptor.path, 'utf8')
      .update('\0')
      .update(String(bytes.length), 'ascii')
      .update('\0')
      .update(bytes)
      .update('\0');
    files.push({
      path: descriptor.path,
      sha256,
      size: bytes.length,
    });
    resources.set(descriptor.requestPath, {
      bytes,
      contentType: descriptor.contentType,
    });
  }

  return {
    binding: {
      schemaVersion: '1.0.0',
      entryPath: PROBE_FILES[0].path,
      bundleSha256: bundleHash.digest('hex'),
      files,
    },
    resources,
  };
}

function requestHeader(request, name) {
  const value = request.headers?.[name];
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
    return value.join(', ');
  }
  return null;
}

/**
 * Describe the exact probe bytes accepted by an M0 machine report.
 */
export function buildControlledProbeBinding(root = LAB_ROOT) {
  return loadProbeBundle(root).binding;
}

export function createControlledProbeHandler(root = LAB_ROOT) {
  const { binding, resources } = loadProbeBundle(root);
  const entryRequests = [];
  return {
    binding,
    entryRequestHeaders() {
      if (entryRequests.length !== 1) {
        throw new TypeError(
          `controlled probe expected exactly one entry request, observed ${entryRequests.length}`,
        );
      }
      return { ...entryRequests[0] };
    },
    handle(request, response) {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        response.writeHead(405, { allow: 'GET, HEAD' });
        response.end('method not allowed');
        return;
      }
      const resource = resources.get(request.url);
      if (!resource) {
        response.writeHead(404);
        response.end('not found');
        return;
      }
      if (request.method === 'GET'
          && request.url === `/${binding.entryPath}`) {
        entryRequests.push({
          acceptLanguage: requestHeader(request, 'accept-language'),
          userAgent: requestHeader(request, 'user-agent'),
        });
      }
      response.writeHead(200, {
        'cache-control': 'no-store',
        'content-length': resource.bytes.length,
        'content-type': resource.contentType,
        'x-content-type-options': 'nosniff',
      });
      response.end(request.method === 'HEAD' ? undefined : resource.bytes);
    },
  };
}

/**
 * Serve a frozen, four-file probe bundle on an OS-assigned IPv4 loopback port.
 *
 * The resources are read before `listen()`, then served from memory. This
 * prevents a concurrent file change from making the reported digest differ
 * from the bytes observed by the browser.
 */
export async function startControlledProbeServer({
  host = DEFAULT_STATIC_HOST,
  root = LAB_ROOT,
} = {}) {
  if (host !== DEFAULT_STATIC_HOST) {
    throw new TypeError('controlled probe server must bind to 127.0.0.1');
  }
  const probe = createControlledProbeHandler(root);
  const { binding, handle } = probe;
  const server = createServer(handle);

  try {
    await new Promise((resolve, reject) => {
      const onError = (error) => {
        server.off('listening', onListening);
        reject(error);
      };
      const onListening = () => {
        server.off('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(0, host);
    });
  } catch (error) {
    server.close();
    throw error;
  }

  const address = server.address();
  if (!address || typeof address === 'string') {
    server.close();
    throw new Error('controlled probe server did not obtain a TCP address');
  }

  let closed = false;
  return {
    binding,
    entryRequestHeaders: probe.entryRequestHeaders,
    url: `http://${DEFAULT_STATIC_HOST}:${address.port}/${binding.entryPath}`,
    async close() {
      if (closed) return;
      closed = true;
      server.closeAllConnections?.();
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}
