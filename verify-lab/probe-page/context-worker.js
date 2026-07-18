// Shared by Dedicated Worker, Shared Worker, and Service Worker probes.
// The collector implementation is byte-bound by the controlled probe server.
importScripts('./collect.js');

(function (scope) {
  'use strict';

  function errorText(error) {
    return String(error?.message ?? error ?? 'unknown error')
      .replace(/[\r\n\t]+/g, ' ')
      .slice(0, 240);
  }

  async function answer(data, port) {
    if (!data
        || data.type !== 'proteus-context-collect'
        || typeof data.requestId !== 'string'
        || !port) {
      return;
    }
    try {
      const values = await scope.ProteusCollect.collectContextValues();
      port.postMessage({
        type: 'proteus-context-result',
        requestId: data.requestId,
        ok: true,
        values,
      });
    } catch (error) {
      port.postMessage({
        type: 'proteus-context-result',
        requestId: data.requestId,
        ok: false,
        error: errorText(error),
      });
    }
  }

  const isServiceWorker = typeof ServiceWorkerGlobalScope !== 'undefined'
    && scope instanceof ServiceWorkerGlobalScope;
  const isSharedWorker = typeof SharedWorkerGlobalScope !== 'undefined'
    && scope instanceof SharedWorkerGlobalScope;

  if (isServiceWorker) {
    scope.addEventListener('install', (event) => {
      event.waitUntil(scope.skipWaiting());
    });
    scope.addEventListener('message', (event) => {
      const work = answer(event.data, event.ports?.[0]);
      event.waitUntil(work);
    });
  } else if (isSharedWorker) {
    scope.addEventListener('connect', (event) => {
      const port = event.ports?.[0];
      if (!port) return;
      port.addEventListener('message', (message) => {
        void answer(message.data, port);
      });
      port.start();
    });
  } else {
    scope.addEventListener('message', (event) => {
      void answer(event.data, scope);
    });
  }
})(self);
