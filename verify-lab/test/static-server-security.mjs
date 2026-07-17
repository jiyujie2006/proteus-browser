import { join, resolve } from 'node:path';
import {
  DEFAULT_STATIC_HOST,
  isPathInsideRoot,
  resolveStaticPath,
} from '../src/static-path.mjs';

export function runStaticServerSecurityTests(assert) {
  const root = resolve('/srv/proteus/verify-lab');
  const expectedIndex = join(root, 'probe-page', 'index.html');

  assert(DEFAULT_STATIC_HOST === '127.0.0.1',
    'static server defaults to the IPv4 loopback interface');
  assert(resolveStaticPath(root, '/') === expectedIndex,
    'static server maps / to the probe entry point');
  assert(resolveStaticPath(root, '/data/reference.json?cache=1') === join(root, 'data', 'reference.json'),
    'static server strips the query without changing the resource path');
  assert(resolveStaticPath(root, '/probe-page/collect.js') === join(root, 'probe-page', 'collect.js'),
    'static server accepts an ordinary in-root resource');

  const rejectedTargets = [
    '/../package.json',
    '/../../etc/passwd',
    '/../verify-lab-private/secret.json',
    '/src/../data/reference.json',
    '/%2e%2e/package.json',
    '/%2E%2E%2fpackage.json',
    '/probe-page%2f..%2f..%2fetc%2fpasswd',
    '/..\\package.json',
    '/%2e%2e%5cpackage.json',
    '/probe-page/index.html%00.json',
    '/probe-page/%E0%A4%A',
    '//example.test/etc/passwd',
    'http://example.test/etc/passwd',
  ];
  for (const target of rejectedTargets) {
    assert(resolveStaticPath(root, target) === null,
      `static server rejects unsafe request target ${JSON.stringify(target)}`);
  }

  assert(isPathInsideRoot(root, join(root, 'data', 'reference.json')),
    'containment accepts a true descendant');
  assert(!isPathInsideRoot(root, `${root}-private/secret.json`),
    'containment rejects a sibling whose name shares the root prefix');
  assert(!isPathInsideRoot(root, resolve(root, '..', 'outside', 'secret.json')),
    'containment rejects a resolved symlink target outside the root');
}
