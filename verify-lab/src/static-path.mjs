import { isAbsolute, relative, resolve, sep } from 'node:path';

export const DEFAULT_STATIC_HOST = '127.0.0.1';

/**
 * Return whether candidate is root itself or a descendant of root.
 *
 * `startsWith(root)` is not a containment check: `/srv/lab-private` starts with
 * `/srv/lab`.  `relative` preserves the path-segment boundary for us.
 */
export function isPathInsideRoot(root, candidate) {
  const rel = relative(resolve(root), resolve(candidate));
  return rel === '' || (
    rel !== '..'
    && !rel.startsWith(`..${sep}`)
    && !isAbsolute(rel)
  );
}

/**
 * Convert an HTTP origin-form request target into a lexically contained path.
 *
 * This function deliberately has no filesystem access so traversal edge cases
 * can be tested deterministically.  The caller must additionally resolve
 * symlinks and run `isPathInsideRoot` again before reading the file.
 */
export function resolveStaticPath(root, requestTarget) {
  if (typeof requestTarget !== 'string' || !requestTarget.startsWith('/') || requestTarget.startsWith('//')) {
    return null;
  }

  const queryIndex = requestTarget.indexOf('?');
  const rawPath = queryIndex === -1 ? requestTarget : requestTarget.slice(0, queryIndex);

  let decodedPath;
  try {
    decodedPath = decodeURIComponent(rawPath);
  } catch {
    return null;
  }

  // Backslashes are path separators on Windows. Rejecting them makes the URL
  // policy identical on every platform instead of relying on the host parser.
  if (decodedPath.includes('\0') || decodedPath.includes('\\')) return null;

  // Reject traversal intent even when normalization would happen to land back
  // inside root. Encoded dot segments are caught after decoding.
  if (decodedPath.split('/').includes('..')) return null;

  const pathname = decodedPath === '/' ? '/probe-page/index.html' : decodedPath;
  const rootPath = resolve(root);
  const candidate = resolve(rootPath, `.${pathname}`);

  return candidate !== rootPath && isPathInsideRoot(rootPath, candidate)
    ? candidate
    : null;
}
