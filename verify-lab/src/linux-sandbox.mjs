import { lstatSync, realpathSync } from 'node:fs';

const REQUIRED_MODE = 0o4755n;

export function assertLinuxSandboxMetadata(path, stat) {
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new TypeError(
      `--linux-sandbox is not an ordinary non-symlink file: ${path}`,
    );
  }
  if (stat.uid !== 0n) {
    throw new TypeError(`--linux-sandbox must be owned by uid 0: ${path}`);
  }
  if ((stat.mode & 0o7777n) !== REQUIRED_MODE) {
    throw new TypeError(
      `--linux-sandbox must have exact mode 4755: ${path}`,
    );
  }
}

export function validateLinuxSandbox(path, {
  lstat = lstatSync,
  realpath = realpathSync,
} = {}) {
  const before = lstat(path, { bigint: true });
  assertLinuxSandboxMetadata(path, before);

  const canonical = realpath(path);
  if (canonical !== path) {
    throw new TypeError(
      `--linux-sandbox must be a canonical path without symlinked components: ${path}`,
    );
  }

  const after = lstat(canonical, { bigint: true });
  assertLinuxSandboxMetadata(canonical, after);
  if (before.dev !== after.dev || before.ino !== after.ino) {
    throw new Error('--linux-sandbox changed while it was validated');
  }
  return canonical;
}
