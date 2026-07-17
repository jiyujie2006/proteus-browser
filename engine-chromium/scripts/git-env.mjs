// Git is a security boundary for source and toolchain verification. Never let
// ambient GIT_* variables redirect a command to a different repository,
// worktree, object database, index, config, hook directory, or executable
// prompt. Callers may add only the explicit variables needed by one operation.

export function sanitizedGitEnvironment(
  source = process.env,
  explicit = {},
) {
  const environment = {};
  for (const [key, value] of Object.entries(source)) {
    if (!key.startsWith('GIT_')) environment[key] = value;
  }
  Object.assign(environment, {
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
  }, explicit);
  if (process.platform === 'win32') {
    Object.assign(environment, {
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'core.longpaths',
      GIT_CONFIG_VALUE_0: 'true',
    });
  }
  return environment;
}
