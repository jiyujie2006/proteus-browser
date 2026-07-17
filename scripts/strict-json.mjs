/**
 * Parse UTF-8 JSON while rejecting duplicate keys at every object depth.
 *
 * `JSON.parse` silently keeps the last duplicate. That is deterministic inside
 * one runtime but unsafe for signed evidence exchanged with parsers that may
 * keep the first value or reject the document.
 */
export function parseStrictJson(bytes, label = 'JSON document') {
  let source;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new SyntaxError(`${label}: input is not valid UTF-8`);
  }
  let cursor = 0;

  function fail(message) {
    throw new SyntaxError(`${label}: ${message} at character ${cursor}`);
  }

  function whitespace() {
    while (cursor < source.length && /\s/u.test(source[cursor])) cursor += 1;
  }

  function string() {
    if (source[cursor] !== '"') fail('expected a JSON string');
    const start = cursor;
    cursor += 1;
    while (cursor < source.length) {
      const char = source[cursor];
      if (char === '"') {
        cursor += 1;
        try {
          return JSON.parse(source.slice(start, cursor));
        } catch {
          fail('invalid JSON string');
        }
      }
      if (char === '\\') cursor += 2;
      else cursor += 1;
    }
    fail('unterminated JSON string');
  }

  function value(path) {
    whitespace();
    const char = source[cursor];
    if (char === '{') {
      cursor += 1;
      whitespace();
      const keys = new Set();
      if (source[cursor] === '}') {
        cursor += 1;
        return;
      }
      for (;;) {
        whitespace();
        const key = string();
        if (keys.has(key)) {
          throw new SyntaxError(`${label}: duplicate object key ${path}.${key}`);
        }
        keys.add(key);
        whitespace();
        if (source[cursor] !== ':') fail('expected ":" after object key');
        cursor += 1;
        value(`${path}.${key}`);
        whitespace();
        if (source[cursor] === '}') {
          cursor += 1;
          return;
        }
        if (source[cursor] !== ',') fail('expected "," or "}"');
        cursor += 1;
      }
    }
    if (char === '[') {
      cursor += 1;
      whitespace();
      if (source[cursor] === ']') {
        cursor += 1;
        return;
      }
      let index = 0;
      for (;;) {
        value(`${path}[${index}]`);
        index += 1;
        whitespace();
        if (source[cursor] === ']') {
          cursor += 1;
          return;
        }
        if (source[cursor] !== ',') fail('expected "," or "]"');
        cursor += 1;
      }
    }
    if (char === '"') {
      string();
      return;
    }
    const token = source.slice(cursor).match(
      /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/,
    )?.[0];
    if (!token) fail('invalid JSON value');
    cursor += token.length;
  }

  value('$');
  whitespace();
  if (cursor !== source.length) fail('unexpected trailing content');
  return JSON.parse(source);
}
