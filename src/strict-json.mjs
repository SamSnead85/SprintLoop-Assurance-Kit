const DEFAULT_MAX_DEPTH = 128;
const DEFAULT_MAX_VALUES = 250_000;

/** Parse JSON without accepting duplicate keys, non-finite numbers, or invalid Unicode strings. */
export function parseJsonStrictText(text, options = {}) {
  return parseJsonStrictTextMeasured(text, options).value;
}

/** Parse strict JSON and report the exact structural-value count for shared budgets. */
export function parseJsonStrictTextMeasured(text, options = {}) {
  if (typeof text !== 'string') throw new TypeError('JSON input must be text');
  const maxDepth = boundedLimit(options.maxDepth, DEFAULT_MAX_DEPTH, 1_024, 'maxDepth');
  const maxValues = boundedLimit(options.maxValues, DEFAULT_MAX_VALUES, 1_000_000, 'maxValues');
  const source = text.startsWith('\uFEFF') ? text.slice(1) : text;
  const grammar = new JsonGrammar(source, maxDepth, maxValues);
  const valueCount = grammar.parse();
  return { value: JSON.parse(source), valueCount };
}

class JsonGrammar {
  constructor(source, maxDepth, maxValues) {
    this.source = source;
    this.maxDepth = maxDepth;
    this.maxValues = maxValues;
    this.index = 0;
    this.values = 0;
  }

  parse() {
    this.skipWhitespace();
    this.parseValue(0);
    this.skipWhitespace();
    if (this.index !== this.source.length) throw new SyntaxError('Trailing JSON data');
    return this.values;
  }

  parseValue(depth) {
    if (depth > this.maxDepth) throw new RangeError('JSON nesting limit exceeded');
    this.values += 1;
    if (this.values > this.maxValues) throw new RangeError('JSON value limit exceeded');
    const character = this.source[this.index];
    if (character === '{') return this.parseObject(depth + 1);
    if (character === '[') return this.parseArray(depth + 1);
    if (character === '"') return this.parseString();
    if (character === 't') return this.literal('true');
    if (character === 'f') return this.literal('false');
    if (character === 'n') return this.literal('null');
    return this.parseNumber();
  }

  parseObject(depth) {
    this.index += 1;
    this.skipWhitespace();
    if (this.source[this.index] === '}') {
      this.index += 1;
      return;
    }
    const keys = new Set();
    while (true) {
      if (this.source[this.index] !== '"') throw new SyntaxError('Object key expected');
      const key = this.parseString();
      if (keys.has(key)) throw new SyntaxError('Duplicate object key');
      keys.add(key);
      this.skipWhitespace();
      if (this.source[this.index] !== ':') throw new SyntaxError('Object colon expected');
      this.index += 1;
      this.skipWhitespace();
      this.parseValue(depth);
      this.skipWhitespace();
      if (this.source[this.index] === '}') {
        this.index += 1;
        return;
      }
      if (this.source[this.index] !== ',') throw new SyntaxError('Object delimiter expected');
      this.index += 1;
      this.skipWhitespace();
    }
  }

  parseArray(depth) {
    this.index += 1;
    this.skipWhitespace();
    if (this.source[this.index] === ']') {
      this.index += 1;
      return;
    }
    while (true) {
      this.parseValue(depth);
      this.skipWhitespace();
      if (this.source[this.index] === ']') {
        this.index += 1;
        return;
      }
      if (this.source[this.index] !== ',') throw new SyntaxError('Array delimiter expected');
      this.index += 1;
      this.skipWhitespace();
    }
  }

  parseString() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.source.length) {
      const character = this.source[this.index];
      if (character === '"') {
        this.index += 1;
        const decoded = JSON.parse(this.source.slice(start, this.index));
        if (hasLoneSurrogate(decoded)) throw new SyntaxError('Lone Unicode surrogate');
        return decoded;
      }
      if (character === '\\') {
        this.index += 1;
        const escape = this.source[this.index];
        if (escape === 'u') {
          if (!/^[A-Fa-f0-9]{4}$/u.test(this.source.slice(this.index + 1, this.index + 5))) {
            throw new SyntaxError('Invalid Unicode escape');
          }
          this.index += 5;
          continue;
        }
        if (!'"\\/bfnrt'.includes(escape)) throw new SyntaxError('Invalid string escape');
        this.index += 1;
        continue;
      }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError('Unescaped control character');
      this.index += 1;
    }
    throw new SyntaxError('Unterminated string');
  }

  literal(value) {
    if (!this.source.startsWith(value, this.index)) throw new SyntaxError('Invalid literal');
    this.index += value.length;
  }

  parseNumber() {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(this.source.slice(this.index));
    if (!match || !Number.isFinite(Number(match[0]))) throw new SyntaxError('Invalid number');
    this.index += match[0].length;
  }

  skipWhitespace() {
    while (/[\u0009\u000a\u000d\u0020]/u.test(this.source[this.index] ?? 'x')) this.index += 1;
  }
}

function hasLoneSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function boundedLimit(value, fallback, maximum, name) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) {
    throw new RangeError(`${name} is outside the supported bound`);
  }
  return selected;
}
