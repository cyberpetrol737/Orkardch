'use strict';
const { visLen, stripAnsi, wrapText, truncate } = require('./utils-format');

const STYLES = {
  bold: [1, 22], dim: [2, 22], red: [31, 39], green: [32, 39], yellow: [33, 39],
  blue: [34, 39], magenta: [35, 39], cyan: [36, 39],
};

// Three-row letter shapes: one set of box-drawing characters, one plain-ASCII fallback.
const GLYPHS = {
  O: ['╔═╗', '║ ║', '╚═╝'], R: ['╦═╗', '╠╦╝', '╩╚═'], K: ['╦╔═', '╠╩╗', '╩ ╩'], A: ['╔═╗', '╠═╣', '╩ ╩'],
  D: ['╔╦╗', ' ║║', '═╩╝'], C: ['╔═╗', '║  ', '╚═╝'], H: ['╦ ╦', '╠═╣', '╩ ╩'],
};
const ASCII_GLYPHS = {
  O: ['/-\\', '| |', '\\-/'], R: ['|-\\', '|-/', '| \\'], K: ['| /', '|< ', '| \\'], A: ['/-\\', '|-|', '| |'],
  D: ['|-\\', '| |', '|-/'], C: ['/--', '|  ', '\\--'], H: ['| |', '|-|', '| |'],
};

class UI {
  constructor({ stream = process.stdout, env = process.env, config = null, columns = null } = {}) {
    this.stream = stream;
    this.env = env;
    this.config = config;
    this.columns = columns;
    this._progressActive = false;
  }

  get width() {
    const c = this.columns || this.stream.columns || Number(this.env.COLUMNS) || 44;
    return Math.max(28, Math.min(c, 100));
  }

  get useColor() {
    const mode = this.config ? this.config.get('color') : 'auto';
    if (mode === 'on') return true;
    if (mode === 'off') return false;
    if (this.env.NO_COLOR) return false;
    if (this.env.FORCE_COLOR && this.env.FORCE_COLOR !== '0') return true;
    return Boolean(this.stream.isTTY) && this.env.TERM !== 'dumb';
  }

  get useUnicode() {
    const mode = this.config ? this.config.get('unicode') : 'auto';
    if (mode === 'on') return true;
    if (mode === 'off') return false;
    if (this.env.TERM === 'dumb' || this.env.TERM === 'linux') return false;
    const loc = this.env.LC_ALL || this.env.LC_CTYPE || this.env.LANG || '';
    return loc ? /utf-?8/i.test(loc) : true;
  }

  c(style, text) {
    if (!this.useColor || !STYLES[style]) return String(text);
    const [on, off] = STYLES[style];
    return `\u001b[${on}m${text}\u001b[${off}m`;
  }

  raw(text) { this.stream.write(text); }
  print(text = '') { this.endProgress(); this.stream.write(`${text}\n`); }
  blank() { this.print(''); }
  lines(arr) { for (const l of arr) this.print(l); }

  wrap(text, indent = '') { return wrapText(text, this.width, indent); }
  /** Wrapped paragraph. Lines that start with "- " or "1. " get a hanging indent. */
  para(text, indent = '') {
    const m = /^(-|\*|\d+\.)\s+/.exec(String(text));
    if (!m) { for (const l of this.wrap(text, indent)) this.print(l); return; }
    const hang = ' '.repeat(m[0].length);
    const lines = wrapText(String(text).slice(m[0].length), this.width - Array.from(indent).length - hang.length);
    lines.forEach((l, i) => this.print(`${indent}${i === 0 ? m[0] : hang}${l}`));
  }

  hr() { this.print(this.c('dim', (this.useUnicode ? '─' : '-').repeat(Math.min(this.width, 40)))); }
  heading(text) { this.blank(); this.print(this.c('bold', text)); }
  ok(text) { this.para(`${this.c('green', this.useUnicode ? '✓' : '+')} ${text}`); }
  warn(text) { for (const l of wrapText(`${this.useUnicode ? '⚠' : '!'} ${text}`, this.width)) this.print(this.c('yellow', l)); }
  error(text) { for (const l of wrapText(`${this.useUnicode ? '✗' : 'x'} ${text}`, this.width)) this.print(this.c('red', l)); }
  note(text, indent = '') { for (const l of this.wrap(text, indent)) this.print(this.c('dim', l)); }

  /** "  Label: value" with wrapping and a hanging indent. */
  kv(label, value, { indent = 2 } = {}) {
    const pad = ' '.repeat(indent);
    const head = `${label}: `;
    const lines = wrapText(String(value), this.width - indent - head.length);
    if (!lines.length) { this.print(`${pad}${this.c('cyan', head.trimEnd())}`); return; }
    this.print(`${pad}${this.c('cyan', head)}${lines[0]}`);
    for (const l of lines.slice(1)) this.print(`${pad}${' '.repeat(head.length)}${l}`);
  }

  menuItem(key, label, note) {
    this.print(`  ${this.c('cyan', `[${/^[a-z]$/.test(String(key)) ? String(key).toUpperCase() : key}]`)} ${label}`);
    if (note) for (const l of wrapText(note, this.width - 6)) this.print(`      ${this.c('dim', l)}`);
  }

  /** Aligned columns when they fit, stacked cards on a narrow screen. */
  table(headers, rows) {
    const cells = rows.map((r) => r.map((c) => String(c == null ? '' : c)));
    const widths = headers.map((h, i) => Math.max(visLen(h), ...cells.map((r) => visLen(r[i] || ''))));
    const total = widths.reduce((a, b) => a + b, 0) + 2 * (headers.length - 1) + 2;
    if (total <= this.width) {
      const fmt = (r) => `  ${r.map((c, i) => c + ' '.repeat(Math.max(0, widths[i] - visLen(c)))).join('  ').trimEnd()}`;
      this.print(this.c('bold', fmt(headers)));
      for (const r of cells) this.print(fmt(r));
      return;
    }
    cells.forEach((r, idx) => {
      if (idx) this.blank();
      r.forEach((c, i) => { if (c !== '') this.kv(headers[i], c); });
    });
  }

  banner({ version, statusLines = [] }) {
    const w = Math.min(this.width, 40);
    const glyphs = this.useUnicode ? GLYPHS : ASCII_GLYPHS;
    const inner = w - 2;
    const rows = inner >= 31 ? [0, 1, 2].map((i) => 'ORKARDCH'.split('').map((ch) => glyphs[ch][i]).join(' ')) : ['O R K A R D C H'];
    const center = (t) => {
      const len = visLen(t);
      const left = Math.max(0, Math.floor((inner - len) / 2));
      return ' '.repeat(left) + t + ' '.repeat(Math.max(0, inner - len - left));
    };
    const [tl, tr, bl, br, h, v] = this.useUnicode ? ['╔', '╗', '╚', '╝', '═', '║'] : ['+', '+', '+', '+', '=', '|'];
    const body = ['', ...rows, '', 'OPEN-SOURCE INTELLIGENCE', `v${version}`, ''];
    this.print(this.c('cyan', `${tl}${h.repeat(inner)}${tr}`));
    for (const line of body) this.print(this.c('cyan', v) + this.c('bold', center(line)) + this.c('cyan', v));
    this.print(this.c('cyan', `${bl}${h.repeat(inner)}${br}`));
    this.blank();
    for (const [k, val] of statusLines) this.print(`${this.c('dim', `${k}:`)} ${val}`);
  }

  progress(done, total, label = '') {
    if (!this.stream.isTTY) return;
    const pct = total > 0 ? Math.min(100, Math.floor((done / total) * 100)) : 0;
    const barW = Math.max(8, Math.min(20, this.width - 16 - visLen(label)));
    const filled = Math.round((pct / 100) * barW);
    const bar = (this.useUnicode ? '█' : '#').repeat(filled) + (this.useUnicode ? '░' : '.').repeat(barW - filled);
    this.stream.write(`\r${truncate(label, 12)} ${bar} ${String(pct).padStart(3)}%`);
    this._progressActive = true;
  }

  endProgress() {
    if (this._progressActive) { this.stream.write(`\r${' '.repeat(Math.min(this.width, 60))}\r`); this._progressActive = false; }
  }
}

module.exports = { UI, stripAnsi };
