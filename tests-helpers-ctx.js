'use strict';
// Test harness: a real application context wired to fake network services and scripted input.
const { PassThrough } = require('stream');
const { createContext } = require('./core-context');
const { Asker } = require('./cli-prompt');
const F = require('./tests-helpers-fixtures');

/** Fake fetch. routes: { "substring or /regex/": {status, body, json, headers, url, delayMs, never, throws} | fn(url, opts) } */
function makeFetch(routes = {}) {
  const calls = [];
  const fn = async (url, opts = {}) => {
    calls.push({ url: String(url), headers: opts.headers || {} });
    let spec = null;
    for (const [k, v] of Object.entries(routes)) {
      const hit = k.startsWith('/') && k.endsWith('/') ? new RegExp(k.slice(1, -1)).test(url) : String(url).includes(k);
      if (hit) { spec = v; break; }
    }
    if (spec === null) throw new Error(`UNEXPECTED NETWORK REQUEST in test: ${url}`);
    if (typeof spec === 'function') spec = await spec(String(url), opts);
    if (spec.throws) throw spec.throws;
    if (spec.never) return new Promise((_, reject) => { if (opts.signal) opts.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' }))); });
    if (spec.delayMs) await new Promise((r) => setTimeout(r, spec.delayMs));
    const body = spec.json !== undefined ? JSON.stringify(spec.json) : (spec.body === undefined ? '' : spec.body);
    const res = new Response(body, { status: spec.status || 200, headers: { 'content-type': spec.json !== undefined ? 'application/json' : 'text/html', ...(spec.headers || {}) } });
    Object.defineProperty(res, 'url', { value: spec.url || String(url) });
    return res;
  };
  fn.calls = calls;
  return fn;
}

/** Fake `dns` module. table: {"A example.com": [{address, ttl}] | "ENOTFOUND"} ; missing keys behave like ENODATA. */
function fakeDns(table = {}) {
  const calls = [];
  const look = (type, name) => {
    calls.push(`${type} ${name}`);
    const v = table[`${type} ${name}`];
    if (v === undefined) throw Object.assign(new Error('ENODATA'), { code: 'ENODATA' });
    if (typeof v === 'string') throw Object.assign(new Error(v), { code: v });
    return v;
  };
  class Resolver {
    setServers() {}
    async resolve4(n) { return look('A', n); }
    async resolve6(n) { return look('AAAA', n); }
    async resolveMx(n) { return look('MX', n); }
    async resolveNs(n) { return look('NS', n); }
    async resolveTxt(n) { return look('TXT', n); }
    async resolveCname(n) { return look('CNAME', n); }
    async resolveSoa(n) { return look('SOA', n); }
    async resolveCaa(n) { return look('CAA', n); }
    async resolvePtr(n) { return look('PTR', n); }
  }
  return { promises: { Resolver }, calls };
}

class ScriptedPrompter {
  constructor(lines) { this.lines = [...lines]; this.closed = false; this.asked = []; }
  async readLine(p) { this.asked.push(p); if (!this.lines.length) return { eof: true }; const l = this.lines.shift(); return l === '\u0003' ? { sigint: true } : { line: l }; }
  async readSecret(p) { return this.readLine(p); }
  async cancellable(fn) { return fn(new AbortController().signal); }
  suspend() {}
  resume() {}
  close() {}
}

/**
 * Build a context for a test. Returns {ctx, home, output(), calls, cleanup()}.
 * config: persisted setting overrides, e.g. {offline: true}.
 */
function makeCtx({ inputs = [], routes = {}, env = {}, config = {}, services = {}, width = 60 } = {}) {
  const home = F.tempDir('ork-home-');
  const out = new PassThrough();
  out.columns = width;
  let buf = '';
  out.on('data', (d) => { buf += d; });
  const fetch = makeFetch(routes);
  const ctx = createContext({ env: { HOME: home, NO_COLOR: '1', LANG: 'C.UTF-8', TERM: 'xterm', COLUMNS: String(width), ...env }, stdout: out, services: { fetch, ...services } });
  ctx.config.set('minRequestIntervalMs', 0);
  ctx.config.set('maxRetries', 0);
  for (const [k, v] of Object.entries(config)) { const r = ctx.config.set(k, v); if (!r.ok) throw new Error(`bad test config ${k}: ${r.error}`); }
  ctx.prompter = new ScriptedPrompter(inputs);
  ctx.ask = new Asker(ctx, ctx.prompter);
  return { ctx, home, output: () => buf, calls: fetch.calls, cleanup: () => F.rmrf(home) };
}

module.exports = { makeFetch, fakeDns, ScriptedPrompter, makeCtx };
