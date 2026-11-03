'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { makeCtx } = require('./tests-helpers-ctx');

test('offline mode never calls fetch and says why', async () => {
  const t = makeCtx({ config: { offline: true }, routes: {} });
  const r = await t.ctx.net.get('https://example.com/');
  assert.equal(r.ok, false);
  assert.equal(r.error.kind, 'offline-mode');
  assert.equal(t.calls.length, 0);
  const j = await t.ctx.net.getJson('https://example.com/x');
  assert.equal(j.error.kind, 'offline-mode');
  assert.equal(t.calls.length, 0);
  t.cleanup();
});

test('every network-facing module refuses to send anything in offline mode', async () => {
  const t = makeCtx({ config: { offline: true }, routes: {}, services: { dns: require('./tests-helpers-ctx').fakeDns({ 'A example.com': [{ address: '192.0.2.1', ttl: 1 }] }) } });
  const dnsRes = await t.ctx.dns.resolve('example.com', 'A');
  assert.equal(dnsRes.status, 'failed');
  assert.equal(dnsRes.error.code, 'OFFLINE_MODE');
  assert.equal(t.ctx.services.dns.calls.length, 0, 'system resolver must not be asked');
  const rdap = await require('./network-intelligence-rdap').lookupDomain(t.ctx, 'example.com');
  assert.equal(rdap.ok, false);
  const ct = await require('./network-intelligence-certs').ctSearch(t.ctx, 'example.com');
  assert.equal(ct.ok, false);
  const tls = await require('./network-intelligence-diagnostics').tlsProbe(t.ctx, 'example.com', { authorized: true });
  assert.equal(tls.error.kind, 'offline-mode');
  const http = await require('./network-intelligence-diagnostics').httpProbe(t.ctx, 'https://example.com/', { authorized: true });
  assert.equal(http.error.kind, 'offline-mode');
  const tcp = await require('./network-intelligence-diagnostics').tcpLatency(t.ctx, 'example.com', 443, { authorized: true });
  assert.equal(tcp.error.kind, 'offline-mode');
  const search = await require('./web-intelligence-providers').searchAll(t.ctx, 'anything');
  assert.ok(search.filter((p) => p.status === 'ok').length === 0);
  assert.equal(t.calls.length, 0);
  t.cleanup();
});

test('timeouts abort the request and report a timeout', async () => {
  const t = makeCtx({ routes: { 'slow.test': { never: true } } });
  const started = Date.now();
  const r = await t.ctx.net.get('https://slow.test/', { timeoutMs: 80 });
  assert.equal(r.error.kind, 'timeout');
  assert.ok(Date.now() - started < 1500);
  t.cleanup();
});

test('answers are cached, the cache expires, and clearing it works', async () => {
  let clock = 1_000_000;
  const t = makeCtx({ routes: { 'ok.test': { status: 200, body: 'hello' } }, services: { now: () => clock } });
  const a = await t.ctx.net.get('https://ok.test/a');
  const b = await t.ctx.net.get('https://ok.test/a');
  assert.equal(a.fromCache, false);
  assert.equal(b.fromCache, true);
  assert.equal(b.body, 'hello');
  assert.equal(t.calls.length, 1);
  clock += 61 * 60 * 1000;
  const c = await t.ctx.net.get('https://ok.test/a');
  assert.equal(c.fromCache, false);
  assert.equal(t.calls.length, 2);
  const cleared = t.ctx.cache.clear();
  assert.ok(cleared.entries >= 1);
  assert.equal(t.ctx.cache.stats().entries, 0);
  t.ctx.net.bypassCache = true;
  await t.ctx.net.get('https://ok.test/a');
  await t.ctx.net.get('https://ok.test/a');
  assert.equal(t.calls.length, 4, 'bypassCache fetches fresh');
  t.cleanup();
});

test('cache can be switched off (0 minutes) and failures are never cached', async () => {
  const t = makeCtx({ config: { cacheTtlMinutes: 0 }, routes: { 'ok.test': { body: 'x' }, 'bad.test': { status: 500 } } });
  await t.ctx.net.get('https://ok.test/');
  await t.ctx.net.get('https://ok.test/');
  assert.equal(t.calls.length, 2);
  t.ctx.config.set('cacheTtlMinutes', 10);
  await t.ctx.net.get('https://bad.test/');
  await t.ctx.net.get('https://bad.test/');
  assert.equal(t.calls.length, 4);
  t.cleanup();
});

test('retries are limited: one retry on 503, then a clear failure', async () => {
  let n = 0;
  const t = makeCtx({ config: { maxRetries: 1 }, routes: { 'flaky.test': () => { n++; return { status: n === 1 ? 503 : 200, body: 'finally' }; }, 'down.test': { status: 503 } }, services: {} });
  t.ctx.net.sleep = async () => {};
  const ok = await t.ctx.net.get('https://flaky.test/');
  assert.equal(ok.ok, true);
  assert.equal(n, 2);
  const bad = await t.ctx.net.get('https://down.test/');
  assert.equal(bad.ok, false);
  assert.equal(t.calls.filter((c) => c.url.includes('down.test')).length, 2, 'no infinite retry loops');
  t.cleanup();
});

test('rate limiter spaces requests to one host but not to different hosts', async () => {
  const waits = [];
  const t = makeCtx({ routes: { 'a.test': { body: 'a' }, 'b.test': { body: 'b' } } });
  t.ctx.config.set('minRequestIntervalMs', 400);
  t.ctx.net.sleep = async (ms) => { waits.push(ms); };
  const fixed = 5_000_000;
  t.ctx.net.now = () => fixed;
  await t.ctx.net.get('https://a.test/1', { useCache: false });
  await t.ctx.net.get('https://a.test/2', { useCache: false });
  await t.ctx.net.get('https://b.test/1', { useCache: false });
  assert.deepEqual(waits, [400]);
  t.cleanup();
});

test('responses are size-limited, redirects report the final address, bad URLs are explained', async () => {
  const t = makeCtx({ routes: { 'big.test': { body: 'x'.repeat(5000) }, 'redir.test': { body: 'landed', url: 'https://final.test/page' } } });
  const big = await t.ctx.net.get('https://big.test/', { maxBytes: 1000 });
  assert.equal(big.truncated, true);
  assert.equal(big.body.length, 1000);
  const r = await t.ctx.net.get('https://redir.test/start');
  assert.equal(r.finalUrl, 'https://final.test/page');
  const bad = await t.ctx.net.get('file:///etc/passwd');
  assert.equal(bad.error.kind, 'bad-url');
  assert.equal(t.calls.length, 2, 'non-http addresses are never requested');
  const dns = await makeCtx({ routes: { 'nx.test': { throws: Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND' } }) } } }).ctx.net.get('https://nx.test/');
  assert.equal(dns.error.kind, 'dns');
  t.cleanup();
});

test('logs never contain API keys or tokens', async () => {
  const t = makeCtx({ routes: { 'x.test': { body: '{}' } } });
  t.ctx.config.set('apiKeys.brave', 'SUPERSECRETKEY12345');
  t.ctx.config.set('logLevel', 'debug');
  t.ctx.log.setLevel('debug');
  await t.ctx.net.get('https://x.test/?api_key=SUPERSECRETKEY12345&token=abc');
  t.ctx.log.info('note', { text: 'key was SUPERSECRETKEY12345', headers: { Authorization: 'Bearer abcdefghijklmnopqrstuvwxyz' } });
  const logFile = path.join(t.ctx.paths.logDir, 'orkardch.log');
  const text = fs.readFileSync(logFile, 'utf8');
  assert.ok(text.length > 0);
  assert.ok(!text.includes('SUPERSECRETKEY12345'));
  assert.ok(!text.includes('abcdefghijklmnopqrstuvwxyz'));
  t.cleanup();
});
