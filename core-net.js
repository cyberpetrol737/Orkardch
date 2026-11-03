'use strict';
const { offlineFailure } = require('./core-errors');
const { sleep: defaultSleep } = require('./utils-format');

const KEEP_HEADERS = ['content-type', 'content-length', 'last-modified', 'etag', 'retry-after', 'location', 'server', 'date', 'link'];

function failure(error, url, startedAt, now) {
  return {
    ok: false, status: 0, url, finalUrl: url, headers: {}, body: '', bytes: 0, truncated: false,
    fromCache: false, retrievedAt: new Date(now()).toISOString(), elapsedMs: now() - startedAt, error,
  };
}

function classify(err, timedOut, userSignal) {
  if (timedOut) return { kind: 'timeout', code: 'TIMEOUT', message: 'The server did not answer in time.' };
  if ((userSignal && userSignal.aborted) || (err && err.name === 'AbortError')) {
    return { kind: 'aborted', code: 'ABORTED', message: 'The request was cancelled.' };
  }
  const code = String((err && err.cause && err.cause.code) || (err && err.code) || '');
  const msg = (err && err.cause && err.cause.message) || (err && err.message) || 'Network error';
  if (/ENOTFOUND|EAI_AGAIN|EAI_NODATA/.test(code)) return { kind: 'dns', code, message: 'The name could not be found (DNS lookup failed).' };
  if (/CERT|SSL|TLS|UNABLE_TO_VERIFY|SELF_SIGNED|DEPTH_ZERO/.test(code + msg)) return { kind: 'tls', code: code || 'TLS_ERROR', message: `Secure connection problem: ${msg}` };
  if (code === 'ECONNREFUSED') return { kind: 'refused', code, message: 'The server refused the connection.' };
  if (/UND_ERR_CONNECT_TIMEOUT|ETIMEDOUT/.test(code)) return { kind: 'timeout', code, message: 'The connection timed out.' };
  return { kind: 'network', code: code || 'NETWORK_ERROR', message: String(msg) };
}

async function readBody(res, maxBytes) {
  if (!res.body || typeof res.body.getReader !== 'function') {
    const t = await res.text();
    return { text: t.slice(0, maxBytes), bytes: Buffer.byteLength(t), truncated: t.length > maxBytes };
  }
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    if (total > maxBytes) { truncated = true; try { await reader.cancel(); } catch { /* ignore */ } break; }
  }
  return { text: Buffer.concat(chunks).subarray(0, maxBytes).toString('utf8'), bytes: total, truncated };
}

function pickHeaders(h) {
  const out = {};
  if (!h || typeof h.get !== 'function') return out;
  for (const k of KEEP_HEADERS) { const v = h.get(k); if (v != null) out[k] = v; }
  return out;
}

/**
 * HTTP GET with offline gate, per-host rate limit, timeout, bounded body size,
 * limited retries and an on-disk cache. get() never throws: check result.ok / result.error.
 */
class NetClient {
  constructor({ config, cache, log, fetchImpl, now = Date.now, sleep = defaultSleep, version = '1.0.0' }) {
    this.config = config;
    this.cache = cache;
    this.log = log;
    this.fetchImpl = fetchImpl;
    this.now = now;
    this.sleep = sleep;
    this.version = version;
    this._next = new Map();
    this.requestCount = 0;
    this.bypassCache = false; // when true, answers are fetched fresh (and the cache is refreshed)
  }

  get offline() { return Boolean(this.config.get('offline')); }
  offlineFailure(purpose) { return this.offline ? offlineFailure(purpose) : null; }
  userAgent() { return `Orkardch/${this.version} (open-source research tool; contact: none)`; }

  async _throttle(host) {
    const gap = this.config.get('minRequestIntervalMs') || 0;
    if (!gap) return;
    const t = this.now();
    const start = Math.max(t, this._next.get(host) || 0);
    this._next.set(host, start + gap);
    if (start > t) await this.sleep(start - t);
  }

  async _once(url, { headers, timeoutMs, maxBytes, signal }) {
    const started = this.now();
    const ctrl = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, timeoutMs);
    const onAbort = () => ctrl.abort();
    if (signal) { if (signal.aborted) ctrl.abort(); else signal.addEventListener('abort', onAbort, { once: true }); }
    this.requestCount++;
    try {
      const res = await this.fetchImpl(url, {
        method: 'GET',
        headers: { 'user-agent': this.userAgent(), accept: '*/*', ...headers },
        redirect: 'follow',
        signal: ctrl.signal,
      });
      const body = await readBody(res, maxBytes);
      const ok = res.status >= 200 && res.status < 300;
      return {
        ok, status: res.status, url, finalUrl: res.url || url, headers: pickHeaders(res.headers),
        body: body.text, bytes: body.bytes, truncated: body.truncated, fromCache: false,
        retrievedAt: new Date(this.now()).toISOString(), elapsedMs: this.now() - started,
        error: ok ? null : {
          kind: res.status === 429 ? 'rate-limited' : 'http', code: `HTTP_${res.status}`,
          message: `The server answered ${res.status}${res.statusText ? ` ${res.statusText}` : ''}.`,
        },
      };
    } catch (err) {
      return failure(classify(err, timedOut, signal), url, started, this.now);
    } finally {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
    }
  }

  async get(url, opts = {}) {
    const {
      headers = {}, timeoutMs = this.config.get('requestTimeoutMs'), maxBytes = 2000000,
      useCache = true, cacheTtlMs, signal, purpose, retries = this.config.get('maxRetries'),
    } = opts;
    const off = this.offlineFailure(purpose || url);
    if (off) return failure(off, url, this.now(), this.now);
    let parsed;
    try { parsed = new URL(url); } catch { parsed = null; }
    if (!parsed || !/^https?:$/.test(parsed.protocol)) {
      return failure({ kind: 'bad-url', code: 'BAD_URL', message: `"${url}" is not a valid web address (use http:// or https://).` }, url, this.now(), this.now);
    }
    const cacheKey = `GET ${url}\naccept=${headers.accept || headers.Accept || ''}`;
    if (useCache && this.cache && !this.bypassCache) {
      const hit = this.cache.get(cacheKey);
      if (hit) return { ...hit.value, fromCache: true, cachedAt: hit.storedAt };
    }
    let attempt = 0;
    let last;
    for (;;) {
      await this._throttle(parsed.host);
      last = await this._once(url, { headers, timeoutMs, maxBytes, signal });
      const retryable = !last.ok && (['timeout', 'network'].includes(last.error && last.error.kind) || [429, 502, 503, 504].includes(last.status));
      if (!retryable || attempt >= retries || (signal && signal.aborted)) break;
      attempt++;
      const ra = Number(last.headers['retry-after']);
      await this.sleep(Number.isFinite(ra) && ra > 0 ? Math.min(ra, 5) * 1000 : 600 * attempt);
    }
    if (last.ok && useCache && this.cache) this.cache.set(cacheKey, last, cacheTtlMs);
    if (this.log) this.log.debug('http.get', { url, status: last.status, ok: last.ok, ms: last.elapsedMs, error: last.error && last.error.kind });
    return last;
  }

  /** GET and parse JSON. Adds .json on success or an error of kind "parse". */
  async getJson(url, opts = {}) {
    const res = await this.get(url, { ...opts, headers: { accept: 'application/json', ...(opts.headers || {}) } });
    if (!res.body) return res;
    try {
      return { ...res, json: JSON.parse(res.body) };
    } catch (err) {
      if (res.ok) return { ...res, ok: false, error: { kind: 'parse', code: 'BAD_JSON', message: `The answer was not valid JSON (${err.message}).` } };
      return res;
    }
  }
}

module.exports = { NetClient, failure, classify };
