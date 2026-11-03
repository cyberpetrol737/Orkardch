'use strict';
const net = require('net');
const { sleep } = require('./utils-format');

const MAX_SAMPLES = 5;

const TLS_CODES = {
  CERT_HAS_EXPIRED: 'The certificate has expired.',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'The certificate is self-signed (not vouched for by a trusted authority).',
  SELF_SIGNED_CERT_IN_CHAIN: 'The certificate chain includes a self-signed certificate that is not trusted.',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'The certificate chain is incomplete or the issuer is unknown.',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'The issuer of the certificate is not trusted on this device.',
  ERR_TLS_CERT_ALTNAME_INVALID: 'The certificate is for a different name than the one you asked for.',
  CERT_NOT_YET_VALID: 'The certificate is not valid yet (its start date is in the future, or this phone\'s clock is wrong).',
};

function mapNetError(err, timedOut) {
  const code = String((err && err.code) || (timedOut ? 'ETIMEDOUT' : 'ERROR'));
  if (timedOut || /ETIMEDOUT|ESOCKETTIMEDOUT/.test(code)) return { kind: 'timeout', code, message: 'No answer before the timeout.' };
  if (/ENOTFOUND|EAI_AGAIN/.test(code)) return { kind: 'dns', code, message: 'The name could not be found (DNS lookup failed).' };
  if (code === 'ECONNREFUSED') return { kind: 'refused', code, message: 'The server refused the connection (nothing is listening on that port, or a firewall blocked it).' };
  if (/EHOSTUNREACH|ENETUNREACH/.test(code)) return { kind: 'unreachable', code, message: 'There is no route to that host from this network.' };
  if (code === 'ECONNRESET') return { kind: 'reset', code, message: 'The connection was cut by the other side.' };
  if (TLS_CODES[code]) return { kind: 'tls', code, message: TLS_CODES[code] };
  if (/CERT|SSL|TLS/.test(code)) return { kind: 'tls', code, message: `Secure connection problem: ${(err && err.message) || code}` };
  return { kind: 'network', code, message: (err && err.message) || 'Network error' };
}

const notAuthorized = () => ({ ok: false, error: { kind: 'not-authorized', code: 'NOT_AUTHORIZED', message: 'Active checks connect to the target, so Orkardch only runs them after you confirm you own it or have permission to test it.' } });

function offlineGate(ctx, purpose) { return ctx.net.offlineFailure(purpose); }
function activeGate(ctx, authorized, purpose) {
  const off = offlineGate(ctx, purpose);
  if (off) return { ok: false, error: off };
  if (!ctx.config.get('activeChecks')) return { ok: false, error: { kind: 'disabled', code: 'ACTIVE_CHECKS_OFF', message: 'Active checks are switched off in Settings.' } };
  if (authorized !== true) return notAuthorized();
  return null;
}

function parseCert(c, host, now) {
  if (!c || !c.subject) return null;
  const tls = require('tls');
  const to = c.valid_to ? new Date(c.valid_to) : null;
  const from = c.valid_from ? new Date(c.valid_from) : null;
  const days = to && !Number.isNaN(to.getTime()) ? Math.floor((to.getTime() - now) / 86400000) : null;
  let nameMatch = null;
  if (!net.isIP(host)) { try { nameMatch = tls.checkServerIdentity(host, c) === undefined; } catch { nameMatch = null; } }
  const chain = [];
  let cur = c;
  for (let i = 0; cur && i < 5; i++) { chain.push({ subject: cur.subject && (cur.subject.CN || cur.subject.O) || null, issuer: cur.issuer && (cur.issuer.CN || cur.issuer.O) || null }); if (!cur.issuerCertificate || cur.issuerCertificate === cur) break; cur = cur.issuerCertificate; }
  return {
    subject: c.subject.CN || c.subject.O || null, issuer: c.issuer ? (c.issuer.CN || c.issuer.O || null) : null,
    validFrom: from && !Number.isNaN(from.getTime()) ? from.toISOString() : null, validTo: to && !Number.isNaN(to.getTime()) ? to.toISOString() : null,
    daysRemaining: days, expired: days !== null ? days < 0 : null,
    altNames: String(c.subjectaltname || '').split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean).slice(0, 30),
    sha256: c.fingerprint256 || null, serial: c.serialNumber || null, nameMatchesHost: nameMatch, chain,
  };
}

/** Connect once and read the live TLS certificate. Needs authorization. */
function tlsProbe(ctx, host, { port = 443, timeoutMs = 8000, authorized } = {}) {
  const gate = activeGate(ctx, authorized, `TLS check of ${host}`);
  if (gate) return Promise.resolve({ ...gate, host, port });
  const now = ctx.services.now();
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve({ host, port, retrievedAt: new Date(ctx.services.now()).toISOString(), ...v }); } };
    const started = ctx.services.now();
    let socket;
    try {
      socket = ctx.services.tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
        const cert = parseCert(socket.getPeerCertificate(true), host, now);
        const out = { ok: true, protocol: socket.getProtocol(), cipher: (socket.getCipher() || {}).name || null, trusted: socket.authorized, trustError: socket.authorizationError ? String(socket.authorizationError) : null, handshakeMs: ctx.services.now() - started, certificate: cert };
        socket.end();
        finish(out);
      });
    } catch (e) { finish({ ok: false, error: mapNetError(e) }); return; }
    socket.on('timeout', () => { socket.destroy(); finish({ ok: false, error: mapNetError(null, true) }); });
    socket.on('error', (e) => finish({ ok: false, error: mapNetError(e) }));
  });
}

function tcpOnce(ctx, host, port, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = ctx.services.now();
    let lookupMs = null;
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const s = ctx.services.net.connect({ host, port, timeout: timeoutMs });
    s.once('lookup', () => { lookupMs = ctx.services.now() - t0; });
    s.once('connect', () => { const ms = ctx.services.now() - t0; const remote = s.remoteAddress; s.destroy(); finish({ ok: true, ms, lookupMs, remote }); });
    s.once('timeout', () => { s.destroy(); finish({ ok: false, error: mapNetError(null, true) }); });
    s.once('error', (e) => finish({ ok: false, error: mapNetError(e) }));
  });
}

/** A few TCP connects to one port. Not a port scan: one host, one port, at most 5 tries. */
async function tcpLatency(ctx, host, port, { count = 4, timeoutMs = 4000, authorized, gapMs = 250 } = {}) {
  const gate = activeGate(ctx, authorized, `connection test of ${host}:${port}`);
  if (gate) return { ...gate, host, port };
  const n = Math.max(1, Math.min(MAX_SAMPLES, count));
  const samples = [];
  for (let i = 0; i < n; i++) {
    samples.push(await tcpOnce(ctx, host, port, timeoutMs));
    if (i < n - 1) await sleep(gapMs);
  }
  const okMs = samples.filter((s) => s.ok).map((s) => s.ms);
  return {
    ok: okMs.length > 0, host, port, attempts: n, successes: okMs.length, lossPercent: Math.round(((n - okMs.length) / n) * 100),
    minMs: okMs.length ? Math.min(...okMs) : null, maxMs: okMs.length ? Math.max(...okMs) : null, avgMs: okMs.length ? Math.round(okMs.reduce((a, b) => a + b, 0) / okMs.length) : null,
    remote: (samples.find((s) => s.ok) || {}).remote || null, error: okMs.length ? null : (samples[0] && samples[0].error), retrievedAt: new Date(ctx.services.now()).toISOString(),
  };
}

/** One HTTP(S) request. Headers only: the body is never downloaded. Redirects are reported, not followed. */
function httpProbe(ctx, urlStr, { timeoutMs = 8000, authorized } = {}) {
  let u;
  try { u = new URL(urlStr); } catch { return Promise.resolve({ ok: false, error: { kind: 'bad-url', code: 'BAD_URL', message: 'That is not a valid web address.' } }); }
  const gate = activeGate(ctx, authorized, `web request to ${u.hostname}`);
  if (gate) return Promise.resolve({ ...gate, url: urlStr });
  const mod = u.protocol === 'https:' ? ctx.services.https : ctx.services.http;
  return new Promise((resolve) => {
    const t0 = ctx.services.now();
    const timing = {};
    let done = false;
    let timedOut = false;
    const finish = (v) => { if (!done) { done = true; resolve({ url: urlStr, retrievedAt: new Date(ctx.services.now()).toISOString(), timing, ...v }); } };
    const req = mod.request({
      protocol: u.protocol, hostname: u.hostname, port: u.port || undefined, path: `${u.pathname}${u.search}`, method: 'GET',
      headers: { 'user-agent': ctx.net.userAgent(), accept: '*/*', connection: 'close' }, timeout: timeoutMs,
    }, (res) => {
      timing.firstByteMs = ctx.services.now() - t0;
      const h = res.headers;
      const info = {
        ok: true, status: res.statusCode, statusText: res.statusMessage || '', redirectTo: h.location || null, server: h.server || null,
        contentType: h['content-type'] || null, hsts: Boolean(h['strict-transport-security']), totalMs: ctx.services.now() - t0,
      };
      res.destroy();
      finish(info);
    });
    req.on('socket', (sock) => {
      sock.once('lookup', () => { timing.dnsMs = ctx.services.now() - t0; });
      sock.once('connect', () => { timing.connectMs = ctx.services.now() - t0; });
      sock.once('secureConnect', () => { timing.tlsMs = ctx.services.now() - t0; });
    });
    req.on('timeout', () => { timedOut = true; req.destroy(); });
    req.on('error', (e) => finish({ ok: false, error: mapNetError(e, timedOut) }));
    req.end();
  });
}

module.exports = { tlsProbe, tcpLatency, httpProbe, mapNetError, TLS_CODES };
