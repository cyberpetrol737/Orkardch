'use strict';
const net = require('net');
const { domainToASCII } = require('url');

const TRACKING = /^(utm_[a-z]+|fbclid|gclid|mc_cid|mc_eid|igshid|ref_src|spm|_hsenc|_hsmi)$/i;

function stripDot(n) { return n.endsWith('.') ? n.slice(0, -1) : n; }

function isValidHostname(name) {
  if (typeof name !== 'string') return false;
  const n = stripDot(name);
  if (!n || n.length > 253) return false;
  return n.split('.').every((l) => l.length >= 1 && l.length <= 63 && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(l));
}

function isValidDomain(name) {
  if (!isValidHostname(name)) return false;
  const labels = stripDot(name).split('.');
  if (labels.length < 2) return false;
  const tld = labels[labels.length - 1];
  return /^[a-z]{2,63}$/i.test(tld) || /^xn--[a-z0-9-]{1,59}$/i.test(tld);
}

/** Reduce "https://User@Example.COM:8080/path?x" to "example.com" (IDN becomes punycode). */
function normalizeDomain(input) {
  let s = String(input || '').trim();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  s = s.split(/[/?#]/)[0];
  s = s.replace(/^[^@]*@/, '');
  if (!s.startsWith('[')) s = s.replace(/:\d+$/, '');
  s = stripDot(s).toLowerCase();
  return domainToASCII(s) || s;
}

function parseAsn(input) {
  const m = /^as\s*(\d{1,10})$/i.exec(String(input || '').trim());
  if (!m) return null;
  const n = Number(m[1]);
  return n > 0 && n <= 4294967295 ? n : null;
}

/** Guess what the person typed. Returns {kind, value}. */
function classifyInput(input) {
  const raw = String(input || '').trim();
  if (!raw) return { kind: 'empty' };
  const asn = parseAsn(raw);
  if (asn) return { kind: 'asn', value: asn };
  const bare = raw.replace(/^\[|\]$/g, '');
  if (net.isIP(bare)) return { kind: 'ip', value: bare };
  if (/^https?:\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      const host = u.hostname.replace(/^\[|\]$/g, '');
      if (net.isIP(host)) return { kind: 'ip', value: host, url: raw };
      return { kind: 'domain', value: normalizeDomain(host), url: raw };
    } catch { return { kind: 'invalid', value: raw }; }
  }
  const d = normalizeDomain(raw);
  if (isValidDomain(d)) return { kind: 'domain', value: d };
  if (isValidHostname(d) && !/\s/.test(raw)) return { kind: 'hostname', value: d };
  return { kind: 'invalid', value: raw };
}

/** Canonical form for comparing URLs: drops fragment, tracking params, default port, trailing "/". */
function normalizeUrl(input) {
  try {
    const u = new URL(String(input).trim());
    if (!/^https?:$/.test(u.protocol)) return null;
    u.hash = '';
    u.hostname = u.hostname.toLowerCase();
    for (const k of [...u.searchParams.keys()]) if (TRACKING.test(k)) u.searchParams.delete(k);
    u.searchParams.sort();
    let s = u.toString();
    if (u.pathname === '/' && !u.search) s = s.replace(/\/$/, '');
    return s;
  } catch { return null; }
}

/** Key used to spot duplicate pages: like normalizeUrl but ignores http/https, a leading "www." and a trailing "/". */
function dedupeKey(input) {
  const n = normalizeUrl(input);
  if (!n) return null;
  return n.replace(/^https?:\/\/(www\.)?/i, '').replace(/\/(?=\?|$)/, '');
}

function urlHost(input) {
  try { return new URL(input).hostname.toLowerCase(); } catch { return null; }
}

const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'gob', 'mil', 'nom']);
/** Approximate registrable domain without a public-suffix list (documented limitation). */
function registrableDomain(host) {
  const h = stripDot(String(host || '').toLowerCase());
  if (!h || net.isIP(h)) return h;
  const p = h.split('.');
  if (p.length <= 2) return h;
  const tld = p[p.length - 1];
  const sld = p[p.length - 2];
  if (tld.length === 2 && SECOND_LEVEL.has(sld)) return p.slice(-3).join('.');
  return p.slice(-2).join('.');
}

module.exports = {
  isValidHostname, isValidDomain, normalizeDomain, parseAsn, classifyInput,
  normalizeUrl, dedupeKey, urlHost, registrableDomain,
};
