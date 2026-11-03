'use strict';
const { ptrName, cymruOriginName } = require('./network-intelligence-ip');
const { mapLimit } = require('./core-concurrency');

const DOH = { cloudflare: 'https://cloudflare-dns.com/dns-query', google: 'https://dns.google/resolve' };
const TYPE_CODE = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
const FALLBACK_CODES = new Set(['ECONNREFUSED', 'ETIMEOUT', 'ECONNRESET', 'ENOTINITIALIZED', 'EBADRESP', 'ECANCELLED']);
const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'];

const stripDot = (s) => String(s).replace(/\.$/, '');

function parseCaaWire(hex) {
  const b = Buffer.from(hex.replace(/\s+/g, ''), 'hex');
  if (b.length < 3) return null;
  const tagLen = b[1];
  return `${b[0]} ${b.toString('latin1', 2, 2 + tagLen)} "${b.toString('utf8', 2 + tagLen)}"`;
}

function quotedChunks(s) {
  const parts = [...String(s).matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, '$1'));
  return parts.length ? parts.join('') : String(s);
}

/** Normalise one DoH answer into the same record shape the system resolver produces. */
function dohRecord(type, a) {
  const d = String(a.data);
  const ttl = a.TTL;
  switch (type) {
    case 'A': case 'AAAA': return { value: d, ttl, data: { address: d } };
    case 'NS': case 'CNAME': case 'PTR': return { value: stripDot(d), ttl, data: { target: stripDot(d) } };
    case 'MX': { const [p, ...rest] = d.split(/\s+/); return { value: `${p} ${stripDot(rest.join(' '))}`, ttl, data: { priority: Number(p), exchange: stripDot(rest.join(' ')) } }; }
    case 'TXT': return { value: quotedChunks(d), ttl, data: {} };
    case 'SOA': { const [ns, host, serial, refresh, retry, expire, minttl] = d.split(/\s+/); return { value: `${stripDot(ns)} ${stripDot(host)} serial ${serial}`, ttl, data: { nsname: stripDot(ns), hostmaster: stripDot(host), serial: Number(serial), refresh: Number(refresh), retry: Number(retry), expire: Number(expire), minttl: Number(minttl) } }; }
    case 'CAA': { const v = d.startsWith('\\#') ? parseCaaWire(d.replace(/^\\#\s+\d+\s+/, '')) : d; return { value: v || d, ttl, data: {} }; }
    default: return { value: d, ttl, data: {} };
  }
}

function describeSystemError(code) {
  const m = {
    ECONNREFUSED: 'No DNS server answered on this phone (nothing was listening). This is common in Termux.',
    ETIMEOUT: 'The DNS server did not answer in time. The network may be down or blocking DNS.',
    ESERVFAIL: 'The DNS server reported a failure while looking this up (the domain\'s own servers may be broken).',
    EREFUSED: 'The DNS server refused the question.',
    EBADNAME: 'That name is not valid for DNS.',
    EBADRESP: 'The DNS server sent a garbled answer.',
    ECANCELLED: 'The lookup was cancelled.',
  };
  return m[code] || `The lookup failed (${code}).`;
}

class DnsClient {
  constructor(ctx) { this.ctx = ctx; this.systemBroken = false; }

  _base(name, type) {
    return { name, type, status: 'failed', records: [], resolver: 'system', retrievedAt: new Date(this.ctx.services.now()).toISOString(), error: null, note: null };
  }

  async _system(name, type) {
    const out = this._base(name, type);
    const svc = this.ctx.services.dns;
    const servers = this.ctx.config.get('dns.servers') || [];
    try {
      const resolver = new svc.promises.Resolver({ timeout: 4000, tries: 2 });
      if (servers.length) resolver.setServers(servers);
      out.resolver = servers.length ? `system (custom servers ${servers.join(', ')})` : 'system';
      let records = [];
      switch (type) {
        case 'A': records = (await resolver.resolve4(name, { ttl: true })).map((r) => ({ value: r.address, ttl: r.ttl, data: { address: r.address } })); break;
        case 'AAAA': records = (await resolver.resolve6(name, { ttl: true })).map((r) => ({ value: r.address, ttl: r.ttl, data: { address: r.address } })); break;
        case 'MX': records = (await resolver.resolveMx(name)).sort((a, b) => a.priority - b.priority).map((r) => ({ value: `${r.priority} ${r.exchange}`, data: r })); break;
        case 'NS': records = (await resolver.resolveNs(name)).map((v) => ({ value: v, data: { target: v } })); break;
        case 'TXT': records = (await resolver.resolveTxt(name)).map((chunks) => ({ value: chunks.join(''), data: {} })); break;
        case 'CNAME': records = (await resolver.resolveCname(name)).map((v) => ({ value: v, data: { target: v } })); break;
        case 'PTR': records = (await resolver.resolvePtr(name)).map((v) => ({ value: v, data: { target: v } })); break;
        case 'SOA': { const r = await resolver.resolveSoa(name); records = [{ value: `${r.nsname} ${r.hostmaster} serial ${r.serial}`, data: r }]; break; }
        case 'CAA': records = (await resolver.resolveCaa(name)).map((r) => ({ value: `${r.critical} ${Object.keys(r).find((k) => k !== 'critical')} "${Object.entries(r).find(([k]) => k !== 'critical')[1]}"`, data: r })); break;
        default: out.error = { code: 'UNSUPPORTED', message: `Record type ${type} is not supported.` }; return out;
      }
      out.records = records;
      out.status = records.length ? 'ok' : 'no-data';
    } catch (err) {
      const code = err && err.code ? String(err.code) : 'ERROR';
      if (code === 'ENODATA') out.status = 'no-data';
      else if (code === 'ENOTFOUND') out.status = 'nxdomain';
      else out.error = { code, message: describeSystemError(code) };
    }
    return out;
  }

  async _doh(name, type) {
    const out = this._base(name, type);
    const provider = this.ctx.config.get('dns.dohProvider');
    out.resolver = `doh:${provider}`;
    const url = `${DOH[provider]}?name=${encodeURIComponent(name)}&type=${type}`;
    const res = await this.ctx.net.getJson(url, { headers: { accept: 'application/dns-json' }, useCache: false, purpose: `DNS-over-HTTPS lookup of ${name}` });
    if (!res.ok || !res.json) { out.error = { code: (res.error && res.error.code) || 'DOH_FAILED', message: (res.error && res.error.message) || 'The DNS-over-HTTPS service did not answer.', kind: res.error && res.error.kind }; return out; }
    const st = res.json.Status;
    if (st === 3) { out.status = 'nxdomain'; return out; }
    if (st !== 0) { out.error = { code: `DOH_STATUS_${st}`, message: describeSystemError(st === 2 ? 'ESERVFAIL' : st === 5 ? 'EREFUSED' : `DNS status ${st}`) }; return out; }
    const answers = (res.json.Answer || []).filter((a) => a.type === TYPE_CODE[type]);
    out.records = answers.map((a) => dohRecord(type, a));
    const chain = (res.json.Answer || []).filter((a) => a.type === TYPE_CODE.CNAME && type !== 'CNAME');
    if (chain.length) out.cnameChain = chain.map((a) => `${stripDot(a.name)} -> ${stripDot(a.data)}`);
    out.status = out.records.length ? 'ok' : 'no-data';
    return out;
  }

  /** Look up one record type. Always resolves; check .status ('ok', 'no-data', 'nxdomain', 'failed'). */
  async resolve(name, type = 'A') {
    const off = this.ctx.net.offlineFailure(`DNS lookup of ${name}`);
    if (off) return { ...this._base(name, type), resolver: 'none', error: { code: off.code, message: off.message, hint: off.hint } };
    const mode = this.ctx.config.get('dns.mode');
    if (mode === 'doh' || (mode === 'auto' && this.systemBroken)) return this._doh(name, type);
    const r = await this._system(name, type);
    if (r.status === 'failed' && mode === 'auto' && r.error && FALLBACK_CODES.has(r.error.code)) {
      const d = await this._doh(name, type);
      if (d.status !== 'failed') {
        this.systemBroken = true;
        d.note = `The phone's own DNS resolver was unreachable (${r.error.code}), so Orkardch asked a public DNS-over-HTTPS service (${this.ctx.config.get('dns.dohProvider')}) instead.`;
        return d;
      }
      r.fallbackError = d.error;
    }
    return r;
  }

  async resolveMany(name, types = TYPES) {
    const limit = this.ctx.config.get('maxParallelRequests');
    const results = await mapLimit(types, limit, (t) => this.resolve(name, t));
    return results.map((r, i) => (r && r.error && !r.status ? { ...this._base(name, types[i]), error: { code: 'ERROR', message: String(r.error.message || r.error) } } : r));
  }

  async reverse(ip) {
    const name = ptrName(ip);
    if (!name) return { ...this._base(String(ip), 'PTR'), error: { code: 'BAD_IP', message: 'Not a valid IP address.' } };
    const r = await this.resolve(name, 'PTR');
    return { ...r, queried: ip };
  }
}

/** Team Cymru IP-to-ASN mapping, answered over DNS. Returns {ok, asns, prefix, country, registry, allocated}. */
async function lookupOrigin(ctx, ip) {
  const name = cymruOriginName(ip);
  const r = await ctx.dns.resolve(name, 'TXT');
  if (r.status !== 'ok') return { ok: false, status: r.status, error: r.error, source: `${name} (Team Cymru, via DNS)`, retrievedAt: r.retrievedAt, resolver: r.resolver };
  const parts = r.records[0].value.split('|').map((s) => s.trim());
  return {
    ok: true, asns: (parts[0] || '').split(/\s+/).filter(Boolean).map(Number), prefix: parts[1] || null, country: parts[2] || null,
    registry: parts[3] || null, allocated: parts[4] || null, source: `${name} (Team Cymru, via DNS)`, retrievedAt: r.retrievedAt, resolver: r.resolver,
  };
}

async function lookupAsnName(ctx, asn) {
  const name = `AS${asn}.asn.cymru.com`;
  const r = await ctx.dns.resolve(name, 'TXT');
  if (r.status !== 'ok') return { ok: false, status: r.status, error: r.error, source: `${name} (Team Cymru, via DNS)`, retrievedAt: r.retrievedAt };
  const parts = r.records[0].value.split('|').map((s) => s.trim());
  return { ok: true, asn, country: parts[1] || null, registry: parts[2] || null, allocated: parts[3] || null, name: parts[4] || null, source: `${name} (Team Cymru, via DNS)`, retrievedAt: r.retrievedAt };
}

const EXPLAIN = {
  A: 'IPv4 address(es) of the server for this name.',
  AAAA: 'IPv6 address(es) of the server for this name.',
  MX: 'Mail servers that accept email for this domain. The lower number is tried first.',
  NS: 'The name servers that hold the official DNS records for this domain.',
  TXT: 'Free-text notes. Often used to prove ownership or to publish email rules (SPF, DKIM, DMARC).',
  CNAME: 'This name is an alias that points to another name.',
  SOA: 'Administrative record for the DNS zone: the primary name server, a contact, and a version number (serial).',
  CAA: 'Which certificate authorities are allowed to issue certificates for this domain.',
  PTR: 'The name registered for this IP address ("reverse DNS"). The owner of the address sets it, so it is a hint, not proof.',
};

function interpretTxt(value) {
  if (/^v=spf1\b/i.test(value)) return 'SPF: lists which servers may send email for this domain.';
  if (/^v=dmarc1\b/i.test(value)) return 'DMARC: tells receivers what to do with email that fails checks.';
  if (/^v=dkim1\b/i.test(value)) return 'DKIM public key: lets receivers verify email signatures.';
  if (/site-verification|domain-verification|verify/i.test(value)) return 'A verification token proving control of the domain to some service.';
  return null;
}

module.exports = { DnsClient, lookupOrigin, lookupAsnName, EXPLAIN, interpretTxt, TYPES, describeSystemError };
