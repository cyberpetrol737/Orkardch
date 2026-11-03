'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const net = require('net');
const tls = require('tls');
const { execFileSync } = require('child_process');
const F = require('./tests-helpers-fixtures');
const { makeCtx, fakeDns } = require('./tests-helpers-ctx');
const { classifyIp, ptrName, cymruOriginName } = require('./network-intelligence-ip');
const { lookupOrigin, lookupAsnName, interpretTxt } = require('./network-intelligence-dns');
const rdap = require('./network-intelligence-rdap');
const { ctSearch } = require('./network-intelligence-certs');
const diag = require('./network-intelligence-diagnostics');

test('IP validation and classification (private, loopback, reserved, malformed, IPv6, mapped)', () => {
  const cat = (ip) => { const c = classifyIp(ip); return c.valid ? `${c.category}:${c.public}` : c.error; };
  assert.equal(cat('8.8.8.8'), 'public:true');
  assert.equal(cat('10.1.2.3'), 'private:false');
  assert.equal(cat('172.16.5.5'), 'private:false');
  assert.equal(cat('192.168.0.9'), 'private:false');
  assert.equal(cat('127.0.0.1'), 'loopback:false');
  assert.equal(cat('::1'), 'loopback:false');
  assert.equal(cat('169.254.1.1'), 'link-local:false');
  assert.equal(cat('fe80::1%wlan0'), 'link-local:false');
  assert.equal(cat('100.64.0.1'), 'shared-cgnat:false');
  assert.equal(cat('192.0.2.5'), 'documentation:false');
  assert.equal(cat('2001:db8::1'), 'documentation:false');
  assert.equal(cat('224.0.0.1'), 'multicast:false');
  assert.equal(cat('255.255.255.255'), 'reserved:false');
  assert.equal(cat('fc00::1'), 'unique-local:false');
  assert.equal(cat('2001:4860:4860::8888'), 'public:true');
  assert.equal(cat('::ffff:192.168.1.1'), 'private:false');
  assert.equal(cat('::ffff:8.8.8.8'), 'public:true');
  for (const bad of ['999.1.1.1', '', 'abc', '1.2.3', '1.2.3.4.5', null, undefined, '12345']) assert.equal(cat(bad), 'MALFORMED');
  assert.match(classifyIp('x').message, /not a valid IP/);
  assert.equal(ptrName('8.8.4.4'), '4.4.8.8.in-addr.arpa');
  assert.equal(ptrName('2001:db8::1'), '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa');
  assert.equal(cymruOriginName('8.8.4.4'), '4.4.8.8.origin.asn.cymru.com');
  assert.match(cymruOriginName('2001:db8::1'), /origin6\.asn\.cymru\.com$/);
});

test('DNS: record found, missing record, missing domain and failed lookup are different things', async () => {
  const dns = fakeDns({
    'A example.com': [{ address: '192.0.2.1', ttl: 300 }], 'MX example.com': [{ exchange: 'b.mail.example.com', priority: 20 }, { exchange: 'a.mail.example.com', priority: 10 }],
    'TXT example.com': [['v=spf1 ', 'include:_spf.example.com ~all']], 'A gone.example': 'ENOTFOUND', 'A broken.example': 'ESERVFAIL',
  });
  const t = makeCtx({ services: { dns }, config: { 'dns.mode': 'system' } });
  const a = await t.ctx.dns.resolve('example.com', 'A');
  assert.equal(a.status, 'ok');
  assert.deepEqual(a.records.map((r) => r.value), ['192.0.2.1']);
  assert.equal(a.records[0].ttl, 300);
  assert.equal(a.resolver, 'system');
  assert.equal((await t.ctx.dns.resolve('example.com', 'AAAA')).status, 'no-data');
  assert.equal((await t.ctx.dns.resolve('gone.example', 'A')).status, 'nxdomain');
  const fail = await t.ctx.dns.resolve('broken.example', 'A');
  assert.equal(fail.status, 'failed');
  assert.match(fail.error.message, /failure|server/i);
  const mx = await t.ctx.dns.resolve('example.com', 'MX');
  assert.deepEqual(mx.records.map((r) => r.value), ['10 a.mail.example.com', '20 b.mail.example.com']);
  const txt = await t.ctx.dns.resolve('example.com', 'TXT');
  assert.equal(txt.records[0].value, 'v=spf1 include:_spf.example.com ~all');
  assert.match(interpretTxt(txt.records[0].value), /SPF/);
  const many = await t.ctx.dns.resolveMany('example.com', ['A', 'AAAA', 'MX']);
  assert.deepEqual(many.map((r) => r.status), ['ok', 'no-data', 'ok']);
  assert.equal(t.calls.length, 0, 'system mode does not use HTTP');
  t.cleanup();
});

test('DNS in Termux: unreachable system resolver falls back to DNS-over-HTTPS once, then remembers', async () => {
  const dns = fakeDns({ 'A example.com': 'ECONNREFUSED' });
  const doh = (url) => ({ json: { Status: 0, Answer: [{ name: 'example.com.', type: 1, TTL: 60, data: '192.0.2.77' }] } });
  const t = makeCtx({ services: { dns }, routes: { 'cloudflare-dns.com/dns-query': doh } });
  const r1 = await t.ctx.dns.resolve('example.com', 'A');
  assert.equal(r1.status, 'ok');
  assert.equal(r1.resolver, 'doh:cloudflare');
  assert.match(r1.note, /unreachable \(ECONNREFUSED\)/);
  assert.equal(r1.records[0].value, '192.0.2.77');
  await t.ctx.dns.resolve('example.com', 'A');
  assert.equal(dns.calls.length, 1, 'the broken system resolver is not retried');
  assert.equal(t.calls.length, 2);
  assert.ok(t.calls[0].url.includes('name=example.com') && t.calls[0].headers.accept === 'application/dns-json');
  t.cleanup();
});

test('DNS-over-HTTPS answers are parsed for every record type, including NXDOMAIN and server failures', async () => {
  const answers = {
    MX: [{ type: 15, TTL: 1, data: '10 mx.example.com.' }], NS: [{ type: 2, TTL: 1, data: 'ns1.example.com.' }], TXT: [{ type: 16, TTL: 1, data: '"v=DMARC1; " "p=none"' }],
    SOA: [{ type: 6, TTL: 1, data: 'ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300' }], CAA: [{ type: 257, TTL: 1, data: '0 issue "letsencrypt.org"' }],
    A: [{ type: 5, TTL: 1, data: 'target.example.net.', name: 'www.example.com.' }, { type: 1, TTL: 1, data: '192.0.2.9' }],
  };
  const t = makeCtx({ config: { 'dns.mode': 'doh', 'dns.dohProvider': 'google' }, routes: {
    'dns.google/resolve': (url) => { const type = new URL(url).searchParams.get('type'); const name = new URL(url).searchParams.get('name'); if (name === 'nx.example') return { json: { Status: 3 } }; if (name === 'sf.example') return { json: { Status: 2 } }; return { json: { Status: 0, Answer: answers[type] } }; },
  } });
  const get = (n, ty) => t.ctx.dns.resolve(n, ty);
  assert.equal((await get('example.com', 'MX')).records[0].value, '10 mx.example.com');
  assert.equal((await get('example.com', 'NS')).records[0].value, 'ns1.example.com');
  assert.equal((await get('example.com', 'TXT')).records[0].value, 'v=DMARC1; p=none');
  assert.equal((await get('example.com', 'SOA')).records[0].data.serial, 2024010101);
  assert.equal((await get('example.com', 'CAA')).records[0].value, '0 issue "letsencrypt.org"');
  const a = await get('www.example.com', 'A');
  assert.deepEqual(a.records.map((r) => r.value), ['192.0.2.9']);
  assert.match(a.cnameChain[0], /www\.example\.com -> target\.example\.net/);
  assert.equal((await get('nx.example', 'A')).status, 'nxdomain');
  assert.equal((await get('sf.example', 'A')).status, 'failed');
  assert.equal((await get('example.com', 'AAAA')).status, 'no-data');
  t.cleanup();
});

test('Team Cymru origin and AS-name answers (over DNS) are parsed', async () => {
  const dns = fakeDns({
    'TXT 4.4.8.8.origin.asn.cymru.com': [['15169 | 8.8.4.0/24 | US | arin | 1992-12-01']],
    'TXT AS15169.asn.cymru.com': [['15169 | US | arin | 2000-03-30 | GOOGLE, US']],
  });
  const t = makeCtx({ services: { dns }, config: { 'dns.mode': 'system' } });
  const o = await lookupOrigin(t.ctx, '8.8.4.4');
  assert.equal(o.ok, true);
  assert.deepEqual(o.asns, [15169]);
  assert.equal(o.prefix, '8.8.4.0/24');
  assert.match(o.source, /Team Cymru/);
  const n = await lookupAsnName(t.ctx, 15169);
  assert.equal(n.name, 'GOOGLE, US');
  const miss = await lookupOrigin(t.ctx, '1.2.3.4');
  assert.equal(miss.ok, false);
  const ptr = await t.ctx.dns.reverse('8.8.4.4');
  assert.equal(ptr.queried, '8.8.4.4');
  assert.equal(ptr.status, 'no-data');
  t.cleanup();
});

test('RDAP domain, IP and ASN records keep their source and retrieval time; 404 is "not found", not a crash', async () => {
  const t = makeCtx({ routes: {
    'rdap.org/domain/example.com': { url: 'https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM', json: {
      ldhName: 'EXAMPLE.COM', status: ['client delete prohibited'], events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }, { eventAction: 'expiration', eventDate: '2027-08-13T04:00:00Z' }],
      entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar, Inc.']]], publicIds: [{ type: 'IANA Registrar ID', identifier: '376' }] }],
      nameservers: [{ ldhName: 'A.IANA-SERVERS.NET' }], secureDNS: { delegationSigned: true },
    } },
    'rdap.org/domain/nope.example': { status: 404, json: { errorCode: 404, title: 'Not Found' } },
    'rdap.org/ip/192.0.2.1': { url: 'https://rdap.arin.net/registry/ip/192.0.2.0', json: { name: 'TEST-NET-1', handle: 'NET-192-0-2-0-1', country: 'US', startAddress: '192.0.2.0', endAddress: '192.0.2.255', cidr0_cidrs: [{ v4prefix: '192.0.2.0', length: 24 }], events: [{ eventAction: 'registration', eventDate: '2010-01-01T00:00:00Z' }] } },
    'rdap.org/autnum/64500': { json: { name: 'EXAMPLE-AS', startAutnum: 64500, endAutnum: 64500, country: 'ZZ' } },
  } });
  const d = await rdap.lookupDomain(t.ctx, 'example.com');
  assert.equal(d.ok, true);
  assert.equal(d.registrar, 'Example Registrar, Inc.');
  assert.equal(d.registrarIanaId, '376');
  assert.equal(d.registered, '1995-08-14T04:00:00Z');
  assert.equal(d.dnssecSigned, true);
  assert.match(d.registrantNote, /hide it for privacy/);
  assert.equal(d.source, 'https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM');
  assert.ok(d.retrievedAt);
  const nf = await rdap.lookupDomain(t.ctx, 'nope.example');
  assert.equal(nf.ok, false);
  assert.equal(nf.error.kind, 'not-found');
  const ip = await rdap.lookupIp(t.ctx, '192.0.2.1');
  assert.deepEqual(ip.cidrs, ['192.0.2.0/24']);
  assert.equal(ip.country, 'US');
  assert.equal((await rdap.lookupAsn(t.ctx, 64500)).range, 'AS64500 - AS64500');
  t.cleanup();
});

test('certificate transparency: duplicates merged, wildcards stripped, only names under the domain kept, failures explained', async () => {
  const rows = [
    { id: 1, common_name: 'example.com', name_value: 'example.com\nwww.example.com', issuer_name: "C=US, O=Let's Encrypt, CN=R3", not_before: '2024-01-01T00:00:00', not_after: '2024-04-01T00:00:00', entry_timestamp: '2024-01-01T01:00:00', serial_number: 'aa' },
    { id: 1, common_name: 'example.com', name_value: 'example.com', issuer_name: 'dup', not_before: '2024-01-01T00:00:00' },
    { id: 2, common_name: '*.example.com', name_value: '*.example.com\napi.example.com\nadmin@example.com\nother.org', issuer_name: 'C=US, O=Other CA, CN=Other', not_before: '2025-01-01T00:00:00', not_after: '2025-04-01T00:00:00' },
  ];
  const t = makeCtx({ routes: { 'crt.sh': { json: rows } } });
  const r = await ctSearch(t.ctx, 'example.com');
  assert.equal(r.ok, true);
  assert.equal(r.total, 2);
  assert.deepEqual(r.subdomains, ['api.example.com', 'example.com', 'www.example.com']);
  assert.equal(r.certificates[0].id, 2, 'newest first');
  assert.match(r.source, /crt\.sh/);
  assert.ok(r.retrievedAt);
  const t2 = makeCtx({ routes: { 'crt.sh': { status: 502, body: 'bad gateway' } } });
  const bad = await ctSearch(t2.ctx, 'example.com');
  assert.equal(bad.ok, false);
  assert.match(bad.error.hint, /slow or overloaded/);
  t.cleanup(); t2.cleanup();
});

test('active checks refuse to run without authorization, or when switched off', async () => {
  const t = makeCtx({ routes: {} });
  for (const fn of [() => diag.tcpLatency(t.ctx, '127.0.0.1', 80, {}), () => diag.tlsProbe(t.ctx, '127.0.0.1', {}), () => diag.httpProbe(t.ctx, 'http://127.0.0.1/', {})]) {
    const r = await fn();
    assert.equal(r.ok, false);
    assert.equal(r.error.kind, 'not-authorized');
  }
  t.ctx.config.set('activeChecks', false);
  const off = await diag.tcpLatency(t.ctx, '127.0.0.1', 80, { authorized: true });
  assert.equal(off.error.kind, 'disabled');
  t.cleanup();
});

test('connectivity diagnostics against a local server: timing, status, redirects, refused ports, bounded attempts', async () => {
  const server = http.createServer((req, res) => { if (req.url === '/moved') { res.writeHead(301, { location: '/new', server: 'fixture' }); res.end(); } else { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('hello'); } });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  const t = makeCtx({});
  const ok = await diag.httpProbe(t.ctx, `http://127.0.0.1:${port}/`, { authorized: true });
  assert.equal(ok.ok, true);
  assert.equal(ok.status, 200);
  assert.ok(ok.timing.connectMs >= 0 && ok.timing.firstByteMs >= 0);
  const mv = await diag.httpProbe(t.ctx, `http://127.0.0.1:${port}/moved`, { authorized: true });
  assert.equal(mv.status, 301);
  assert.equal(mv.redirectTo, '/new', 'redirects are reported, not followed');
  assert.equal(mv.server, 'fixture');
  const lat = await diag.tcpLatency(t.ctx, '127.0.0.1', port, { authorized: true, count: 50, gapMs: 1 });
  assert.equal(lat.attempts, 5, 'never more than 5 attempts');
  assert.equal(lat.successes, 5);
  assert.equal(lat.lossPercent, 0);
  assert.ok(lat.avgMs >= 0);
  await new Promise((r) => server.close(r));
  const closed = await diag.tcpLatency(t.ctx, '127.0.0.1', port, { authorized: true, count: 2, gapMs: 1 });
  assert.equal(closed.ok, false);
  assert.equal(closed.error.kind, 'refused');
  assert.equal(closed.lossPercent, 100);
  const refusedHttp = await diag.httpProbe(t.ctx, `http://127.0.0.1:${port}/`, { authorized: true });
  assert.equal(refusedHttp.error.kind, 'refused');
  t.cleanup();
});

test('TLS check reads a live certificate and reports that a self-signed one is not trusted', async (tt) => {
  let ssl;
  try {
    const dir = F.tempDir();
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'), '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
    ssl = { key: fs.readFileSync(path.join(dir, 'k.pem')), cert: fs.readFileSync(path.join(dir, 'c.pem')), dir };
  } catch { tt.skip('openssl not available'); return; }
  const server = tls.createServer({ key: ssl.key, cert: ssl.cert }, (s) => s.end());
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const t = makeCtx({});
  const r = await diag.tlsProbe(t.ctx, 'localhost', { port: server.address().port, authorized: true });
  assert.equal(r.ok, true);
  assert.equal(r.trusted, false);
  assert.match(r.trustError, /SELF_SIGNED|self.signed/i);
  assert.equal(r.certificate.subject, 'localhost');
  assert.equal(r.certificate.nameMatchesHost, true);
  assert.ok(r.certificate.daysRemaining >= 0 && r.certificate.daysRemaining <= 3);
  assert.ok(r.certificate.sha256);
  await new Promise((rr) => server.close(rr));
  F.rmrf(ssl.dir);
  t.cleanup();
});
