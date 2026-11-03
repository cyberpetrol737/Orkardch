'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const F = require('./tests-helpers-fixtures');
const { makeCtx, fakeDns } = require('./tests-helpers-ctx');
const { NavSignal } = require('./core-errors');

const SAMPLE = path.join(__dirname, 'sample-evidence.json');
async function drive(fn, t) {
  try { await fn(t.ctx); } catch (e) { if (!(e instanceof NavSignal)) throw e; }
  return t;
}
const flat = (s) => s.replace(/\s*\n\s*/g, ' ');
const list = (dir) => { try { return fs.readdirSync(dir); } catch { return []; } };

test('forensics: GPS stays hidden unless the person says yes, and exports leave out GPS and the folder path by default', async () => {
  const t = makeCtx();
  const file = path.join(t.home, 'photo.jpg');
  fs.writeFileSync(file, F.buildJpeg({ tiff: F.SAMPLE_EXIF() }));
  t.ctx.prompter.lines.push('1', file, 'n', 'n', '2', '', '', 'n', '0', '0');
  await drive(require('./file-forensics-index').run, t);
  const out = flat(t.output());
  assert.match(out, /contains GPS coordinates/);
  assert.match(out, /SHA-256/);
  assert.match(out, /TestCam Model X1/);
  assert.match(out, /GPS: present, hidden/);
  assert.ok(!/48\.85|2\.35/.test(out), 'coordinates are never shown without consent');
  const dir = path.join(t.ctx.config.outputDir(), 'forensics');
  const [exported] = list(dir);
  assert.ok(exported && exported.endsWith('.txt'));
  const text = fs.readFileSync(path.join(dir, exported), 'utf8');
  assert.match(text, /SHA-256/);
  assert.ok(!/48\.85|2\.35/.test(text));
  assert.ok(!text.includes(t.home), 'the local path is not exported by default');
  assert.equal(fs.statSync(path.join(dir, exported)).mode & 0o777, 0o600);
  t.cleanup();
  const t2 = makeCtx();
  const f2 = path.join(t2.home, 'photo.jpg');
  fs.writeFileSync(f2, F.buildJpeg({ tiff: F.SAMPLE_EXIF() }));
  t2.ctx.prompter.lines.push('1', f2, 'n', 'y', '0', '0');
  await drive(require('./file-forensics-index').run, t2);
  assert.match(flat(t2.output()), /GPS: 48\.856667, 2\.350000/);
  t2.cleanup();
});

test('forensics: saving findings keeps provenance, and a second inspection of the same bytes links to the first', async () => {
  const t = makeCtx();
  const a = path.join(t.home, 'one.jpg');
  const b = path.join(t.home, 'two.jpg');
  fs.writeFileSync(a, F.buildJpeg({ tiff: F.SAMPLE_EXIF() }));
  fs.writeFileSync(b, F.buildJpeg({ tiff: F.SAMPLE_EXIF() }));
  t.ctx.prompter.lines.push('1', a, 'n', 'n', '1', 'Photo case', '0', '1', b, 'n', 'n', '1', 'y', '0', '0');
  await drive(require('./file-forensics-index').run, t);
  const inv = t.ctx.activeInvestigation();
  assert.equal(inv.title, 'Photo case');
  const hashes = inv.findings.filter((f) => f.type === 'file_hash');
  assert.equal(hashes.length, 2);
  assert.ok(hashes.every((f) => f.source.file.sha256 && f.source.file.name && f.source.module === 'file-forensics'));
  assert.ok(!inv.findings.some((f) => f.attribute === 'gps_position'), 'GPS not saved when not shown');
  const { analyze } = require('./evidence-correlator-analysis');
  assert.ok(analyze(inv).relationships.some((e) => /identical file contents/.test(e.relation) && e.match === 'exact'));
  assert.ok(inv.methods.length === 2 && /Inspected local file/.test(inv.methods[0].description));
  t.cleanup();
});

test('forensics: bad input never crashes: missing file, folder, empty entry, Ctrl+C and end of input', async () => {
  const t = makeCtx();
  t.ctx.prompter.lines.push('1', '/definitely/missing.jpg', '', 'back', '0');
  await drive(require('./file-forensics-index').run, t);
  assert.match(flat(t.output()), /I could not find/);
  assert.match(flat(t.output()), /Please type something/);
  assert.equal(t.ctx.session.lastError.code, 'FILE_NOT_FOUND');
  const t2 = makeCtx();
  t2.ctx.prompter.lines.push('1', '\u0003');
  await drive(require('./file-forensics-index').run, t2);
  assert.match(flat(t2.output()), /\(cancelled\)/);
  const t3 = makeCtx();
  await drive(require('./file-forensics-index').run, t3);
  t.cleanup(); t2.cleanup(); t3.cleanup();
});

test('file browser: folders open as numbered lists and files can be picked by number', async () => {
  const t = makeCtx();
  const dir = path.join(t.home, 'Pics');
  fs.mkdirSync(path.join(dir, 'sub'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'a.txt'), 'hello');
  fs.writeFileSync(path.join(dir, '.hidden'), 'x');
  const { pickFile } = require('./file-forensics-browse');
  t.ctx.prompter.lines.push(dir, '1', 'u', '2');
  const picked = await pickFile(t.ctx);
  assert.equal(picked, path.join(dir, 'a.txt'));
  assert.match(flat(t.output()), /\[1\] sub\//);
  assert.ok(!/\.hidden/.test(t.output()));
  assert.match(flat(t.output()), /\[2\] a\.txt {2}\(5 B\)/);
  t.cleanup();
});

test('IP lookup: results come from the lookups, show their source and time, and carry the approximation warning', async () => {
  const dns = fakeDns({ 'TXT 8.8.8.8.origin.asn.cymru.com': [['15169 | 8.8.8.0/24 | US | arin | 1992-12-01']], 'TXT AS15169.asn.cymru.com': [['15169 | US | arin | 2000-03-30 | GOOGLE, US']], 'PTR 8.8.8.8.in-addr.arpa': [['dns.google'].join('')] });
  const t = makeCtx({ services: { dns }, config: { 'dns.mode': 'system' }, routes: {
    'rdap.org/ip/8.8.8.8': { url: 'https://rdap.arin.net/registry/ip/8.8.8.0', json: { name: 'GOGL', handle: 'NET-8-8-8-0-2', country: 'US', startAddress: '8.8.8.0', endAddress: '8.8.8.255', cidr0_cidrs: [{ v4prefix: '8.8.8.0', length: 24 }], events: [{ eventAction: 'registration', eventDate: '2023-12-28T17:24:56Z' }] } },
  } });
  t.ctx.prompter.lines.push('n', '1', 'Net case', '0');
  const net = require('./network-intelligence-index');
  await drive((c) => net.ipFlow(c, '8.8.8.8'), t);
  const out = flat(t.output());
  assert.match(out, /GOGL \(NET-8-8-8-0-2\)/);
  assert.match(out, /Origin AS: AS15169 \(GOOGLE, US\)/);
  assert.match(out, /Announced prefix: 8\.8\.8\.0\/24/);
  assert.match(out, /Name: dns\.google/);
  assert.match(out, /Source: RDAP - https:\/\/rdap\.arin\.net\/registry\/ip\/8\.8\.8\.0 \(retrieved \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC\)/);
  assert.match(out, /does not reveal a person's name or home address/);
  assert.match(out, /approximate and often points to an internet provider, VPN, proxy, company or data centre/);
  assert.deepEqual([...new Set(t.calls.map((c) => new URL(c.url).host))], ['rdap.org'], 'only the registry lookup used HTTP');
  const inv = t.ctx.activeInvestigation();
  assert.ok(inv.findings.some((f) => f.type === 'asn' && f.value === 'AS15169' && f.source.provider === 'Team Cymru DNS'));
  assert.ok(inv.findings.some((f) => f.type === 'network_registration' && f.source.url === 'https://rdap.arin.net/registry/ip/8.8.8.0' && f.source.retrievedAt));
  assert.ok(inv.findings.every((f) => f.statementType === 'observation' || f.type === 'ip_location'));
  t.cleanup();
});

test('IP lookup: private, loopback and malformed addresses make no network requests and explain themselves', async () => {
  const t = makeCtx();
  const net = require('./network-intelligence-index');
  await net.ipFlow(t.ctx, '192.168.1.20');
  await net.ipFlow(t.ctx, '127.0.0.1');
  assert.match(flat(t.output()), /Private network address/);
  assert.match(flat(t.output()), /not a public internet address/);
  await net.ipFlow(t.ctx, '999.1.1.1');
  assert.match(flat(t.output()), /not a valid IP address/);
  assert.equal(t.ctx.session.lastError.code, 'MALFORMED_IP');
  assert.equal(t.calls.length, 0);
  t.cleanup();
});

test('domain lookup separates "no record" from "failed" and keeps each source; findings save with provenance', async () => {
  const dns = fakeDns({ 'A example.com': [{ address: '192.0.2.1', ttl: 60 }], 'MX example.com': 'ETIMEOUT', 'NS example.com': [' ns1.example.net'.trim()] });
  const t = makeCtx({ services: { dns }, config: { 'dns.mode': 'system' }, routes: { 'rdap.org/domain/example.com': { url: 'https://rdap.example-registry.test/domain/example.com', json: { ldhName: 'example.com', events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }], entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Reg Inc']]] }] } } } });
  t.ctx.prompter.lines.push('1', 'Domain case', '0');
  const net = require('./network-intelligence-index');
  await drive((c) => net.domainFlow(c, 'example.com'), t);
  const out = flat(t.output());
  assert.match(out, /AAAA - none \(the name exists, but has no AAAA record\)/);
  assert.match(out, /MX - lookup FAILED/);
  assert.match(out, /This is not the same as "no record"/);
  assert.match(out, /Registrar: Reg Inc/);
  assert.match(out, /Registered: 1995-08-14/);
  const inv = t.ctx.activeInvestigation();
  const rec = inv.findings.find((f) => f.type === 'dns_record' && f.value === 'A 192.0.2.1');
  assert.equal(rec.data.domain, 'example.com');
  assert.equal(rec.source.provider, 'DNS (system)');
  assert.ok(inv.findings.some((f) => f.attribute === 'registrar' && f.value === 'Reg Inc' && f.source.url.includes('example-registry.test')));
  t.cleanup();
});

test('connectivity checks ask for authorization first and connect to nothing when it is refused', async () => {
  const t = makeCtx({ inputs: ['n'] });
  const net = require('./network-intelligence-index');
  await net.connectivityFlow(t.ctx, 'some-host.example');
  assert.ok(t.ctx.prompter.asked.some((q) => /Do you own some-host\.example or have permission to test it\?/.test(q)));
  assert.match(flat(t.output()), /Skipped\. No connection was made\./);
  assert.equal(t.calls.length, 0);
  assert.ok(!t.ctx.authorized || !t.ctx.authorized.has('some-host.example'));
  t.cleanup();
});

const WIKI = { json: { query: { search: [{ title: 'Solar panel', snippet: 'A solar panel converts light', timestamp: '2026-01-02T03:04:05Z' }] } } };
const GDELT = { json: { articles: [{ url: 'https://news.example.com/solar-boom', title: 'Solar boom continues', seendate: '20261001T120000Z', domain: 'news.example.com' }] } };
const PAGE = '<html lang="en"><head><title>Solar panel - Example</title><meta name="description" content="A solar panel converts sunlight into electricity using photovoltaic cells."><script type="application/ld+json">{"@type":"Article","datePublished":"2025-11-05T00:00:00Z"}</script></head><body><article><p>A solar panel converts sunlight into electricity, and installations of solar panels doubled last year in many regions.</p></article></body></html>';
const webRoutes = (wiki = WIKI) => ({ 'wikipedia.org/w/api.php': wiki, 'wikipedia.org/wiki/': { body: PAGE }, 'api.gdeltproject.org': GDELT, 'html.duckduckgo.com': { status: 202, body: 'anomaly-modal' } });

test('web research: real source URLs are kept, claims are kept apart from observations, sources and the search can be saved, and re-running shows what changed', async () => {
  const t = makeCtx({ routes: webRoutes() });
  t.ctx.prompter.lines.push('1', 'solar panels', '1', '1', 'y', '3', '', 'Solar case', '0', '0');
  const web = require('./web-intelligence-index');
  await drive(web.run, t);
  const out = flat(t.output());
  assert.match(out, /Source: Wikipedia Result: 1 result/);
  assert.match(out, /Source: GDELT news Result: 1 result/);
  assert.match(out, /FAILED: DuckDuckGo showed a bot check/);
  assert.match(out, /skipped: no API key/);
  assert.ok(out.includes('https://en.wikipedia.org/wiki/Solar_panel'), 'the real URL is shown');
  assert.match(out, /Observed by Orkardch/);
  assert.match(out, /Claimed by the source/);
  assert.match(out, /Published: 2025-11-05 \(JSON-LD datePublished; the page says this itself\)/);
  assert.match(out, /Retrieved: \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC \(when Orkardch got it, not when it was written\)/);
  assert.match(out, /Summary \[meta-description/);
  assert.match(out, /Things to be careful about/);
  const inv = t.ctx.activeInvestigation();
  const srcs = inv.findings.filter((f) => f.type === 'source');
  assert.deepEqual(srcs.map((f) => f.source.url).sort(), ['https://en.wikipedia.org/wiki/Solar_panel', 'https://news.example.com/solar-boom']);
  assert.ok(srcs.every((f) => f.source.retrievedAt && f.statementType === 'observation'));
  assert.equal(inv.findings.find((f) => f.type === 'source_date').statementType, 'claim');
  assert.equal(inv.searches.length, 1);
  assert.equal(inv.searches[0].query, 'solar panels');
  assert.equal(inv.searches[0].urls.length, 2);
  // re-run later: the provider now returns something different
  t.calls.length = 0;
  const changed = makeCtx({ routes: webRoutes({ json: { query: { search: [{ title: 'Solar power', snippet: 'x' }] } } }) });
  changed.ctx.paths = t.ctx.paths;
  changed.ctx.store = t.ctx.store;
  changed.ctx.state = t.ctx.state;
  changed.ctx.prompter.lines.push('3', '1', '0', '0');
  await drive(web.run, changed);
  assert.match(flat(changed.output()), /Compared with the earlier run/);
  assert.match(flat(changed.output()), /1 new, 1 no longer returned/);
  assert.match(flat(changed.output()), /New: Solar power/);
  t.cleanup(); changed.cleanup();
});

test('web research: a page that cannot be opened keeps its URL and the reason, and nothing is invented', async () => {
  const t = makeCtx({ routes: { ...webRoutes(), 'wikipedia.org/wiki/': { status: 404, body: 'nope' } } });
  t.ctx.prompter.lines.push('1', 'solar panels', '1', '1', 'y', '0', '0');
  await drive(require('./web-intelligence-index').run, t);
  const out = flat(t.output());
  assert.match(out, /could not open/);
  assert.match(out, /The page was not found/);
  assert.match(out, /could not be retrieved, so nothing here was checked/);
  assert.ok(out.includes('https://en.wikipedia.org/wiki/Solar_panel'));
  assert.ok(!/Published:/.test(out), 'no date is made up');
  t.cleanup();
});

test('web research: when every source fails the person is told, and nothing is fabricated', async () => {
  const t = makeCtx({ routes: { 'wikipedia.org': { status: 500 }, 'api.gdeltproject.org': { status: 500 }, 'html.duckduckgo.com': { status: 403, body: 'captcha' } } });
  t.ctx.prompter.lines.push('1', 'anything at all', '0');
  await drive(require('./web-intelligence-index').run, t);
  assert.match(flat(t.output()), /No source could be reached, so there is nothing to show\. Nothing was made up\./);
  assert.ok(!/Results \(/.test(t.output()));
  t.cleanup();
});

test('offline mode: network and web flows make zero requests and say why', async () => {
  const t = makeCtx({ config: { offline: true }, services: { dns: fakeDns({}) } });
  const net = require('./network-intelligence-index');
  const web = require('./web-intelligence-index');
  await net.ipFlow(t.ctx, '8.8.8.8');
  await net.domainFlow(t.ctx, 'example.com');
  await net.dnsFlow(t.ctx, 'example.com', 'A');
  await net.certFlow(t.ctx, 'example.com');
  await net.asnFlow(t.ctx, 64500);
  await net.connectivityFlow(t.ctx, 'example.com');
  t.ctx.prompter.lines.push('solar');
  await web.researchFlow(t.ctx);
  assert.equal(t.calls.length, 0);
  assert.equal(t.ctx.services.dns.calls.length, 0);
  assert.ok((t.output().match(/Offline mode is ON/g) || []).length >= 7);
  assert.equal(t.ctx.session.lastError.code, 'OFFLINE_MODE');
  t.cleanup();
});

test('correlator: import, analysis showing both sides of a contradiction, manual entry, and guarded deletion', async () => {
  const t = makeCtx();
  t.ctx.prompter.lines.push('1', 'Case X', '6', SAMPLE, '7', '5', '', '', 'Plain claim', '', '', '', '0');
  const corr = require('./evidence-correlator-index');
  await drive(corr.run, t);
  const out = flat(t.output());
  assert.match(out, /Imported 11 record\(s\)/);
  assert.match(out, /Acme Corp \/ founding year {2}\[conflict\]/);
  assert.match(out, /Founded in 2010/);
  assert.match(out, /Founded in 2012/);
  assert.match(out, /registry\.example\.org/);
  assert.match(out, /does not pick a side/);
  assert.match(out, /No source recorded\. This finding will be rated "Unknown"/);
  assert.match(out, /Categories, not percentages/);
  let inv = t.ctx.activeInvestigation();
  assert.equal(inv.findings.length, 12);
  assert.ok(inv.findings.every((f) => f.source && f.firstObserved));
  t.ctx.prompter.lines.push('d', '1', 'delete', '0');
  await drive(corr.run, t);
  assert.ok(t.ctx.store.load(inv.id), 'wrong confirmation word deletes nothing');
  assert.match(flat(t.output()), /Cancelled\. Nothing was deleted\./);
  t.ctx.prompter.lines.push('d', '1', 'DELETE', '0');
  await drive(corr.run, t);
  assert.equal(t.ctx.store.load(inv.id), null);
  assert.equal(t.ctx.activeInvestigation(), null);
  t.cleanup();
});

test('settings: values are validated and saved privately, API keys are masked, offline mode toggles, cache clears', async () => {
  const t = makeCtx({ routes: { 'ok.test': { body: 'x' } } });
  await t.ctx.net.get('https://ok.test/');
  assert.equal(t.ctx.cache.stats().entries, 1);
  t.ctx.prompter.lines.push('2', '5', '4', '99', '6', '1', 'SECRET-BRAVE-KEY-4321', '0', '9', 'c', 'p', '0');
  await drive(require('./settings-index').run, t);
  const out = flat(t.output());
  assert.equal(t.ctx.config.get('cacheTtlMinutes'), 5);
  assert.equal(t.ctx.config.get('maxParallelRequests'), 3, 'out-of-range value rejected');
  assert.match(out, /Please enter a number from 1 to 8/);
  assert.equal(t.ctx.config.get('apiKeys.brave'), 'SECRET-BRAVE-KEY-4321');
  assert.ok(!out.includes('SECRET-BRAVE-KEY-4321'), 'the key is never printed');
  assert.match(out, /Brave Search key: ••••4321/);
  assert.equal(t.ctx.config.get('offline'), true);
  assert.equal(t.ctx.cache.stats().entries, 0);
  assert.match(out, /What leaves this phone/);
  assert.match(out, /Nothing leaves this phone/);
  assert.match(out, /No question or result is sent to any AI service/);
  const saved = JSON.parse(fs.readFileSync(t.ctx.paths.configFile, 'utf8'));
  assert.equal(saved.cacheTtlMinutes, 5);
  assert.equal(saved.offline, true);
  assert.equal(fs.statSync(t.ctx.paths.configFile).mode & 0o777, 0o600);
  t.cleanup();
});

test('DNS results show where and when they were retrieved', async () => {
  const dns = fakeDns({ 'A example.com': [{ address: '192.0.2.1', ttl: 60 }] });
  const t = makeCtx({ services: { dns }, config: { 'dns.mode': 'system' }, inputs: ['0'] });
  await require('./network-intelligence-index').dnsFlow(t.ctx, 'example.com', 'A');
  assert.match(flat(t.output()), /Source: DNS answers via system \(retrieved \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC\)/);
  t.cleanup();
});
