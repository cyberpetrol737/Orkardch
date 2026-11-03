'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeCtx } = require('./tests-helpers-ctx');
const P = require('./web-intelligence-providers');
const { extractPage, looksBlocked } = require('./web-intelligence-extract');
const S = require('./web-intelligence-sources');
const { listSnapshots, parseCdx } = require('./web-intelligence-archive');
const { sourceFindings, claimFinding } = require('./web-intelligence-findings');
const { renderSources } = require('./web-intelligence-export');
const { parseSelection } = require('./web-intelligence-index');

const WIKI = { json: { query: { search: [{ title: 'Solar panel (device)', snippet: 'A <span class="searchmatch">solar</span> panel &amp; more', timestamp: '2026-01-02T03:04:05Z' }, { title: 'Photovoltaics', snippet: 'Direct conversion', timestamp: '2025-12-01T00:00:00Z' }] } } };
const GDELT = { json: { articles: [{ url: 'https://news.example.com/solar-boom?utm_source=tw', title: 'Solar boom continues', seendate: '20261001T120000Z', domain: 'news.example.com', language: 'English', sourcecountry: 'US' }] } };
const DDG = `<html><body>
<div class="result results_links"><h2 class="result__title"><a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fpage%3Futm_source%3Dx&amp;rut=abc">Example <b>Page</b> on solar</a></h2>
<a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fpage">Snippet about <b>solar</b> energy.</a></div>
<div class="result result--ad"><a class="result__a" href="https://duckduckgo.com/y.js?ad_provider=x">Buy now</a></div>
<div class="result"><a class="result__a" href="https://direct.example.net/x">Direct link</a><a class="result__snippet">Another one</a></div></body></html>`;
const PAGE = `<!doctype html><html lang="en"><head><title>Solar boom - Example News</title>
<link rel="canonical" href="/news/solar-boom"><meta name="description" content="Installations of solar panels doubled last year according to the report.">
<meta property="og:site_name" content="Example News"><script type="application/ld+json">{"@context":"https://schema.org","@type":"NewsArticle","datePublished":"2025-12-30T08:00:00Z","dateModified":"2026-01-02T09:00:00Z","author":{"name":"A. Writer"}}</script></head>
<body><nav>menu menu</nav><article><h1>Solar boom</h1><p>Installations of solar panels doubled last year, the industry report says, driven by falling prices and new subsidies.</p><p>Analysts expect the trend to continue through 2027 although grid connections remain a bottleneck for developers.</p></article><footer>copyright</footer></body></html>`;

test('Wikipedia, GDELT, DuckDuckGo and Brave results keep their real URLs, publishers and the provider\'s own dates', async () => {
  const t = makeCtx({ routes: { 'wikipedia.org/w/api.php': WIKI, 'api.gdeltproject.org': GDELT, 'html.duckduckgo.com': { body: DDG }, 'api.search.brave.com': { json: { web: { results: [{ title: 'Brave <b>hit</b>', url: 'https://brave.example.com/a', description: 'desc', page_age: '2026-02-01T00:00:00', profile: { name: 'Brave Example' } }] } } } } });
  t.ctx.config.set('apiKeys.brave', 'KEY-1234-ABCD');
  const wiki = await P.wikipedia(t.ctx, 'solar panel');
  assert.equal(wiki.status, 'ok');
  assert.equal(wiki.results[0].url, 'https://en.wikipedia.org/wiki/Solar_panel_(device)');
  assert.equal(wiki.results[0].snippet, 'A solar panel & more');
  assert.equal(wiki.results[0].dates.lastModified.value, '2026-01-02T03:04:05Z');
  assert.ok(wiki.retrievedAt);
  const g = await P.gdelt(t.ctx, 'solar');
  assert.equal(g.results[0].url, 'https://news.example.com/solar-boom?utm_source=tw');
  assert.equal(g.results[0].dates.providerSeen.value, '2026-10-01T12:00:00Z');
  assert.match(g.results[0].dates.providerSeen.basis, /not necessarily when it was published/);
  const d = await P.duckduckgo(t.ctx, 'solar');
  assert.deepEqual(d.results.map((r) => r.url), ['https://example.org/page?utm_source=x', 'https://direct.example.net/x'], 'redirect links are decoded and ads are dropped');
  assert.equal(d.results[0].title, 'Example Page on solar');
  const b = await P.brave(t.ctx, 'solar');
  assert.equal(b.results[0].publisher, 'Brave Example');
  assert.equal(t.calls.find((c) => c.url.includes('brave')).headers['x-subscription-token'], 'KEY-1234-ABCD');
  t.cleanup();
});

test('provider problems are reported per provider: rate limit, bot protection, odd text, missing key, offline', async () => {
  const t = makeCtx({ routes: { 'wikipedia.org': WIKI, 'api.gdeltproject.org': { status: 429, body: 'slow down' }, 'html.duckduckgo.com': { status: 202, body: '<div class="anomaly-modal">Select all squares</div>' } } });
  const all = await P.searchAll(t.ctx, 'solar');
  const by = Object.fromEntries(all.map((p) => [p.id, p]));
  assert.equal(by.wikipedia.status, 'ok');
  assert.equal(by.gdelt.status, 'error');
  assert.equal(by.gdelt.error.kind, 'rate-limited');
  assert.equal(by.duckduckgo.status, 'error');
  assert.equal(by.duckduckgo.error.kind, 'bot-protection');
  assert.match(by.duckduckgo.error.hint, /does not try to get around/);
  assert.equal(by.brave.status, 'skipped');
  assert.match(by.brave.reason, /no API key/);
  const total = all.reduce((n, p) => n + p.results.length, 0);
  assert.equal(total, 2, 'only real results from the provider that answered; nothing fabricated');
  const t2 = makeCtx({ routes: { 'api.gdeltproject.org': { body: 'Your query was too short or too long.' } } });
  const odd = await P.gdelt(t2.ctx, 'a');
  assert.equal(odd.error.kind, 'provider-message');
  assert.match(odd.error.message, /too short/);
  t.ctx.config.set('providers.wikipedia', false);
  assert.equal((await P.searchAll(t.ctx, 'solar')).find((p) => p.id === 'wikipedia').status, 'disabled');
  t.cleanup(); t2.cleanup();
});

test('page extraction separates claims by the page: canonical URL, self-reported date with its basis, summary method, excerpts', () => {
  const ex = extractPage(PAGE, { url: 'https://news.example.com/x', query: 'solar panels subsidies' });
  assert.equal(ex.title, 'Solar boom - Example News');
  assert.equal(ex.canonicalUrl, 'https://news.example.com/news/solar-boom');
  assert.equal(ex.published.value, '2025-12-30T08:00:00.000Z');
  assert.equal(ex.published.basis, 'JSON-LD datePublished');
  assert.equal(ex.published.selfReported, true);
  assert.equal(ex.modified.value, '2026-01-02T09:00:00.000Z');
  assert.equal(ex.author, 'A. Writer');
  assert.match(ex.summary.method, /meta-description/);
  assert.ok(ex.excerpts.length >= 1 && ex.excerpts.every((e) => e.text.length <= 250 && /paragraph \d/.test(e.location)));
  assert.ok(ex.excerpts[0].text.toLowerCase().includes('solar'));
  assert.ok(!ex.textSample.includes('menu menu'), 'navigation is not treated as article text');
  const bare = extractPage('<html><body><p>tiny</p></body></html>', { url: 'https://x.test', query: 'solar' });
  assert.equal(bare.published, null);
  assert.equal(bare.summary, null);
  assert.match(bare.notes.join(' '), /Very little readable text/);
});

test('opening a page: success keeps claims and cautions; every failure keeps the URL and the reason', async () => {
  const t = makeCtx({ routes: {
    'ok.example/solar': { body: PAGE }, 'gone.example/x': { status: 404, body: 'nope' }, 'wall.example/x': { status: 403, body: '<html>Just a moment... captcha</html>' },
    'pdf.example/x': { body: '%PDF', headers: { 'content-type': 'application/pdf' } }, 'slow.example/x': { never: true }, 'jump.example/x': { body: PAGE, url: 'https://elsewhere.test/landing' },
  } });
  t.ctx.config.set('requestTimeoutMs', 1000);
  const mk = (url) => S.makeRecord({ title: 'T', url, snippet: 'provider snippet', rank: 1 }, { provider: 'wikipedia', query: 'solar', retrievedAt: '2026-01-01T00:00:00Z' });
  const ok = await S.analyzePage(t.ctx, mk('https://ok.example/solar'), { query: 'solar panels' });
  assert.equal(ok.status, 'fetched');
  assert.equal(ok.dates.published.basis, 'JSON-LD datePublished');
  assert.notEqual(ok.dates.retrieved, '2026-01-01T00:00:00Z', 'retrieval time is the real fetch time');
  assert.ok(ok.uncertainty.some((u) => /not independently confirmed/.test(u)));
  assert.equal(ok.url, 'https://ok.example/solar');
  const gone = await S.analyzePage(t.ctx, mk('https://gone.example/x'));
  assert.equal(gone.status, 'fetch-failed');
  assert.equal(gone.url, 'https://gone.example/x');
  assert.match(gone.statusDetail, /not found/);
  assert.ok(gone.uncertainty.some((u) => /could not be retrieved/.test(u)));
  assert.equal(gone.excerpts.length, 0);
  assert.match((await S.analyzePage(t.ctx, mk('https://wall.example/x'))).statusDetail, /bot check/);
  assert.equal((await S.analyzePage(t.ctx, mk('https://pdf.example/x'))).status, 'fetched-not-analysed');
  t.ctx.config.set('requestTimeoutMs', 1000);
  const slow = await S.analyzePage(t.ctx, mk('https://slow.example/x'));
  assert.match(slow.statusDetail, /did not answer in time/);
  const jump = await S.analyzePage(t.ctx, mk('https://jump.example/x'));
  assert.ok(jump.uncertainty.some((u) => /redirected to a different site/.test(u)));
  t.cleanup();
});

test('de-duplication merges exact duplicates, flags look-alikes without merging, and keeps every provider that found it', () => {
  const mk = (title, url, provider) => S.makeRecord({ title, url }, { provider, query: 'q', retrievedAt: 't' });
  const out = S.dedupeRecords([
    mk('Solar boom', 'https://www.example.com/a?utm_source=x', 'gdelt'), mk('Solar boom', 'http://example.com/a/', 'duckduckgo'),
    mk('Solar boom continues strongly', 'https://other.test/b', 'brave'), mk('Completely different', 'https://third.test/c', 'wikipedia'),
    mk('Solar Boom', 'https://mirror.test/zzz', 'brave'),
  ]);
  assert.equal(out.length, 4);
  assert.deepEqual(out[0].foundBy.map((f) => f.provider), ['gdelt', 'duckduckgo']);
  assert.equal(out[3].possibleDuplicateOf.position, 1);
  assert.match(out[3].possibleDuplicateOf.basis, /fuzzy/);
  assert.equal(out[1].possibleDuplicateOf, undefined);
});

test('Internet Archive captures: dates come from the archive, empty means "not archived", rate limits are explained', async () => {
  const body = JSON.stringify([['timestamp', 'original', 'statuscode', 'mimetype', 'digest'], ['20100102030405', 'http://example.com/', '200', 'text/html', 'AAA'], ['20240101000000', 'http://example.com/', '200', 'text/html', 'BBB']]);
  const t = makeCtx({ routes: { 'web.archive.org/cdx': { body } } });
  const r = await listSnapshots(t.ctx, 'http://example.com/');
  assert.equal(r.ok, true);
  assert.deepEqual(r.snapshots.map((s) => s.timestamp), ['2010-01-02T03:04:05Z', '2024-01-01T00:00:00Z']);
  assert.equal(r.snapshots[0].archiveUrl, 'https://web.archive.org/web/20100102030405/http://example.com/');
  assert.match(r.note, /when the archive saved the page, not when it was written/);
  assert.deepEqual(parseCdx(''), []);
  const empty = makeCtx({ routes: { 'web.archive.org/cdx': { body: '' } } });
  const e = await listSnapshots(empty.ctx, 'http://nothing.example/');
  assert.equal(e.snapshots.length, 0);
  assert.match(e.note, /does not prove the page never existed/);
  const limited = makeCtx({ routes: { 'web.archive.org/cdx': { status: 429, body: '' } } });
  const l = await listSnapshots(limited.ctx, 'http://example.com/');
  assert.equal(l.ok, false);
  assert.match(l.error.hint, /slow down/);
  t.cleanup(); empty.cleanup(); limited.cleanup();
});

test('comparison highlights shared words and differing years, and says it is a hint', async () => {
  const a = { title: 'A', url: 'https://a.test/x', textSample: 'The company Acme was founded in 2010 in Berlin and builds solar panels for homes.', summary: null };
  const b = { title: 'B', url: 'https://b.test/y', textSample: 'Acme builds solar panels. The firm was founded in 2012 in Berlin according to registry records.', summary: null };
  const c = S.compareSources(a, b);
  assert.match(c.basis, /readable text/);
  assert.ok(c.sharedTerms.includes('acme') && c.sharedTerms.includes('solar'));
  assert.deepEqual(c.yearsOnlyA, ['2010']);
  assert.deepEqual(c.yearsOnlyB, ['2012']);
  assert.match(c.note, /does not check which one is right/);
  const same = S.compareSources(a, { ...b, url: 'https://a.test/x' });
  assert.equal(same.sameUrl, true);
  assert.equal(S.compareSources(a, { ...b, url: 'https://a.test/z' }).sameRegistrableDomain, true);
  const thin = S.compareSources({ title: 'Only title', url: 'https://a.test', summary: null }, { title: 'Other title', url: 'https://c.test', summary: null });
  assert.match(thin.basis, /titles and snippets only/);
});

test('saved sources, claims and exports keep provenance and never include bulky page text', async () => {
  const t = makeCtx({ routes: { 'ok.example/solar': { body: PAGE } } });
  const rec = S.makeRecord({ title: 'Solar boom', url: 'https://ok.example/solar', publisher: 'ok.example' }, { provider: 'gdelt', query: 'solar', retrievedAt: 't' });
  await S.analyzePage(t.ctx, rec, { query: 'solar' });
  const f = sourceFindings(rec);
  assert.equal(f[0].type, 'source');
  assert.equal(f[0].statementType, 'observation');
  assert.equal(f[0].source.url, 'https://ok.example/solar');
  assert.ok(!('textSample' in f[0].data));
  const pub = f.find((x) => x.type === 'source_date');
  assert.equal(pub.statementType, 'claim');
  assert.equal(pub.attribute, 'publication_date');
  assert.equal(pub.subject, 'https://ok.example/news/solar-boom', 'the canonical address, resolved against the page URL');
  const claim = claimFinding({ subject: 'Acme', attribute: 'founding year', value: 'Founded in 2010', rec });
  assert.equal(claim.statementType, 'claim');
  assert.equal(claim.source.url, 'https://ok.example/solar');
  const md = renderSources([rec], { format: 'md', query: 'solar', generatedAt: '2026-10-01T00:00:00Z' });
  assert.match(md, /URL: https:\/\/ok\.example\/solar/);
  assert.match(md, /Retrieved by Orkardch:/);
  assert.match(md, /^> "/m);
  assert.match(md, /not verified facts/);
  assert.ok(!JSON.parse(renderSources([rec], { format: 'json' })).sources[0].textSample);
  t.cleanup();
});

test('selection parser accepts numbers, ranges and "all", and explains mistakes', () => {
  assert.deepEqual(parseSelection('1,3', 5).indices, [1, 3]);
  assert.deepEqual(parseSelection('2-4', 5).indices, [2, 3, 4]);
  assert.deepEqual(parseSelection('all', 3).indices, [1, 2, 3]);
  assert.equal(parseSelection('9', 5).ok, false);
  assert.match(parseSelection('x', 5).error, /not a number or range/);
  assert.equal(parseSelection('', 5).ok, false);
  assert.ok(looksBlocked({ status: 200, body: 'Please verify you are human', headers: {} }));
  assert.ok(!looksBlocked({ status: 200, body: '<p>' + 'x'.repeat(40000) + '</p>', headers: {} }));
});
