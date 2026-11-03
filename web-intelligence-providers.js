'use strict';
const { decodeHtml, htmlToText } = require('./utils-html');
const { looksBlocked } = require('./web-intelligence-extract');
const { mapLimit } = require('./core-concurrency');
const { truncate } = require('./utils-format');
const { urlHost } = require('./utils-validate');

const strip = (s) => htmlToText(s || '');

function done(id, res, url, results) { return { id, status: 'ok', results, requestUrl: url, retrievedAt: res.retrievedAt, fromCache: Boolean(res.fromCache) }; }
function failed(id, res, url, error) { return { id, status: 'error', results: [], requestUrl: url, retrievedAt: res && res.retrievedAt, error }; }
function netError(id, res, url) {
  const e = res.error || { kind: 'network', code: 'FAILED', message: 'Request failed.' };
  const hints = {
    'rate-limited': 'The provider says too many requests were made. Wait a minute and try again.',
    'offline-mode': e.hint, timeout: 'The provider was slow. Try again later.',
  };
  return failed(id, res, url, { ...e, hint: hints[e.kind] || null });
}

async function wikipedia(ctx, q, { limit = 5, signal } = {}) {
  const url = `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(q)}&srlimit=${limit}&format=json&utf8=1`;
  const res = await ctx.net.getJson(url, { purpose: 'Wikipedia search', signal, useCache: !signal || true });
  if (!res.ok || !res.json) return netError('wikipedia', res, url);
  const items = (res.json.query && res.json.query.search) || [];
  return done('wikipedia', res, url, items.map((it, i) => ({
    title: it.title, url: `https://en.wikipedia.org/wiki/${encodeURIComponent(String(it.title).replace(/ /g, '_'))}`, snippet: strip(it.snippet),
    publisher: 'Wikipedia (Wikimedia Foundation)', sourceType: 'reference work (crowd-edited)', rank: i + 1,
    dates: it.timestamp ? { lastModified: { value: it.timestamp, basis: 'last edit time reported by Wikipedia' } } : {},
    uncertainty: ['Wikipedia is edited by volunteers. Treat it as a pointer to sources, not as a primary source.'],
  })));
}

function gdeltDate(s) {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z?$/.exec(String(s || ''));
  return m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z` : null;
}

async function gdelt(ctx, q, { limit = 8, signal } = {}) {
  const url = `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(q)}&mode=ArtList&maxrecords=${limit}&format=json&sort=DateDesc`;
  const res = await ctx.net.get(url, { purpose: 'GDELT news search', headers: { accept: 'application/json' }, signal });
  if (!res.ok) return netError('gdelt', res, url);
  const body = (res.body || '').trim();
  if (!body) return done('gdelt', res, url, []);
  let json;
  try { json = JSON.parse(body); } catch {
    return failed('gdelt', res, url, { kind: 'provider-message', code: 'GDELT_TEXT', message: `GDELT answered with a message instead of results: "${truncate(strip(body), 140)}"`, hint: 'This usually means the search was too short or too many searches were made. Try longer words or wait a few seconds.' });
  }
  const items = json.articles || [];
  return done('gdelt', res, url, items.map((a, i) => ({
    title: strip(a.title), url: a.url, snippet: null, publisher: a.domain || urlHost(a.url), sourceType: 'news article', rank: i + 1,
    language: a.language || null, country: a.sourcecountry || null,
    dates: gdeltDate(a.seendate) ? { providerSeen: { value: gdeltDate(a.seendate), basis: 'when GDELT first saw the article (not necessarily when it was published)' } } : {},
    uncertainty: ['The date is when GDELT first saw the article, not a confirmed publication date.'],
  })));
}

function ddgTarget(href) {
  try {
    const u = new URL(decodeHtml(href), 'https://duckduckgo.com');
    if (/duckduckgo\.com$/.test(u.hostname)) {
      if (u.pathname === '/l/' && u.searchParams.get('uddg')) return u.searchParams.get('uddg');
      return null;
    }
    return u.toString();
  } catch { return null; }
}

function parseDdg(html, limit) {
  const out = [];
  const re = /<a\b([^>]*\bclass="[^"]*\bresult__a\b[^"]*"[^>]*)>([\s\S]*?)<\/a>/gi;
  const hits = [...html.matchAll(re)];
  hits.forEach((m, i) => {
    if (out.length >= limit) return;
    const href = /href="([^"]*)"/i.exec(m[1]);
    const target = href && ddgTarget(href[1]);
    if (!target || !/^https?:/i.test(target)) return;
    const end = hits[i + 1] ? hits[i + 1].index : html.length;
    const sn = /class="[^"]*\bresult__snippet\b[^"]*"[^>]*>([\s\S]*?)<\/a>/i.exec(html.slice(m.index, end));
    out.push({
      title: strip(m[2]), url: target, snippet: sn ? strip(sn[1]) : null, publisher: urlHost(target), sourceType: 'web page', rank: out.length + 1,
      dates: {}, uncertainty: ['The snippet is the search engine\'s text and has not been checked against the page.'],
    });
  });
  return out;
}

async function duckduckgo(ctx, q, { limit = 8, signal } = {}) {
  const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(q)}`;
  const res = await ctx.net.get(url, { purpose: 'DuckDuckGo search', headers: { accept: 'text/html', 'accept-language': 'en' }, retries: 0, signal });
  if (looksBlocked(res)) {
    return failed('duckduckgo', res, url, { kind: 'bot-protection', code: 'BLOCKED', message: 'DuckDuckGo showed a bot check instead of results.', hint: 'Orkardch does not try to get around bot protection. Use the other sources, add a Brave Search key in Settings, or try later.' });
  }
  if (!res.ok) return netError('duckduckgo', res, url);
  const results = parseDdg(res.body, limit);
  if (!results.length && !/no results/i.test(res.body)) {
    return failed('duckduckgo', res, url, { kind: 'parse', code: 'NO_PARSE', message: 'The page layout was not recognised, so no results could be read.', hint: 'DuckDuckGo may have changed its page. Other sources still work.' });
  }
  return done('duckduckgo', res, url, results);
}

async function brave(ctx, q, { limit = 8, signal } = {}) {
  const key = ctx.config.get('apiKeys.brave');
  if (!key) return { id: 'brave', status: 'skipped', results: [], reason: 'no API key set (optional; add one in Settings)' };
  const url = `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(q)}&count=${limit}`;
  const res = await ctx.net.getJson(url, { headers: { 'x-subscription-token': key, accept: 'application/json' }, purpose: 'Brave Search', signal });
  if (res.status === 401 || res.status === 403) return failed('brave', res, url, { kind: 'auth', code: `HTTP_${res.status}`, message: 'Brave rejected the API key.', hint: 'Check or replace the key in Settings > API keys.' });
  if (!res.ok || !res.json) return netError('brave', res, url);
  const items = (res.json.web && res.json.web.results) || [];
  return done('brave', res, url, items.map((r, i) => ({
    title: strip(r.title), url: r.url, snippet: strip(r.description), rank: i + 1, sourceType: 'web page',
    publisher: (r.profile && r.profile.name) || (r.meta_url && r.meta_url.hostname) || urlHost(r.url),
    dates: r.page_age ? { providerSeen: { value: r.page_age, basis: 'page age reported by Brave Search' } } : {},
    uncertainty: ['The snippet is the search engine\'s text and has not been checked against the page.'],
  })));
}

const PROVIDERS = [
  { id: 'wikipedia', label: 'Wikipedia', run: wikipedia },
  { id: 'gdelt', label: 'GDELT news', run: gdelt },
  { id: 'duckduckgo', label: 'DuckDuckGo', run: duckduckgo },
  { id: 'brave', label: 'Brave Search', run: brave },
];

/** Ask every enabled provider (a few at a time). Failures are reported per provider; nothing is invented. */
async function searchAll(ctx, query, { limit = 8, signal, only } = {}) {
  const enabled = PROVIDERS.filter((p) => ctx.config.get(`providers.${p.id}`) && (!only || only.includes(p.id)));
  const disabled = PROVIDERS.filter((p) => !enabled.includes(p)).map((p) => ({ id: p.id, label: p.label, status: 'disabled', results: [] }));
  const runs = await mapLimit(enabled, ctx.config.get('maxParallelRequests'), async (p) => {
    try { return { label: p.label, ...(await p.run(ctx, query, { limit, signal })) }; } catch (e) { return { id: p.id, label: p.label, status: 'error', results: [], error: { kind: 'internal', code: e.code || 'ERROR', message: e.message } }; }
  });
  return [...runs.map((r, i) => (r && r.status ? r : { id: enabled[i].id, label: enabled[i].label, status: 'error', results: [], error: { message: String(r && r.error && r.error.message) } })), ...disabled];
}

module.exports = { PROVIDERS, searchAll, parseDdg, gdeltDate, wikipedia, gdelt, duckduckgo, brave };
