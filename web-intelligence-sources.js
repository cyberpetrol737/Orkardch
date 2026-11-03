'use strict';
const { uid, truncate } = require('./utils-format');
const { dedupeKey, urlHost, registrableDomain } = require('./utils-validate');
const { extractPage, looksBlocked, STOP } = require('./web-intelligence-extract');

/** One search result becomes one source record. Provider data and page data are kept apart. */
function makeRecord(p, { provider, query, retrievedAt }) {
  return {
    id: uid('src_'), title: p.title || '(untitled)', url: p.url, canonicalUrl: null,
    publisher: p.publisher || urlHost(p.url) || null, sourceType: p.sourceType || 'web page', language: p.language || null,
    dates: { ...(p.dates || {}), retrieved: retrievedAt },
    summary: p.snippet ? { text: truncate(p.snippet, 300), method: `search snippet from ${provider}` } : null,
    excerpts: [], status: 'listed',
    statusDetail: 'Listed by a search provider. The page itself has not been opened, so nothing here is checked against its contents.',
    uncertainty: [...(p.uncertainty || [])], foundBy: [{ provider, rank: p.rank || null, query }],
  };
}

function tokens(s) { return new Set((String(s).toLowerCase().match(/\p{L}{2,}/gu) || [])); }
function titleSimilarity(a, b) {
  const A = tokens(a);
  const B = tokens(b);
  if (!A.size || !B.size) return 0;
  let inter = 0;
  for (const t of A) if (B.has(t)) inter++;
  return inter / (A.size + B.size - inter);
}

function mergeInto(base, other) {
  base.foundBy.push(...other.foundBy);
  if (!base.summary && other.summary) base.summary = other.summary;
  for (const [k, v] of Object.entries(other.dates)) if (!base.dates[k]) base.dates[k] = v;
  for (const u of other.uncertainty) if (!base.uncertainty.includes(u)) base.uncertainty.push(u);
}

/**
 * Merge exact duplicates (same address after tidying) and flag look-alikes.
 * Exact matches are merged; fuzzy matches are only flagged, never merged silently.
 */
function dedupeRecords(records) {
  const byKey = new Map();
  const out = [];
  for (const r of records) {
    const key = dedupeKey(r.url) || r.url;
    if (byKey.has(key)) { mergeInto(byKey.get(key), r); continue; }
    byKey.set(key, r);
    out.push(r);
  }
  out.forEach((r, i) => {
    for (let j = 0; j < i; j++) {
      const sim = titleSimilarity(r.title, out[j].title);
      if (sim >= 0.85) { r.possibleDuplicateOf = { id: out[j].id, position: j + 1, similarity: Number(sim.toFixed(2)), basis: 'very similar title (fuzzy match, not proof)' }; break; }
    }
  });
  return out;
}

function explainFetchFailure(res) {
  const e = res.error || {};
  const byKind = {
    'offline-mode': 'Offline mode is on, so the page was not requested.',
    timeout: 'The site did not answer in time.', dns: 'The website name could not be found (DNS failed).',
    tls: `Secure connection problem: ${e.message || ''}`, refused: 'The site refused the connection.',
    'rate-limited': 'The site says too many requests were made. Wait and try again.', 'bad-url': e.message,
    aborted: 'The request was cancelled.',
  };
  if (byKind[e.kind]) return byKind[e.kind];
  const byStatus = { 401: 'The page needs a login.', 403: 'The site refused access.', 404: 'The page was not found (moved or deleted).', 410: 'The page has been removed.', 451: 'The page is unavailable for legal reasons.' };
  if (byStatus[res.status]) return byStatus[res.status];
  if (res.status >= 500) return `The site had a server problem (${res.status}).`;
  return e.message || 'The page could not be retrieved.';
}

/** Open one page and record what it says. On failure the URL stays and the reason is recorded. */
async function analyzePage(ctx, rec, { query, signal } = {}) {
  const res = await ctx.net.get(rec.url, {
    headers: { accept: 'text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.5' }, maxBytes: 1500000, purpose: `open ${urlHost(rec.url) || 'page'}`, signal,
  });
  rec.dates.retrieved = res.retrievedAt;
  const fail = (detail, extra) => {
    rec.status = 'fetch-failed';
    rec.statusDetail = detail;
    rec.http = { status: res.status || null, error: (res.error && res.error.kind) || null };
    if (!rec.uncertainty.includes('The page could not be retrieved, so nothing here was checked against its real contents.')) rec.uncertainty.push('The page could not be retrieved, so nothing here was checked against its real contents.');
    if (extra) rec.uncertainty.push(extra);
    return rec;
  };
  if (looksBlocked(res)) return fail('The site showed a bot check or refused automated access. Orkardch does not get around this, so the page was not analysed.');
  if (!res.ok) return fail(explainFetchFailure(res));
  const ctype = (res.headers['content-type'] || '').toLowerCase();
  rec.http = { status: res.status, finalUrl: res.finalUrl, contentType: ctype || null, bytes: res.bytes, truncated: res.truncated, fromCache: Boolean(res.fromCache) };
  if (res.headers['last-modified']) {
    const d = new Date(res.headers['last-modified']);
    if (!Number.isNaN(d.getTime())) rec.dates.lastModifiedHeader = { value: d.toISOString(), basis: 'HTTP Last-Modified header (when the file last changed, not when it was written)' };
  }
  if (!/html|xml|text\/plain/.test(ctype) && ctype) {
    rec.status = 'fetched-not-analysed';
    rec.statusDetail = `The server answered, but the content type is ${ctype.split(';')[0]}, which Orkardch does not read as a web page. (Documents can be inspected with Image & File Forensics after you download them yourself.)`;
    return rec;
  }
  const ex = extractPage(res.body, { url: res.finalUrl || rec.url, query });
  rec.status = 'fetched';
  rec.statusDetail = `Retrieved (HTTP ${res.status})${res.fromCache ? ' from the local cache' : ''}${res.truncated ? '; only the first part of the page was read' : ''}.`;
  rec.pageTitle = ex.title;
  rec.canonicalUrl = ex.canonicalUrl;
  if (ex.siteName && !rec.publisher) rec.publisher = ex.siteName;
  rec.pagePublisher = ex.siteName;
  rec.author = ex.author;
  rec.language = ex.language || rec.language;
  if (ex.published) rec.dates.published = ex.published;
  if (ex.modified) rec.dates.modified = ex.modified;
  if (ex.summary) rec.summary = ex.summary;
  rec.excerpts = ex.excerpts;
  rec.textSample = ex.textSample;
  rec.uncertainty = rec.uncertainty.filter((u) => !u.startsWith('The snippet is the search engine')).concat(ex.notes);
  if (res.finalUrl && urlHost(res.finalUrl) && registrableDomain(urlHost(res.finalUrl)) !== registrableDomain(urlHost(rec.url))) rec.uncertainty.push(`The address redirected to a different site (${urlHost(res.finalUrl)}).`);
  if (!rec.dates.published) rec.uncertainty.push('No publication date was found on the page.');
  else rec.uncertainty.push('The publication date is what the page says about itself and was not independently confirmed.');
  return rec;
}

const MONTHS = 'January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec';
function datesIn(text) {
  const found = new Set();
  for (const re of [/\b(?:19|20)\d{2}-\d{2}-\d{2}\b/g, new RegExp(`\\b(?:${MONTHS})\\.?\\s+\\d{1,2},?\\s+(?:19|20)\\d{2}\\b`, 'g'), new RegExp(`\\b\\d{1,2}\\s+(?:${MONTHS})\\.?\\s+(?:19|20)\\d{2}\\b`, 'g')]) {
    for (const m of text.matchAll(re)) found.add(m[0]);
  }
  return found;
}
function yearsIn(text) { return new Set(text.match(/\b(?:19|20)\d{2}\b/g) || []); }
function freq(text) {
  const f = new Map();
  for (const w of text.toLowerCase().match(/\p{L}{4,}/gu) || []) if (!STOP.has(w)) f.set(w, (f.get(w) || 0) + 1);
  return f;
}
const top = (f, n) => [...f.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n).map((e) => e[0]);

/** A rough, transparent word-overlap comparison. It is a prompt to read both, not a fact check. */
function compareSources(a, b) {
  const text = (r) => r.textSample || [r.title, r.summary && r.summary.text].filter(Boolean).join('. ');
  const ta = text(a);
  const tb = text(b);
  const full = Boolean(a.textSample && b.textSample);
  const ka = new Set(top(freq(ta), 40));
  const kb = new Set(top(freq(tb), 40));
  const shared = [...ka].filter((k) => kb.has(k));
  const union = new Set([...ka, ...kb]);
  const ya = yearsIn(ta);
  const yb = yearsIn(tb);
  const da = datesIn(ta);
  const db = datesIn(tb);
  return {
    basis: full ? 'the readable text of both pages' : 'titles and snippets only (open both pages for a better comparison)',
    overlap: union.size ? Number((shared.length / union.size).toFixed(2)) : 0,
    sharedTerms: shared.slice(0, 12),
    onlyA: [...ka].filter((k) => !kb.has(k)).slice(0, 8),
    onlyB: [...kb].filter((k) => !ka.has(k)).slice(0, 8),
    yearsOnlyA: [...ya].filter((y) => !yb.has(y)).sort(),
    yearsOnlyB: [...yb].filter((y) => !ya.has(y)).sort(),
    datesOnlyA: [...da].filter((d) => !db.has(d)).slice(0, 6),
    datesOnlyB: [...db].filter((d) => !da.has(d)).slice(0, 6),
    sameUrl: (dedupeKey(a.url) || a.url) === (dedupeKey(b.url) || b.url),
    sameRegistrableDomain: registrableDomain(urlHost(a.url)) === registrableDomain(urlHost(b.url)),
    note: 'This counts shared words, years and dates. Two pages can share many words and still disagree, or agree in different words. It does not check which one is right.',
  };
}

/** A copy that is safe to store or export (no bulky page text). */
function publicRecord(rec) {
  const { textSample, ...rest } = rec;
  void textSample;
  return JSON.parse(JSON.stringify(rest));
}

module.exports = { makeRecord, dedupeRecords, analyzePage, compareSources, publicRecord, titleSimilarity, explainFetchFailure, datesIn };
