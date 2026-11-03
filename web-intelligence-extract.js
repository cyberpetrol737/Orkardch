'use strict';
const { decodeHtml, htmlToText, parseAttrs } = require('./utils-html');
const { truncate } = require('./utils-format');

const STOP = new Set('about above after again against also among because been before being below between both could does doing down during each from further have having here hers himself into itself just more most myself once only other ours ourselves over same should some such than that their theirs them themselves then there these they this those through under until very were what when where which while whom will with would your yours yourself yourselves said says will than also its are was has had can the and for not but you all any'.split(' '));

function metaMap(html) {
  const m = {};
  const re = /<meta\s+([^>]*?)\/?>/gi;
  let x;
  while ((x = re.exec(html))) {
    const a = parseAttrs(x[1]);
    const key = (a.property || a.name || a.itemprop || '').toLowerCase();
    if (key && a.content !== undefined && m[key] === undefined) m[key] = a.content.trim();
  }
  return m;
}

function canonicalLink(html, base) {
  const re = /<link\s+([^>]*?)\/?>/gi;
  let x;
  while ((x = re.exec(html))) {
    const a = parseAttrs(x[1]);
    if ((a.rel || '').toLowerCase().split(/\s+/).includes('canonical') && a.href) {
      try { return new URL(a.href, base).toString(); } catch { return null; }
    }
  }
  return null;
}

function jsonLdObjects(html) {
  const out = [];
  const re = /<script[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let x;
  while ((x = re.exec(html)) && out.length < 10) {
    try {
      const j = JSON.parse(x[1].trim());
      const walk = (n, d) => {
        if (!n || d > 4) return;
        if (Array.isArray(n)) { n.forEach((i) => walk(i, d + 1)); return; }
        if (typeof n === 'object') { out.push(n); if (n['@graph']) walk(n['@graph'], d + 1); }
      };
      walk(j, 0);
    } catch { /* invalid JSON-LD is ignored */ }
  }
  return out;
}

function validDate(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function nameOf(v) {
  if (!v) return null;
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return v.map(nameOf).filter(Boolean).join(', ') || null;
  return typeof v.name === 'string' ? v.name : null;
}

function mainText(html) {
  let h = html.replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style|noscript|svg|head|nav|footer|aside|form|template|iframe)\b[\s\S]*?<\/\1>/gi, ' ');
  const pick = /<article\b[^>]*>([\s\S]*?)<\/article>/i.exec(h) || /<main\b[^>]*>([\s\S]*?)<\/main>/i.exec(h) || /<body\b[^>]*>([\s\S]*)<\/body>/i.exec(h);
  h = pick ? pick[1] : h;
  h = h.replace(/<\/(p|div|li|h[1-6]|tr|br|section|blockquote)>|<br\s*\/?>/gi, '\n');
  return decodeHtml(h.replace(/<[^>]*>/g, ' ')).split('\n').map((l) => l.replace(/\s+/g, ' ').trim()).filter((l) => l.length >= 40);
}

function queryTerms(query) {
  return [...new Set(String(query || '').toLowerCase().split(/[^\p{L}\p{N}]+/u).filter((t) => t.length >= 3 && !STOP.has(t)))];
}

function excerptAround(par, terms, max = 240) {
  const low = par.toLowerCase();
  let idx = -1;
  for (const t of terms) { const i = low.indexOf(t); if (i >= 0 && (idx < 0 || i < idx)) idx = i; }
  if (par.length <= max) return par;
  const start = Math.max(0, (idx < 0 ? 0 : idx) - 60);
  return `${start > 0 ? '...' : ''}${par.slice(start, start + max).trim()}${start + max < par.length ? '...' : ''}`;
}

/**
 * Pull labelled facts out of one HTML page. Everything returned is something the PAGE says
 * (a claim), with the place it came from. Nothing is generated or guessed.
 */
function extractPage(html, { url, query } = {}) {
  const meta = metaMap(html);
  const ld = jsonLdObjects(html);
  const title = (/<title[^>]*>([\s\S]*?)<\/title>/i.exec(html) || [])[1];
  const ldArticle = ld.find((o) => o.datePublished || o.headline) || {};
  const publishedCandidates = [
    [meta['article:published_time'], 'meta tag article:published_time'], [meta['og:published_time'], 'meta tag og:published_time'],
    [ldArticle.datePublished, 'JSON-LD datePublished'], [meta['date'], 'meta tag date'], [meta['dc.date'], 'meta tag dc.date'],
    [meta['pubdate'], 'meta tag pubdate'], [meta['datepublished'], 'meta tag datePublished'],
  ];
  let published = null;
  for (const [raw, basis] of publishedCandidates) { const iso = validDate(raw); if (iso) { published = { value: iso, raw, basis, selfReported: true }; break; } }
  if (!published) {
    const t = /<time\b[^>]*datetime\s*=\s*["']([^"']+)["']/i.exec(html);
    const iso = t && validDate(t[1]);
    if (iso) published = { value: iso, raw: t[1], basis: 'first <time> element on the page (less reliable)', selfReported: true };
  }
  let modified = null;
  for (const [raw, basis] of [[meta['article:modified_time'], 'meta tag article:modified_time'], [ldArticle.dateModified, 'JSON-LD dateModified'], [meta['og:updated_time'], 'meta tag og:updated_time']]) {
    const iso = validDate(raw);
    if (iso) { modified = { value: iso, raw, basis, selfReported: true }; break; }
  }
  const paragraphs = mainText(html);
  const terms = queryTerms(query);
  const description = meta.description || meta['og:description'] || null;
  let summary = null;
  if (description && description.length >= 30) summary = { text: truncate(decodeHtml(description).trim(), 300), method: 'meta-description (the site\'s own wording)' };
  else if (paragraphs.find((p) => p.length >= 80)) summary = { text: truncate(paragraphs.find((p) => p.length >= 80), 300), method: 'first long paragraph on the page' };
  const hits = [];
  if (terms.length) {
    paragraphs.forEach((p, i) => { const low = p.toLowerCase(); const score = terms.filter((t) => low.includes(t)).length; if (score) hits.push({ i, score, p }); });
    hits.sort((a, b) => b.score - a.score || a.i - b.i);
  }
  const excerpts = hits.slice(0, 3).map((h) => ({ text: excerptAround(h.p, terms), location: `paragraph ${h.i + 1}` }));
  const langM = /<html\b[^>]*\blang\s*=\s*["']([^"']+)["']/i.exec(html);
  const notes = [];
  if (paragraphs.length < 2) notes.push('Very little readable text was found. The page may need JavaScript, be behind a login or paywall, or be mostly images.');
  if (terms.length && !excerpts.length && paragraphs.length) notes.push('None of your search words appear in the readable text of this page.');
  return {
    title: title ? htmlToText(title).slice(0, 300) : (meta['og:title'] || null),
    canonicalUrl: canonicalLink(html, url) || meta['og:url'] || null,
    description, siteName: meta['og:site_name'] || nameOf(ldArticle.publisher) || null,
    author: meta.author || nameOf(ldArticle.author) || null, published, modified, language: langM ? langM[1] : null,
    summary, excerpts, paragraphCount: paragraphs.length, textSample: paragraphs.join('\n').slice(0, 20000), notes,
  };
}

const BLOCK_MARKERS = /captcha|are you (a )?robot|unusual traffic|cf-chl|just a moment\.\.\.|attention required|access denied|enable javascript and cookies|anomaly-modal|verify you are human/i;
function looksBlocked(res) {
  if ([403, 429, 503].includes(res.status) && (BLOCK_MARKERS.test((res.body || '').slice(0, 20000)) || res.headers['server'] === 'cloudflare')) return true;
  return res.status === 202 || (res.body && res.body.length < 30000 && BLOCK_MARKERS.test(res.body));
}

module.exports = { extractPage, looksBlocked, queryTerms, STOP, mainText };
