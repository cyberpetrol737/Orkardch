'use strict';
const { publicRecord } = require('./web-intelligence-sources');

const day = (v) => (v ? String(v).replace('T', ' ').replace(/\.000Z$/, 'Z') : null);

function dateLines(rec) {
  const d = rec.dates;
  const out = [];
  if (d.published) out.push(`Published (as claimed by the page): ${day(d.published.value)} - ${d.published.basis}`);
  if (d.modified) out.push(`Modified (as claimed by the page): ${day(d.modified.value)} - ${d.modified.basis}`);
  if (d.providerSeen) out.push(`First seen by provider: ${day(d.providerSeen.value)} - ${d.providerSeen.basis}`);
  if (d.lastModified) out.push(`Last edited: ${day(d.lastModified.value)} - ${d.lastModified.basis}`);
  if (d.lastModifiedHeader) out.push(`Server last-modified: ${day(d.lastModifiedHeader.value)}`);
  if (!d.published && !d.providerSeen && !d.lastModified) out.push('Publication date: not available');
  out.push(`Retrieved by Orkardch: ${day(d.retrieved)} UTC`);
  return out;
}

/** Render a source list as 'json' | 'md' | 'txt'. */
function renderSources(records, { format = 'md', query = '', generatedAt = new Date().toISOString() } = {}) {
  const notice = 'Search results and page text are claims by their sources. They are not verified facts.';
  if (format === 'json') return `${JSON.stringify({ generatedAt, query, notice, sources: records.map(publicRecord) }, null, 2)}\n`;
  const md = format === 'md';
  const out = [md ? '# Orkardch source list' : 'Orkardch source list', ''];
  out.push(`Query: ${query || '(none)'}`, `Exported: ${day(generatedAt)} UTC`, notice, '');
  records.forEach((r, i) => {
    out.push(md ? `## ${i + 1}. ${r.title}` : `${i + 1}. ${r.title}`);
    out.push(`URL: ${r.url}`);
    if (r.canonicalUrl && r.canonicalUrl !== r.url) out.push(`Canonical URL: ${r.canonicalUrl}`);
    if (r.publisher) out.push(`Publisher: ${r.publisher}`);
    out.push(...dateLines(r));
    out.push(`Status: ${r.status} - ${r.statusDetail}`);
    out.push(`Found by: ${r.foundBy.map((f) => f.provider).join(', ')}`);
    if (r.summary) out.push(`Summary (${r.summary.method}): ${r.summary.text}`);
    for (const e of r.excerpts || []) out.push(md ? `> "${e.text}" (${e.location})` : `Excerpt (${e.location}): "${e.text}"`);
    for (const u of r.uncertainty || []) out.push(`Uncertainty: ${u}`);
    if (r.possibleDuplicateOf) out.push(`Possible duplicate of result ${r.possibleDuplicateOf.position} (${r.possibleDuplicateOf.basis}).`);
    out.push('');
  });
  return `${out.join('\n')}\n`;
}

module.exports = { renderSources, dateLines };
