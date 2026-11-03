'use strict';
const path = require('path');
const { searchAll } = require('./web-intelligence-providers');
const { makeRecord, dedupeRecords, analyzePage, compareSources } = require('./web-intelligence-sources');
const { listSnapshots } = require('./web-intelligence-archive');
const { sourceFindings, claimFinding, archiveFindings } = require('./web-intelligence-findings');
const { renderSources } = require('./web-intelligence-export');
const { saveFindings } = require('./evidence-correlator-pick');
const { classifyInput, dedupeKey, urlHost } = require('./utils-validate');
const { mapLimit } = require('./core-concurrency');
const { writeFileAtomic } = require('./storage-jsonstore');
const { slugify, fileStamp, truncate, formatBytes } = require('./utils-format');

const withCancel = (ctx, fn) => (ctx.prompter && ctx.prompter.cancellable ? ctx.prompter.cancellable(fn) : fn(undefined));
const day = (v) => (v ? String(v).slice(0, 10) : null);
const stamp = (v) => (v ? String(v).replace('T', ' ').replace(/\.\d+Z$/, 'Z').replace(/Z$/, ' UTC') : '?');
const now = (ctx) => new Date(ctx.services.now()).toISOString();

function dateLabel(rec) {
  const d = rec.dates;
  if (d.published) return `published ${day(d.published.value)}`;
  if (d.providerSeen) return `first seen ${day(d.providerSeen.value)}`;
  if (d.lastModified) return `edited ${day(d.lastModified.value)}`;
  return 'date unknown';
}
const statusShort = (rec) => ({ listed: 'listed only', fetched: 'opened', 'fetch-failed': 'could not open', 'fetched-not-analysed': 'opened (not a web page)' }[rec.status] || rec.status);

function parseSelection(text, max) {
  const t = String(text).trim().toLowerCase();
  if (t === 'all') return { ok: true, indices: Array.from({ length: max }, (_, i) => i + 1) };
  const out = new Set();
  for (const part of t.split(/[,\s]+/).filter(Boolean)) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(part);
    if (!m) return { ok: false, error: `"${part}" is not a number or range. Try 1,3 or 2-4 or all.` };
    const a = Number(m[1]);
    const b = m[2] ? Number(m[2]) : a;
    if (a < 1 || b > max || a > b) return { ok: false, error: `Choose numbers from 1 to ${max}.` };
    for (let i = a; i <= b; i++) out.add(i);
  }
  return out.size ? { ok: true, indices: [...out] } : { ok: false, error: 'Choose at least one number.' };
}

async function selectRecords(ctx, state, { prompt, def, max = Infinity, step }) {
  const answer = await ctx.ask.text(`${prompt} (like 1,3 or 2-4 or all)`, {
    default: def, step,
    validate: (v) => { const p = parseSelection(v, state.records.length); if (!p.ok) return p.error; return p.indices.length > max ? `Please pick at most ${max} at a time.` : null; },
  });
  return parseSelection(answer, state.records.length).indices.map((i) => ({ i, rec: state.records[i - 1] }));
}

function showList(ctx, state) {
  const ui = ctx.ui;
  const shown = state.records.slice(0, 12);
  ui.heading(`Results (${state.records.length})`);
  shown.forEach((r, i) => {
    ui.menuItem(String(i + 1), truncate(r.title, ui.width * 2 - 10));
    ui.note(`${truncate(r.publisher || urlHost(r.url) || '?', 28)} - ${dateLabel(r)} - ${statusShort(r)}`, '      ');
    if (r.possibleDuplicateOf) ui.note(`May duplicate result ${r.possibleDuplicateOf.position} (similar title).`, '      ');
  });
  if (state.records.length > shown.length) ui.note(`Showing ${shown.length} of ${state.records.length}. Export the list to see all of them.`);
  ui.note('These are search results, not verified facts. Open one to see what the page itself says.');
}

function showRecord(ctx, rec, idx) {
  const ui = ctx.ui;
  ui.heading(`[${idx}] ${truncate(rec.title, 120)}`);
  ui.print(ui.c('bold', 'Observed by Orkardch'));
  ui.kv('Address', rec.url);
  if (rec.canonicalUrl && rec.canonicalUrl !== rec.url) ui.kv('Canonical address', rec.canonicalUrl);
  ui.kv('Retrieved', `${stamp(rec.dates.retrieved)} (when Orkardch got it, not when it was written)`);
  ui.kv('Status', `${statusShort(rec)}. ${rec.statusDetail}`);
  ui.kv('Found by', rec.foundBy.map((f) => f.provider).filter((v, i, a) => a.indexOf(v) === i).join(', '));
  ui.print(ui.c('bold', 'Claimed by the source'));
  if (rec.publisher) ui.kv('Publisher', rec.publisher);
  if (rec.author) ui.kv('Author', rec.author);
  const d = rec.dates;
  if (d.published) ui.kv('Published', `${day(d.published.value)} (${d.published.basis}; the page says this itself)`);
  if (d.modified) ui.kv('Modified', `${day(d.modified.value)} (${d.modified.basis})`);
  if (d.providerSeen) ui.kv('First seen', `${day(d.providerSeen.value)} (${d.providerSeen.basis})`);
  if (d.lastModified) ui.kv('Last edited', `${day(d.lastModified.value)} (${d.lastModified.basis})`);
  if (d.lastModifiedHeader) ui.kv('Server date', `${day(d.lastModifiedHeader.value)} (file last changed)`);
  if (rec.summary) ui.kv(`Summary [${rec.summary.method}]`, rec.summary.text);
  for (const e of rec.excerpts || []) ui.kv(`Excerpt, ${e.location}`, `"${e.text}"`);
  const notes = [...rec.uncertainty];
  if (rec.possibleDuplicateOf) notes.push(`Orkardch's inference: this may duplicate result ${rec.possibleDuplicateOf.position} (${rec.possibleDuplicateOf.basis}).`);
  if (notes.length) { ui.print(ui.c('bold', 'Things to be careful about')); notes.forEach((n) => ui.note(`- ${n}`)); }
}

async function runSearch(ctx, state, { fresh = false, only } = {}) {
  const ui = ctx.ui;
  ui.note('Searching public sources. Your search words are sent to each one. Press Ctrl+C to stop.');
  ctx.net.bypassCache = fresh;
  let providers;
  try { providers = await withCancel(ctx, (signal) => searchAll(ctx, state.query, { signal, only })); } finally { ctx.net.bypassCache = false; }
  const at = now(ctx);
  const raw = [];
  for (const p of providers) for (const r of p.results) raw.push(makeRecord(r, { provider: p.id, query: state.query, retrievedAt: p.retrievedAt || at }));
  state.providers = providers;
  state.records = dedupeRecords(raw);
  state.ranAt = at;
  state.kind = 'search';
  ui.heading('Where the results came from');
  ui.table(['Source', 'Result'], providers.map((p) => [p.label, ({
    ok: `${p.results.length} result${p.results.length === 1 ? '' : 's'}${p.fromCache ? ' (from cache)' : ''}`,
    skipped: `skipped: ${p.reason}`, disabled: 'turned off in Settings',
  }[p.status]) || `FAILED: ${(p.error && p.error.message) || 'unknown'}${p.error && p.error.hint ? ` ${p.error.hint}` : ''}`]));
  const firstError = providers.find((p) => p.status === 'error');
  if (firstError) ctx.session.setError({ code: firstError.error.code || firstError.error.kind, message: firstError.error.message, hint: firstError.error.hint });
  if (!state.records.length) {
    ui.warn(providers.some((p) => p.status === 'ok') ? 'The sources answered, but found nothing for these words. Try different or fewer words.' : 'No source could be reached, so there is nothing to show. Nothing was made up.');
  } else {
    if (state.previousKeys) {
      const keys = new Set(state.records.map((r) => dedupeKey(r.url) || r.url));
      const added = state.records.filter((r) => !state.previousKeys.has(dedupeKey(r.url) || r.url));
      const gone = [...state.previousKeys].filter((k) => !keys.has(k));
      ui.heading(`Compared with the earlier run${state.previousAt ? ` (${day(state.previousAt)})` : ''}`);
      ui.para(`${added.length} new, ${gone.length} no longer returned.`);
      added.slice(0, 3).forEach((r) => ui.note(`New: ${truncate(r.title, 70)}`));
    }
    state.previousKeys = new Set(state.records.map((r) => dedupeKey(r.url) || r.url));
    showList(ctx, state);
  }
  ctx.session.setResult('search-results', {
    query: state.query, resultCount: state.records.length,
    providers: providers.map((p) => ({ id: p.id, status: p.status, count: p.results.length, error: p.error ? (p.error.kind || p.error.code) : null })),
  });
}

async function fetchRecords(ctx, state, list) {
  const ui = ctx.ui;
  if (!ctx.requireOnline('open web pages')) return;
  ui.note(`Opening ${list.length} page${list.length === 1 ? '' : 's'} (a few at a time)...`);
  await withCancel(ctx, (signal) => mapLimit(list, ctx.config.get('maxParallelRequests'), async ({ i, rec }) => {
    await analyzePage(ctx, rec, { query: state.query, signal });
    if (rec.pageTitle && rec.status === 'fetched') rec.title = rec.pageTitle;
    ui.print(`  [${i}] ${statusShort(rec)}${rec.status === 'fetch-failed' ? `: ${rec.statusDetail}` : ''}`);
  }));
  const failed = list.filter(({ rec }) => rec.status === 'fetch-failed').length;
  ctx.session.setResult('pages', { opened: list.length - failed, failed, query: state.query });
}

async function archiveFlow(ctx, url) {
  const ui = ctx.ui;
  if (!ctx.requireOnline('look up old versions of a page')) return;
  ctx.session.setInput('archive url', url);
  ui.heading('Old versions (Internet Archive)');
  ui.note('Asking the public Wayback Machine. The address is sent to archive.org. No logins are bypassed.');
  const r = await withCancel(ctx, (signal) => listSnapshots(ctx, url, { signal }));
  if (!r.ok) { ui.warn(`Archive lookup failed: ${(r.error && r.error.message) || 'unknown problem'} ${(r.error && r.error.hint) || ''}`); ctx.session.setError(r.error); return; }
  if (!r.snapshots.length) ui.para(r.note);
  r.snapshots.forEach((s) => { ui.print(`  ${stamp(s.timestamp)}  ${s.statusCode}`); ui.note(`  ${s.archiveUrl}`); });
  if (r.snapshots.length) ui.note(r.note);
  ctx.session.setResult('archive', { url, captures: r.snapshots.length, first: r.snapshots[0] && r.snapshots[0].timestamp, last: r.snapshots.length ? r.snapshots[r.snapshots.length - 1].timestamp : null });
  if (r.snapshots.length && await ctx.ask.confirm('Save these captures to an investigation?', { def: false, step: 'web.archive.save' })) {
    await saveFindings(ctx, archiveFindings(url, r.snapshots, r.retrievedAt), { module: 'web-intelligence', method: `Looked up Internet Archive captures of ${url} (${r.snapshots.length} found).` });
  }
}

async function exportFlow(ctx, state) {
  const ui = ctx.ui;
  const sel = await selectRecords(ctx, state, { prompt: 'Which results to export?', def: 'all', step: 'web.export.pick' });
  const cfg = ctx.config.get('reportFormat');
  const fmt = await ctx.ask.select('Which format?', [
    { label: 'Markdown (.md)', value: 'md' }, { label: 'Plain text (.txt)', value: 'txt' }, { label: 'JSON (.json)', value: 'json' },
  ], { def: cfg === 'json' ? 2 : cfg === 'txt' ? 1 : 0, step: 'web.export.format' });
  const content = renderSources(sel.map((s) => s.rec), { format: fmt, query: state.query, generatedAt: now(ctx) });
  const file = path.join(ctx.config.outputDir(), 'web', `sources-${slugify(state.query)}-${fileStamp(ctx.services.now)}.${fmt}`);
  writeFileAtomic(file, content, { mode: 0o600, dirMode: 0o700 });
  ui.ok(`Saved ${sel.length} source(s), ${formatBytes(Buffer.byteLength(content))}:`);
  ui.print(`  ${file}`);
}

async function claimFlow(ctx, state) {
  const ui = ctx.ui;
  const [{ i, rec }] = await selectRecords(ctx, state, { prompt: 'Which source made the claim?', max: 1, step: 'web.claim.pick' });
  ui.para(`Type the claim exactly as "${truncate(rec.title, 50)}" states it, not what you believe. Orkardch records it as a claim by that source, with its link and retrieval time.`);
  const value = await ctx.ask.text('The claim (for example: Founded in 2010):', { step: 'web.claim.value', validate: (v) => (v.length > 500 ? 'Please keep it under 500 characters.' : null) });
  const subject = await ctx.ask.text('Who or what is it about? (optional, press Enter to skip):', { allowEmpty: true, step: 'web.claim.subject' });
  const attribute = subject ? await ctx.ask.text('Which property is it? (for example "founding year"; Enter to skip):', { allowEmpty: true, step: 'web.claim.attribute' }) : '';
  ui.note('Using the same subject and property wording for claims from different sources lets the Evidence Correlator spot disagreements.');
  await saveFindings(ctx, [claimFinding({ subject: subject || null, attribute: attribute || null, value, rec })], { module: 'web-intelligence', method: `Recorded a claim attributed to source [${i}] ${truncate(rec.title, 60)}.` });
}

async function compareFlow(ctx, state) {
  const ui = ctx.ui;
  if (state.records.length < 2) { ui.note('You need at least two results to compare.'); return; }
  const sel = await selectRecords(ctx, state, { prompt: 'Which two results?', def: '1-2', step: 'web.compare.pick', max: 2 });
  if (sel.length !== 2) { ui.warn('Please choose exactly two.'); return; }
  if (sel.some(({ rec }) => rec.status === 'listed') && await ctx.ask.confirm('Open both pages first so I can compare what they say? (Otherwise only titles and snippets are compared.)', { def: true, step: 'web.compare.fetch' })) {
    await fetchRecords(ctx, state, sel.filter(({ rec }) => rec.status === 'listed'));
  }
  const [a, b] = [sel[0].rec, sel[1].rec];
  const c = compareSources(a, b);
  ui.heading(`Compare [${sel[0].i}] and [${sel[1].i}]`);
  ui.kv('Based on', c.basis);
  ui.kv('Word overlap', `${Math.round(c.overlap * 100)}% of the main words are shared`);
  if (c.sameUrl) ui.warn('These are the same page address, so this is one source, not two.');
  else if (c.sameRegistrableDomain) ui.note('Both are from the same website, so they are not independent of each other.');
  if (c.sharedTerms.length) ui.kv('Shared words', c.sharedTerms.join(', '));
  if (c.onlyA.length) ui.kv(`Only in [${sel[0].i}]`, c.onlyA.join(', '));
  if (c.onlyB.length) ui.kv(`Only in [${sel[1].i}]`, c.onlyB.join(', '));
  if (c.yearsOnlyA.length || c.yearsOnlyB.length) ui.kv('Years that differ', `[${sel[0].i}] only: ${c.yearsOnlyA.join(', ') || '-'} | [${sel[1].i}] only: ${c.yearsOnlyB.join(', ') || '-'}`);
  if (c.datesOnlyA.length || c.datesOnlyB.length) ui.kv('Dates that differ', `[${sel[0].i}] only: ${c.datesOnlyA.join('; ') || '-'} | [${sel[1].i}] only: ${c.datesOnlyB.join('; ') || '-'}`);
  ui.note(c.note);
  ctx.session.setResult('source-comparison', { overlap: c.overlap, basis: c.basis, sameUrl: c.sameUrl, sameSite: c.sameRegistrableDomain });
}

async function saveSources(ctx, state) {
  const sel = await selectRecords(ctx, state, { prompt: 'Which results to save?', def: 'all', step: 'web.save.pick' });
  const ok = (state.providers || []).filter((p) => p.status === 'ok').map((p) => p.id);
  const method = state.kind === 'search'
    ? `Searched public sources for "${truncate(state.query, 80)}" (${ok.join(', ') || 'no source answered'}); saved ${sel.length} result(s).`
    : `Opened ${truncate(state.query, 100)}; saved the source record.`;
  const saved = await saveFindings(ctx, sel.flatMap(({ rec }) => sourceFindings(rec)), { module: 'web-intelligence', method });
  if (saved && state.kind === 'search') ctx.store.addSearch(saved.inv.id, { query: state.query, providers: ok, resultCount: state.records.length, urls: state.records.slice(0, 50).map((r) => r.url) });
}

async function resultsMenu(ctx, state) {
  const ui = ctx.ui;
  const isSearch = () => state.kind === 'search';
  await ctx.ask.menu({
    title: 'What next?', step: 'web.results',
    items: [
      {
        key: '1', label: 'Open a result and see what it says', run: async () => {
          const [{ i, rec }] = await selectRecords(ctx, state, { prompt: 'Which result?', max: 1, def: state.records.length === 1 ? '1' : undefined, step: 'web.open.pick' });
          if (rec.status === 'listed' && await ctx.ask.confirm('Open the page now and read it? (Contacts that website)', { def: true, step: 'web.open.fetch' })) await fetchRecords(ctx, state, [{ i, rec }]);
          showRecord(ctx, rec, i);
          ctx.session.setResult('source-record', { title: rec.title, status: rec.status, hasPublished: Boolean(rec.dates.published), excerpts: rec.excerpts.length, uncertainty: rec.uncertainty.length });
        },
      },
      {
        key: '2', label: 'Open several pages at once (up to 5)', run: async () => {
          const sel = await selectRecords(ctx, state, { prompt: 'Which results?', def: state.records.length > 1 ? '1-3' : '1', max: 5, step: 'web.fetch.pick' });
          await fetchRecords(ctx, state, sel);
        },
      },
      { key: '3', label: 'Save sources to an investigation', run: () => saveSources(ctx, state) },
      {
        key: '4', label: 'See old versions of a result (archives)', run: async () => {
          const [{ rec }] = await selectRecords(ctx, state, { prompt: 'Which result?', max: 1, def: state.records.length === 1 ? '1' : undefined, step: 'web.archive.pick' });
          await archiveFlow(ctx, rec.canonicalUrl || rec.url);
        },
      },
      { key: '5', label: 'Compare two results', run: () => compareFlow(ctx, state) },
      { key: '6', label: 'Record a claim from a source', run: () => claimFlow(ctx, state) },
      { key: '7', label: 'Export this list', run: () => exportFlow(ctx, state) },
      { key: '8', label: 'Search again (fresh results)', hidden: !isSearch(), run: async () => { await runSearch(ctx, state, { fresh: true }); } },
      {
        key: '9', label: 'Look for public documents (PDF) on this', hidden: !isSearch(), run: async () => {
          const docState = { kind: 'search', query: `${state.query} filetype:pdf`, records: [] };
          await runSearch(ctx, docState, { only: ['duckduckgo', 'brave'] });
          if (docState.records.length) await resultsMenu(ctx, docState);
          else ui.note('Document search needs DuckDuckGo or a Brave Search key (Settings). Wikipedia and GDELT do not search documents.');
        },
      },
      { key: 'e', label: 'Explain these results', aliases: ['explain'], run: () => require('./mother-index').explainResults(ctx) },
    ],
  });
}

async function pageFlow(ctx, url, original) {
  if (!ctx.requireOnline('open that page')) return;
  const rec = makeRecord({ title: url, url, publisher: urlHost(url), sourceType: 'web page' }, { provider: 'direct address', query: original, retrievedAt: now(ctx) });
  rec.uncertainty = [];
  ctx.ui.note('Opening the page (this contacts that website)...');
  await withCancel(ctx, (signal) => analyzePage(ctx, rec, { signal }));
  if (rec.pageTitle) rec.title = rec.pageTitle;
  const state = { kind: 'page', query: original, records: [rec], providers: [] };
  showRecord(ctx, rec, 1);
  ctx.session.setResult('source-record', { title: rec.title, status: rec.status, hasPublished: Boolean(rec.dates.published), excerpts: rec.excerpts.length, uncertainty: rec.uncertainty.length });
  if (rec.status === 'fetch-failed') ctx.session.setError({ code: 'FETCH_FAILED', message: rec.statusDetail });
  await resultsMenu(ctx, state);
}

async function researchFlow(ctx, preset) {
  const ui = ctx.ui;
  const q = preset || await ctx.ask.text('What do you want to research?', { step: 'web.query', validate: (v) => (v.length > 300 ? 'Please keep it under 300 characters.' : null) });
  ctx.session.setInput('query', q);
  const cls = classifyInput(q);
  if (/^https?:\/\//i.test(q) || (cls.kind === 'domain' && !/\s/.test(q))) {
    ui.note('That looks like a web address, so I will open that page. (Type words instead to search.)');
    return pageFlow(ctx, /^https?:\/\//i.test(q) ? q : `https://${cls.value}/`, q);
  }
  if (!ctx.requireOnline('search public sources')) return undefined;
  const state = { kind: 'search', query: q, records: [], providers: [] };
  await runSearch(ctx, state);
  if (state.records.length) await resultsMenu(ctx, state);
  return undefined;
}

async function rerunSaved(ctx) {
  const ui = ctx.ui;
  const inv = ctx.activeInvestigation();
  if (!inv || !inv.searches.length) {
    ui.note('No saved searches yet. Run a search, then choose "Save sources to an investigation" to keep it so you can re-run it later.');
    return;
  }
  const list = inv.searches.slice(-9).reverse();
  ui.heading(`Saved searches in "${truncate(inv.title, 40)}"`);
  list.forEach((s, i) => ui.menuItem(String(i + 1), `${truncate(s.query, 36)} (${day(s.ranAt)}, ${s.resultCount} results)`));
  const key = await ctx.ask.choice(list.map((s, i) => ({ key: String(i + 1) })), { step: 'web.rerun.pick' });
  const s = list[Number(key) - 1];
  if (!ctx.requireOnline('re-run a search')) return;
  ctx.session.setInput('query', s.query);
  const state = { kind: 'search', query: s.query, records: [], providers: [], previousKeys: new Set((s.urls || []).map((u) => dedupeKey(u) || u)), previousAt: s.ranAt };
  await runSearch(ctx, state, { fresh: true });
  if (state.records.length) await resultsMenu(ctx, state);
}

async function run(ctx) {
  const ui = ctx.ui;
  ui.heading('Public Web Intelligence');
  ui.para('Research a topic or website using public sources only. I keep each real link and the time I retrieved it, and I keep what a page claims separate from what I could confirm.');
  if (ctx.net.offline) ui.warn('Offline mode is ON, so nothing can be searched or opened. Turn it off in Settings.');
  await ctx.ask.menu({
    step: 'web.menu',
    items: [
      { key: '1', label: 'Research something (words, a website, or a web address)', aliases: ['research', 'search'], run: () => researchFlow(ctx) },
      {
        key: '2', label: 'See old versions of a web page', aliases: ['archive', 'old'], run: async () => {
          const u = await ctx.ask.text('Web address (like https://example.com/page):', { step: 'web.archive.input', validate: (v) => (/^https?:\/\/\S+$/i.test(v) ? null : 'Start with http:// or https://') });
          return archiveFlow(ctx, u);
        },
      },
      { key: '3', label: 'Re-run a saved search', aliases: ['rerun', 'saved'], run: () => rerunSaved(ctx) },
    ],
  });
}

module.exports = { id: 'web', title: 'Public Web Intelligence', run, researchFlow, parseSelection, runSearch };
