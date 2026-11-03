'use strict';
const fs = require('fs');
const path = require('path');
const { analyze, sourceSummary } = require('./evidence-correlator-analysis');
const { renderTextGraph } = require('./evidence-correlator-graph');
const { pickInvestigation, createInvestigation } = require('./evidence-correlator-pick');
const { pickFile } = require('./file-forensics-browse');
const { writeFileAtomic } = require('./storage-jsonstore');
const { truncate, formatBytes, slugify, fileStamp } = require('./utils-format');

const SHORT = { confirmed_direct: 'observed', multi_independent: 'multi-source', plausible: 'unverified', conflicting: 'CONFLICT', unknown: 'unknown' };
const KIND = { observation: 'Something observed (by a tool or by you)', claim: 'A claim made by a source', inference: 'An inference (a conclusion drawn from other evidence)' };
const day = (v) => (v ? String(v).slice(0, 10) : '?');

async function needActive(ctx) {
  const inv = ctx.activeInvestigation();
  if (inv) return inv;
  ctx.ui.note('No investigation is open yet.');
  return pickInvestigation(ctx);
}
const reload = (ctx, inv) => ctx.store.load(inv.id) || inv;

function showFinding(ctx, inv, f, a) {
  const ui = ctx.ui;
  const as = a.assessments[f.id];
  ui.heading(`${f.type}: ${truncate(f.value, 100)}`);
  ui.kv('ID', f.id);
  ui.kv('Kind', KIND[f.statementType]);
  ui.kv('Value', f.value);
  if (f.subject) ui.kv('About', `${f.subject}${f.attribute ? ` / ${f.attribute}` : ''}`);
  ui.print(ui.c('bold', 'Where it came from (provenance)'));
  const s = f.source || {};
  ui.kv('Module', `${s.module || '?'}${s.provider ? ` via ${s.provider}` : ''}`);
  if (s.url) ui.kv('Address', s.url);
  if (s.publisher) ui.kv('Publisher', s.publisher);
  if (s.file) ui.kv('File', `${s.file.name || '?'} (${s.file.size != null ? formatBytes(s.file.size) : '?'}) SHA-256 ${s.file.sha256 || '?'}`);
  if (s.description) ui.kv('Note', s.description);
  if (s.importNote) ui.kv('Imported', s.importNote);
  if (s.retrievedAt) ui.kv('Retrieved', s.retrievedAt);
  ui.kv('First seen', f.firstObserved);
  ui.kv('Last seen', f.lastObserved);
  ui.print(ui.c('bold', 'Confidence'));
  ui.kv('Assessment', as.label);
  as.reasons.forEach((r) => ui.note(`- ${r}`));
  ui.kv('Verification', f.verification);
  if (f.statementType !== 'observation') ui.kv('Independence', f.independence.status + (f.independence.derivedFrom ? ` (copied from ${f.independence.derivedFrom})` : ''));
  if (f.sensitive) ui.warn(`Marked sensitive (${f.sensitive}). It is left out of reports unless you allow it.`);
  const conflicts = a.contradictions.filter((c) => c.findingIds.includes(f.id));
  for (const c of conflicts) ui.kv('Disagreement', `${c.subject} / ${c.attribute}: ${c.sides.map((x) => x.value).join('  vs  ')}`);
  const edges = a.relationships.filter((e) => e.from === f.id || e.to === f.id);
  const byId = new Map(inv.findings.map((x) => [x.id, x]));
  for (const e of edges.slice(0, 6)) { const o = byId.get(e.from === f.id ? e.to : e.from); ui.kv(e.match === 'fuzzy' ? 'Fuzzy link' : 'Linked', `${e.relation}: ${o ? truncate(`${o.type} ${o.value}`, 60) : '?'}`); }
  if (f.supporting.length) f.supporting.forEach((r) => ui.kv('Supporting', r.description || r.url || r.findingId));
  if (f.contradicting.length) f.contradicting.forEach((r) => ui.kv('Contradicting', r.description || r.url || r.findingId));
  if (f.notes.length) { ui.print(ui.c('bold', 'Your notes')); f.notes.forEach((n) => ui.note(`${day(n.at)}: ${n.text}`)); }
}

async function findingMenu(ctx, inv, f) {
  const ui = ctx.ui;
  await ctx.ask.menu({
    title: 'This finding', step: 'correlator.finding',
    items: [
      { key: '1', label: 'Add a note', run: async () => { const t = await ctx.ask.text('Your note:', { step: 'correlator.note.text' }); ctx.store.addFindingNote(inv.id, f.id, t); f.notes.push({ at: new Date().toISOString(), text: t }); ui.ok('Note added. The original evidence was not changed.'); } },
      {
        key: '2', label: 'Set verification status', run: async () => {
          const v = await ctx.ask.select('How sure are you?', [
            { label: 'Unverified', value: 'unverified' }, { label: 'Verified by me (I checked it myself)', value: 'verified-by-user' }, { label: 'Disputed', value: 'disputed' },
          ], { def: 0, step: 'correlator.verify' });
          const note = v === 'unverified' ? null : await ctx.ask.text('Briefly, how did you check (or why dispute)?', { step: 'correlator.verify.note' });
          ctx.store.setVerification(inv.id, f.id, v, note);
          f.verification = v;
          ui.ok('Updated.');
        },
      },
      {
        key: '3', label: 'Say whether its source is independent', hidden: f.statementType === 'observation', run: async () => {
          const s = await ctx.ask.select('Compared with other sources of the same claim, this source is:', [
            { label: 'Not known yet', value: 'unknown' }, { label: 'Independent (it did its own research or observation)', value: 'independent' }, { label: 'Copied from another finding', value: 'derived' },
          ], { def: 0, step: 'correlator.independence' });
          let from = null;
          if (s === 'derived') {
            const others = inv.findings.filter((x) => x.id !== f.id).slice(0, 9);
            others.forEach((x, i) => ui.menuItem(String(i + 1), truncate(`${x.type}: ${x.value}`, 50)));
            from = others[Number(await ctx.ask.choice(others.map((x, i) => ({ key: String(i + 1) })), { step: 'correlator.independence.from' })) - 1].id;
          }
          ctx.store.setIndependence(inv.id, f.id, { status: s, derivedFrom: from });
          f.independence = { status: s, derivedFrom: from };
          ui.ok('Updated. Re-run the analysis to see how confidence changes.');
        },
      },
      {
        key: '4', label: 'Link another finding as supporting or contradicting', run: async () => {
          const kind = await ctx.ask.select('How does the other finding relate to this one?', [{ label: 'It supports this', value: 'supporting' }, { label: 'It contradicts this', value: 'contradicting' }], { def: 0, step: 'correlator.link.kind' });
          const others = inv.findings.filter((x) => x.id !== f.id).slice(0, 9);
          if (!others.length) { ui.note('There are no other findings to link.'); return; }
          others.forEach((x, i) => ui.menuItem(String(i + 1), truncate(`${x.type}: ${x.value}`, 50)));
          const key = await ctx.ask.choice(others.map((x, i) => ({ key: String(i + 1) })), { step: 'correlator.link.pick' });
          const why = await ctx.ask.text('Why? (optional)', { allowEmpty: true, step: 'correlator.link.why' });
          const ref = ctx.store.addReference(inv.id, f.id, kind, { otherFindingId: others[Number(key) - 1].id, description: why });
          f[kind].push(ref);
          ui.ok('Linked. Re-run the analysis to see the effect.');
        },
      },
      { key: '5', label: 'Explain this', aliases: ['explain'], run: () => require('./mother-index').explainResults(ctx) },
    ],
  });
}

async function reviewFindings(ctx) {
  const ui = ctx.ui;
  let inv = await needActive(ctx);
  if (!inv) return;
  if (!inv.findings.length) { ui.note('There are no findings yet. Save results from another module, add evidence by hand, or import a file.'); return; }
  const types = [...new Set(inv.findings.map((f) => f.type))];
  ui.note(`Types here: ${types.join(', ')}`);
  const filter = (await ctx.ask.text('Show which type? (press Enter for all)', { allowEmpty: true, step: 'correlator.review.filter' })).toLowerCase();
  let page = 0;
  for (;;) {
    inv = reload(ctx, inv);
    const a = analyze(inv, { now: ctx.services.now });
    const list = inv.findings.filter((f) => !filter || f.type === filter);
    if (!list.length) { ui.note(`No findings of type "${filter}".`); return; }
    const per = 8;
    const pages = Math.ceil(list.length / per);
    page = Math.min(page, pages - 1);
    ui.heading(`Findings (${list.length}) - page ${page + 1}/${pages}`);
    list.slice(page * per, page * per + per).forEach((f, i) => {
      ui.menuItem(String(i + 1), truncate(`${f.type}: ${f.value}`, ui.width * 2 - 10));
      ui.note(`${f.statementType} - ${SHORT[a.assessments[f.id].level]} - ${truncate(sourceSummary(f), 50)}`, '      ');
    });
    ctx.session.setResult('findings-review', { total: list.length, conflicts: list.filter((f) => a.assessments[f.id].level === 'conflicting').length });
    const ans = (await ctx.ask.text('Number for details, n/p for pages, or back:', { step: 'correlator.review.pick' })).trim().toLowerCase();
    if (ans === 'n') { page = Math.min(pages - 1, page + 1); continue; }
    if (ans === 'p') { page = Math.max(0, page - 1); continue; }
    const f = /^\d+$/.test(ans) ? list.slice(page * per, page * per + per)[Number(ans) - 1] : null;
    if (!f) { ui.warn('Type a number from the list, n, p, or back.'); continue; }
    showFinding(ctx, inv, f, a);
    await findingMenu(ctx, inv, f);
  }
}

async function reviewSources(ctx) {
  const ui = ctx.ui;
  const inv = await needActive(ctx);
  if (!inv) return;
  const groups = new Map();
  for (const f of inv.findings) {
    const s = f.source || {};
    const k = `${s.module}|${s.provider || ''}|${s.url ? new URL(s.url, 'http://x').host : (s.file && s.file.name) || s.publisher || ''}`;
    if (!groups.has(k)) groups.set(k, { label: sourceSummary(f), n: 0, first: f.firstObserved, last: f.lastObserved });
    const g = groups.get(k);
    g.n++;
    if (f.firstObserved < g.first) g.first = f.firstObserved;
    if (f.lastObserved > g.last) g.last = f.lastObserved;
  }
  ui.heading(`Sources in "${truncate(inv.title, 40)}" (${groups.size})`);
  [...groups.values()].slice(0, 20).forEach((g) => { ui.kv(`${g.n} finding${g.n === 1 ? '' : 's'}`, g.label); ui.note(`  ${day(g.first)} to ${day(g.last)}`); });
  if (!groups.size) ui.note('No sources yet.');
  ctx.session.setResult('sources-review', { sources: groups.size });
}

async function addManual(ctx) {
  const ui = ctx.ui;
  const inv = await needActive(ctx);
  if (!inv) return;
  const kind = await ctx.ask.select('What are you adding?', [
    { label: 'A claim a source made (most common)', value: 'claim' }, { label: 'Something I observed myself', value: 'observation' }, { label: 'My own inference or conclusion', value: 'inference' },
  ], { def: 0, step: 'correlator.add.kind' });
  const type = (await ctx.ask.text('What type is it? (claim, domain, ip, username, organization, email, ...)', { default: 'claim', step: 'correlator.add.type', validate: (v) => (/^[a-z0-9][a-z0-9 _-]{0,39}$/i.test(v) ? null : 'Use letters, numbers, spaces, - or _ (up to 40).') })).toLowerCase();
  const value = await ctx.ask.text('The value or statement:', { step: 'correlator.add.value', validate: (v) => (v.length > 1000 ? 'Please keep it under 1000 characters.' : null) });
  const subject = await ctx.ask.text('Who or what is it about? (optional)', { allowEmpty: true, step: 'correlator.add.subject' });
  const attribute = subject ? await ctx.ask.text('Which property? (optional, e.g. "founding date")', { allowEmpty: true, step: 'correlator.add.attribute' }) : '';
  const url = await ctx.ask.text('Where did it come from? Web address (optional):', { allowEmpty: true, step: 'correlator.add.url', validate: (v) => (!v || /^https?:\/\/\S+$/i.test(v) ? null : 'Start with http:// or https://, or leave it empty.') });
  const desc = url ? '' : await ctx.ask.text('No address, so describe the source (book, interview, document...). Enter to skip:', { allowEmpty: true, step: 'correlator.add.desc' });
  if (!url && !desc) ui.warn('No source recorded. This finding will be rated "Unknown" until you add one.');
  const f = ctx.store.addFinding(inv.id, {
    type: type.replace(/\s+/g, '_'), value, statementType: kind, subject: subject || null, attribute: attribute || null,
    source: { module: 'manual', url: url || null, description: desc || (url ? null : 'entered by hand'), retrievedAt: new Date(ctx.services.now()).toISOString() },
  }, { module: 'manual' });
  ctx.store.logMethod(inv.id, { module: 'manual', description: `Added a ${kind} by hand (${f.type}).` });
  ui.ok(`Added ${f.id}.`);
}

async function importFlow(ctx) {
  const ui = ctx.ui;
  const inv = await needActive(ctx);
  if (!inv) return;
  ui.para('Import a JSON file of evidence records. Imported records are treated as claims unless they say otherwise, because Orkardch did not observe them itself. See sample-evidence.json for the shape.');
  const file = await pickFile(ctx, 'JSON file to import:');
  const size = fs.statSync(file).size;
  if (size > 5 * 1024 * 1024) { ui.warn('That file is larger than 5 MB, which is too big to import safely.'); return; }
  let obj;
  try { obj = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { ctx.reportError(Object.assign(new Error(`That file is not valid JSON (${e.message}).`), { code: 'EJSON', hint: 'Open it in a text editor and check for missing commas or quotes.' })); return; }
  const res = ctx.store.importJson(inv.id, obj, { filename: file });
  ui.ok(`Imported ${res.added.length} record(s).`);
  if (res.errors.length) { ui.warn(`Skipped ${res.errors.length} record(s):`); res.errors.slice(0, 5).forEach((e) => ui.note(`- record ${e.index + 1}: ${e.message}`)); }
  ctx.session.setResult('import', { added: res.added.length, skipped: res.errors.length });
}

async function analysisFlow(ctx) {
  const ui = ctx.ui;
  let inv = await needActive(ctx);
  if (!inv) return;
  inv = reload(ctx, inv);
  const a = analyze(inv, { now: ctx.services.now });
  const byId = new Map(inv.findings.map((f) => [f.id, f]));
  ui.heading(`Analysis: ${truncate(inv.title, 50)}`);
  ui.kv('Findings', String(inv.findings.length));
  const names = { confirmed_direct: 'Confirmed by direct observation', multi_independent: 'Multiple independent sources', plausible: 'Plausible but unverified', conflicting: 'Conflicting evidence', unknown: 'Unknown' };
  for (const [k, n] of Object.entries(a.counts)) ui.kv(names[k], String(n));
  ui.note('Categories, not percentages: a number would suggest precision that does not exist.');
  ui.heading(`Contradictions (${a.contradictions.length})`);
  if (!a.contradictions.length) ui.note('None found. That only means no two findings share a subject and property with different values.');
  for (const c of a.contradictions) {
    ui.print(ui.c('bold', `${c.subject} / ${c.attribute}  [${c.kind}]`));
    c.sides.forEach((s) => ui.kv(`  "${truncate(s.value, 40)}"`, s.findings.map((x) => x.source).join(' | ')));
    ui.note(c.note);
  }
  const ex = a.relationships.filter((e) => e.match === 'exact').length;
  const st = a.relationships.filter((e) => e.match === 'structural').length;
  const fz = a.relationships.filter((e) => e.match === 'fuzzy').length;
  ui.heading(`Connections (${a.relationships.length})`);
  ui.para(`${ex} exact, ${st} structural (built from known fields), ${fz} fuzzy (similar only).`);
  a.relationships.slice(0, 8).forEach((e) => {
    const f1 = byId.get(e.from); const f2 = byId.get(e.to);
    ui.para(`${e.match === 'fuzzy' ? '~ ' : ''}${truncate(f1.value, 24)} --${e.relation}--> ${truncate(f2.value, 24)} [${e.match}]`, '  ');
    if (e.caution) ui.note(`    ${e.caution}`);
  });
  if (a.relationships.length > 8) ui.note(`...and ${a.relationships.length - 8} more. Use "Show the relationship graph".`);
  ui.heading('Suggested next steps');
  a.nextSteps.forEach((s, i) => ui.para(`${i + 1}. ${s}`, '  '));
  ctx.session.setResult('analysis', { counts: a.counts, contradictions: a.contradictions.length, exact: ex, structural: st, fuzzy: fz, findings: inv.findings.length });
}

async function graphFlow(ctx) {
  const ui = ctx.ui;
  const inv = await needActive(ctx);
  if (!inv) return;
  const a = analyze(inv, { now: ctx.services.now });
  ui.heading('Relationship graph');
  const lines = renderTextGraph(inv, a, { width: ui.width, unicode: ui.useUnicode });
  if (!a.relationships.length) ui.note('No connections were found yet. Save more findings (for example DNS records and the domain they belong to).');
  lines.forEach((l) => ui.print(l));
  ui.note('For an interactive graph, export an HTML report from [6] Investigation Reports.');
  ctx.session.setResult('graph', { edges: a.relationships.length, nodes: inv.findings.length });
}

async function notesFlow(ctx) {
  const ui = ctx.ui;
  const inv = await needActive(ctx);
  if (!inv) return;
  await ctx.ask.menu({
    title: `Notes for "${truncate(inv.title, 40)}"`, step: 'correlator.notes',
    intro: 'Notes are yours. Editing a note never changes the evidence.',
    items: [
      { key: '1', label: 'Show notes', run: async () => { const cur = reload(ctx, inv); if (!cur.notes.length) ui.note('No notes yet.'); cur.notes.forEach((n, i) => ui.kv(`${i + 1}. ${day(n.at)}${n.editedAt ? ' (edited)' : ''}`, n.text)); } },
      { key: '2', label: 'Add a note', run: async () => { const t = await ctx.ask.text('Your note:', { step: 'correlator.notes.add' }); ctx.store.addNote(inv.id, t); ui.ok('Added.'); } },
      {
        key: '3', label: 'Edit a note', run: async () => {
          const cur = reload(ctx, inv);
          if (!cur.notes.length) { ui.note('No notes yet.'); return; }
          cur.notes.slice(-9).forEach((n, i) => ui.menuItem(String(i + 1), truncate(n.text, 50)));
          const shown = cur.notes.slice(-9);
          const key = await ctx.ask.choice(shown.map((n, i) => ({ key: String(i + 1) })), { step: 'correlator.notes.pick' });
          const t = await ctx.ask.text('New text:', { step: 'correlator.notes.edit' });
          ctx.store.updateNote(inv.id, shown[Number(key) - 1].id, t);
          ui.ok('Updated.');
        },
      },
    ],
  });
}

async function exportFlow(ctx) {
  const ui = ctx.ui;
  const inv = await needActive(ctx);
  if (!inv) return;
  ui.para('A full backup keeps everything, including details marked sensitive (such as GPS or author names). Keep it private. For something you can share, use [6] Investigation Reports instead.');
  if (!(await ctx.ask.confirm('Create a full backup file?', { def: true, step: 'correlator.export.confirm' }))) return;
  const kind = await ctx.ask.select('Which kind?', [
    { label: 'Compressed archive (.json.gz) with a checksum', value: 'gz' }, { label: 'Readable JSON bundle (.json)', value: 'json' },
  ], { def: 0, step: 'correlator.export.kind' });
  const dir = path.join(ctx.config.outputDir(), 'investigations');
  if (kind === 'gz') {
    const r = ctx.store.archive(inv.id, dir);
    ui.ok(`Archive written (${formatBytes(r.bytes)}):`);
    ui.print(`  ${r.file}`);
    ui.kv('SHA-256', r.sha256);
  } else {
    const bundle = ctx.store.exportBundle(inv.id);
    const file = path.join(dir, `${slugify(inv.title)}-${fileStamp(ctx.services.now)}.orkardch.json`);
    writeFileAtomic(file, `${JSON.stringify(bundle, null, 2)}\n`, { mode: 0o600, dirMode: 0o700 });
    ui.ok('Bundle written:');
    ui.print(`  ${file}`);
    ui.kv('Integrity SHA-256', bundle.integrity.value);
  }
  ui.note('Nothing was sent anywhere. The file stays on this phone.');
}

async function openFlow(ctx) {
  const ui = ctx.ui;
  const list = ctx.store.list();
  if (!list.length) { ui.note('You have no investigations yet. Choose "Start a new investigation".'); return; }
  const shown = list.slice(0, 9);
  shown.forEach((x, i) => ui.menuItem(String(i + 1), `${truncate(x.title, 40)} (${x.findings} findings)`));
  const key = await ctx.ask.choice(shown.map((x, i) => ({ key: String(i + 1) })), { step: 'correlator.open.pick' });
  const chosen = shown[Number(key) - 1];
  ctx.setActiveInvestigation(chosen.id);
  ui.ok(`Opened "${chosen.title}".`);
}

async function deleteFlow(ctx) {
  const ui = ctx.ui;
  const list = ctx.store.list();
  if (!list.length) { ui.note('There is nothing to delete.'); return; }
  const shown = list.slice(0, 9);
  shown.forEach((x, i) => ui.menuItem(String(i + 1), `${truncate(x.title, 40)} (${x.findings} findings)`));
  const key = await ctx.ask.choice(shown.map((x, i) => ({ key: String(i + 1) })), { step: 'correlator.delete.pick' });
  const target = shown[Number(key) - 1];
  ui.warn(`This permanently deletes "${target.title}" and its ${target.findings} findings from this phone. Exported files are not affected. There is no undo.`);
  const word = await ctx.ask.text('Type DELETE (in capitals) to confirm, or back to cancel:', { step: 'correlator.delete.confirm' });
  if (word !== 'DELETE') { ui.note('Cancelled. Nothing was deleted.'); return; }
  ctx.store.delete(target.id, { confirm: word });
  if (ctx.state.get('activeInvestigationId') === target.id) ctx.setActiveInvestigation(null);
  ui.ok('Deleted.');
}

async function run(ctx) {
  const ui = ctx.ui;
  ui.heading('Evidence Correlator');
  ui.para('Keep findings from every module in one place, with where each came from. I find connections, rate confidence in plain categories, and show where sources disagree. Your evidence is never edited.');
  const act = ctx.activeInvestigation();
  ui.kv('Open investigation', act ? `${act.title} (${act.findings.length} findings)` : 'none');
  await ctx.ask.menu({
    step: 'correlator.menu',
    items: [
      { key: '1', label: 'Start a new investigation', aliases: ['new'], run: () => createInvestigation(ctx) },
      { key: '2', label: 'Open another investigation', aliases: ['open', 'switch'], run: () => openFlow(ctx) },
      { key: '3', label: 'Review findings', aliases: ['review', 'findings'], run: () => reviewFindings(ctx) },
      { key: '4', label: 'Review sources', aliases: ['sources'], run: () => reviewSources(ctx) },
      { key: '5', label: 'Add evidence by hand', aliases: ['add'], run: () => addManual(ctx) },
      { key: '6', label: 'Import evidence from a JSON file', aliases: ['import'], run: () => importFlow(ctx) },
      { key: '7', label: 'Find connections, confidence and contradictions', aliases: ['analyze', 'analyse', 'correlate'], run: () => analysisFlow(ctx) },
      { key: '8', label: 'Show the relationship graph', aliases: ['graph'], run: () => graphFlow(ctx) },
      { key: '9', label: 'Notes', aliases: ['notes'], run: () => notesFlow(ctx) },
      { key: 'e', label: 'Back up or archive this investigation', aliases: ['export', 'archive', 'backup'], run: () => exportFlow(ctx) },
      { key: 'd', label: 'Delete an investigation', aliases: ['delete'], run: () => deleteFlow(ctx) },
    ],
  });
}

module.exports = { id: 'correlator', title: 'Evidence Correlator', run };
