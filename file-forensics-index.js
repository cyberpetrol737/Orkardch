'use strict';
const path = require('path');
const { inspectFile } = require('./file-forensics-inspect');
const { describeInspection, sectionsToText } = require('./file-forensics-describe');
const { sanitizeInspection, sensitiveInventory } = require('./file-forensics-export');
const { compareInspections } = require('./file-forensics-compare');
const { inspectionFindings } = require('./file-forensics-findings');
const { verifyBaseline } = require('./file-forensics-baseline');
const { pickFile } = require('./file-forensics-browse');
const { BaselineStore } = require('./storage-baselines');
const { saveFindings } = require('./evidence-correlator-pick');
const { writeFileAtomic } = require('./storage-jsonstore');
const { redactDeep } = require('./security-redact');
const { slugify, fileStamp, formatBytes } = require('./utils-format');

function printSections(ui, sections) {
  for (const s of sections) {
    ui.heading(s.title);
    for (const [k, v] of s.rows) ui.kv(k, v);
    for (const n of s.notes || []) if (n) ui.note(n);
  }
}

async function analyse(ctx, file, algorithms) {
  const ui = ctx.ui;
  let last = 0;
  const onProgress = (done, total) => {
    const t = Date.now();
    if (t - last > 200 || done === total) { last = t; ui.progress(done, total, 'Hashing'); }
  };
  const job = (signal) => inspectFile(file, { algorithms, onProgress, signal, now: ctx.services.now });
  try {
    const res = ctx.prompter && ctx.prompter.cancellable ? await ctx.prompter.cancellable(job) : await job();
    ui.endProgress();
    return res;
  } catch (e) {
    ui.endProgress();
    if (e.code === 'ABORTED') { ui.note('Cancelled.'); return null; }
    throw e;
  }
}

function summarize(res, gps) {
  const inv = sensitiveInventory(res);
  const m = res.metadata;
  return {
    name: res.name, type: res.type.description, extensionMatches: res.type.extensionMatches, size: res.size,
    hashes: Object.keys(res.hashes.digests), metadataSupported: m.supported, metadataKind: m.kind,
    hasExif: Boolean(m.exif), hasGps: inv.gps, gpsShown: gps === 'show', hasPersonal: inv.personal,
    hasDocFields: Boolean(m.fields && Object.keys(m.fields).length), noMetadataFound: Boolean(m.supported && m.kind === 'image' && !m.exif && !m.xmp),
  };
}

async function exportFlow(ctx, kind, payload) {
  const ui = ctx.ui;
  const fmt = await ctx.ask.select('Which format?', [
    { label: 'Readable text (.txt)', value: 'txt' }, { label: 'JSON, for other programs (.json)', value: 'json' },
  ], { def: ctx.config.get('reportFormat') === 'json' ? 1 : 0, step: 'forensics.export.format' });
  let gps = 'hide';
  let includePath = false;
  let includePersonal = false;
  const inv = kind === 'inspection' ? sensitiveInventory(payload) : { gps: false, personal: false };
  if (inv.gps) {
    gps = await ctx.ask.select('This file has GPS coordinates. What should the export file contain?', [
      { label: 'Leave GPS out (safest)', value: 'hide' }, { label: 'Rounded to about 1 km', value: 'rounded' }, { label: 'Exact coordinates', value: 'show' },
    ], { def: 0, step: 'forensics.export.gps' });
  }
  if (kind === 'inspection') {
    includePath = await ctx.ask.confirm('Include the full folder path? (It can reveal your username and folder names.)', { def: false, step: 'forensics.export.path' });
    if (inv.personal) includePersonal = await ctx.ask.confirm('Include author, owner and serial-number details found inside the file?', { def: false, step: 'forensics.export.personal' });
  } else {
    includePersonal = await ctx.ask.confirm('Include GPS, author and owner details in the comparison?', { def: false, step: 'forensics.export.personal' });
  }
  let content;
  let stem;
  if (kind === 'inspection') {
    const clean = redactDeep(sanitizeInspection(payload, { gps, includePath, includePersonal }), ctx.config.secrets());
    content = fmt === 'json' ? `${JSON.stringify(clean, null, 2)}\n` : `${sectionsToText(describeInspection(clean, { gps, includePath: true, includePersonal: true }))}\n`;
    stem = slugify(payload.name);
  } else {
    const SENS = /gps|author|owner|serial|lastModifiedBy|company|artist|creator/i;
    const keep = (k) => includePersonal || !SENS.test(typeof k === 'string' ? k : k.key);
    const cmp = { ...payload.cmp, metadata: {
      same: payload.cmp.metadata.same.filter(keep), different: payload.cmp.metadata.different.filter(keep),
      onlyA: payload.cmp.metadata.onlyA.filter(keep), onlyB: payload.cmp.metadata.onlyB.filter(keep),
    } };
    const clean = redactDeep({ files: payload.files, comparison: cmp, notice: 'Sensitive fields were removed unless the exporter chose to include them.' }, ctx.config.secrets());
    if (fmt === 'json') content = `${JSON.stringify(clean, null, 2)}\n`;
    else {
      const lines = ['Orkardch file comparison', '========================', '', ...payload.files.map((f, i) => `File ${'AB'[i]}: ${f.name} | ${f.type} | ${formatBytes(f.size)} | SHA-256 ${f.sha256}`), '', cmp.explanation, ''];
      for (const d of cmp.metadata.different) lines.push(`Different - ${d.key}: A = ${d.a} | B = ${d.b}`);
      for (const d of cmp.metadata.onlyA) lines.push(`Only in A - ${d.key}: ${d.value}`);
      for (const d of cmp.metadata.onlyB) lines.push(`Only in B - ${d.key}: ${d.value}`);
      content = `${lines.join('\n')}\n`;
    }
    stem = 'comparison';
  }
  const file = path.join(ctx.config.outputDir(), 'forensics', `${stem}-${fileStamp(ctx.services.now)}.${fmt}`);
  writeFileAtomic(file, content, { mode: 0o600, dirMode: 0o700 });
  ui.ok(`Saved ${formatBytes(Buffer.byteLength(content))} to:`);
  ui.print(`  ${file}`);
  ui.note('This file stays on your phone. Share it only if you mean to.');
  ctx.session.setInput('last export', path.basename(file));
}

async function inspectFlow(ctx) {
  const ui = ctx.ui;
  const file = await pickFile(ctx);
  ctx.session.setInput('file name', path.basename(file));
  const legacy = await ctx.ask.confirm('Also compute the older SHA-1 and MD5 fingerprints? (Only useful to match old checksums.)', { def: false, step: 'forensics.legacy' });
  ctx.session.setStep('forensics.hashing');
  const res = await analyse(ctx, file, legacy ? ['sha256', 'sha1', 'md5'] : ['sha256']);
  if (!res) return;
  let gps = 'hide';
  const inv = sensitiveInventory(res);
  if (inv.gps) {
    ui.warn('This file contains GPS coordinates. Showing them reveals roughly where it was taken. Keep them private unless you mean to share them.');
    if (await ctx.ask.confirm('Show the exact coordinates on screen?', { def: false, step: 'forensics.gps' })) gps = 'show';
  }
  ctx.session.setStep('forensics.results');
  printSections(ui, describeInspection(res, { gps }));
  ctx.session.setResult('file-inspection', summarize(res, gps));
  await ctx.ask.menu({
    title: 'What next?', step: 'forensics.after',
    items: [
      {
        key: '1', label: 'Save findings to an investigation', run: async () => {
          const withGps = inv.gps && gps === 'show' && await ctx.ask.confirm('Save the GPS position too? (It stays on this phone and is left out of reports unless you allow it.)', { def: false });
          await saveFindings(ctx, inspectionFindings(res, { includeGps: Boolean(withGps) }), { module: 'file-forensics', method: `Inspected local file "${res.name}" (SHA-256 ${res.hashes.digests.sha256.slice(0, 12)}...).` });
        },
      },
      { key: '2', label: 'Export this report (text or JSON)', run: () => exportFlow(ctx, 'inspection', res) },
      { key: '3', label: 'Save this fingerprint to re-check later', run: () => saveBaseline(ctx, res) },
      { key: '4', label: 'Explain these results', aliases: ['explain'], run: () => require('./mother-index').explainResults(ctx) },
    ],
  });
}

async function compareFlow(ctx) {
  const ui = ctx.ui;
  ui.para('Pick two files. I will tell you whether their contents are identical and how their inner details differ.');
  const a = await pickFile(ctx, 'First file:');
  const b = await pickFile(ctx, 'Second file:');
  const ra = await analyse(ctx, a, ['sha256']);
  if (!ra) return;
  const rb = await analyse(ctx, b, ['sha256']);
  if (!rb) return;
  const cmp = compareInspections(ra, rb);
  ui.heading('Comparison');
  if (cmp.sameContent) ui.ok('Identical contents'); else ui.warn('Different contents');
  ui.para(cmp.explanation);
  ui.kv('A', `${ra.name} (${formatBytes(ra.size)})`);
  ui.kv('B', `${rb.name} (${formatBytes(rb.size)})`);
  ui.kv('SHA-256 A', cmp.sha256.a);
  ui.kv('SHA-256 B', cmp.sha256.b);
  ui.kv('Types', cmp.type.same ? `both ${ra.type.description}` : `A: ${ra.type.description} | B: ${rb.type.description}`);
  const d = cmp.metadata;
  ui.heading('Inner details');
  ui.para(`${d.same.length} fields match, ${d.different.length} differ, ${d.onlyA.length} only in A, ${d.onlyB.length} only in B.`);
  const sens = /gps|author|owner|serial|lastModifiedBy|company|artist|creator/i;
  for (const x of d.different.slice(0, 8)) ui.kv(x.key, sens.test(x.key) ? 'differs (hidden: personal field)' : `A: ${x.a} | B: ${x.b}`);
  if (d.different.length > 8) ui.note(`...and ${d.different.length - 8} more. Export to see them all.`);
  if (cmp.sameContent) ui.note('Identical contents always mean identical inner details. Only the names and the phone\'s own timestamps can differ.');
  ctx.session.setResult('file-comparison', { sameContent: cmp.sameContent, sizeSame: cmp.size.same, typeSame: cmp.type.same, different: d.different.length, same: d.same.length });
  const files = [ra, rb].map((r) => ({ name: r.name, type: r.type.description, size: r.size, sha256: r.hashes.digests.sha256 }));
  await ctx.ask.menu({
    title: 'What next?', step: 'forensics.compare.after',
    items: [
      { key: '1', label: 'Export this comparison', run: () => exportFlow(ctx, 'comparison', { cmp, files }) },
      { key: '2', label: 'Explain these results', aliases: ['explain'], run: () => require('./mother-index').explainResults(ctx) },
    ],
  });
}

async function saveBaseline(ctx, res) {
  const store = new BaselineStore(ctx.paths.baselinesFile, ctx.services.now);
  const e = store.add({ path: res.path, name: res.name, size: res.size, sha256: res.hashes.digests.sha256, modified: res.filesystem.modified });
  ctx.ui.ok(`Saved a fingerprint for "${e.name}".`);
  ctx.ui.note('Later, choose "Check a file against a saved fingerprint" to see if its contents changed.');
}

async function baselineFlow(ctx) {
  const ui = ctx.ui;
  const store = new BaselineStore(ctx.paths.baselinesFile, ctx.services.now);
  const listAll = () => store.list().slice(-9);
  await ctx.ask.menu({
    title: 'Saved fingerprints', step: 'forensics.baseline',
    intro: 'A saved fingerprint lets you check later whether a file\'s contents have changed.',
    items: [
      {
        key: '1', label: 'Save a fingerprint of a file now', run: async () => {
          const file = await pickFile(ctx);
          const res = await analyse(ctx, file, ['sha256']);
          if (res) await saveBaseline(ctx, res);
        },
      },
      {
        key: '2', label: 'Check a file against its saved fingerprint', run: async () => {
          const all = listAll();
          if (!all.length) { ui.note('Nothing saved yet. Choose option 1 first.'); return; }
          all.forEach((b, i) => ui.menuItem(String(i + 1), `${b.name}  (saved ${b.savedAt.slice(0, 10)})`));
          const key = await ctx.ask.choice(all.map((b, i) => ({ key: String(i + 1) })), { step: 'forensics.baseline.pick' });
          const entry = all[Number(key) - 1];
          let last = 0;
          const r = await verifyBaseline(entry, { now: ctx.services.now, onProgress: (d, t) => { const n = Date.now(); if (n - last > 200) { last = n; ui.progress(d, t, 'Checking'); } } });
          ui.endProgress();
          ui.heading(`Check: ${entry.name}`);
          if (r.status === 'match') ui.ok('Unchanged'); else if (r.status === 'changed') ui.error('Changed'); else ui.warn(r.status === 'missing' ? 'File not found' : 'Could not read the file');
          ui.para(r.detail);
          if (r.actual) { ui.kv('Saved SHA-256', r.expected); ui.kv('Now SHA-256', r.actual); }
          if (r.sizeChanged) ui.kv('Size', `${formatBytes(r.sizeBefore)} -> ${formatBytes(r.sizeNow)}`);
          ctx.session.setResult('baseline-check', { status: r.status, sizeChanged: Boolean(r.sizeChanged), name: entry.name });
        },
      },
      {
        key: '3', label: 'Show saved fingerprints', run: async () => {
          const all = store.list();
          if (!all.length) { ui.note('Nothing saved yet.'); return; }
          all.slice(-15).forEach((b) => { ui.kv(b.name, `${b.sha256.slice(0, 16)}... saved ${b.savedAt.slice(0, 10)}`); });
        },
      },
      {
        key: '4', label: 'Remove a saved fingerprint', run: async () => {
          const all = listAll();
          if (!all.length) { ui.note('Nothing to remove.'); return; }
          all.forEach((b, i) => ui.menuItem(String(i + 1), b.name));
          const key = await ctx.ask.choice(all.map((b, i) => ({ key: String(i + 1) })), { step: 'forensics.baseline.remove' });
          if (await ctx.ask.confirm('Remove this saved fingerprint? (Your file is not touched.)', { def: false })) { store.remove(all[Number(key) - 1].id); ui.ok('Removed.'); }
        },
      },
    ],
  });
}

async function run(ctx) {
  const ui = ctx.ui;
  ui.heading('Image & File Forensics');
  ui.para('Look inside a file on this phone: what it really is, its fingerprint (hash), and hidden details such as camera, dates or author. Everything stays on your device and your original file is never changed.');
  ui.note('Type ? at any question and Mother will explain.');
  await ctx.ask.menu({
    step: 'forensics.menu',
    items: [
      { key: '1', label: 'Inspect a file', aliases: ['inspect', 'file'], run: () => inspectFlow(ctx) },
      { key: '2', label: 'Compare two files', aliases: ['compare'], run: () => compareFlow(ctx) },
      { key: '3', label: 'Check a file against a saved fingerprint', aliases: ['verify', 'baseline', 'fingerprint'], run: () => baselineFlow(ctx) },
    ],
  });
}

module.exports = { id: 'forensics', title: 'Image & File Forensics', run, exportFlow, summarize };
