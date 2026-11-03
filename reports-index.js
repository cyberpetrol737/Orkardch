'use strict';
const path = require('path');
const { analyze } = require('./evidence-correlator-analysis');
const { pickInvestigation } = require('./evidence-correlator-pick');
const { buildReportModel, sensitiveInventory } = require('./reports-model');
const { RENDERERS } = require('./reports-render');
const { writeFileAtomic } = require('./storage-jsonstore');
const { slugify, fileStamp, formatBytes, sha256Hex } = require('./utils-format');

/** Write one report per chosen format. Returns [{format, file, bytes, sha256}]. */
function writeReports(ctx, inv, formats, sensitive) {
  const a = analyze(inv, { now: ctx.services.now });
  const model = buildReportModel(inv, { analysis: a, sensitive, secrets: ctx.config.secrets(), now: ctx.services.now, version: ctx.version });
  const dir = path.join(ctx.config.outputDir(), 'reports');
  const stem = `${slugify(inv.title)}-${fileStamp(ctx.services.now)}`;
  return formats.map((fmt) => {
    const [render, ext] = RENDERERS[fmt];
    const content = render(model);
    const file = path.join(dir, `${stem}.${ext}`);
    writeFileAtomic(file, content, { mode: 0o600, dirMode: 0o700 });
    return { format: fmt, file, bytes: Buffer.byteLength(content), sha256: sha256Hex(content) };
  });
}

async function reportFlow(ctx, inv) {
  const ui = ctx.ui;
  if (!inv.findings.length) ui.warn('This investigation has no findings yet. The report will be mostly empty.');
  const cfg = ctx.config.get('reportFormat');
  const fmt = await ctx.ask.select('Which report format?', [
    { label: 'Markdown notes (.md)', value: ['md'] }, { label: 'Standalone web page with graph (.html)', value: ['html'] },
    { label: 'Plain text (.txt)', value: ['txt'] }, { label: 'JSON for other programs (.json)', value: ['json'] }, { label: 'All four', value: ['md', 'html', 'txt', 'json'] },
  ], { def: Math.max(0, ['md', 'html', 'txt', 'json'].indexOf(cfg)), step: 'reports.format' });
  const inventory = sensitiveInventory(inv);
  const sensitive = { gps: 'exclude', personal: false, paths: false };
  if (inventory.gps || inventory.personal || inventory.paths) {
    ui.warn(`This investigation contains sensitive details: ${[inventory.gps && `${inventory.gps} GPS position(s)`, inventory.personal && `${inventory.personal} personal-metadata item(s) such as author names`, inventory.paths && `${inventory.paths} local file path(s)`].filter(Boolean).join(', ')}. A report can be shared, so I will ask before including them.`);
    if (inventory.gps) sensitive.gps = await ctx.ask.select('GPS positions in the report:', [
      { label: 'Leave them out (safest)', value: 'exclude' }, { label: 'Rounded to about 1 km', value: 'round' }, { label: 'Exact', value: 'include' },
    ], { def: 0, step: 'reports.gps' });
    if (inventory.personal) sensitive.personal = await ctx.ask.confirm('Include author, owner and serial-number details?', { def: false, step: 'reports.personal' });
    if (inventory.paths) sensitive.paths = await ctx.ask.confirm('Include full local file paths? (They can reveal your username and folders.)', { def: false, step: 'reports.paths' });
  }
  const out = writeReports(ctx, inv, fmt, sensitive);
  ui.ok(`Report${out.length > 1 ? 's' : ''} created:`);
  for (const r of out) { ui.print(`  ${r.file}`); ui.note(`  ${formatBytes(r.bytes)}, SHA-256 ${r.sha256.slice(0, 16)}...`); }
  ui.note('Reports work offline. Secrets (API keys) are never included. Nothing was uploaded.');
  if (ctx.termux) ui.note('Open one with:  termux-open <file>  (needs the Termux:API app)');
  ctx.session.setResult('report', { formats: fmt, files: out.length, withheld: { gps: sensitive.gps !== 'include' ? inventory.gps : 0, personal: sensitive.personal ? 0 : inventory.personal, paths: sensitive.paths ? 0 : inventory.paths }, findings: inv.findings.length });
}

async function run(ctx) {
  const ui = ctx.ui;
  ui.heading('Investigation Reports');
  ui.para('Turn an investigation into a report you can read offline: summary, methods, findings, sources, contradictions, limits and next steps.');
  const inv = await pickInvestigation(ctx);
  if (inv) await reportFlow(ctx, inv);
}

module.exports = { id: 'reports', title: 'Investigation Reports', run, reportFlow, writeReports };
