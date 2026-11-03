'use strict';

/** Shared helpers: choose or create the investigation that findings are saved into. */

async function createInvestigation(ctx) {
  const title = await ctx.ask.text('Give this investigation a short title:', {
    step: 'investigation.create',
    validate: (v) => (v.length > 120 ? 'Please keep it under 120 characters.' : null),
  });
  const inv = ctx.store.create(title);
  ctx.setActiveInvestigation(inv.id);
  ctx.ui.ok(`Created "${inv.title}".`);
  return inv;
}

async function pickInvestigation(ctx) {
  const ui = ctx.ui;
  const active = ctx.activeInvestigation();
  if (active) {
    if (await ctx.ask.confirm(`Use the active investigation "${active.title}"?`, { def: true, step: 'investigation.pick' })) return active;
  }
  const list = ctx.store.list();
  if (!list.length) {
    ui.note('You have no investigations yet, so let us create one.');
    return createInvestigation(ctx);
  }
  const shown = list.slice(0, 9);
  ui.heading('Choose an investigation');
  shown.forEach((x, i) => ui.menuItem(String(i + 1), `${x.title} (${x.findings} findings)`));
  ui.menuItem('N', 'Create a new investigation');
  const key = await ctx.ask.choice([...shown.map((x, i) => ({ key: String(i + 1) })), { key: 'n', aliases: ['new'] }], { step: 'investigation.pick' });
  if (key === 'n') return createInvestigation(ctx);
  const chosen = shown[Number(key) - 1];
  ctx.setActiveInvestigation(chosen.id);
  return ctx.store.load(chosen.id);
}

/**
 * Save evidence records into an investigation the person picks.
 * `method` is written to the investigation's "methods used" log for the report.
 */
async function saveFindings(ctx, findings, { module, method, defaults = {} }) {
  const ui = ctx.ui;
  if (!findings.length) { ui.note('There was nothing to save.'); return null; }
  const inv = await pickInvestigation(ctx);
  if (!inv) return null;
  const res = ctx.store.addFindings(inv.id, findings, { module, ...defaults });
  ctx.store.logMethod(inv.id, { module, description: method });
  ui.ok(`Saved ${res.added.length} finding(s) to "${inv.title}".`);
  for (const e of res.errors.slice(0, 3)) ui.warn(`Skipped one record: ${e.message}`);
  ui.note('Open [4] Evidence Correlator to review them, find connections and spot contradictions.');
  ctx.session.setInput('investigation', inv.title);
  return { inv, result: res };
}

module.exports = { pickInvestigation, createInvestigation, saveFindings };
