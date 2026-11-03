'use strict';
const fs = require('fs');
const path = require('path');
const { NavSignal } = require('./core-errors');
const { fsError } = require('./file-forensics-inspect');
const { formatBytes, truncate } = require('./utils-format');

function expandPath(input, ctx) {
  let p = String(input).trim().replace(/^["']|["']$/g, '');
  const home = ctx.paths.home;
  if (p === '~') p = home;
  else if (p.startsWith('~/')) p = path.join(home, p.slice(2));
  else if (p.startsWith('$HOME')) p = path.join(home, p.slice(5));
  return path.resolve(p);
}

const PAGE = 10;

/** A tiny phone-friendly file browser: pick by number instead of typing long paths. */
async function browse(ctx, startDir) {
  const ui = ctx.ui;
  let dir = startDir;
  let page = 0;
  for (;;) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true }).filter((e) => !e.name.startsWith('.'));
    } catch (e) {
      ctx.reportError(fsError(e, dir));
      return null;
    }
    entries.sort((a, b) => (b.isDirectory() - a.isDirectory()) || a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
    const pages = Math.max(1, Math.ceil(entries.length / PAGE));
    page = Math.min(page, pages - 1);
    const slice = entries.slice(page * PAGE, page * PAGE + PAGE);
    ui.heading(truncate(dir, Math.max(20, ui.width - 2)));
    if (!entries.length) ui.note('(this folder is empty, or only has hidden items)');
    slice.forEach((e, i) => {
      let label = e.isDirectory() ? `${e.name}/` : e.name;
      if (e.isFile()) { try { label += `  (${formatBytes(fs.statSync(path.join(dir, e.name)).size)})`; } catch { /* unreadable size */ } }
      ui.menuItem(String(i + 1), truncate(label, ui.width - 8));
    });
    ui.note(`Page ${page + 1}/${pages}.  Number = open,  u = up,  n/p = next/previous page,  or type a path.`);
    let answer;
    try {
      answer = (await ctx.ask.text('Pick:', { step: 'forensics.browse' })).trim();
    } catch (e) {
      if (e instanceof NavSignal && e.kind === 'back') return null;
      throw e;
    }
    const low = answer.toLowerCase();
    if (low === 'u') { dir = path.dirname(dir); page = 0; continue; }
    if (low === 'n') { page = Math.min(pages - 1, page + 1); continue; }
    if (low === 'p') { page = Math.max(0, page - 1); continue; }
    if (/^\d+$/.test(answer)) {
      const e = slice[Number(answer) - 1];
      if (!e) { ui.warn(`There is no item ${answer} on this page.`); continue; }
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { dir = full; page = 0; continue; }
      return full;
    }
    const p = expandPath(answer, ctx);
    try {
      const st = fs.statSync(p);
      if (st.isDirectory()) { dir = p; page = 0; continue; }
      return p;
    } catch (e) { ctx.reportError(fsError(e, answer)); }
  }
}

/** Ask for a file. A folder path opens the browser. Returns an absolute path to a file. */
async function pickFile(ctx, promptText = 'Which file? Type its path, or a folder to browse:') {
  const ui = ctx.ui;
  ui.note(ctx.termux
    ? 'Tip: phone storage is under ~/storage/shared (run termux-setup-storage once to allow it). Type a folder to browse it.'
    : 'Tip: type a folder path to browse it, or a file path to use it directly.');
  for (;;) {
    const input = await ctx.ask.text(promptText, { step: 'forensics.path' });
    const p = expandPath(input, ctx);
    let st;
    try { st = fs.statSync(p); } catch (e) { ctx.reportError(fsError(e, input)); continue; }
    if (st.isDirectory()) {
      const picked = await browse(ctx, p);
      if (picked) return picked;
      continue;
    }
    if (!st.isFile()) { ctx.ui.warn('That is not a regular file. Pick a document, photo or other normal file.'); continue; }
    return p;
  }
}

module.exports = { pickFile, browse, expandPath };
