'use strict';
const fs = require('fs');
const path = require('path');
const registry = require('./cli-registry');
const launcher = require('./cli-launcher');

async function onlineChecks(ctx, check) {
  ctx.ui.heading('Live lookups (three tiny requests)');
  const d = await ctx.dns.resolve('example.com', 'A');
  check(d.status === 'ok', `DNS lookup of example.com via ${d.resolver}: ${d.status === 'ok' ? `${d.records.length} address(es)` : (d.error && d.error.message) || d.status}`, true);
  if (d.note) ctx.ui.note(d.note);
  const w = await ctx.net.get('https://en.wikipedia.org/w/api.php?action=query&meta=siteinfo&format=json', { useCache: false, purpose: 'doctor check' });
  check(w.ok, `HTTPS request to Wikipedia: ${w.ok ? `HTTP ${w.status} in ${w.elapsedMs} ms` : (w.error && w.error.message)}`, true);
  const r = await ctx.net.getJson('https://rdap.org/domain/example.com', { useCache: false, headers: { accept: 'application/rdap+json' }, purpose: 'doctor check' });
  check(r.ok && r.json && r.json.ldhName, `RDAP lookup (rdap.org) for example.com: ${r.ok && r.json ? `answered by ${new URL(r.finalUrl).host}` : (r.error && r.error.message)}`, true);
}

/** Installation self-check. Uses no network unless --online is given. Exit code 0 = no failures. */
async function run(ctx, flags) {
  const ui = ctx.ui;
  let failures = 0;
  let warnings = 0;
  const check = (ok, msg, isNet) => { if (ok) ui.ok(msg); else { if (isNet) failures++; else failures++; ui.error(msg); } return ok; };
  const warn = (msg) => { warnings++; ui.warn(msg); };
  ui.print(`Orkardch ${ctx.version} - self check`);
  const major = Number(process.versions.node.split('.')[0]);
  check(major >= 18, major >= 18 ? `Node.js ${process.versions.node}` : `Node.js ${process.versions.node} is too old (need 18 or newer). In Termux: pkg upgrade nodejs`);
  check(typeof fetch === 'function', 'fetch is available');
  try { require('crypto').createHash('md5').update('x').digest('hex'); ui.ok('SHA-256, SHA-1 and MD5 are available'); } catch { warn('MD5 is not available in this Node.js build (the legacy hash will be skipped)'); }
  for (const [label, dir] of [['Settings folder', ctx.paths.configDir], ['Data folder', ctx.paths.dataDir]]) {
    try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); fs.accessSync(dir, fs.constants.W_OK); ui.ok(`${label} is writable: ${dir}`); } catch (e) { check(false, `${label} is not writable (${dir}): ${e.code || e.message}`); }
  }
  const out = ctx.config.outputDir();
  ui.note(`Exports and reports will go to: ${out}`);
  ctx.config.warnings.forEach(warn);
  for (const m of registry.MODULES) {
    const st = registry.status(ctx, m);
    if (!st.present) { check(false, `${m.title}: files missing`); continue; }
    try { registry.load(m); st.enabled ? ui.ok(`${m.title}: loads`) : warn(`${m.title}: loads but is turned off in Settings`); } catch (e) { check(false, `${m.title} failed to load: ${e.message}`); }
  }
  try { require('./mother-index'); ui.ok('Mother (help and lessons): loads'); } catch (e) { check(false, `Mother failed to load: ${e.message}`); }
  await new Promise((resolve) => {
    ctx.services.childProcess.execFile('git', ['--version'], { timeout: 4000 }, (err, so) => { if (err) warn('git was not found. TunnelR\'s Git details will be limited. In Termux: pkg install git'); else ui.ok(String(so).trim()); resolve(); });
  });
  const t = require('./tunnelr-adapter').quickStatus(ctx);
  if (!t.configured) ui.note('TunnelR: not connected yet (optional). Open [5] TunnelR in the menu to connect it.');
  else if (!t.exists) warn(`TunnelR: the saved folder is missing: ${t.path}`);
  else ui.ok(`TunnelR folder is set: ${t.path}`);
  const found = launcher.findOnPath(ctx.env);
  if (found) ui.ok(`Launcher found: ${found}`);
  else { warn('The "orkardch" command is not installed yet. Install it with:'); ui.print(`  node ${path.join(ctx.paths.projectDir, 'orkardch.js')} --install-launcher`); }
  ui.note(ctx.config.get('offline') ? 'Offline mode is ON: no network requests will be made.' : 'Offline mode is off.');
  if (flags.online) {
    if (ctx.config.get('offline')) warn('--online was requested but offline mode is on, so the live lookups were skipped.');
    else await onlineChecks(ctx, check);
  } else ui.note('Tip: run with --online to prove the network features work on this phone.');
  ui.blank();
  ui.print(failures ? `Result: ${failures} problem(s), ${warnings} warning(s).` : `Result: all good${warnings ? ` (${warnings} warning(s))` : ''}.`);
  return failures ? 1 : 0;
}

module.exports = { run };
