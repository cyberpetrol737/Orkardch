'use strict';
const path = require('path');
const fs = require('fs');
const A = require('./tunnelr-adapter');
const { NavSignal } = require('./core-errors');
const { truncate, formatDuration } = require('./utils-format');
const { expandPath } = require('./file-forensics-browse');

async function connect(ctx) {
  const ui = ctx.ui;
  let info = await A.describe(ctx, { refresh: true });
  if (info.connected) return info;
  if (info.missing) ui.warn(`The saved TunnelR folder is no longer there: ${info.path}`);
  if (info.error) ui.warn(info.error);
  ui.note('Looking for your TunnelR folder (read-only; nothing is run)...');
  const cands = A.findCandidates(ctx);
  let chosen = null;
  if (cands.length === 1) {
    ui.para(`I found one folder that may be TunnelR: ${cands[0].path} (${cands[0].why.join('; ')}).`);
    if (await ctx.ask.confirm('Is this your TunnelR folder?', { def: true, step: 'tunnelr.confirm' })) chosen = cands[0].path;
  } else if (cands.length > 1) {
    ui.heading('Possible TunnelR folders');
    cands.slice(0, 9).forEach((c, i) => ui.menuItem(String(i + 1), `${truncate(c.path, ui.width * 2 - 8)}`));
    ctx.ui.note('Match reasons: ' + cands.slice(0, 9).map((c, i) => `${i + 1} = ${c.why[0]}`).join('; '));
    ui.menuItem('M', 'None of these - I will type the path');
    const key = await ctx.ask.choice([...cands.slice(0, 9).map((c, i) => ({ key: String(i + 1) })), { key: 'm', aliases: ['manual', 'other'] }], { step: 'tunnelr.pick' });
    if (key !== 'm') chosen = cands[Number(key) - 1].path;
  } else ui.para('I could not find a folder that looks like TunnelR.');
  while (!chosen) {
    ui.note('Type the folder path (for example ~/TunnelR), or type back to leave. You can also set TUNNELR_PATH.');
    const input = await ctx.ask.text('TunnelR folder:', { step: 'tunnelr.path' });
    const p = expandPath(input, ctx);
    try { if (fs.statSync(p).isDirectory()) chosen = p; else ui.warn('That is a file, not a folder.'); } catch (e) { ctx.reportError(Object.assign(new Error(`I could not open "${input}" (${e.code || e.message}).`), { code: e.code || 'ENOENT', hint: 'Check the spelling. Phone storage needs termux-setup-storage first.' })); }
  }
  A.saveConfig(ctx, { path: chosen });
  ui.ok('Saved. (This pointer lives in Orkardch\'s own settings; TunnelR\'s files and settings are untouched.)');
  info = await A.describe(ctx, { refresh: true });
  return info;
}

function showAbout(ctx, info) {
  const ui = ctx.ui;
  ui.heading('What Orkardch can tell about TunnelR');
  ui.note('Everything below was read from your TunnelR folder. Nothing is guessed.');
  ui.kv('Folder', info.path);
  if (info.manifest) {
    const m = info.manifest;
    ui.kv('Project (package.json)', `${m.name || '(no name)'}${m.version ? ` v${m.version}` : ''}`);
    if (m.description) ui.kv('Its own description', m.description);
    if (m.engines) ui.kv('Needs', JSON.stringify(m.engines));
    const sc = Object.keys(m.scripts);
    if (sc.length) ui.kv('Scripts it defines', sc.join(', '));
    if (m.dependencies.length) ui.kv('Depends on', truncate(m.dependencies.join(', '), 120));
  }
  if (info.python) ui.kv('Python requirements', truncate(info.python.requirements.join(', '), 120) || '(none listed)');
  if (info.otherMarkers && info.otherMarkers.length) ui.kv('Also contains', info.otherMarkers.join(', '));
  if (info.readme) {
    ui.heading(`From its ${info.readme.file}`);
    if (info.readme.title) ui.kv('Title', info.readme.title);
    if (info.readme.excerpt) ui.para(info.readme.excerpt, '  ');
    if (info.readme.headings.length > 1) ui.kv('Sections', truncate(info.readme.headings.slice(1).join(' | '), 160));
  } else ui.note('No README was found, so the explanation above relies on project files only.');
  info.warnings.forEach((w) => ui.warn(w));
  if (info.configFiles.length) ui.kv('Config-like files (names only)', info.configFiles.join(', '));
  ctx.session.setResult('tunnelr', { connected: true, hasReadme: Boolean(info.readme), launchOptions: info.launch.length, risks: info.risks.length, dirty: info.git && info.git.uncommitted });
}

function showLaunchInfo(ctx, info) {
  const ui = ctx.ui;
  ui.heading('How TunnelR can be started');
  if (!info.launch.length) ui.para('Orkardch found no start script, bin entry or common entry file. You can type your own command when you launch.');
  info.launch.forEach((o, i) => { ui.menuItem(String(i + 1), `${o.label}${o.available ? '' : '  (needs ' + o.needs + ': NOT installed)'}`); ui.note(`from ${o.source}`); });
  if (info.deps) {
    if (info.deps.missing.length) ui.warn(`Not installed yet: ${info.deps.missing.join(', ')}. Run npm install inside the TunnelR folder yourself when you are ready (Orkardch will not).`);
    else if (info.deps.declared.length) ui.ok('All declared dependencies appear to be installed.');
  }
  if (info.risks.length) {
    ui.heading('Things worth reviewing before you run it');
    ui.note('These are patterns found in the code. They are prompts to look closer, not verdicts.');
    info.risks.slice(0, 8).forEach((r) => ui.kv(`${r.file}:${r.line}`, `${r.what}  "${r.snippet}"`));
  } else ui.note('No risky-looking patterns were found in the files Orkardch scanned (it scans a limited set).');
}

async function pickCommand(ctx, info) {
  const ui = ctx.ui;
  const saved = A.readConfig(ctx).launch;
  const items = info.launch.map((o, i) => ({ key: String(i + 1) }));
  info.launch.forEach((o, i) => ui.menuItem(String(i + 1), `${o.label}${o.available ? '' : ' (tool missing)'}`));
  if (saved) { ui.menuItem('S', `Saved command: ${saved.join(' ')}`); items.push({ key: 's', aliases: ['saved'] }); }
  ui.menuItem('C', 'Type my own command');
  items.push({ key: 'c', aliases: ['custom', 'own'] });
  const key = await ctx.ask.choice(items, { step: 'tunnelr.command' });
  if (key === 's') return { argv: saved, label: saved.join(' ') };
  if (key === 'c') {
    for (;;) {
      const t = await ctx.ask.text('Command (runs inside the TunnelR folder, no shell):', { step: 'tunnelr.custom' });
      const r = A.splitCommand(t);
      if (!r.ok) { ui.warn(r.error); continue; }
      if (await ctx.ask.confirm('Remember this command for next time? (stored in Orkardch settings only)', { def: false })) A.saveConfig(ctx, { launch: r.argv });
      return { argv: r.argv, label: r.argv.join(' ') };
    }
  }
  const o = info.launch[Number(key) - 1];
  return { argv: o.argv, label: o.label };
}

async function launchFlow(ctx, info, mode) {
  const ui = ctx.ui;
  const cmd = await pickCommand(ctx, info);
  if (!A.commandExists(cmd.argv[0], ctx.env)) { ui.warn(`"${cmd.argv[0]}" is not installed or not on your PATH, so this cannot start. In Termux: pkg install ${cmd.argv[0] === 'python3' || cmd.argv[0] === 'python' ? 'python' : cmd.argv[0] === 'npm' ? 'nodejs' : cmd.argv[0]}`); return; }
  ui.heading('Please confirm');
  ui.kv('Command', cmd.argv.join(' '));
  ui.kv('Folder', info.path);
  ui.kv('Mode', mode === 'foreground' ? 'foreground (you will see its output; Ctrl+C stops it)' : 'background (output is logged by Orkardch; you can check and stop it here)');
  if (info.risks.length) ui.warn(`${info.risks.length} pattern(s) worth reviewing were found in the code (see "How to run it"). Orkardch cannot judge whether they are safe.`);
  ui.note('Orkardch runs exactly this command and does not change TunnelR\'s files or settings. Its errors are shown as they are.');
  if (!(await ctx.ask.confirm('Run it now?', { def: false, step: 'tunnelr.confirm.run' }))) { ui.note('Cancelled. Nothing was started.'); return; }
  ctx.log.info('tunnelr.launch', { mode, argv: cmd.argv, cwd: info.path });
  if (mode === 'foreground') {
    ui.note('--- TunnelR output starts below ---');
    const noop = () => {};
    process.on('SIGINT', noop);
    if (ctx.prompter) ctx.prompter.suspend();
    let r;
    try { r = await A.runForeground(ctx, { argv: cmd.argv, cwd: info.path }); } finally { process.off('SIGINT', noop); if (ctx.prompter) ctx.prompter.resume(); }
    ui.note('--- TunnelR output ends ---');
    const politeStop = r.exitCode == null && (r.signal === 'SIGINT' || r.signal === 'SIGTERM');
    if (r.error) { ui.error(`Could not start it: ${r.error.message}`); ctx.session.setError({ code: r.error.code || 'SPAWN_FAILED', message: r.error.message }); }
    else if (r.ok) ui.ok(`It finished normally after ${formatDuration(r.durationMs)}.`);
    else if (politeStop) ui.note(`It was ended by ${r.signal}${r.signal === 'SIGINT' ? ' (what Ctrl+C sends)' : ''} after ${formatDuration(r.durationMs)}. That is a normal way to stop it.`);
    else if (r.exitCode == null) { ui.warn(`It was ended by signal ${r.signal} after ${formatDuration(r.durationMs)}. Its own messages above may explain why.`); ctx.session.setError({ code: `SIGNAL_${r.signal}`, message: `TunnelR was ended by ${r.signal}.` }); }
    else { ui.warn(`It stopped with exit code ${r.exitCode}${r.signal ? ` (signal ${r.signal})` : ''} after ${formatDuration(r.durationMs)}. Its own messages above explain why.`); ctx.session.setError({ code: `EXIT_${r.exitCode}`, message: `TunnelR exited with code ${r.exitCode}.` }); }
    ctx.session.setResult('tunnelr-run', { mode, ok: Boolean(r.ok), exitCode: r.exitCode == null ? null : r.exitCode, signal: r.signal || null, stoppedByUser: politeStop, spawnError: r.error ? r.error.code : null });
  } else {
    const st = A.status(ctx);
    if (st.running) { ui.warn(`A background TunnelR is already running (process ${st.pid}). Stop it first.`); return; }
    const r = await A.startBackground(ctx, { argv: cmd.argv, cwd: info.path });
    if (r.ok) { ui.ok(`Started in the background (process ${r.pid}).`); ui.kv('Log file', r.logFile); ui.note('Use "Status, logs and stop" to check on it.'); }
    else {
      ui.error(r.error ? `Could not start it: ${r.error.message}` : `It exited right away (code ${r.exitCode}${r.signal ? `, signal ${r.signal}` : ''}). Here is what it printed, unchanged:`);
      if (r.tail) { ui.print(''); r.tail.split('\n').forEach((l) => ui.print(`  | ${l}`)); }
      ctx.session.setError({ code: r.error ? r.error.code : `EXIT_${r.exitCode}`, message: r.error ? r.error.message : 'TunnelR exited immediately.' });
    }
    ctx.session.setResult('tunnelr-run', { mode, ok: r.ok, pid: r.pid || null });
  }
}

async function statusFlow(ctx) {
  const ui = ctx.ui;
  await ctx.ask.menu({
    title: 'Background TunnelR', step: 'tunnelr.status',
    items: [
      {
        key: '1', label: 'Show status and recent output', run: async () => {
          const st = A.status(ctx);
          if (!st.known) { ui.note('Orkardch has not started TunnelR in the background.'); return; }
          if (st.running) { ui.ok(`Running (process ${st.pid}) for ${formatDuration(st.uptimeMs)}.`); ui.kv('Command', st.argv.join(' ')); }
          else ui.warn(`Not running any more (it was process ${st.pid}, started ${st.startedAt}).`);
          const tail = A.tailFile(st.logFile, 25, ctx.config.secrets());
          ui.heading('Last output (unchanged)');
          if (tail.trim()) tail.split('\n').forEach((l) => ui.print(`  | ${l}`)); else ui.note('(no output yet)');
          ctx.session.setResult('tunnelr-status', { running: st.running, known: st.known });
        },
      },
      {
        key: '2', label: 'Stop it', run: async () => {
          const st = A.status(ctx);
          if (!st.running) { ui.note('It is not running.'); A.stop(ctx); return; }
          if (!(await ctx.ask.confirm(`Stop process ${st.pid}?`, { def: true }))) return;
          let r = await A.stop(ctx);
          if (!r.stopped && await ctx.ask.confirm('It did not stop politely. Force it to stop?', { def: false })) r = await A.stop(ctx, { force: true });
          if (r.stopped) ui.ok('Stopped.'); else ui.warn('It is still running.');
        },
      },
    ],
  });
}

function showGit(ctx, info) {
  const ui = ctx.ui;
  ui.heading('Files and Git (read-only)');
  const g = info.git;
  if (!g || !g.isRepo) ui.note('This folder is not a Git repository.');
  else if (!g.available) ui.warn(g.note);
  else {
    ui.kv('Branch', g.branch || '?');
    if (g.lastCommit) ui.kv('Last commit', `${g.lastCommit.hash} ${String(g.lastCommit.date).slice(0, 10)} ${g.lastCommit.subject}`);
    ui.kv('Uncommitted changes', `${g.uncommitted} changed, ${g.untracked} untracked`);
    g.remotes.forEach((r) => ui.kv('Remote', r));
    if (g.uncommitted || g.untracked) ui.note('You have unsaved work in TunnelR. Orkardch does not touch it.');
  }
  ui.kv('Top-level items', truncate(info.files.join('  '), 300));
}

async function run(ctx) {
  const ui = ctx.ui;
  ui.heading('TunnelR');
  ui.para('Orkardch connects to your existing TunnelR project. It reads the real folder to learn what is there, and only runs something when you confirm the exact command.');
  const info = await connect(ctx);
  if (!info.connected) { ui.warn('TunnelR is not connected yet, so there is nothing to show or launch.'); ctx.session.setResult('tunnelr', { connected: false }); return; }
  const st = A.status(ctx);
  ui.kv('Connected to', info.path);
  if (info.git && info.git.isRepo && info.git.branch) ui.kv('Git', `${info.git.branch}, ${info.git.uncommitted} uncommitted`);
  if (st.running) ui.kv('Background run', `running (process ${st.pid})`);
  await ctx.ask.menu({
    step: 'tunnelr.menu',
    items: [
      { key: '1', label: 'What is TunnelR? (read from its files)', aliases: ['about', 'what'], run: () => showAbout(ctx, info) },
      { key: '2', label: 'How to run it (and what to check first)', aliases: ['howto', 'run'], run: () => showLaunchInfo(ctx, info) },
      { key: '3', label: 'Launch it now (in front)', aliases: ['launch', 'start'], run: () => launchFlow(ctx, info, 'foreground') },
      { key: '4', label: 'Launch in the background and monitor', aliases: ['background'], run: () => launchFlow(ctx, info, 'background') },
      { key: '5', label: 'Status, logs and stop', aliases: ['status', 'logs', 'stop'], run: () => statusFlow(ctx) },
      { key: '6', label: 'Git and files check', aliases: ['git', 'files'], run: () => showGit(ctx, info) },
      { key: '7', label: 'Choose a different TunnelR folder', aliases: ['change', 'folder'], run: async () => { A.saveConfig(ctx, { path: null }); ctx._tunnelrInfo = null; ui.note('Pointer cleared. Open TunnelR again from the main menu to choose the folder.'); return 'back'; } },
    ],
  });
}

module.exports = { id: 'tunnelr', title: 'TunnelR', run, connect, launchFlow, showAbout, showLaunchInfo };
