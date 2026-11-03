'use strict';
const os = require('os');
const fs = require('fs');
const path = require('path');
const { createContext } = require('./core-context');
const { Prompter, Asker } = require('./cli-prompt');
const registry = require('./cli-registry');
const launcher = require('./cli-launcher');
const { NavSignal } = require('./core-errors');
const { version } = require('./package.json');

const USAGE = `Orkardch ${version} - open-source intelligence toolkit for Termux

Usage: orkardch [options]
  (no options)          Start the interactive menu
  --doctor              Check this installation (uses no network)
  --doctor --online     Also run three tiny live lookups to prove the network features work
  --install-launcher    Install the "orkardch" command ($PREFIX/bin on Termux)
  --uninstall-launcher  Remove the command (your project and data stay untouched)
  --offline             Start with all network access switched off
  --no-color, --ascii   Plain-text display options
  --version, --help`;

function parseArgs(argv) {
  const f = { unknown: [] };
  for (const a of argv) {
    if (a === '--version' || a === '-v') f.version = true;
    else if (a === '--help' || a === '-h') f.help = true;
    else if (a === '--doctor') f.doctor = true;
    else if (a === '--online') f.online = true;
    else if (a === '--install-launcher') f.installLauncher = true;
    else if (a === '--uninstall-launcher') f.uninstallLauncher = true;
    else if (a === '--force') f.force = true;
    else if (a === '--offline') f.offline = true;
    else if (a === '--no-color') f.noColor = true;
    else if (a === '--ascii') f.ascii = true;
    else f.unknown.push(a);
  }
  return f;
}

function networkStatus(ctx) {
  if (ctx.config.get('offline')) return ctx.ui.c('yellow', 'Offline mode (requests disabled)');
  try {
    const up = Object.values(os.networkInterfaces()).flat().some((i) => i && !i.internal && i.address);
    return up ? 'Online (link up, not tested)' : ctx.ui.c('yellow', 'Offline (no network link)');
  } catch {
    return 'Unknown';
  }
}

function statusLines(ctx) {
  const mods = registry.MODULES.map((m) => registry.status(ctx, m));
  const ready = mods.filter((m) => m.ready).length;
  const inv = ctx.activeInvestigation();
  return [
    ['System', ctx.termux ? 'Termux / Android' : `${os.type()} (not Termux)`],
    ['Network', networkStatus(ctx)],
    ['Modules', ready === mods.length ? `Available (${ready}/${mods.length})` : ctx.ui.c('yellow', `${ready}/${mods.length} available`)],
    ['Investigation', inv ? `${inv.title} (${inv.findings.length} findings)` : 'none yet'],
  ];
}

async function openModule(ctx, m) {
  const st = registry.status(ctx, m);
  if (!st.ready) {
    ctx.ui.warn(`${m.title} is not available: ${st.detail}.`);
    if (!st.enabled) ctx.ui.note('Turn it on in [7] Settings, then try again.');
    return;
  }
  ctx.session.enter(m.id, m.title);
  try {
    await registry.load(m).run(ctx);
  } catch (e) {
    if (!(e instanceof NavSignal) || e.kind === 'exit') throw e;
  } finally {
    ctx.session.enter('main', 'Main menu');
  }
}

async function mainLoop(ctx) {
  const ui = ctx.ui;
  ui.banner({ version, statusLines: statusLines(ctx) });
  if (!launcher.findOnPath(ctx.env)) {
    ui.note('Tip: to start Orkardch by just typing "orkardch", run this once:');
    ui.print(`  node ${path.join(ctx.paths.projectDir, 'orkardch.js')} --install-launcher`);
  }
  ctx.session.enter('main', 'Main menu');
  const items = registry.MODULES.map((m) => ({
    key: m.key, label: m.title, aliases: m.aliases,
    run: async () => { try { await openModule(ctx, m); } catch (e) { if (e instanceof NavSignal && e.kind !== 'exit') return; throw e; } },
  }));
  items.push({
    key: 'm', get label() { return `Mother ${ctx.ui.useUnicode ? '\u2014' : '-'} Teach Me Everything`; }, aliases: ['8', 'mother', 'teach', 'learn'],
    run: async () => {
      ctx.session.enter('mother', 'Mother');
      try { await require('./mother-index').run(ctx); } catch (e) { if (!(e instanceof NavSignal) || e.kind === 'exit') throw e; } finally { ctx.session.enter('main', 'Main menu'); }
    },
  });
  try {
    await ctx.ask.menu({ title: 'What would you like to do?', items, zero: 'exit', backLabel: 'Exit', step: 'main-menu' });
  } catch (e) {
    if (!(e instanceof NavSignal)) throw e;
  }
  ui.blank();
  ui.print('Goodbye. Nothing left this device unless you chose to export it.');
}

async function runInteractive(ctx) {
  const prompter = new Prompter({ input: process.stdin, output: process.stdout });
  ctx.prompter = prompter;
  ctx.ask = new Asker(ctx, prompter);
  const onSigint = () => prompter.interrupt();
  process.on('SIGINT', onSigint);
  try {
    await mainLoop(ctx);
    return 0;
  } finally {
    process.off('SIGINT', onSigint);
    prompter.close();
  }
}

async function run(argv, env = process.env) {
  process.stdout.on('error', (e) => { if (e && e.code === 'EPIPE') process.exit(0); });
  const flags = parseArgs(argv);
  const out = (s) => process.stdout.write(`${s}\n`);
  if (flags.unknown.length) { process.stderr.write(`Unknown option: ${flags.unknown[0]}\n\n${USAGE}\n`); return 2; }
  if (flags.help) { out(USAGE); return 0; }
  if (flags.version) { out(`Orkardch ${version}`); return 0; }
  const projectDir = __dirname;
  if (flags.installLauncher) {
    const r = launcher.install({ env, projectDir, force: flags.force });
    if (!r.ok) { out(r.message); return 1; }
    out(`Launcher installed: ${r.file}`);
    out('Open a new session or type this to start:  orkardch');
    if (!r.onPath) out(`Note: ${r.dir} is not on your PATH yet. Add it with:\n  export PATH="${r.dir}:$PATH"\n(Orkardch does not edit your shell startup files.)`);
    return 0;
  }
  if (flags.uninstallLauncher) {
    const r = launcher.uninstall({ env });
    out(r.message);
    return r.ok ? 0 : 1;
  }
  const ctx = createContext({ env, flags });
  if (flags.doctor) return require('./cli-doctor').run(ctx, flags);
  return runInteractive(ctx);
}

module.exports = { run, parseArgs, USAGE };
