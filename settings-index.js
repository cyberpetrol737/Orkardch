'use strict';
const fs = require('fs');
const { maskSecret } = require('./security-redact');
const { formatBytes } = require('./utils-format');
const registry = require('./cli-registry');

function persist(ctx) {
  try { ctx.config.save(); return true; } catch (e) {
    ctx.reportError(Object.assign(new Error(`Settings could not be saved (${e.code || e.message}).`), { code: e.code || 'SAVE_FAILED', hint: 'The change is active for this session only.' }));
    return false;
  }
}

function checkWritable(dir) {
  try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); fs.accessSync(dir, fs.constants.W_OK); return null; } catch (e) {
    return `Cannot write there (${e.code || e.message}). In Termux, run termux-setup-storage first if the folder is in phone storage.`;
  }
}

const PRIVACY = [
  ['Image & File Forensics', 'Nothing leaves this phone. Files are read here and never changed.'],
  ['Public Web Intelligence', 'Your search words go to the sources that are on: Wikipedia, GDELT, DuckDuckGo, and Brave if you added a key. Opening a result contacts that website. Old-version lookups send the page address to archive.org.'],
  ['IP & Network Intelligence', 'The IP, domain or AS you type goes to: rdap.org (which forwards to the registry), Team Cymru (via DNS), your DNS resolver (or Cloudflare/Google DNS-over-HTTPS if your resolver is unreachable), crt.sh for certificate logs, and RIPEstat only if you say yes to a location lookup. Connectivity checks connect to the target directly, only after you confirm.'],
  ['Evidence Correlator & Reports', 'Local only. Exports are files on this phone.'],
  ['TunnelR', 'Orkardch only reads the folder and runs a command you confirm. What TunnelR sends is up to TunnelR.'],
  ['Mother (help)', 'Built-in lessons stored on this phone. No question or result is sent to any AI service.'],
  ['Offline mode', 'Blocks every request listed above. Local tools keep working.'],
  ['Stored on this phone', 'Settings (including any API key, readable only by you), investigations, a short-lived cache of answers, and a log with secrets removed.'],
];

async function run(ctx) {
  const ui = ctx.ui;
  const cfg = ctx.config;
  const onOff = (v) => (v ? 'ON' : 'off');
  const edit = async (key, question, { toDisplay = (v) => v, fromInput = (v) => v, hint, pre } = {}) => {
    if (hint) ui.note(hint);
    const raw = await ctx.ask.text(question, { default: toDisplay(cfg.get(key)), step: `settings.${key}` });
    const value = fromInput(raw);
    if (pre) { const err = pre(value); if (err) { ui.warn(err); return; } }
    const r = cfg.set(key, value);
    if (!r.ok) { ui.warn(r.error); return; }
    if (persist(ctx)) ui.ok('Saved.');
    if (key === 'logLevel') ctx.log.setLevel(value);
  };
  const toggle = (key) => { const r = cfg.set(key, !cfg.get(key)); if (r.ok && persist(ctx)) ui.ok(`Now ${onOff(cfg.get(key))}.`); };

  const modulesMenu = () => ctx.ask.menu({
    title: 'Which tools are on?', step: 'settings.modules',
    items: registry.MODULES.filter((m) => m.cfg).map((m, i) => ({ key: String(i + 1), get label() { return `${m.title}: ${onOff(cfg.get(`modules.${m.cfg}`))}`; }, run: async () => toggle(`modules.${m.cfg}`) })),
  });
  const keysMenu = () => ctx.ask.menu({
    title: 'Optional API keys', step: 'settings.apikey', intro: 'Orkardch works without any key. A key only adds an extra source.',
    items: [
      {
        key: '1', get label() { return `Brave Search key: ${maskSecret(cfg.get('apiKeys.brave'))}`; }, run: async () => {
          ui.note('A free key from the Brave Search API dashboard. It is stored only on this phone, hidden here, and never written to logs or reports. Leave empty to remove it.');
          const v = await ctx.ask.secret('Paste the key (hidden):', { step: 'settings.apikey.input' });
          const r = cfg.set('apiKeys.brave', v);
          if (!r.ok) { ui.warn(r.error); return; }
          if (persist(ctx)) ui.ok(v ? 'Key saved.' : 'Key removed.');
        },
      },
    ],
  });
  const networkMenu = () => ctx.ask.menu({
    title: 'Network preferences', step: 'settings.network',
    items: [
      { key: '1', get label() { return `DNS mode: ${cfg.get('dns.mode')}`; }, run: () => edit('dns.mode', 'auto, system or doh?', { hint: 'auto uses your phone\'s resolver and falls back to DNS-over-HTTPS if it is unreachable (common in Termux).' }) },
      { key: '2', get label() { return `DNS-over-HTTPS provider: ${cfg.get('dns.dohProvider')}`; }, run: () => edit('dns.dohProvider', 'cloudflare or google?') },
      { key: '3', get label() { return `Custom DNS servers: ${(cfg.get('dns.servers') || []).join(', ') || 'none'}`; }, run: () => edit('dns.servers', 'IP addresses separated by commas (empty = none):', { toDisplay: (v) => (v || []).join(', '), fromInput: (v) => (v.trim() === '' || v.trim().toLowerCase() === 'none' ? [] : v) }) },
      { key: '4', get label() { return `Active connectivity checks: ${onOff(cfg.get('activeChecks'))}`; }, run: async () => toggle('activeChecks') },
      { key: '5', get label() { return `Gap between requests to one site: ${cfg.get('minRequestIntervalMs')} ms`; }, run: () => edit('minRequestIntervalMs', 'Milliseconds:') },
      { key: '6', get label() { return `Retries: ${cfg.get('maxRetries')}`; }, run: () => edit('maxRetries', 'Retries after a failure (0 to 3):') },
      ...['wikipedia', 'gdelt', 'duckduckgo', 'brave'].map((p, i) => ({ key: String(7 + i), get label() { return `Search source ${p}: ${onOff(cfg.get(`providers.${p}`))}`; }, run: async () => toggle(`providers.${p}`) })),
    ],
  });

  ui.heading('Settings');
  ui.kv('Settings file', ctx.paths.configFile);
  cfg.warnings.forEach((w) => ui.warn(w));
  await ctx.ask.menu({
    step: 'settings.menu',
    items: [
      {
        key: '1', get label() { return `Output folder: ${cfg.outputDir()}`; }, run: () => edit('outputDir', 'Folder for exports and reports:', { toDisplay: () => cfg.outputDir(), pre: (v) => checkWritable(require('path').resolve(String(v).replace(/^~(?=$|\/)/, ctx.paths.home))), fromInput: (v) => require('path').resolve(String(v).replace(/^~(?=$|\/)/, ctx.paths.home)) }),
      },
      { key: '2', get label() { return `Cache time: ${cfg.get('cacheTtlMinutes')} min (0 = off)`; }, run: () => edit('cacheTtlMinutes', 'Minutes to remember answers:') },
      { key: '3', get label() { return `Request timeout: ${cfg.get('requestTimeoutMs') / 1000} s`; }, run: () => edit('requestTimeoutMs', 'Seconds to wait for a website:', { toDisplay: (v) => v / 1000, fromInput: (v) => Math.round(Number(v) * 1000) }) },
      { key: '4', get label() { return `Parallel requests: ${cfg.get('maxParallelRequests')}`; }, run: () => edit('maxParallelRequests', 'How many at once (1 to 8):', { hint: 'Lower is gentler on a phone and on websites.' }) },
      { key: '5', label: 'Which tools are on', run: modulesMenu },
      { key: '6', label: 'Optional API keys', aliases: ['keys', 'api'], run: keysMenu },
      { key: '7', get label() { return `Colors: ${cfg.get('color')}   Box characters: ${cfg.get('unicode')}`; }, run: async () => { await edit('color', 'Colors: auto, on or off?'); await edit('unicode', 'Box-drawing characters: auto, on or off?', { hint: 'Choose off if the title box looks broken.' }); } },
      { key: '8', get label() { return `Report format: ${cfg.get('reportFormat')}`; }, run: () => edit('reportFormat', 'md, html, txt or json?') },
      { key: '9', get label() { return `Offline mode: ${onOff(cfg.get('offline'))}`; }, run: async () => { toggle('offline'); ui.note(cfg.get('offline') ? 'No network request will be made. Local tools still work.' : 'Network features are available again.'); } },
      { key: 'n', label: 'Network and DNS preferences', aliases: ['network', 'dns', 'search'], run: networkMenu },
      {
        key: 'c', get label() { const s = ctx.cache.stats(); return `Clear cache (${s.entries} items, ${formatBytes(s.bytes)})`; }, aliases: ['cache'], run: async () => {
          const before = ctx.cache.clear();
          ui.ok(`Cleared ${before.entries} cached answer(s), ${formatBytes(before.bytes)}.`);
        },
      },
      { key: 'p', label: 'What leaves this phone (privacy)', aliases: ['privacy'], run: async () => { ui.heading('What leaves this phone'); for (const [k, v] of PRIVACY) { ui.print(ui.c('cyan', k)); ui.para(v, '  '); } } },
      {
        key: 'r', label: 'Reset settings to defaults', aliases: ['reset'], run: async () => {
          if (!(await ctx.ask.confirm('Reset all settings (including any API key)? Investigations are not touched.', { def: false }))) return;
          cfg.reset();
          if (persist(ctx)) ui.ok('Settings reset.');
        },
      },
    ],
  });
}

module.exports = { id: 'settings', title: 'Settings', run, PRIVACY };
