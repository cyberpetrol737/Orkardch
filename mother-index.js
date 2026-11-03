'use strict';
const { LESSONS, BASICS, GLOSSARY } = require('./mother-lessons');
const { explainError } = require('./mother-errors');
const { explainResult } = require('./mother-explain');
const { NavSignal } = require('./core-errors');
const registry = require('./cli-registry');
const { truncate } = require('./utils-format');

const WELCOME = 'Hi! I\'m Mother. I\'ll help you understand Orkardch. You don\'t need to memorize commands. Pick something you want to learn, and I\'ll explain it one small step at a time.';

// What to say about the exact question the person is looking at. Matched by longest prefix of the step id.
const STEP_HELP = {
  'main-menu': 'This is the main menu. Type the number of what you want, like 1 to look inside a file. Type M to learn with me, or 0 to leave.',
  'investigation.pick': 'Findings are saved into an investigation, like a case folder. Choose one, or create a new one with a short title.',
  'investigation.create': 'Give your case folder a short name you will recognise later, like "Suspicious email" or "Photo check".',
  'forensics.menu': 'Pick what to do with a file: look inside one, compare two, or check one against a fingerprint you saved earlier.',
  'forensics.path': 'I need the address (path) of a file. Type it, or type a folder such as ~/storage/shared/Download and I will show a numbered list to pick from.',
  'forensics.browse': 'Type the number of a file or folder to open it. u goes up one folder, n and p flip pages. You can also type a path.',
  'forensics.legacy': 'SHA-256 is the fingerprint you normally want. SHA-1 and MD5 are old and weak. Say yes only if you must match an old checksum.',
  'forensics.hashing': 'I am reading the file in small pieces to make its fingerprint, so even a huge file is fine. Ctrl+C cancels.',
  'forensics.gps': 'This file has GPS coordinates inside it. They show roughly where it was taken. Say yes only if you want them on screen right now.',
  'forensics.results': 'These are the results for your file. The phone dates come from your phone; the details inside the file were written by a camera or program and can be edited.',
  'forensics.after': 'Choose what to do with this result: save it into an investigation, export a file, save its fingerprint to re-check later, or ask me to explain it.',
  'forensics.export': 'Exports are files on your phone. I ask before including anything sensitive: exact GPS, your folder path, or author names. "No" is the safe answer.',
  'forensics.baseline': 'A saved fingerprint lets you check later whether a file changed. Save one now, then check it whenever you like.',
  'forensics.compare': 'I compare the contents of two files. Same fingerprint means identical bytes.',
  'web.menu': 'Choose to research a topic, look at old versions of a web page, or re-run a saved search.',
  'web.query': 'Type what you want to learn about. Words search public sources. A web address or website name opens that page.',
  'web.results': 'These are your results. Open one to see what the page claims, save the useful ones, compare two, or look for old versions.',
  'web.open': 'Pick the number of the result to look at.',
  'web.fetch': 'I will open up to 5 pages, a few at a time, and record what each says. Pages that cannot be opened keep their link and the reason.',
  'web.claim': 'A claim is something a source says. Type it as the source says it, not what you believe, so it can be checked and compared later.',
  'web.compare': 'Pick exactly two results. I compare shared words, years and dates. It is a hint about overlap, not a fact check.',
  'web.export': 'Exports the chosen results with their links, dates and cautions into a file on your phone.',
  'web.archive': 'The Internet Archive keeps old copies of web pages. I list the earliest and latest copies it has.',
  'web.save': 'Saving keeps each source with its link and retrieval time in an investigation.',
  'web.rerun': 'Choose a saved search. I run it again and tell you what is new.',
  'network.menu': 'Choose what you have: an IP address, a domain, DNS records, certificates, an AS number, or a connectivity test of something you own.',
  'network.ip': 'Type an IP address like 192.0.2.1. I check it is valid before asking any registry.',
  'network.ip.geo': 'This asks RIPE NCC for an approximate place. It is often wrong for mobile networks and VPNs, and it never shows a person\'s address.',
  'network.domain': 'Type a domain like example.com (no http://).',
  'network.dns': 'Pick the kind of DNS record. A is the address, MX is mail, NS is the name servers, TXT is notes. Type all to see the common ones.',
  'network.certs': 'Type a domain you own or are allowed to assess. I search the public certificate logs for names that have had certificates.',
  'network.asn': 'An AS number looks like AS64500. It names a network run by one organisation.',
  'network.conn': 'Connectivity checks connect directly to the host. Only test things you own or have permission to test.',
  'network.authorize': 'Connecting to a machine you do not own can break rules or laws. Answer yes only if it is yours or you have permission.',
  'network.port': 'Which port to try. 443 is normal secure web traffic and 80 is plain web traffic.',
  'network.after': 'Save these findings into an investigation, or ask me to explain what they mean.',
  'correlator.menu': 'This is your case folder. Start or open an investigation, then review, add, import, analyse, graph, or back it up.',
  'correlator.review': 'Findings are listed with how they were observed and how much to trust them. Type a number to see where one came from.',
  'correlator.add': 'Adding by hand: say whether it is a source\'s claim, something you saw, or your own inference, then give the value and where it came from.',
  'correlator.independence': 'Independent means the source found this out on its own. Copied means it repeated another source. Repeats count as one source.',
  'correlator.finding': 'This is one finding. You can add a note, say how sure you are, say whether its source is independent, or ask me to explain it.',
  'correlator.note': 'A note is yours. It never changes the original evidence.',
  'correlator.open': 'Pick which investigation to open. It becomes the one new findings are saved into.',
  'correlator.link': 'Linking says how two findings relate: one supports the other, or contradicts it. A contradiction link makes both show as "conflicting evidence".',
  'correlator.verify': 'Mark how sure you are. "Verified by me" needs a short note saying how you checked.',
  'correlator.export': 'A full backup keeps everything, including sensitive details, so keep it private.',
  'correlator.delete': 'Deleting is permanent. Type DELETE in capitals to confirm, or back to cancel.',
  'correlator.notes': 'Notes are yours. They never change the evidence.',
  'reports.format': 'Markdown is easy to read anywhere. The web page has a tappable graph. Text and JSON are plain.',
  'reports.gps': 'Reports can be shared, so GPS positions are left out unless you choose otherwise. Rounded means about 1 km.',
  'reports.personal': 'Names and serial numbers found inside files can identify people. Include them only if you are sure.',
  'reports.paths': 'A full path can reveal your username and folders.',
  'tunnelr.pick': 'I found several folders that might be TunnelR. Pick the right one, or choose M to type the path yourself.',
  'tunnelr.custom': 'Type the command to run inside the TunnelR folder, like: node server.js. No pipes or && here: I run the program directly, without a shell.',
  'tunnelr.menu': 'Learn what TunnelR is from its own files, see how it can be started, launch it, or check on a background run.',
  'tunnelr.confirm': 'I found a folder that looks like TunnelR. Say yes only if it is really your project.',
  'tunnelr.path': 'Type the folder where your TunnelR project lives, like ~/TunnelR.',
  'tunnelr.command': 'Pick how to start it. I run exactly the command you pick, inside TunnelR\'s folder, without a shell.',
  'tunnelr.confirm.run': 'This starts the program shown above. Say yes only if you know what it does. I do not change TunnelR\'s files.',
  'tunnelr.status': 'Check whether the background run is alive, see its latest output, or stop it.',
  'mother.menu': 'Pick a topic and I will teach it in small steps. B explains the basics (menus, back, ?). G is a glossary of words.',
  'mother.lesson': 'Choose how you want to learn about this tool: what it does, how to use it, an example, what a result means, or fixing an error.',
  'mother.glossary': 'Type n or p to flip pages, or type a word like "hash" to look it up.',
  'settings.modules': 'Switch tools on or off. A tool that is off cannot be opened, but nothing is deleted.',
  'settings.network': 'DNS and network preferences. DNS mode "auto" is the right choice for most people.',
  'menu': 'Pick one of the numbered choices. Type 0 to go back.',
  'settings.menu': 'Pick a setting to change. Press Enter to keep a value.',
  'settings.offline': 'Offline mode stops every network request from Orkardch. Local tools keep working.',
  'settings.apikey': 'An optional key for Brave Search. It is stored privately on this phone and never shown in logs or reports. Typing is hidden.',
};

const RESULT_MODULE = { 'file-inspection': 'forensics', 'file-comparison': 'forensics', 'baseline-check': 'forensics' };
void RESULT_MODULE;

function stepHelp(step) {
  if (!step) return null;
  const keys = Object.keys(STEP_HELP).filter((k) => step === k || step.startsWith(`${k}.`) || step.startsWith(k));
  keys.sort((a, b) => b.length - a.length);
  return keys.length ? STEP_HELP[keys[0]] : null;
}

const M = (ctx, text) => ctx.ui.para(`${ctx.ui.c('magenta', 'Mother:')} ${text}`);
const section = (ctx, title, lines) => { ctx.ui.heading(title); lines.forEach((l) => ctx.ui.para(l)); };

function printError(ctx, err) {
  const e = explainError(err);
  if (!e) return;
  ctx.ui.heading(`About that error: ${e.title}`);
  ctx.ui.para(`What it means: ${e.meaning}`);
  ctx.ui.print(ctx.ui.c('bold', 'Things to try:'));
  e.fix.forEach((f) => ctx.ui.para(`- ${f}`, '  '));
}

async function tunnelrLesson(ctx) {
  const adapter = require('./tunnelr-adapter');
  const info = await adapter.describe(ctx);
  const base = {
    id: 'tunnelr', title: 'TunnelR', module: 'tunnelr',
    input: ['Mostly the folder where your TunnelR project lives. Orkardch looks for it and asks you to confirm, or you can type the path.'],
    save: ['Orkardch keeps only a pointer to the folder (and a command, if you ask) in its own settings. TunnelR\'s files and settings stay inside TunnelR. Background runs are logged to Orkardch\'s log folder.'],
    back: 'Type 0 to go back, or "menu" for the main menu.',
    cannot: [
      'Orkardch can only tell you what TunnelR\'s files say. It cannot check that the code does what its README claims.',
      'Patterns flagged in the code are prompts to look closer, not verdicts.',
      'Orkardch\'s Offline mode does not control what TunnelR itself sends over the network.',
    ],
  };
  if (!info.connected) {
    return {
      ...base,
      what: ['TunnelR is your own project. Orkardch has not found it on this phone yet, so I cannot tell you what it does. I will not guess.', 'Open [5] TunnelR from the main menu. I will look for the folder (read-only), or you can type its path.'],
      source: ['Nothing yet. Once connected, everything I say about TunnelR comes from reading its README, project files and Git state.'],
      howTo: ['1. Choose [5] TunnelR from the main menu.', '2. Confirm the folder I find, or type its path.', '3. Come back here and I will teach you from its real files.'],
      normal: ['Not connected yet, so there is nothing to show.'],
      errors: [{ when: '"I could not find a folder"', meaning: 'TunnelR is not in a place I know to look.', fix: 'Type its path, or set the TUNNELR_PATH variable.' }],
      example: () => ({ intro: 'There is no example yet because I do not want to invent one for your project.', lines: ['Connect TunnelR first, and this lesson will use its real details.'] }),
    };
  }
  const m = info.manifest;
  const what = ['Here is what I can read from your TunnelR folder (nothing here is guessed):'];
  if (info.readme && info.readme.excerpt) what.push(`Its ${info.readme.file} says: "${truncate(info.readme.excerpt.replace(/\s+/g, ' '), 400)}"`);
  if (m && m.description) what.push(`Its package.json describes it as: "${m.description}"`);
  if (m && Object.keys(m.scripts).length) what.push(`It defines these scripts: ${Object.keys(m.scripts).join(', ')}.`);
  if (info.python) what.push(`It lists ${info.python.requirements.length} Python requirement(s).`);
  if (!info.readme && !m && !info.python) what.push('I found no README or project file, so I cannot say what it does. Please check this is the right folder.');
  const howTo = [];
  if (info.launch.length) { howTo.push('I found these ways to start it:'); info.launch.forEach((o, i) => howTo.push(`  ${i + 1}. ${o.label} (from ${o.source})`)); } else howTo.push('I found no standard start command. You can type your own in Orkardch.');
  howTo.push('In Orkardch, choose [5] TunnelR and then "Launch it now". I show the exact command and ask you to confirm before anything runs.');
  if (info.deps && info.deps.missing.length) howTo.push(`Before it will work, these dependencies are not installed: ${info.deps.missing.join(', ')}. Install them yourself (for example npm install in its folder).`);
  return {
    ...base,
    what,
    source: [`I only read your folder ${info.path}: its README, project files and top-level file names. Git details come from read-only git commands. I never open .env or key files.`],
    howTo,
    normal: ['In "Launch now" you see TunnelR\'s own output, and when it ends I tell you its exit code. In the background mode I log its output and you can check on it. A non-zero exit code means TunnelR reported a problem.'],
    errors: [
      { when: '"exited right away"', meaning: 'TunnelR started and stopped immediately. Its own last words are shown unchanged.', fix: 'Read them. Missing dependencies and missing settings are the usual causes.' },
      { when: '"is not installed or not on your PATH"', meaning: 'The program needed to start it (node, npm, python...) is missing.', fix: 'Install it with pkg install, for example pkg install nodejs.' },
      ...(info.deps && info.deps.missing.length ? [{ when: 'Missing dependencies', meaning: `Not installed: ${info.deps.missing.slice(0, 5).join(', ')}.`, fix: 'Install them yourself inside the TunnelR folder.' }] : []),
    ],
    example: () => ({ intro: 'This is not sample data. It is a real look at your TunnelR folder:', lines: [`Folder: ${info.path}`, `Top-level items: ${truncate(info.files.join('  '), 200)}`, info.git && info.git.isRepo && info.git.branch ? `Git branch: ${info.git.branch}, ${info.git.uncommitted} uncommitted change(s)` : 'Not a Git repository.'] }),
  };
}

async function lessonMenu(ctx, lesson) {
  const ui = ctx.ui;
  const lastResultHere = () => (ctx.session.lastResult && ctx.session.lastResult.module === lesson.module ? ctx.session.lastResult : null);
  await ctx.ask.menu({
    title: `${lesson.title}: what would you like to learn?`, step: 'mother.lesson',
    items: [
      { key: '1', label: 'Show me what this tool does.', run: async () => { section(ctx, 'What it does', lesson.what); section(ctx, 'Where the information comes from', lesson.source); } },
      {
        key: '2', label: 'Teach me how to use it.', run: async () => {
          section(ctx, 'What you give it', lesson.input);
          section(ctx, 'How to run it, step by step', lesson.howTo);
          section(ctx, 'Saving or exporting', lesson.save);
          section(ctx, 'Getting back', [lesson.back]);
        },
      },
      { key: '3', label: 'Show me an example.', run: async () => { const e = lesson.example(); ui.heading('An example'); ui.para(e.intro); e.lines.forEach((l) => ui.para(l, '  ')); } },
      {
        key: '4', label: 'Explain these results.', run: async () => {
          section(ctx, 'What a normal result looks like', lesson.normal);
          const r = lastResultHere();
          const live = r && explainResult(r);
          if (live) { ui.heading('Your latest result, in plain words'); live.forEach((l) => ui.para(`- ${l}`, '  ')); } else ui.note('You have no recent result from this tool in this session. Run it, then come back and I will explain your own result.');
          section(ctx, 'What results from this tool cannot prove', lesson.cannot);
        },
      },
      {
        key: '5', label: 'Help me fix an error.', run: async () => {
          ui.heading('Common errors');
          lesson.errors.forEach((e) => { ui.para(`${e.when}`); ui.para(`Means: ${e.meaning}`, '    '); ui.para(`Try: ${e.fix}`, '    '); });
          if (ctx.session.lastError) { ui.note(`Your most recent error was in: ${ctx.session.lastError.module}.`); printError(ctx, ctx.session.lastError); } else ui.note('You have not had an error this session.');
        },
      },
      { key: '6', label: 'Back to the main menu.', aliases: ['main'], run: async () => { throw new NavSignal('menu'); } },
    ],
  });
}

async function glossary(ctx) {
  const ui = ctx.ui;
  let page = 0;
  const per = 6;
  const pages = Math.ceil(GLOSSARY.length / per);
  for (;;) {
    ui.heading(`Words I can explain (page ${page + 1}/${pages})`);
    GLOSSARY.slice(page * per, page * per + per).forEach(([t, d]) => { ui.print(ui.c('cyan', t)); ui.para(d, '  '); });
    const ans = (await ctx.ask.text('n = next, p = previous, or type a word to look up:', { step: 'mother.glossary' })).trim().toLowerCase();
    if (ans === 'n') { page = (page + 1) % pages; continue; }
    if (ans === 'p') { page = (page + pages - 1) % pages; continue; }
    const hits = GLOSSARY.filter(([t]) => t.toLowerCase().includes(ans));
    if (!hits.length) { ui.note(`I do not have "${ans}" yet. Try another word.`); continue; }
    hits.slice(0, 3).forEach(([t, d]) => { ui.print(ui.c('cyan', t)); ui.para(d, '  '); });
  }
}

async function run(ctx) {
  const ui = ctx.ui;
  ui.blank();
  ui.print(ui.c('magenta', 'Mother'));
  ui.para(WELCOME);
  const lessonFor = async (id) => (id === 'tunnelr' ? tunnelrLesson(ctx) : LESSONS.find((l) => l.id === id));
  const order = ['forensics', 'web', 'network', 'correlator', 'tunnelr', 'reports', 'settings'];
  const titles = { forensics: 'Image and file forensics', web: 'Public web intelligence', network: 'IP and network intelligence', correlator: 'Evidence correlation', tunnelr: 'TunnelR', reports: 'Investigation reports', settings: 'Settings and privacy' };
  const items = order.map((id, i) => ({ key: String(i + 1), label: titles[id], aliases: [id], run: async () => lessonMenu(ctx, await lessonFor(id)) }));
  items.push({ key: 'b', label: 'How Orkardch works (menus, back, ?)', aliases: ['basics', 'start'], run: async () => { section(ctx, 'The basics', BASICS); } });
  items.push({ key: 'g', label: 'Words I can explain (glossary)', aliases: ['glossary', 'words'], run: () => glossary(ctx) });
  await ctx.ask.menu({ title: 'What would you like to learn?', items, step: 'mother.menu' });
}

/** Help for wherever the person is right now: the step, the inputs so far, the last result and error. */
async function contextHelp(ctx) {
  const ui = ctx.ui;
  const s = ctx.session;
  ui.blank();
  M(ctx, 'Let me help with where you are.');
  if (s.moduleId === 'main') {
    ui.para(stepHelp(s.step) || STEP_HELP['main-menu']);
    ui.note('Type M to open my full lessons. Type 0 to leave.');
    return;
  }
  ui.kv('You are in', s.moduleTitle);
  const help = stepHelp(s.step);
  if (help) ui.para(help);
  else {
    const lesson = LESSONS.find((l) => l.module === s.moduleId);
    if (lesson) ui.para(lesson.what[0]);
  }
  const inputs = Object.entries(s.inputs).slice(-5);
  if (inputs.length) { ui.print(ui.c('bold', 'What you have told me so far:')); inputs.forEach(([k, v]) => ui.kv(k, truncate(String(v), 60), { indent: 4 })); }
  if (s.options.length) ui.kv('Your options here', s.options.map((o, i) => `${i + 1}) ${truncate(o, 30)}`).join('; '));
  if (s.lastResult && s.lastResult.module === s.moduleId) {
    const lines = explainResult(s.lastResult);
    if (lines) { ui.print(ui.c('bold', 'About your latest result:')); lines.forEach((l) => ui.para(`- ${l}`, '  ')); }
  }
  if (s.lastError && s.lastError.module === s.moduleId) printError(ctx, s.lastError);
  ui.note('Type back to go back, or menu for the main menu. For a full lesson, choose M from the main menu.');
}

/** Explain the most recent result, whatever module it came from. */
async function explainResults(ctx) {
  const ui = ctx.ui;
  ui.blank();
  M(ctx, 'Here is what your latest result means.');
  const lines = explainResult(ctx.session.lastResult);
  if (!lines) { ui.para('I do not have a recent result to explain yet. Run something first, then ask me again.'); return; }
  lines.forEach((l) => ui.para(`- ${l}`, '  '));
  if (ctx.session.lastError && ctx.session.lastError.module === ctx.session.lastResult.module) printError(ctx, ctx.session.lastError);
}

module.exports = { run, contextHelp, explainResults, stepHelp, STEP_HELP, tunnelrLesson, WELCOME };
