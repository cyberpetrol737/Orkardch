'use strict';
const fs = require('fs');
const path = require('path');
const { writeJsonAtomic, readJsonSafe } = require('./storage-jsonstore');
const { redactString } = require('./security-redact');
const { OrkardchError } = require('./core-errors');
const { sleep, truncate, fileStamp } = require('./utils-format');

/*
 * The TunnelR adapter. It NEVER assumes what TunnelR is or does. It looks at the real folder,
 * reports what it finds, and only runs something after the person confirms the exact command.
 * It never writes inside the TunnelR folder, never reads secret files, never touches Git history.
 * Orkardch's own pointer to TunnelR lives in the Orkardch config folder (tunnelr.json).
 */

const README_NAMES = ['README.md', 'README', 'README.txt', 'readme.md', 'Readme.md', 'README.rst'];
const SECRET_FILE = /(^\.env($|\.)(?!example|sample|template)|\.pem$|\.key$|^id_(rsa|ed25519|ecdsa)|secret|credential|token)/i;
const RISKS = [
  [/\brm\s+-[a-z]*r[a-z]*f?\b/i, 'deletes files (rm -r)'],
  [/\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b/i, 'downloads and runs a script from the internet'],
  [/\bsudo\b|\bsu\s+-c\b|\btsu\b/, 'asks for administrator (root) rights'],
  [/\bchmod\s+(-R\s+)?7[0-7]{2}\b/, 'changes file permissions broadly'],
  [/\b(iptables|ip6tables|nftables|nft)\b|\bip\s+(route|rule|link|addr)\b/, 'changes firewall, routing or network interfaces'],
  [/\/dev\/net\/tun|\bVpnService\b|\btun0\b|\btap0\b/i, 'creates a virtual network (VPN or tunnel) device'],
  [/['"`]0\.0\.0\.0['"`]|INADDR_ANY|host\s*[:=]\s*['"]?0\.0\.0\.0/i, 'may listen on all network interfaces'],
  [/\.listen\s*\(|createServer\s*\(|socketserver|\bsocket\.bind\b|\bbind\s*\(\s*\(/i, 'opens a listening network port'],
  [/\bchild_process\b|\bexecSync?\s*\(|\bspawnSync?\s*\(|\bos\.system\b|\bsubprocess\./, 'starts other programs'],
  [/\beval\s*\(|new\s+Function\s*\(/, 'runs dynamically built code'],
  [/\b(sshpass|socat|ncat)\b|\bnc\s+-l|\bssh\s+-[A-Za-z]*[RLD]\b/, 'uses remote-access or raw network tools'],
  [/termux-(wake-lock|sms-|camera|location|microphone|contact|telephony)/i, 'uses Termux phone-feature commands'],
  [/process\.env\.[A-Z0-9_]*(TOKEN|KEY|SECRET|PASSWORD)|os\.environ\S*(TOKEN|KEY|SECRET|PASSWORD)/i, 'reads secret-looking environment variables'],
];

const readText = (file, max = 16384) => {
  try {
    const fd = fs.openSync(file, 'r');
    try { const b = Buffer.alloc(max); const n = fs.readSync(fd, b, 0, max, 0); return b.subarray(0, n).toString('utf8'); } finally { fs.closeSync(fd); }
  } catch { return null; }
};
const readPkg = (dir) => { const t = readText(path.join(dir, 'package.json'), 65536); if (!t) return null; try { return JSON.parse(t); } catch { return { _invalid: true }; } };

function readConfig(ctx) {
  const r = readJsonSafe(ctx.paths.tunnelrFile);
  return r.ok && r.value && typeof r.value === 'object' ? r.value : {};
}
function saveConfig(ctx, patch) {
  const cur = readConfig(ctx);
  writeJsonAtomic(ctx.paths.tunnelrFile, { ...cur, ...patch }, { mode: 0o600 });
}

/** Cheap check used at startup and by --doctor: no scanning, no processes. */
function quickStatus(ctx) {
  const p = readConfig(ctx).path || ctx.env.TUNNELR_PATH || null;
  if (!p) return { configured: false, path: null, exists: false };
  let exists = false;
  try { exists = fs.statSync(p).isDirectory(); } catch { /* missing */ }
  return { configured: true, path: p, exists };
}

function commandExists(cmd, env = process.env) {
  if (cmd.includes(path.sep)) { try { fs.accessSync(cmd, fs.constants.X_OK); return true; } catch { return false; } }
  for (const d of (env.PATH || '').split(path.delimiter)) {
    if (!d) continue;
    try { fs.accessSync(path.join(d, cmd), fs.constants.X_OK); return true; } catch { /* next */ }
  }
  return false;
}

/** Look for folders that could be TunnelR. Bounded: at most ~500 directory entries are examined. */
function findCandidates(ctx, { cwd = process.cwd() } = {}) {
  const home = ctx.paths.home;
  const found = new Map();
  const add = (p, why) => {
    try {
      const rp = fs.realpathSync(p);
      if (!fs.statSync(rp).isDirectory() || rp === ctx.paths.projectDir) return;
      const arr = found.get(rp) || [];
      if (!arr.includes(why)) arr.push(why);
      found.set(rp, arr);
    } catch { /* not there */ }
  };
  const saved = readConfig(ctx).path;
  if (saved) add(saved, 'saved in Orkardch settings');
  if (ctx.env.TUNNELR_PATH) add(ctx.env.TUNNELR_PATH, 'TUNNELR_PATH environment variable');
  let d = cwd;
  for (let i = 0; i < 4; i++) {
    if (/tunnel/i.test(path.basename(d))) add(d, 'current or parent folder name');
    const pkg = readPkg(d);
    if (pkg && typeof pkg.name === 'string' && /tunnel/i.test(pkg.name)) add(d, `package.json name "${pkg.name}"`);
    const up = path.dirname(d);
    if (up === d) break;
    d = up;
  }
  const roots = [home, ...['projects', 'dev', 'code', 'src', 'repos', 'git', 'Documents', 'storage/shared', 'storage/downloads'].map((x) => path.join(home, x))];
  let budget = 500;
  for (const r of roots) {
    let ents;
    try { ents = fs.readdirSync(r, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      if (budget-- <= 0) break;
      if (!e.isDirectory() || e.name.startsWith('.') || e.name === 'node_modules') continue;
      const full = path.join(r, e.name);
      if (/tunnel/i.test(e.name)) { add(full, 'folder name'); continue; }
      const pkg = readPkg(full);
      if (pkg && typeof pkg.name === 'string' && /tunnelr/i.test(pkg.name)) { add(full, `package.json name "${pkg.name}"`); continue; }
      const gc = readText(path.join(full, '.git', 'config'), 8192);
      if (gc && /tunnelr/i.test(gc)) add(full, 'Git remote mentions tunnelr');
    }
  }
  const rank = (p) => (/^tunnelr$/i.test(path.basename(p)) ? 0 : /tunnelr/i.test(path.basename(p)) ? 1 : 2);
  return [...found].map(([p, why]) => ({ path: p, why })).sort((a, b) => rank(a.path) - rank(b.path));
}

function execGit(ctx, dir, args) {
  return new Promise((resolve) => {
    try {
      ctx.services.childProcess.execFile('git', args, { cwd: dir, timeout: 5000, env: { ...process.env, GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0' }, maxBuffer: 256 * 1024 }, (err, stdout) => {
        if (err) resolve({ ok: false, code: err.code, message: err.message });
        else resolve({ ok: true, out: String(stdout).trim() });
      });
    } catch (e) { resolve({ ok: false, code: e.code, message: e.message }); }
  });
}

/** Read-only Git facts. GIT_OPTIONAL_LOCKS=0 keeps `git status` from touching the repository. */
async function gitInfo(ctx, dir) {
  if (!fs.existsSync(path.join(dir, '.git'))) return { available: true, isRepo: false };
  const v = await execGit(ctx, dir, ['--version']);
  if (!v.ok) return { available: false, isRepo: true, note: 'This folder is a Git repository, but git is not installed or not runnable (pkg install git).' };
  const [branch, last, status, remotes] = await Promise.all([
    execGit(ctx, dir, ['rev-parse', '--abbrev-ref', 'HEAD']), execGit(ctx, dir, ['log', '-1', '--format=%h|%cI|%s']),
    execGit(ctx, dir, ['status', '--porcelain=v1']), execGit(ctx, dir, ['remote', '-v']),
  ]);
  const lines = status.ok && status.out ? status.out.split('\n') : [];
  const [hash, date, ...subj] = last.ok ? last.out.split('|') : [];
  return {
    available: true, isRepo: true, branch: branch.ok ? branch.out : null,
    lastCommit: last.ok && hash ? { hash, date, subject: subj.join('|').slice(0, 120) } : null,
    uncommitted: lines.filter((l) => !l.startsWith('??')).length, untracked: lines.filter((l) => l.startsWith('??')).length,
    remotes: remotes.ok ? [...new Set(remotes.out.split('\n').filter(Boolean).map((l) => l.replace(/\/\/[^/@\s]+(:[^/@\s]*)?@/, '//***@')))].slice(0, 4) : [],
  };
}

function summarizeReadme(dir) {
  for (const n of README_NAMES) {
    const t = readText(path.join(dir, n), 16384);
    if (t === null) continue;
    const clean = t.replace(/!\[[^\]]*\]\([^)]*\)/g, '').replace(/<[^>]+>/g, ' ').replace(/\[([^\]]*)\]\([^)]*\)/g, '$1');
    const lines = clean.split('\n');
    const headings = lines.filter((l) => /^#{1,3}\s+\S/.test(l)).map((l) => l.replace(/^#+\s+/, '').trim()).slice(0, 12);
    const paras = clean.split(/\n\s*\n/).map((p) => p.trim()).filter((p) => p && !/^#{1,6}\s/.test(p) && !/^[-=*_`]{3,}/.test(p) && p.length > 25);
    return { file: n, title: headings[0] || null, excerpt: truncate(paras.slice(0, 2).join('\n\n'), 700), headings, bytes: t.length };
  }
  return null;
}

function buildLaunchOptions(dir, pkg, files, env) {
  const opts = [];
  const has = (f) => files.includes(f);
  if (pkg && !pkg._invalid) {
    for (const k of ['start', 'dev', 'serve']) if (pkg.scripts && pkg.scripts[k]) opts.push({ id: `npm-${k}`, label: `npm run ${k}`, argv: ['npm', 'run', k], source: `package.json scripts.${k}: ${truncate(pkg.scripts[k], 80)}`, needs: 'npm' });
    const bins = typeof pkg.bin === 'string' ? { [pkg.name || 'bin']: pkg.bin } : (pkg.bin || {});
    for (const [n, f] of Object.entries(bins)) if (has(f.split('/')[0]) || fs.existsSync(path.join(dir, f))) opts.push({ id: `bin-${n}`, label: `node ${f}`, argv: ['node', f], source: `package.json bin "${n}"`, needs: 'node' });
    if (pkg.main && fs.existsSync(path.join(dir, pkg.main))) opts.push({ id: 'main', label: `node ${pkg.main}`, argv: ['node', pkg.main], source: 'package.json main', needs: 'node' });
  }
  for (const f of ['main.py', 'app.py', '__main__.py', 'cli.py', 'tunnelr.py']) if (has(f)) opts.push({ id: `py-${f}`, label: `python ${f}`, argv: [commandExists('python3', env) ? 'python3' : 'python', f], source: `file ${f}`, needs: 'python' });
  for (const f of ['run.sh', 'start.sh', 'tunnelr.sh', 'tunnelr']) {
    if (has(f)) { const t = readText(path.join(dir, f), 200) || ''; if (t.startsWith('#!') || f.endsWith('.sh')) opts.push({ id: `sh-${f}`, label: `sh ${f}`, argv: ['sh', f], source: `file ${f}`, needs: 'sh' }); }
  }
  if (has('go.mod')) opts.push({ id: 'go-run', label: 'go run .', argv: ['go', 'run', '.'], source: 'go.mod present', needs: 'go' });
  if (has('Cargo.toml')) opts.push({ id: 'cargo-run', label: 'cargo run', argv: ['cargo', 'run'], source: 'Cargo.toml present', needs: 'cargo' });
  const seen = new Set();
  return opts.filter((o) => (seen.has(o.label) ? false : seen.add(o.label)));
}

function scanRisks(dir, pkg, files, launch, ctx) {
  const targets = new Set();
  const addFile = (f) => { if (f && !SECRET_FILE.test(path.basename(f))) targets.add(f); };
  for (const o of launch) if (o.argv[1] && !o.argv[1].startsWith('-') && o.argv[0] !== 'npm') addFile(o.argv[1]);
  for (const f of files) if (/\.(sh|js|mjs|cjs|py)$/.test(f)) addFile(f);
  for (const f of ['src/index.js', 'index.js', 'src/main.js', 'lib/index.js', 'bin/tunnelr']) if (fs.existsSync(path.join(dir, f))) addFile(f);
  if (pkg && pkg.scripts) {
    for (const v of Object.values(pkg.scripts)) {
      for (const m of String(v).matchAll(/([\w./-]+\.(?:m?js|cjs|py|sh))\b/g)) {
        const rel = path.normalize(m[1]);
        if (!rel.startsWith('..') && !path.isAbsolute(rel) && fs.existsSync(path.join(dir, rel))) addFile(rel);
      }
    }
  }
  for (const sub of ['src', 'lib', 'bin', 'scripts']) {
    try {
      for (const e of fs.readdirSync(path.join(dir, sub), { withFileTypes: true }).slice(0, 40)) {
        if (e.isFile() && /\.(m?js|cjs|py|sh)$/.test(e.name)) addFile(`${sub}/${e.name}`);
      }
    } catch { /* folder not present */ }
  }
  const out = [];
  const seen = new Set();
  const scan = (label, text) => {
    text.split('\n').forEach((line, i) => {
      for (const [re, what] of RISKS) {
        if (re.test(line) && !seen.has(`${label}|${what}`)) {
          seen.add(`${label}|${what}`);
          out.push({ file: label, line: i + 1, what, snippet: redactString(truncate(line.trim(), 90), ctx.config.secrets()) });
        }
      }
    });
  };
  if (pkg && pkg.scripts) scan('package.json (scripts)', Object.entries(pkg.scripts).map(([k, v]) => `${k}: ${v}`).join('\n'));
  for (const f of [...targets].slice(0, 24)) { const t = readText(path.join(dir, f), 120000); if (t) scan(f, t); }
  return out.slice(0, 20);
}

function depStatus(dir, pkg) {
  if (!pkg || pkg._invalid) return null;
  const declared = Object.keys(pkg.dependencies || {});
  if (!declared.length) return { declared, installed: [], missing: [], nodeModules: fs.existsSync(path.join(dir, 'node_modules')) };
  const nm = path.join(dir, 'node_modules');
  const installed = declared.filter((d) => fs.existsSync(path.join(nm, d)));
  return { declared, installed, missing: declared.filter((d) => !installed.includes(d)), nodeModules: fs.existsSync(nm) };
}

/** Inspect a TunnelR folder. Read-only. Returns facts, never guesses at purpose. */
async function inspect(ctx, dir) {
  const out = { path: dir, exists: false, files: [], readme: null, manifest: null, python: null, deps: null, git: null, launch: [], risks: [], configFiles: [], warnings: [], inspectedAt: new Date(ctx.services.now()).toISOString() };
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); out.exists = true; } catch (e) {
    throw new OrkardchError('TUNNELR_UNREADABLE', `Could not read the TunnelR folder "${dir}" (${e.code || e.message}).`, { hint: e.code === 'EACCES' ? 'Run termux-setup-storage, or copy TunnelR into the Termux home folder.' : 'Check the path.' });
  }
  const files = entries.map((e) => (e.isDirectory() ? `${e.name}/` : e.name)).sort();
  out.files = files.slice(0, 80);
  const plain = entries.filter((e) => e.isFile()).map((e) => e.name);
  out.readme = summarizeReadme(dir);
  const pkg = readPkg(dir);
  if (pkg && !pkg._invalid) out.manifest = { type: 'node', name: pkg.name || null, version: pkg.version || null, description: pkg.description || null, bin: pkg.bin || null, main: pkg.main || null, scripts: pkg.scripts || {}, dependencies: Object.keys(pkg.dependencies || {}), devDependencies: Object.keys(pkg.devDependencies || {}), engines: pkg.engines || null };
  else if (pkg && pkg._invalid) out.warnings.push('package.json exists but is not valid JSON.');
  const req = readText(path.join(dir, 'requirements.txt'), 8192);
  if (req) out.python = { requirements: req.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).slice(0, 30) };
  const other = [];
  if (plain.includes('go.mod')) other.push('Go module (go.mod)');
  if (plain.includes('Cargo.toml')) other.push('Rust crate (Cargo.toml)');
  if (plain.includes('Makefile')) other.push('Makefile');
  if (plain.includes('Dockerfile')) other.push('Dockerfile');
  if (plain.includes('pyproject.toml') || plain.includes('setup.py')) other.push('Python project files');
  out.otherMarkers = other;
  out.configFiles = plain.filter((f) => /^(\.env(\.example|\.sample|\.template)?|config\.(json|ya?ml|toml|ini)|settings\.(json|ya?ml|toml|ini)|.*\.(conf|ini))$/i.test(f));
  if (plain.some((f) => /^\.env$/i.test(f))) out.warnings.push('A .env file exists. Orkardch never opens it.');
  out.deps = depStatus(dir, pkg);
  out.git = await gitInfo(ctx, dir);
  out.launch = buildLaunchOptions(dir, pkg, plain, ctx.env);
  out.launch.forEach((o) => { o.available = commandExists(o.argv[0], ctx.env); });
  out.risks = scanRisks(dir, pkg, plain, out.launch, ctx);
  if (!out.readme && !out.manifest && !out.python && !other.length) out.warnings.push('No README or project file was found, so Orkardch cannot tell what this folder is. Check that it is the right one.');
  return out;
}

/** Split "node server.js --port 8080" into argv. Shell operators are refused: programs run directly, never through a shell. */
function splitCommand(text) {
  const t = String(text || '').trim();
  if (!t) return { ok: false, error: 'Type a command to run.' };
  if (/[|&;<>`]|\$\(|\$\{/.test(t.replace(/(["'])(?:\\.|(?!\1).)*\1/g, ''))) {
    return { ok: false, error: 'Orkardch runs the program directly, without a shell, so | & ; < > and $( ) are not supported here. Put them in a script inside TunnelR and run that script.' };
  }
  const argv = [];
  const re = /"((?:\\.|[^"\\])*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(t))) argv.push((m[1] !== undefined ? m[1].replace(/\\(.)/g, '$1') : m[2] !== undefined ? m[2] : m[3]));
  return argv.length ? { ok: true, argv } : { ok: false, error: 'Type a command to run.' };
}

function runForeground(ctx, { argv, cwd }) {
  const started = ctx.services.now();
  return new Promise((resolve) => {
    let child;
    try { child = ctx.services.childProcess.spawn(argv[0], argv.slice(1), { cwd, stdio: 'inherit', env: process.env }); } catch (e) { resolve({ ok: false, error: { code: e.code, message: e.message }, durationMs: 0 }); return; }
    child.on('error', (e) => resolve({ ok: false, error: { code: e.code, message: e.message }, durationMs: ctx.services.now() - started }));
    child.on('close', (code, signal) => resolve({ ok: code === 0, exitCode: code, signal, durationMs: ctx.services.now() - started }));
  });
}

const stateFile = (ctx) => path.join(ctx.paths.runtimeDir, 'tunnelr-run.json');
function tailFile(file, lines = 30, secrets = []) {
  const t = readText(file, 1) === null ? null : (() => { try { const st = fs.statSync(file); const fd = fs.openSync(file, 'r'); const len = Math.min(st.size, 16384); const b = Buffer.alloc(len); fs.readSync(fd, b, 0, len, st.size - len); fs.closeSync(fd); return b.toString('utf8'); } catch { return null; } })();
  if (t === null) return '';
  return redactString(t.split('\n').slice(-lines).join('\n'), secrets);
}

async function startBackground(ctx, { argv, cwd, settleMs = 1500 }) {
  fs.mkdirSync(ctx.paths.logDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(ctx.paths.runtimeDir, { recursive: true, mode: 0o700 });
  const logFile = path.join(ctx.paths.logDir, `tunnelr-${fileStamp(ctx.services.now)}.log`);
  const fd = fs.openSync(logFile, 'a', 0o600);
  const startedAt = new Date(ctx.services.now()).toISOString();
  let early = null;
  let child;
  try {
    child = ctx.services.childProcess.spawn(argv[0], argv.slice(1), { cwd, detached: true, stdio: ['ignore', fd, fd], env: process.env });
  } catch (e) { fs.closeSync(fd); return { ok: false, error: { code: e.code, message: e.message }, logFile, tail: '' }; }
  fs.closeSync(fd);
  child.on('exit', (code, signal) => { early = { exitCode: code, signal }; });
  child.on('error', (e) => { early = { error: { code: e.code, message: e.message } }; });
  await sleep(settleMs);
  if (early) return { ok: false, ...early, logFile, tail: tailFile(logFile, 30, ctx.config.secrets()) };
  child.unref();
  writeJsonAtomic(stateFile(ctx), { pid: child.pid, argv, cwd, logFile, startedAt }, { mode: 0o600 });
  return { ok: true, pid: child.pid, logFile };
}

function pidAlive(pid) { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } }
function pidMatches(pid, argv) {
  const t = readText(`/proc/${pid}/cmdline`, 4096);
  if (t === null) return true; // cannot check on this system: trust the record
  return t.replace(/\0/g, ' ').includes(path.basename(argv[0]));
}

function status(ctx) {
  const r = readJsonSafe(stateFile(ctx));
  if (!r.ok || !r.value || !r.value.pid) return { running: false, known: false };
  const s = r.value;
  const alive = pidAlive(s.pid) && pidMatches(s.pid, s.argv || ['']);
  return { running: alive, known: true, stale: !alive, pid: s.pid, argv: s.argv, cwd: s.cwd, logFile: s.logFile, startedAt: s.startedAt, uptimeMs: alive ? ctx.services.now() - new Date(s.startedAt).getTime() : null };
}

async function stop(ctx, { force = false } = {}) {
  const st = status(ctx);
  if (!st.running) { try { fs.unlinkSync(stateFile(ctx)); } catch { /* none */ } return { stopped: true, wasRunning: false }; }
  const sig = force ? 'SIGKILL' : 'SIGTERM';
  try { process.kill(-st.pid, sig); } catch { try { process.kill(st.pid, sig); } catch (e) { return { stopped: false, error: e.message }; } }
  for (let i = 0; i < 15; i++) { await sleep(200); if (!pidAlive(st.pid)) break; }
  const dead = !pidAlive(st.pid);
  if (dead) { try { fs.unlinkSync(stateFile(ctx)); } catch { /* ignore */ } }
  return { stopped: dead, wasRunning: true, pid: st.pid };
}

/** Everything the menu and Mother need, using a per-session cache. */
async function describe(ctx, { refresh = false } = {}) {
  if (ctx._tunnelrInfo && !refresh) return ctx._tunnelrInfo;
  const q = quickStatus(ctx);
  if (!q.configured || !q.exists) { ctx._tunnelrInfo = { connected: false, configured: q.configured, path: q.path, missing: q.configured && !q.exists }; return ctx._tunnelrInfo; }
  try { ctx._tunnelrInfo = { connected: true, ...(await inspect(ctx, q.path)) }; } catch (e) { ctx._tunnelrInfo = { connected: false, configured: true, path: q.path, error: e.message }; }
  return ctx._tunnelrInfo;
}

module.exports = {
  readConfig, saveConfig, quickStatus, findCandidates, inspect, describe, splitCommand, runForeground, startBackground, status, stop, tailFile,
  commandExists, gitInfo, RISKS, stateFile,
};
