'use strict';
// Integration tests: run the real program as a separate process, the way a person would.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');
const F = require('./tests-helpers-fixtures');

const BIN = path.join(__dirname, 'orkardch.js');

function runCli(args = [], input = '', { env = {}, cwd, home, timeoutMs = 25000, keepOpen = false, onStart } = {}) {
  const h = home || F.tempDir('ork-cli-');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, ...args], { cwd: cwd || os.tmpdir(), env: { PATH: process.env.PATH, HOME: h, LANG: 'C.UTF-8', NO_COLOR: '1', TERM: 'xterm', COLUMNS: '40', ...env } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const timer = setTimeout(() => { child.kill('SIGKILL'); }, timeoutMs);
    child.on('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr, flat: stdout.replace(/\s*\n\s*/g, ' '), home: h }); });
    if (input) child.stdin.write(input);
    if (!keepOpen) child.stdin.end();
    if (onStart) onStart(child);
  });
}

test('launching shows the banner, version, status summary and the full numbered menu', async () => {
  const r = await runCli([], '0\n');
  assert.equal(r.code, 0);
  assert.equal(r.stderr, '');
  assert.match(r.flat, /OPEN-SOURCE INTELLIGENCE/);
  assert.match(r.flat, /v1\.0\.0/);
  assert.match(r.flat, /╔═+╗/);
  for (const line of ['System: ', 'Network: ', 'Modules: Available \\(7/7\\)', 'Investigation: none yet', 'What would you like to do\\?']) assert.match(r.flat, new RegExp(line));
  for (const item of ['[1] Image & File Forensics', '[2] Public Web Intelligence', '[3] IP & Network Intelligence', '[4] Evidence Correlator', '[5] TunnelR', '[6] Investigation Reports', '[7] Settings', '[M] Mother — Teach Me Everything', '[0] Exit']) assert.ok(r.stdout.includes(item), item);
  assert.match(r.flat, /Goodbye/);
  F.rmrf(r.home);
});

test('the ASCII fallback works without colours or box characters, and the layout fits a narrow phone screen', async () => {
  const r = await runCli(['--ascii', '--no-color'], '0\n', { env: { COLUMNS: '28' } });
  assert.equal(r.code, 0);
  assert.ok(!/[╔║╚═╗╝]/.test(r.stdout), 'no box-drawing characters in ASCII mode');
  assert.ok(r.stdout.includes('[M] Mother - Teach Me Everything'));
  assert.ok(!/\u001b\[/.test(r.stdout));
  const banner = r.stdout.split('\n').slice(0, 10);
  assert.ok(banner.every((l) => l.length <= 28), banner.filter((l) => l.length > 28).join('|'));
  assert.match(r.flat, /O R K A R D C H/);
  const wide = await runCli([], '0\n', { env: { COLUMNS: '80' } });
  assert.match(wide.stdout.split('\n').slice(0, 6).join('\n'), /╦═╗/);
  F.rmrf(r.home); F.rmrf(wide.home);
});

test('colours appear only when allowed', async () => {
  const on = await runCli([], '0\n', { env: { FORCE_COLOR: '1', NO_COLOR: '' } });
  assert.match(on.flat, /\u001b\[36m/);
  const off = await runCli([], '0\n', { env: { FORCE_COLOR: '1', NO_COLOR: '1' } });
  assert.ok(!/\u001b\[/.test(off.stdout));
  F.rmrf(on.home); F.rmrf(off.home);
});

test('invalid, empty and odd input never crashes the menu', async () => {
  const r = await runCli([], 'banana\n\n   \n99\n-1\n1.5\n;rm -rf /\n$(id)\n' + 'x'.repeat(5000) + '\n0\n');
  assert.equal(r.code, 0);
  assert.equal(r.stderr, '');
  assert.ok((r.stdout.match(/I didn't understand/g) || []).length >= 5);
  assert.match(r.flat, /Goodbye/);
  F.rmrf(r.home);
});

test('end of input (Ctrl+D) and an empty pipe exit cleanly', async () => {
  for (const input of ['', '3\n']) {
    const r = await runCli([], input);
    assert.equal(r.code, 0, `input ${JSON.stringify(input)}`);
    assert.equal(r.stderr, '');
    assert.match(r.flat, /Goodbye/);
    F.rmrf(r.home);
  }
});

test('Ctrl+C (SIGINT): the first one only warns, the second leaves cleanly', async () => {
  let r;
  r = await runCli([], '', { keepOpen: true, onStart: (child) => { setTimeout(() => child.kill('SIGINT'), 700); setTimeout(() => child.kill('SIGINT'), 1100); } });
  assert.equal(r.code, 0, `exit code ${r.code} signal ${r.signal}`);
  assert.match(r.flat, /Press Ctrl\+C again, or type 0, to leave Orkardch/);
  assert.match(r.flat, /Goodbye/);
  assert.equal(r.stderr, '');
  F.rmrf(r.home);
});

test('navigation: numbers, aliases, back, menu and ? work, so nothing needs to be memorised', async () => {
  const r = await runCli([], '2\nback\nforensics\n0\nnetwork\nmenu\n7\n0\n?\n0\n');
  assert.equal(r.code, 0);
  for (const heading of ['Public Web Intelligence', 'Image & File Forensics', 'IP & Network Intelligence', 'Settings']) assert.ok(r.stdout.includes(heading), heading);
  assert.match(r.flat, /This is the main menu\. Type the number of what you want/);
  F.rmrf(r.home);
});

test('Mother is reachable from the menu and teaches in simple words', async () => {
  const r = await runCli([], 'm\n1\n3\n1\n2\n3\n6\n0\n', { env: { COLUMNS: '60' } });
  assert.equal(r.code, 0);
  assert.match(r.flat, /Hi! I'm Mother\. I'll help you understand Orkardch\./);
  assert.match(r.flat, /Image and file forensics: what would you like to learn\?/);
  assert.match(r.flat, /A hash is like a digital fingerprint/);
  assert.match(r.flat, /Goodbye/);
  const alias = await runCli([], 'mother\n0\n0\n');
  assert.match(alias.flat, /Hi! I'm Mother/);
  const eight = await runCli([], '8\n0\n0\n');
  assert.match(eight.flat, /Hi! I'm Mother/);
  F.rmrf(r.home); F.rmrf(alias.home); F.rmrf(eight.home);
});

test('file hashing through the real program matches the system sha256sum', async () => {
  const home = F.tempDir('ork-cli-');
  const file = path.join(home, 'sample.bin');
  fs.writeFileSync(file, require('crypto').randomBytes(200000));
  const expected = execFileSync('sha256sum', [file]).toString().split(' ')[0];
  const r = await runCli([], `1\n1\n${file}\nn\n0\n0\n0\n`, { home });
  assert.equal(r.code, 0);
  assert.ok(r.stdout.includes(expected), 'SHA-256 shown equals sha256sum');
  assert.match(r.flat, /Phone filesystem times/);
  assert.match(r.flat, /they do not prove when a file was originally created/);
  F.rmrf(home);
});

test('--version, --help, unknown flags and --doctor', async () => {
  const v = await runCli(['--version']);
  assert.equal(v.stdout.trim(), 'Orkardch 1.0.0');
  const h = await runCli(['--help']);
  assert.match(h.flat, /--install-launcher/);
  assert.match(h.flat, /--doctor --online/);
  const bad = await runCli(['--bogus']);
  assert.equal(bad.code, 2);
  assert.match(bad.stderr, /Unknown option: --bogus/);
  const d = await runCli(['--doctor']);
  assert.equal(d.code, 0, d.stdout);
  assert.match(d.flat, /self check/);
  assert.match(d.flat, /Node\.js \d+/);
  assert.match(d.flat, /Image & File Forensics: loads/);
  assert.match(d.flat, /Mother \(help and lessons\): loads/);
  assert.match(d.flat, /Tip: run with --online/);
  assert.match(d.flat, /Result: all good/);
  const off = await runCli(['--doctor', '--online', '--offline']);
  assert.match(off.flat, /--online was requested but offline mode is on/);
  for (const r of [v, h, bad, d, off]) F.rmrf(r.home);
});

test('works from any folder and survives a damaged settings file', async () => {
  const home = F.tempDir('ork-cli-');
  fs.mkdirSync(path.join(home, '.config', 'orkardch'), { recursive: true });
  fs.writeFileSync(path.join(home, '.config', 'orkardch', 'config.json'), '{ this is not json');
  const r = await runCli([], '7\n0\n0\n', { cwd: '/', home });
  assert.equal(r.code, 0);
  assert.match(r.flat, /Settings could not be read|Settings file could not be read/);
  F.rmrf(home);
});

test('a module switched off in Settings explains how to turn it on', async () => {
  const home = F.tempDir('ork-cli-');
  fs.mkdirSync(path.join(home, '.config', 'orkardch'), { recursive: true });
  fs.writeFileSync(path.join(home, '.config', 'orkardch', 'config.json'), JSON.stringify({ modules: { forensics: false } }));
  const r2 = await runCli([], '1\n0\n', { home });
  assert.match(r2.flat, /6\/7 available/);
  assert.match(r2.flat, /Image & File Forensics is not available: turned off in Settings/);
  assert.match(r2.flat, /Turn it on in \[7\] Settings/);
  F.rmrf(home); F.rmrf(r2.home);
});

test('--offline starts the whole session with network access disabled', async () => {
  const r = await runCli(['--offline'], '3\n1\n8.8.8.8\n0\n0\n0\n');
  assert.match(r.flat, /Network: Offline mode \(requests disabled\)/);
  assert.match(r.flat, /Offline mode is ON, so I cannot look up\s+8\.8\.8\.8/);
  F.rmrf(r.home);
});

test('a closed output pipe (orkardch | head) ends quietly instead of crashing', async () => {
  const home = F.tempDir('ork-cli-');
  const r = require('child_process').spawnSync('sh', ['-c', `node "${BIN}" --doctor 2>&1 | head -n 1; echo "pipe-status=$?"`], { env: { PATH: process.env.PATH, HOME: home, NO_COLOR: '1' }, encoding: 'utf8' });
  assert.ok(!/EPIPE|Unhandled|at .*\.js:\d+/.test(r.stdout + r.stderr), r.stdout + r.stderr);
  assert.match(r.stdout, /self check/);
  F.rmrf(home);
});
