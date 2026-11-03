'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const F = require('./tests-helpers-fixtures');
const launcher = require('./cli-launcher');

const BIN = path.join(__dirname, 'orkardch.js');
const PROJECT = __dirname;
const run = (args, env, opts = {}) => spawnSync(process.execPath, [BIN, ...args], { env: { PATH: process.env.PATH, ...env }, encoding: 'utf8', ...opts });

test('the launcher installs into $PREFIX/bin and works from any directory, passing arguments through', () => {
  const prefix = F.tempDir('ork-prefix-');
  const home = F.tempDir('ork-home-');
  const env = { PREFIX: prefix, HOME: home };
  const r = run(['--install-launcher'], env);
  assert.equal(r.status, 0, r.stderr);
  const file = path.join(prefix, 'bin', 'orkardch');
  assert.match(r.stdout, new RegExp(`Launcher installed: ${file.replace(/[/.]/g, '\\$&')}`));
  assert.ok(fs.statSync(file).mode & 0o111, 'executable');
  const text = fs.readFileSync(file, 'utf8');
  assert.ok(text.startsWith('#!'));
  assert.ok(text.includes(launcher.MARKER));
  assert.ok(text.includes(path.join(PROJECT, 'orkardch.js')));
  for (const cwd of ['/', os.tmpdir(), home]) {
    const v = spawnSync(file, ['--version'], { cwd, env: { PATH: process.env.PATH, HOME: home }, encoding: 'utf8' });
    assert.equal(v.stdout.trim(), 'Orkardch 1.0.0', `from ${cwd}`);
  }
  const named = spawnSync('orkardch', ['--version'], { cwd: '/', env: { PATH: `${path.join(prefix, 'bin')}${path.delimiter}${process.env.PATH}`, HOME: home }, encoding: 'utf8' });
  assert.equal(named.stdout.trim(), 'Orkardch 1.0.0', 'typing "orkardch" works once the folder is on PATH');
  const menu = spawnSync(file, [], { cwd: '/', input: '0\n', env: { PATH: process.env.PATH, HOME: home, NO_COLOR: '1', LANG: 'C.UTF-8' }, encoding: 'utf8' });
  assert.match(menu.stdout, /OPEN-SOURCE INTELLIGENCE/);
  assert.equal(menu.status, 0);
  F.rmrf(prefix); F.rmrf(home);
});

test('a launcher file that Orkardch did not create is never overwritten without --force', () => {
  const prefix = F.tempDir('ork-prefix-');
  fs.mkdirSync(path.join(prefix, 'bin'));
  const file = path.join(prefix, 'bin', 'orkardch');
  fs.writeFileSync(file, '#!/bin/sh\necho someone elses program\n');
  const r = run(['--install-launcher'], { PREFIX: prefix, HOME: prefix });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /was not created by Orkardch, so I left it alone/);
  assert.match(fs.readFileSync(file, 'utf8'), /someone elses program/);
  assert.equal(run(['--uninstall-launcher'], { PREFIX: prefix, HOME: prefix }).status, 1);
  assert.match(fs.readFileSync(file, 'utf8'), /someone elses program/, 'uninstall leaves foreign files alone too');
  assert.equal(run(['--install-launcher', '--force'], { PREFIX: prefix, HOME: prefix }).status, 0);
  assert.ok(fs.readFileSync(file, 'utf8').includes(launcher.MARKER));
  F.rmrf(prefix);
});

test('uninstall removes only the launcher: project files, settings and investigations stay', () => {
  const prefix = F.tempDir('ork-prefix-');
  const home = F.tempDir('ork-home-');
  const env = { PREFIX: prefix, HOME: home };
  run(['--install-launcher'], env);
  const cfgDir = path.join(home, '.config', 'orkardch');
  const dataDir = path.join(home, '.local', 'share', 'orkardch', 'investigations');
  fs.mkdirSync(cfgDir, { recursive: true }); fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(path.join(cfgDir, 'config.json'), '{}'); fs.writeFileSync(path.join(dataDir, 'inv_x.json'), '{}');
  const before = fs.readdirSync(PROJECT).sort();
  const r = run(['--uninstall-launcher'], env);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Launcher removed\. Your project folder and data were not touched\./);
  assert.ok(!fs.existsSync(path.join(prefix, 'bin', 'orkardch')));
  assert.deepEqual(fs.readdirSync(PROJECT).sort(), before);
  assert.ok(fs.existsSync(path.join(cfgDir, 'config.json')) && fs.existsSync(path.join(dataDir, 'inv_x.json')));
  assert.match(run(['--uninstall-launcher'], env).stdout, /No launcher was installed/);
  F.rmrf(prefix); F.rmrf(home);
});

test('outside Termux the launcher goes to ~/.local/bin, the PATH line is only shown, and shell startup files are never edited', () => {
  const home = F.tempDir('ork-home-');
  for (const rc of ['.bashrc', '.profile', '.zshrc']) fs.writeFileSync(path.join(home, rc), '# mine\n');
  const before = ['.bashrc', '.profile', '.zshrc'].map((f) => fs.readFileSync(path.join(home, f), 'utf8'));
  const r = run(['--install-launcher'], { HOME: home });
  assert.equal(r.status, 0);
  assert.ok(fs.existsSync(path.join(home, '.local', 'bin', 'orkardch')));
  assert.match(r.stdout, /is not on your PATH yet/);
  assert.match(r.stdout, /export PATH=".*\.local\/bin:\$PATH"/);
  assert.match(r.stdout, /does not edit your shell startup files/);
  assert.deepEqual(['.bashrc', '.profile', '.zshrc'].map((f) => fs.readFileSync(path.join(home, f), 'utf8')), before);
  F.rmrf(home);
});

test('project paths with spaces and quotes are quoted safely', () => {
  const dir = F.tempDir('ork-odd-');
  const odd = path.join(dir, "my 'odd' dir; echo hacked");
  fs.mkdirSync(odd, { recursive: true });
  fs.writeFileSync(path.join(odd, 'orkardch.js'), "console.log('stub ran with: ' + process.argv.slice(2).join(' '));\n");
  const script = launcher.render({ projectDir: odd, shell: '/bin/sh' });
  const file = path.join(dir, 'launch.sh');
  fs.writeFileSync(file, script, { mode: 0o755 });
  assert.equal(spawnSync('sh', ['-n', file]).status, 0, 'valid shell syntax');
  const r = spawnSync('sh', [file, 'a b', '--flag'], { env: { PATH: process.env.PATH }, encoding: 'utf8' });
  assert.equal(r.stdout.trim(), 'stub ran with: a b --flag');
  assert.ok(!r.stdout.includes('hacked'));
  F.rmrf(dir);
});
