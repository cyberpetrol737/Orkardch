'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');

const MARKER = 'ORKARDCH-LAUNCHER';

const shq = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;

function target(env) {
  if (env.PREFIX) return { dir: path.join(env.PREFIX, 'bin'), kind: 'termux' };
  return { dir: path.join(env.HOME || os.homedir(), '.local', 'bin'), kind: 'home' };
}

function render({ projectDir, shell }) {
  return [
    `#!${shell}`,
    `# ${MARKER} v1 - created by "orkardch --install-launcher".`,
    '# It runs the Orkardch project at the path below, from any folder.',
    `exec node ${shq(path.join(projectDir, 'orkardch.js'))} "$@"`,
    '',
  ].join('\n');
}

function install({ env = process.env, projectDir, force = false }) {
  const t = target(env);
  const file = path.join(t.dir, 'orkardch');
  const prefixSh = env.PREFIX ? path.join(env.PREFIX, 'bin', 'sh') : null;
  const shell = prefixSh && fs.existsSync(prefixSh) ? prefixSh : '/bin/sh';
  if (fs.existsSync(file)) {
    const current = fs.readFileSync(file, 'utf8');
    if (!current.includes(MARKER) && !force) {
      return { ok: false, code: 'EXISTS_FOREIGN', file, message: `${file} already exists and was not created by Orkardch, so I left it alone. Use --force to replace it.` };
    }
  }
  fs.mkdirSync(t.dir, { recursive: true });
  fs.writeFileSync(file, render({ projectDir, shell }), { mode: 0o755 });
  fs.chmodSync(file, 0o755);
  const onPath = (env.PATH || '').split(path.delimiter).includes(t.dir);
  return { ok: true, file, dir: t.dir, onPath, kind: t.kind };
}

function uninstall({ env = process.env }) {
  const file = path.join(target(env).dir, 'orkardch');
  if (!fs.existsSync(file)) return { ok: true, removed: false, file, message: 'No launcher was installed.' };
  if (!fs.readFileSync(file, 'utf8').includes(MARKER)) {
    return { ok: false, removed: false, file, message: `${file} was not created by Orkardch, so I did not touch it.` };
  }
  fs.unlinkSync(file);
  return { ok: true, removed: true, file, message: 'Launcher removed. Your project folder and data were not touched.' };
}

/** Is an Orkardch launcher reachable on PATH? Returns the path or null. */
function findOnPath(env = process.env) {
  for (const d of (env.PATH || '').split(path.delimiter)) {
    if (!d) continue;
    const f = path.join(d, 'orkardch');
    try { if (fs.statSync(f).isFile()) return f; } catch { /* keep looking */ }
  }
  return null;
}

module.exports = { install, uninstall, findOnPath, render, target, MARKER };
