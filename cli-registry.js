'use strict';
const fs = require('fs');
const path = require('path');

/** The main-menu modules. Code is loaded only when a module is opened. */
const MODULES = [
  { id: 'forensics', key: '1', title: 'Image & File Forensics', cfg: 'forensics', dir: 'file-forensics', aliases: ['forensics', 'file', 'files', 'image', 'hash'] },
  { id: 'web', key: '2', title: 'Public Web Intelligence', cfg: 'web', dir: 'web-intelligence', aliases: ['web', 'research', 'search', 'website'] },
  { id: 'network', key: '3', title: 'IP & Network Intelligence', cfg: 'network', dir: 'network-intelligence', aliases: ['network', 'ip', 'dns', 'domain'] },
  { id: 'correlator', key: '4', title: 'Evidence Correlator', cfg: 'correlator', dir: 'evidence-correlator', aliases: ['evidence', 'correlator', 'case', 'investigation'] },
  { id: 'tunnelr', key: '5', title: 'TunnelR', cfg: 'tunnelr', dir: 'tunnelr', aliases: ['tunnelr', 'tunnel'] },
  { id: 'reports', key: '6', title: 'Investigation Reports', cfg: 'reports', dir: 'reports', aliases: ['reports', 'report', 'export'] },
  { id: 'settings', key: '7', title: 'Settings', cfg: null, dir: 'settings', aliases: ['settings', 'config', 'privacy'] },
];

// Each tool's code lives in <dir>-index.js next to this file (the project is one flat folder).
const modFile = (m) => path.join(__dirname, `${m.dir}-index.js`);
const load = (m) => require(modFile(m));

function status(ctx, m) {
  const enabled = m.cfg ? Boolean(ctx.config.get(`modules.${m.cfg}`)) : true;
  const present = fs.existsSync(modFile(m));
  return {
    enabled, present, ready: enabled && present,
    detail: !present ? 'files missing - reinstall Orkardch' : !enabled ? 'turned off in Settings' : 'ready',
  };
}

const byId = (id) => MODULES.find((m) => m.id === id);

module.exports = { MODULES, load, status, byId };
