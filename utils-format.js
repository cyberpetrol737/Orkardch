'use strict';
const crypto = require('crypto');

const ANSI_RE = /\u001b\[[0-9;]*m/g;
const stripAnsi = (s) => String(s).replace(ANSI_RE, '');
const visLen = (s) => Array.from(stripAnsi(s)).length;

function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return 'unknown';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  const txt = i === 0 ? String(Math.round(v)) : v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2);
  return `${txt} ${units[i]}`;
}

function formatDuration(ms) {
  if (!Number.isFinite(ms)) return '?';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 2 : 1)} s`;
  const m = Math.floor(s / 60);
  return `${m} min ${Math.round(s - m * 60)} s`;
}

function truncate(str, max) {
  const chars = Array.from(String(str));
  if (chars.length <= max) return chars.join('');
  return chars.slice(0, Math.max(0, max - 1)).join('') + '…';
}

/** Word-wrap plain text (no ANSI) to `width`. Long unbroken tokens are kept intact so they can be copied. */
function wrapText(text, width, indent = '') {
  const w = Math.max(10, width - Array.from(indent).length);
  const lines = [];
  for (const para of String(text).split('\n')) {
    if (!para.trim()) { lines.push(''); continue; }
    let cur = '';
    for (const word of para.split(/\s+/).filter(Boolean)) {
      // Very long tokens (paths, hashes, URLs) stay whole on their own line so they can be copied;
      // the terminal wraps them visually.
      if (!cur) cur = word;
      else if (Array.from(cur).length + 1 + Array.from(word).length <= w) cur += ' ' + word;
      else { lines.push(cur); cur = word; }
    }
    if (cur) lines.push(cur);
  }
  return lines.map((l) => (l ? indent + l : l));
}

function slugify(s, max = 40) {
  const out = String(s || '').toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return (out || 'untitled').slice(0, max).replace(/-+$/, '') || 'untitled';
}

const uid = (prefix, bytes = 4) => `${prefix}${crypto.randomBytes(bytes).toString('hex')}`;
const sha256Hex = (data) => crypto.createHash('sha256').update(data).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const isoNow = (now = Date.now) => new Date(now()).toISOString();
const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function safeJsonParse(text) {
  try { return { ok: true, value: JSON.parse(text) }; } catch (e) { return { ok: false, error: e.message }; }
}

/** Compact timestamp for filenames: 20261026T114700Z */
function fileStamp(now = Date.now) {
  return new Date(now()).toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
}

module.exports = {
  stripAnsi, visLen, formatBytes, formatDuration, truncate, wrapText, slugify, uid, sha256Hex,
  sleep, isoNow, clone, isPlainObject, safeJsonParse, fileStamp,
};
