'use strict';
const fs = require('fs');
const path = require('path');
const { sha256Hex } = require('./utils-format');
const { writeJsonAtomic, readJsonSafe } = require('./storage-jsonstore');

const MAX_ENTRY_BYTES = 3 * 1024 * 1024;

/** Small on-disk cache with expiry. One JSON file per key. */
class Cache {
  constructor({ dir, ttlMs, now = Date.now }) {
    this.dir = dir;
    this.ttlMs = typeof ttlMs === 'function' ? ttlMs : () => ttlMs;
    this.now = now;
  }

  _file(key) { return path.join(this.dir, `${sha256Hex(key).slice(0, 40)}.json`); }

  get(key) {
    if (this.ttlMs() <= 0) return null;
    const file = this._file(key);
    const r = readJsonSafe(file);
    if (!r.ok || !r.value || r.value.key !== key) return null;
    if (r.value.expiresAt <= this.now()) { try { fs.unlinkSync(file); } catch { /* ignore */ } return null; }
    return { value: r.value.value, storedAt: new Date(r.value.storedAt).toISOString() };
  }

  set(key, value, ttlMs) {
    const ttl = ttlMs ?? this.ttlMs();
    if (ttl <= 0) return false;
    try {
      const entry = { key, storedAt: this.now(), expiresAt: this.now() + ttl, value };
      if (JSON.stringify(entry).length > MAX_ENTRY_BYTES) return false;
      writeJsonAtomic(this._file(key), entry, { mode: 0o600 });
      return true;
    } catch { return false; }
  }

  stats() {
    let entries = 0;
    let bytes = 0;
    try {
      for (const f of fs.readdirSync(this.dir)) {
        if (!f.endsWith('.json')) continue;
        entries++;
        bytes += fs.statSync(path.join(this.dir, f)).size;
      }
    } catch { /* no cache dir yet */ }
    return { entries, bytes };
  }

  /** Remove expired entries. */
  prune() {
    let removed = 0;
    try {
      for (const f of fs.readdirSync(this.dir)) {
        if (!f.endsWith('.json')) continue;
        const r = readJsonSafe(path.join(this.dir, f));
        if (!r.ok || !r.value || r.value.expiresAt <= this.now()) {
          try { fs.unlinkSync(path.join(this.dir, f)); removed++; } catch { /* ignore */ }
        }
      }
    } catch { /* no cache dir */ }
    return removed;
  }

  clear() {
    const before = this.stats();
    try {
      for (const f of fs.readdirSync(this.dir)) {
        if (f.endsWith('.json') || f.endsWith('.tmp')) {
          try { fs.unlinkSync(path.join(this.dir, f)); } catch { /* ignore */ }
        }
      }
    } catch { /* no cache dir */ }
    return before;
  }
}

module.exports = { Cache };
