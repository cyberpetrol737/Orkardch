'use strict';
const { writeJsonAtomic, readJsonSafe } = require('./storage-jsonstore');
const { uid } = require('./utils-format');

/** Saved file fingerprints, so a file can be re-checked later. Stored locally only. */
class BaselineStore {
  constructor(file, now = Date.now) { this.file = file; this.now = now; }
  _read() {
    const r = readJsonSafe(this.file);
    return r.ok && r.value && Array.isArray(r.value.baselines) ? r.value.baselines : [];
  }
  list() { return this._read(); }
  get(id) { return this._read().find((b) => b.id === id) || null; }
  add({ path, name, size, sha256, modified }) {
    const all = this._read();
    const entry = { id: uid('b_'), path, name, size, sha256, fileModifiedAtSave: modified || null, savedAt: new Date(this.now()).toISOString() };
    all.push(entry);
    writeJsonAtomic(this.file, { baselines: all.slice(-200) });
    return entry;
  }
  remove(id) {
    const all = this._read();
    const next = all.filter((b) => b.id !== id);
    if (next.length === all.length) return false;
    writeJsonAtomic(this.file, { baselines: next });
    return true;
  }
}

module.exports = { BaselineStore };
