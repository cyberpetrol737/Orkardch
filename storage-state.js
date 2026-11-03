'use strict';
const { writeJsonAtomic, readJsonSafe } = require('./storage-jsonstore');

/** Tiny persistent state (which investigation is active). Safe to lose. */
class StateStore {
  constructor(file) { this.file = file; this.data = {}; }
  load() {
    const r = readJsonSafe(this.file);
    this.data = r.ok && r.value && typeof r.value === 'object' ? r.value : {};
    return this.data;
  }
  get(key) { return this.data[key]; }
  set(key, value) {
    this.data[key] = value;
    try { writeJsonAtomic(this.file, this.data); } catch { /* state is optional */ }
  }
}

module.exports = { StateStore };
