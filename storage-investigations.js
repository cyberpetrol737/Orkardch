'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { writeJsonAtomic, writeFileAtomic, readJsonSafe } = require('./storage-jsonstore');
const { uid, sha256Hex, isPlainObject, slugify, fileStamp } = require('./utils-format');
const { OrkardchError } = require('./core-errors');

const SCHEMA = 1;
const TYPE_RE = /^[a-z0-9][a-z0-9_-]{0,39}$/;
const ID_RE = /^inv_[a-z0-9_]{6,40}$/;
const STATEMENT_TYPES = ['observation', 'claim', 'inference'];
const VERIFICATION = ['observed', 'unverified', 'verified-by-user', 'disputed'];
const INDEPENDENCE = ['unknown', 'independent', 'derived'];
const SENSITIVE = ['gps', 'local-path', 'personal-metadata'];
const MAX_VALUE = 4000;
const MAX_DATA_BYTES = 40000;
const MAX_FINDINGS = 5000;

const bad = (msg) => new OrkardchError('BAD_RECORD', msg);
const str = (v, max = 300) => (v === undefined || v === null || v === '' ? null : String(v).slice(0, max));
const validIso = (v) => { if (!v) return null; const d = new Date(v); return Number.isNaN(d.getTime()) ? null : d.toISOString(); };

function cleanRefs(list) {
  if (!Array.isArray(list)) return [];
  return list.slice(0, 50).map((r) => (typeof r === 'string' ? { description: r.slice(0, 300) } : {
    description: str(r && r.description, 300) || '',
    findingId: str(r && r.findingId, 40),
    url: str(r && r.url, 2000),
  })).filter((r) => r.description || r.findingId || r.url);
}

/** Validate and normalise one evidence record. Throws OrkardchError('BAD_RECORD') with a plain reason. */
function normalizeFinding(raw, { nowIso, defaults = {} } = {}) {
  if (!isPlainObject(raw)) throw bad('Each evidence record must be an object.');
  const type = String(raw.type == null ? '' : raw.type).trim().toLowerCase().replace(/\s+/g, '_');
  if (!TYPE_RE.test(type)) throw bad('"type" is required (letters, numbers, _ or -, up to 40 characters).');
  let value = raw.value;
  if (value === undefined || value === null || value === '') throw bad('"value" is required.');
  if (typeof value === 'object') value = JSON.stringify(value);
  value = String(value);
  if (value.length > MAX_VALUE) throw bad(`"value" is too long (max ${MAX_VALUE} characters).`);
  const statementType = raw.statementType || defaults.statementType || 'claim';
  if (!STATEMENT_TYPES.includes(statementType)) throw bad(`"statementType" must be one of ${STATEMENT_TYPES.join(', ')}.`);
  const src = isPlainObject(raw.source) ? raw.source : {};
  const f = isPlainObject(src.file) ? src.file : null;
  const source = {
    module: str(src.module || defaults.module || 'manual', 40),
    provider: str(src.provider, 60),
    url: str(src.url, 2000),
    file: f ? { name: str(f.name, 255), path: str(f.path, 1000), sha256: str(f.sha256, 64), size: Number.isFinite(f.size) ? f.size : null } : null,
    publisher: str(src.publisher, 200),
    retrievedAt: validIso(src.retrievedAt),
    description: str(src.description, 500),
    importNote: str(src.importNote, 300),
  };
  let first = validIso(raw.firstObserved) || nowIso;
  let last = validIso(raw.lastObserved) || first;
  if (last < first) [first, last] = [last, first];
  const verification = raw.verification || (statementType === 'observation' ? 'observed' : 'unverified');
  if (!VERIFICATION.includes(verification)) throw bad(`"verification" must be one of ${VERIFICATION.join(', ')}.`);
  const ind = isPlainObject(raw.independence) ? raw.independence : {};
  const independence = {
    status: INDEPENDENCE.includes(ind.status) ? ind.status : 'unknown',
    derivedFrom: str(ind.derivedFrom, 40),
    note: str(ind.note, 300),
  };
  const sensitive = SENSITIVE.includes(raw.sensitive) ? raw.sensitive : (SENSITIVE.includes(defaults.sensitive) ? defaults.sensitive : null);
  let data = isPlainObject(raw.data) ? raw.data : null;
  if (data && JSON.stringify(data).length > MAX_DATA_BYTES) data = { truncated: true, note: 'Details were too large to store.' };
  const notes = Array.isArray(raw.notes) ? raw.notes.slice(0, 50).map((n) => ({
    id: str(n && n.id, 20) || uid('n_'), at: validIso(n && n.at) || nowIso, text: String((n && n.text) || (typeof n === 'string' ? n : '')).slice(0, 2000),
  })).filter((n) => n.text) : [];
  return {
    id: /^f_[a-z0-9]{6,16}$/.test(raw.id || '') ? raw.id : uid('f_'),
    investigationId: defaults.investigationId || null,
    type, value, statementType,
    subject: str(raw.subject, 200), attribute: str(raw.attribute, 100),
    source, firstObserved: first, lastObserved: last,
    supporting: cleanRefs(raw.supporting), contradicting: cleanRefs(raw.contradicting),
    verification, independence, sensitive, notes, data,
  };
}

class InvestigationStore {
  constructor({ dir, now = Date.now }) { this.dir = dir; this.now = now; }

  _nowIso() { return new Date(this.now()).toISOString(); }
  _file(id) {
    if (!ID_RE.test(String(id))) throw new OrkardchError('BAD_ID', 'That investigation ID is not valid.');
    return path.join(this.dir, `${id}.json`);
  }

  list() {
    let files = [];
    try { files = fs.readdirSync(this.dir).filter((f) => /^inv_.*\.json$/.test(f)); } catch { return []; }
    const out = [];
    for (const f of files) {
      const r = readJsonSafe(path.join(this.dir, f));
      if (r.ok && r.value && ID_RE.test(r.value.id || '')) {
        out.push({ id: r.value.id, title: r.value.title, createdAt: r.value.createdAt, updatedAt: r.value.updatedAt, findings: (r.value.findings || []).length });
      }
    }
    return out.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
  }

  create(title, { description = '' } = {}) {
    const t = String(title || '').trim().slice(0, 120);
    if (!t) throw new OrkardchError('BAD_TITLE', 'An investigation needs a title.');
    const d = new Date(this.now());
    const id = `inv_${d.toISOString().slice(0, 10).replace(/-/g, '')}_${uid('', 3)}`;
    const now = this._nowIso();
    const inv = { schema: SCHEMA, id, title: t, description: String(description).slice(0, 1000), createdAt: now, updatedAt: now, notes: [], findings: [], searches: [], methods: [] };
    this.save(inv);
    return inv;
  }

  load(id) {
    const file = this._file(id);
    const r = readJsonSafe(file);
    if (!r.ok) {
      if (r.missing) return null;
      throw new OrkardchError('CORRUPT', `Investigation file could not be read: ${r.error}`, { hint: 'The file may be damaged. Other investigations are not affected.' });
    }
    const inv = r.value;
    if (!isPlainObject(inv) || inv.id !== id || !Array.isArray(inv.findings)) throw new OrkardchError('CORRUPT', 'Investigation file has an unexpected structure.');
    inv.notes = inv.notes || []; inv.searches = inv.searches || []; inv.methods = inv.methods || [];
    return inv;
  }

  save(inv) {
    inv.updatedAt = this._nowIso();
    writeJsonAtomic(this._file(inv.id), inv, { mode: 0o600 });
    return inv;
  }

  _mutate(id, fn) {
    const inv = this.load(id);
    if (!inv) throw new OrkardchError('NOT_FOUND', 'That investigation no longer exists.');
    const result = fn(inv);
    this.save(inv);
    return result;
  }

  /** Add findings. Invalid records are skipped with a reason; valid ones are saved. */
  addFindings(id, rawList, defaults = {}) {
    return this._mutate(id, (inv) => {
      const added = [];
      const errors = [];
      const ids = new Set(inv.findings.map((f) => f.id));
      rawList.forEach((raw, index) => {
        try {
          if (inv.findings.length + added.length >= MAX_FINDINGS) throw bad(`This investigation is full (${MAX_FINDINGS} findings).`);
          const f = normalizeFinding(raw, { nowIso: this._nowIso(), defaults: { ...defaults, investigationId: inv.id } });
          if (ids.has(f.id)) f.id = uid('f_');
          ids.add(f.id);
          added.push(f);
        } catch (e) {
          errors.push({ index, message: e.message });
        }
      });
      inv.findings.push(...added);
      return { added, errors };
    });
  }

  addFinding(id, raw, defaults = {}) {
    const r = this.addFindings(id, [raw], defaults);
    if (r.errors.length) throw bad(r.errors[0].message);
    return r.added[0];
  }

  addNote(id, text) {
    const t = String(text || '').trim().slice(0, 2000);
    if (!t) throw bad('A note cannot be empty.');
    return this._mutate(id, (inv) => { const n = { id: uid('n_'), at: this._nowIso(), text: t }; inv.notes.push(n); return n; });
  }

  updateNote(id, noteId, text) {
    return this._mutate(id, (inv) => {
      const n = inv.notes.find((x) => x.id === noteId);
      if (!n) throw new OrkardchError('NOT_FOUND', 'Note not found.');
      n.text = String(text).trim().slice(0, 2000); n.editedAt = this._nowIso();
      return n;
    });
  }

  addFindingNote(id, findingId, text) {
    const t = String(text || '').trim().slice(0, 2000);
    if (!t) throw bad('A note cannot be empty.');
    return this._mutate(id, (inv) => {
      const f = inv.findings.find((x) => x.id === findingId);
      if (!f) throw new OrkardchError('NOT_FOUND', 'Finding not found.');
      const n = { id: uid('n_'), at: this._nowIso(), text: t };
      f.notes.push(n);
      return n;
    });
  }

  /** Assessment metadata only: never touches value, source or timestamps. */
  setIndependence(id, findingId, { status, derivedFrom = null, note = null }) {
    if (!INDEPENDENCE.includes(status)) throw bad(`Independence must be one of ${INDEPENDENCE.join(', ')}.`);
    return this._mutate(id, (inv) => {
      const f = inv.findings.find((x) => x.id === findingId);
      if (!f) throw new OrkardchError('NOT_FOUND', 'Finding not found.');
      f.independence = { status, derivedFrom: status === 'derived' ? derivedFrom : null, note: note ? String(note).slice(0, 300) : null };
      return f;
    });
  }

  setVerification(id, findingId, status, note) {
    if (!VERIFICATION.includes(status)) throw bad(`Verification must be one of ${VERIFICATION.join(', ')}.`);
    return this._mutate(id, (inv) => {
      const f = inv.findings.find((x) => x.id === findingId);
      if (!f) throw new OrkardchError('NOT_FOUND', 'Finding not found.');
      f.verification = status;
      if (note) f.notes.push({ id: uid('n_'), at: this._nowIso(), text: `Verification set to "${status}": ${String(note).slice(0, 500)}` });
      return f;
    });
  }

  /** Link another finding (or a note) as supporting or contradicting evidence. Stored beside the evidence, never over it. */
  addReference(id, findingId, kind, { otherFindingId = null, description = '' } = {}) {
    if (!['supporting', 'contradicting'].includes(kind)) throw bad('A link must be "supporting" or "contradicting".');
    return this._mutate(id, (inv) => {
      const f = inv.findings.find((x) => x.id === findingId);
      if (!f) throw new OrkardchError('NOT_FOUND', 'Finding not found.');
      if (otherFindingId && !inv.findings.some((x) => x.id === otherFindingId)) throw new OrkardchError('NOT_FOUND', 'The other finding was not found.');
      if (otherFindingId === findingId) throw bad('A finding cannot support or contradict itself.');
      const ref = { description: String(description || '').slice(0, 300), findingId: otherFindingId, url: null };
      if (f[kind].length >= 50) throw bad('That finding already has 50 links.');
      f[kind].push(ref);
      return ref;
    });
  }

  logMethod(id, { module, description }) {
    return this._mutate(id, (inv) => {
      inv.methods.push({ at: this._nowIso(), module: String(module).slice(0, 40), description: String(description).slice(0, 400) });
      if (inv.methods.length > 500) inv.methods.splice(0, inv.methods.length - 500);
    });
  }

  addSearch(id, search) {
    return this._mutate(id, (inv) => {
      const s = { id: uid('s_'), ranAt: this._nowIso(), ...search };
      inv.searches.push(s);
      if (inv.searches.length > 200) inv.searches.splice(0, inv.searches.length - 200);
      return s;
    });
  }

  /** Import {findings:[...]} or a bare array. Never overwrites existing evidence. */
  importJson(id, obj, { filename = 'import' } = {}) {
    const list = Array.isArray(obj) ? obj : (isPlainObject(obj) && Array.isArray(obj.findings) ? obj.findings : null);
    if (!list) throw new OrkardchError('BAD_IMPORT', 'The file must contain a list of evidence records, or an object with a "findings" list.', { hint: 'See sample-evidence.json for the expected shape.' });
    const importedAt = this._nowIso();
    const prepared = list.map((raw) => {
      if (!isPlainObject(raw)) return raw;
      const src = isPlainObject(raw.source) ? raw.source : {};
      return {
        ...raw,
        id: undefined,
        statementType: raw.statementType || 'claim',
        verification: raw.verification || 'unverified',
        source: { ...src, module: 'import', importNote: `Imported from ${path.basename(filename)} on ${importedAt}` },
        data: { ...(isPlainObject(raw.data) ? raw.data : {}), importedFrom: path.basename(filename), originalId: raw.id || null },
      };
    });
    const res = this.addFindings(id, prepared, { module: 'import' });
    this.logMethod(id, { module: 'import', description: `Imported ${res.added.length} record(s) from ${path.basename(filename)}; ${res.errors.length} skipped.` });
    return res;
  }

  exportBundle(id) {
    const inv = this.load(id);
    if (!inv) throw new OrkardchError('NOT_FOUND', 'That investigation no longer exists.');
    const body = JSON.stringify(inv);
    return { orkardchExport: SCHEMA, exportedAt: this._nowIso(), integrity: { algorithm: 'sha256', value: sha256Hex(body), covers: 'JSON.stringify(investigation)' }, investigation: inv };
  }

  /** Write a gzip-compressed export bundle. Returns {file, bytes, sha256}. */
  archive(id, outDir) {
    const bundle = this.exportBundle(id);
    const gz = zlib.gzipSync(Buffer.from(JSON.stringify(bundle, null, 2)));
    const file = path.join(outDir, `${slugify(bundle.investigation.title)}-${fileStamp(this.now)}.orkardch.json.gz`);
    writeFileAtomic(file, gz, { mode: 0o600, dirMode: 0o700 });
    return { file, bytes: gz.length, sha256: sha256Hex(gz) };
  }

  /** Permanent. The caller must pass confirm === "DELETE". */
  delete(id, { confirm } = {}) {
    if (confirm !== 'DELETE') throw new OrkardchError('NOT_CONFIRMED', 'Deleting needs the word DELETE as confirmation. Nothing was deleted.');
    const file = this._file(id);
    if (!fs.existsSync(file)) throw new OrkardchError('NOT_FOUND', 'That investigation no longer exists.');
    fs.unlinkSync(file);
    return true;
  }
}

module.exports = { InvestigationStore, normalizeFinding, STATEMENT_TYPES, VERIFICATION, INDEPENDENCE, SENSITIVE };
