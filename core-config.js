'use strict';
const path = require('path');
const net = require('net');
const { clone, isPlainObject } = require('./utils-format');
const { writeJsonAtomic, readJsonSafe } = require('./storage-jsonstore');

const DEFAULTS = {
  schemaVersion: 1,
  outputDir: null,
  cacheTtlMinutes: 60,
  requestTimeoutMs: 10000,
  maxParallelRequests: 3,
  minRequestIntervalMs: 400,
  maxRetries: 1,
  modules: { forensics: true, web: true, network: true, correlator: true, tunnelr: true, reports: true },
  providers: { wikipedia: true, gdelt: true, duckduckgo: true, brave: true },
  apiKeys: { brave: '' },
  color: 'auto',
  unicode: 'auto',
  reportFormat: 'md',
  offline: false,
  dns: { mode: 'auto', dohProvider: 'cloudflare', servers: [] },
  activeChecks: true,
  logLevel: 'info',
};

const bool = (label) => ({ type: 'bool', label });
const SCHEMA = {
  outputDir: { type: 'path', nullable: true, label: 'Output folder' },
  cacheTtlMinutes: { type: 'int', min: 0, max: 43200, label: 'Cache time (minutes)' },
  requestTimeoutMs: { type: 'int', min: 1000, max: 120000, label: 'Request timeout (ms)' },
  maxParallelRequests: { type: 'int', min: 1, max: 8, label: 'Parallel requests' },
  minRequestIntervalMs: { type: 'int', min: 0, max: 10000, label: 'Gap between requests to one site (ms)' },
  maxRetries: { type: 'int', min: 0, max: 3, label: 'Retries' },
  'modules.forensics': bool('Image & File Forensics'),
  'modules.web': bool('Public Web Intelligence'),
  'modules.network': bool('IP & Network Intelligence'),
  'modules.correlator': bool('Evidence Correlator'),
  'modules.tunnelr': bool('TunnelR'),
  'modules.reports': bool('Investigation Reports'),
  'providers.wikipedia': bool('Wikipedia search'),
  'providers.gdelt': bool('GDELT news search'),
  'providers.duckduckgo': bool('DuckDuckGo web search (best effort)'),
  'providers.brave': bool('Brave Search (needs your own key)'),
  'apiKeys.brave': { type: 'string', max: 200, label: 'Brave Search API key' },
  color: { type: 'enum', values: ['auto', 'on', 'off'], label: 'Colors' },
  unicode: { type: 'enum', values: ['auto', 'on', 'off'], label: 'Box-drawing characters' },
  reportFormat: { type: 'enum', values: ['json', 'md', 'html', 'txt'], label: 'Report format' },
  offline: bool('Offline mode'),
  'dns.mode': { type: 'enum', values: ['auto', 'system', 'doh'], label: 'DNS mode' },
  'dns.dohProvider': { type: 'enum', values: ['cloudflare', 'google'], label: 'DNS-over-HTTPS provider' },
  'dns.servers': { type: 'ipList', label: 'Custom DNS servers' },
  activeChecks: bool('Allow active connectivity checks'),
  logLevel: { type: 'enum', values: ['error', 'warn', 'info', 'debug'], label: 'Log level' },
};

function getPath(obj, key) {
  return key.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), obj);
}
function setPath(obj, key, value) {
  const parts = key.split('.');
  let o = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!isPlainObject(o[parts[i]])) o[parts[i]] = {};
    o = o[parts[i]];
  }
  o[parts[parts.length - 1]] = value;
}

function validateValue(key, raw) {
  const def = SCHEMA[key];
  if (!def) return { ok: false, error: `Unknown setting "${key}".` };
  switch (def.type) {
    case 'bool': {
      if (typeof raw === 'boolean') return { ok: true, value: raw };
      const s = String(raw).trim().toLowerCase();
      if (['on', 'yes', 'y', 'true', '1'].includes(s)) return { ok: true, value: true };
      if (['off', 'no', 'n', 'false', '0'].includes(s)) return { ok: true, value: false };
      return { ok: false, error: 'Please answer on or off.' };
    }
    case 'int': {
      const n = typeof raw === 'number' ? raw : Number(String(raw).trim());
      if (!Number.isInteger(n)) return { ok: false, error: 'Please enter a whole number.' };
      if (n < def.min || n > def.max) return { ok: false, error: `Please enter a number from ${def.min} to ${def.max}.` };
      return { ok: true, value: n };
    }
    case 'enum': {
      const s = String(raw).trim().toLowerCase();
      return def.values.includes(s) ? { ok: true, value: s } : { ok: false, error: `Choose one of: ${def.values.join(', ')}.` };
    }
    case 'string': {
      const s = String(raw == null ? '' : raw).trim();
      if (s.length > def.max) return { ok: false, error: `That is too long (max ${def.max} characters).` };
      if (/\s/.test(s)) return { ok: false, error: 'This value cannot contain spaces.' };
      return { ok: true, value: s };
    }
    case 'path': {
      if (raw === null || raw === '' || raw === undefined) return def.nullable ? { ok: true, value: null } : { ok: false, error: 'A folder is required.' };
      const s = String(raw).trim();
      if (!s || s.includes('\0')) return { ok: false, error: 'That does not look like a folder path.' };
      return { ok: true, value: s };
    }
    case 'ipList': {
      const list = Array.isArray(raw) ? raw : String(raw || '').split(/[,\s]+/).filter(Boolean);
      if (!list.every((x) => net.isIP(x))) return { ok: false, error: 'Use IP addresses separated by commas, for example 1.1.1.1, 9.9.9.9.' };
      return { ok: true, value: list.slice(0, 4) };
    }
    default:
      return { ok: false, error: 'Unsupported setting type.' };
  }
}

class Config {
  constructor({ paths }) {
    this.paths = paths;
    this.data = clone(DEFAULTS);
    this.session = {};
    this.warnings = [];
  }

  load() {
    this.data = clone(DEFAULTS);
    this.warnings = [];
    const r = readJsonSafe(this.paths.configFile);
    if (!r.ok) {
      if (!r.missing) this.warnings.push(`Settings file could not be read (${r.error}). Using defaults.`);
      return this;
    }
    if (!isPlainObject(r.value)) { this.warnings.push('Settings file has an unexpected shape. Using defaults.'); return this; }
    for (const key of Object.keys(SCHEMA)) {
      const raw = getPath(r.value, key);
      if (raw === undefined) continue;
      const v = validateValue(key, raw);
      if (v.ok) setPath(this.data, key, v.value);
      else this.warnings.push(`Ignored invalid saved value for ${key}: ${v.error}`);
    }
    return this;
  }

  get(key) {
    const s = getPath(this.session, key);
    return s !== undefined ? s : getPath(this.data, key);
  }

  /** Change a persisted setting. Returns {ok, error}. */
  set(key, raw) {
    const v = validateValue(key, raw);
    if (!v.ok) return v;
    setPath(this.data, key, v.value);
    return v;
  }

  /** Session-only override (command-line flags). Never saved. */
  override(key, value) { setPath(this.session, key, value); }

  save() {
    writeJsonAtomic(this.paths.configFile, this.data, { mode: 0o600 });
  }

  reset() { this.data = clone(DEFAULTS); }

  secrets() { return Object.values(this.data.apiKeys || {}).filter((s) => typeof s === 'string' && s.length >= 4); }

  outputDir() { return path.resolve(this.get('outputDir') || this.paths.defaultOutputDir); }

  describe(key) { return SCHEMA[key] || null; }
  keys() { return Object.keys(SCHEMA); }
}

module.exports = { Config, DEFAULTS, SCHEMA, validateValue };
