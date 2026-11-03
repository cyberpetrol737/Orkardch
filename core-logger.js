'use strict';
const fs = require('fs');
const path = require('path');
const { redactDeep } = require('./security-redact');

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };

/** Structured JSON-lines logger. Secrets are redacted; failures to log never crash the app. */
class Logger {
  constructor({ dir, level = 'info', secrets = () => [], maxBytes = 512 * 1024, now = Date.now } = {}) {
    this.dir = dir;
    this.level = level;
    this.secrets = secrets;
    this.maxBytes = maxBytes;
    this.now = now;
    this.file = dir ? path.join(dir, 'orkardch.log') : null;
  }

  setLevel(level) { if (LEVELS[level] !== undefined) this.level = level; }

  _write(level, event, fields) {
    if (!this.file || LEVELS[level] > LEVELS[this.level]) return;
    try {
      fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      try {
        if (fs.statSync(this.file).size > this.maxBytes) fs.renameSync(this.file, `${this.file}.1`);
      } catch { /* no file yet */ }
      const line = JSON.stringify(redactDeep({ t: new Date(this.now()).toISOString(), level, event, ...fields }, this.secrets()));
      fs.appendFileSync(this.file, `${line}\n`, { mode: 0o600 });
    } catch { /* logging must never break the app */ }
  }

  error(event, fields = {}) { this._write('error', event, fields); }
  warn(event, fields = {}) { this._write('warn', event, fields); }
  info(event, fields = {}) { this._write('info', event, fields); }
  debug(event, fields = {}) { this._write('debug', event, fields); }
}

module.exports = { Logger };
