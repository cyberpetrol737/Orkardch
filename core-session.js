'use strict';
const { redactDeep } = require('./security-redact');

/**
 * What the person is doing right now. Mother reads this to give help that fits the
 * current screen, the inputs supplied this session, the running step and the last error.
 */
class Session {
  constructor() {
    this.moduleId = 'main';
    this.moduleTitle = 'Main menu';
    this.step = 'menu';
    this.inputs = {};
    this.lastError = null;
    this.lastResult = null;
    this.options = [];
  }
  enter(moduleId, title) {
    this.moduleId = moduleId;
    this.moduleTitle = title;
    this.step = 'menu';
    this.options = [];
  }
  setStep(step) { this.step = step; }
  setInput(key, value) { this.inputs[key] = redactDeep(value); }
  setOptions(list) { this.options = list; }
  setError(err) {
    this.lastError = err ? { code: err.code || 'ERROR', message: err.message || String(err), hint: err.hint || null, module: this.moduleId, step: this.step } : null;
  }
  setResult(kind, data) { this.lastResult = { kind, data, module: this.moduleId }; }
}

module.exports = { Session };
