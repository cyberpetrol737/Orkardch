'use strict';
const readline = require('readline');
const { NavSignal } = require('./core-errors');

/**
 * Line reader that survives piped input, Ctrl+C and Ctrl+D.
 * Lines are queued, so scripted input (tests, pipes) works the same as a person typing.
 */
class Prompter {
  constructor({ input = process.stdin, output = process.stdout } = {}) {
    this.input = input;
    this.output = output;
    this.queue = [];
    this.waiters = [];
    this.closed = false;
    this.muted = false;
    this.abortCtrl = null;
    this.rl = readline.createInterface({ input, output, terminal: Boolean(input.isTTY && output.isTTY), historySize: 50 });
    this.rl.on('line', (line) => this._deliver({ line }));
    this.rl.on('close', () => { this.closed = true; this._flush({ eof: true }); });
    this.suspended = false;
    this.rl.on('SIGINT', () => this.interrupt());
    const orig = typeof this.rl._writeToOutput === 'function' ? this.rl._writeToOutput.bind(this.rl) : null;
    if (orig) this.rl._writeToOutput = (s) => { if (!this.muted || s === '\r\n' || s === '\n') orig(s); };
  }

  _deliver(item) {
    const w = this.waiters.shift();
    if (w) w(item); else this.queue.push(item);
  }
  _flush(item) { while (this.waiters.length) this.waiters.shift()(item); }
  _next() {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    if (this.closed) return Promise.resolve({ eof: true });
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  /** Ctrl+C (or a SIGINT signal): cancel the running operation, or tell the current prompt. */
  interrupt() {
    if (this.suspended) return; // a child program (TunnelR) owns the terminal right now
    if (this.abortCtrl) { this.abortCtrl.abort(); return; }
    this._deliver({ sigint: true });
  }

  /** Resolves {line} | {eof:true} | {sigint:true}. */
  async readLine(promptText) {
    if (this.closed && !this.queue.length) return { eof: true };
    if (!this.closed) { this.rl.setPrompt(promptText); this.rl.prompt(); }
    return this._next();
  }

  /** Like readLine but typed characters are not echoed. */
  async readSecret(promptText) {
    if (this.closed && !this.queue.length) return { eof: true };
    if (this.input.isTTY) {
      this.output.write(promptText);
      this.rl.setPrompt('');
      this.muted = true;
      this.rl.prompt();
      try { return await this._next(); } finally { this.muted = false; }
    }
    return this.readLine(promptText);
  }

  /** Run fn(signal). Ctrl+C aborts the signal instead of closing the app. */
  async cancellable(fn) {
    const ctrl = new AbortController();
    this.abortCtrl = ctrl;
    try { return await fn(ctrl.signal); } finally { this.abortCtrl = null; }
  }

  /** Give the terminal to a child process (TunnelR) and take it back afterwards. */
  suspend() {
    this.suspended = true;
    if (this.input.isTTY && typeof this.input.setRawMode === 'function') this.input.setRawMode(false);
    this.rl.pause();
  }
  resume() {
    this.suspended = false;
    if (this.closed) return;
    this.rl.resume();
    if (this.input.isTTY && typeof this.input.setRawMode === 'function' && this.rl.terminal) this.input.setRawMode(true);
  }

  close() { if (!this.closed) this.rl.close(); }
}

const BACK_WORDS = new Set(['back', 'cancel', '..']);
const EXIT_WORDS = new Set(['exit', 'quit']);

/** Friendly prompts used by every module. They throw NavSignal for back / menu / exit. */
class Asker {
  constructor(ctx, prompter) {
    this.ctx = ctx;
    this.p = prompter;
    this.lastSigint = 0;
  }

  async _read(promptText, { step, main = false } = {}) {
    const ui = this.ctx.ui;
    if (step) this.ctx.session.setStep(step);
    for (;;) {
      const r = await this.p.readLine(ui.c('cyan', promptText));
      if (r.eof) { ui.print(''); throw new NavSignal('exit'); }
      if (r.sigint) {
        const now = Date.now();
        if (main) {
          if (now - this.lastSigint < 4000) throw new NavSignal('exit');
          this.lastSigint = now;
          ui.print('');
          ui.note('Press Ctrl+C again, or type 0, to leave Orkardch.');
          continue;
        }
        ui.print('');
        ui.note('(cancelled)');
        throw new NavSignal('back');
      }
      return r.line;
    }
  }

  /** Free text. Handles back / menu / exit / help words for you. */
  async text(promptText, { step, allowEmpty = false, default: def, validate } = {}) {
    const ui = this.ctx.ui;
    for (;;) {
      const shown = def !== undefined ? `${promptText} [${def}] ` : `${promptText} `;
      const line = (await this._read(shown, { step })).trim();
      const low = line.toLowerCase();
      if (BACK_WORDS.has(low)) throw new NavSignal('back');
      if (low === 'menu') throw new NavSignal('menu');
      if (EXIT_WORDS.has(low)) throw new NavSignal('exit');
      if (low === '?' || low === 'help') { await this.ctx.help(); continue; }
      if (!line) {
        if (def !== undefined) return String(def);
        if (allowEmpty) return '';
        ui.print(ui.c('yellow', "Please type something, or type 'back' to go back."));
        continue;
      }
      if (validate) {
        const err = validate(line);
        if (err) { ui.print(ui.c('yellow', err)); continue; }
      }
      return line;
    }
  }

  async secret(promptText, { step } = {}) {
    if (step) this.ctx.session.setStep(step);
    const r = await this.p.readSecret(this.ctx.ui.c('cyan', `${promptText} `));
    if (r.eof) throw new NavSignal('exit');
    if (r.sigint) throw new NavSignal('back');
    const line = r.line.trim();
    if (BACK_WORDS.has(line.toLowerCase())) throw new NavSignal('back');
    return line;
  }

  async confirm(promptText, { def = false, step } = {}) {
    const ui = this.ctx.ui;
    const suffix = def ? '[Y/n]' : '[y/N]';
    for (;;) {
      const line = (await this._read(`${promptText} ${suffix} `, { step })).trim().toLowerCase();
      if (!line) return def;
      if (['y', 'yes'].includes(line)) return true;
      if (['n', 'no'].includes(line)) return false;
      if (BACK_WORDS.has(line) || line === '0') throw new NavSignal('back');
      if (line === '?' || line === 'help') { await this.ctx.help(); continue; }
      ui.print(ui.c('yellow', 'Please answer y (yes) or n (no), or 0 to go back.'));
    }
  }

  async pause(message = 'Press Enter to continue') {
    const line = (await this._read(`${message} `)).trim().toLowerCase();
    if (BACK_WORDS.has(line)) throw new NavSignal('back');
    if (line === '?' || line === 'help') await this.ctx.help();
  }

  /**
   * Pick one of `items` ({key, aliases}). `0` means back (or exit when zero === 'exit').
   * Returns the chosen item's key.
   */
  async choice(items, { step, zero = 'back', promptText = '> ', emptyKey } = {}) {
    const ui = this.ctx.ui;
    const main = zero === 'exit';
    for (;;) {
      const line = (await this._read(promptText, { step, main })).trim().toLowerCase();
      if (!line) { if (emptyKey !== undefined) return emptyKey; continue; }
      if (line === '0') throw new NavSignal(zero);
      if (BACK_WORDS.has(line) || line === 'b') { if (main) { ui.note('You are already at the main menu. Type 0 to exit.'); continue; } throw new NavSignal('back'); }
      if (line === 'menu') throw new NavSignal('menu');
      if (EXIT_WORDS.has(line) || line === 'q') throw new NavSignal('exit');
      if (line === '?' || line === 'help' || line === 'h') { await this.ctx.help(); continue; }
      const exact = items.find((i) => String(i.key).toLowerCase() === line || (i.aliases || []).includes(line));
      if (exact) return exact.key;
      if (line.length >= 3) {
        const pref = items.filter((i) => (i.aliases || []).some((a) => a.startsWith(line)));
        if (pref.length === 1) return pref[0].key;
      }
      ui.print(ui.c('yellow', `I didn't understand "${line.slice(0, 30)}". Type one of the numbers shown, or ? for help.`));
    }
  }

  /** One-off numbered question. Enter picks the default. options: [{label, value, aliases?}]. */
  async select(question, options, { def = 0, step } = {}) {
    const ui = this.ctx.ui;
    ui.print(question);
    options.forEach((o, i) => ui.menuItem(String(i + 1), `${o.label}${i === def ? ' (default)' : ''}`));
    const items = options.map((o, i) => ({ key: String(i + 1), aliases: o.aliases || [] }));
    const key = await this.choice(items, { step, emptyKey: String(def + 1) });
    return options[Number(key) - 1].value;
  }

  /**
   * Generic menu loop. Each item: {key, label, note?, aliases?, hidden?, run()}.
   * An item may return 'back' to close this menu. The menu itself always returns 'left' when it
   * closes, so a submenu never closes its parent by accident. Errors inside an item are shown, not thrown.
   */
  async menu({ title, intro, items, step = 'menu', zero = 'back', backLabel = 'Back' }) {
    const ui = this.ctx.ui;
    for (;;) {
      this.ctx.session.setStep(step);
      this.ctx.session.setOptions(items.filter((i) => !i.hidden).map((i) => i.label));
      ui.blank();
      if (title) ui.print(ui.c('bold', title));
      if (intro) ui.para(intro);
      for (const it of items) if (!it.hidden) ui.menuItem(it.key, it.label, it.note);
      ui.menuItem('0', backLabel);
      let key;
      try {
        key = await this.choice(items, { step, zero });
      } catch (e) {
        if (e instanceof NavSignal && e.kind === 'back') return 'left';
        throw e;
      }
      const item = items.find((i) => i.key === key);
      try {
        const r = await item.run();
        if (r === 'back') return 'left';
      } catch (e) {
        if (e instanceof NavSignal) { if (e.kind === 'back') continue; throw e; }
        this.ctx.reportError(e);
      }
    }
  }
}

module.exports = { Prompter, Asker };
