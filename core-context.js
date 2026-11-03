'use strict';
const { resolvePaths, isTermux } = require('./core-paths');
const { Config } = require('./core-config');
const { Logger } = require('./core-logger');
const { Cache } = require('./core-cache');
const { NetClient } = require('./core-net');
const { Session } = require('./core-session');
const { describeError } = require('./core-errors');
const { StateStore } = require('./storage-state');
const { InvestigationStore } = require('./storage-investigations');
const { UI } = require('./cli-ui');
const { version } = require('./package.json');

/**
 * Build the shared application context. Node built-ins are injected through `services`
 * so tests can replace fetch, dns, tls, sockets and child processes with fakes.
 */
function createContext({ env = process.env, flags = {}, stdout = process.stdout, services = {} } = {}) {
  const paths = resolvePaths(env);
  const config = new Config({ paths }).load();
  if (flags.offline) config.override('offline', true);
  if (flags.noColor) config.override('color', 'off');
  if (flags.ascii) config.override('unicode', 'off');

  const ui = new UI({ stream: stdout, env, config });
  const log = new Logger({ dir: paths.logDir, level: config.get('logLevel'), secrets: () => config.secrets() });
  const svc = {
    fetch: globalThis.fetch, dns: require('dns'), tls: require('tls'), net: require('net'),
    http: require('http'), https: require('https'), childProcess: require('child_process'),
    now: Date.now, ...services,
  };
  const cache = new Cache({ dir: paths.cacheDir, ttlMs: () => (config.get('cacheTtlMinutes') || 0) * 60000, now: () => svc.now() });
  const net = new NetClient({ config, cache, log, fetchImpl: (...a) => svc.fetch(...a), now: () => svc.now(), version });
  const store = new InvestigationStore({ dir: paths.investigationsDir, now: () => svc.now() });
  const state = new StateStore(paths.stateFile);
  state.load();
  const session = new Session();

  const ctx = {
    version, env, paths, config, ui, log, services: svc, cache, net, store, state, session,
    termux: isTermux(env), ask: null, prompter: null, _dns: null,

    get dns() {
      if (!this._dns) {
        const { DnsClient } = require('./network-intelligence-dns');
        this._dns = new DnsClient(this);
      }
      return this._dns;
    },

    async help() { return require('./mother-index').contextHelp(this); },

    reportError(err) {
      const d = describeError(err);
      this.ui.error(d.message);
      if (d.hint) this.ui.note(d.hint);
      this.ui.note('Type ? and I will explain what this means.');
      this.session.setError({ code: d.code, message: d.message, hint: d.hint });
      this.log.error('error', { module: this.session.moduleId, step: this.session.step, code: d.code, message: d.message });
    },

    /** Friendly offline check for flows that need the network. Returns true when it is fine to go on. */
    requireOnline(purpose) {
      if (!this.net.offline) return true;
      this.ui.warn(`Offline mode is ON, so I cannot ${purpose}. Nothing was sent anywhere. Turn offline mode off in [7] Settings to use this.`);
      this.session.setError({ code: 'OFFLINE_MODE', message: 'Offline mode is on, so no network request was made.', hint: 'Turn offline mode off in Settings.' });
      return false;
    },

    activeInvestigation() {
      const id = this.state.get('activeInvestigationId');
      if (!id) return null;
      try { return this.store.load(id); } catch { return null; }
    },
    setActiveInvestigation(id) { this.state.set('activeInvestigationId', id); },
  };
  return ctx;
}

module.exports = { createContext };
