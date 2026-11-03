'use strict';

/** Thrown to move around the menus: back (one level), menu (main menu) or exit. */
class NavSignal extends Error {
  constructor(kind) {
    super(`nav:${kind}`);
    this.name = 'NavSignal';
    this.kind = kind;
  }
}

class OrkardchError extends Error {
  constructor(code, message, { hint, details, cause } = {}) {
    super(message);
    this.name = 'OrkardchError';
    this.code = code;
    this.hint = hint || null;
    this.details = details || null;
    if (cause) this.cause = cause;
  }
}

const OFFLINE_HINT = 'Turn offline mode off in Settings (or start without --offline) to use online features.';

function offlineFailure(purpose) {
  return {
    kind: 'offline-mode',
    code: 'OFFLINE_MODE',
    message: `Offline mode is on, so Orkardch did not contact the network${purpose ? ` (${purpose})` : ''}.`,
    hint: OFFLINE_HINT,
  };
}

/** Normalise anything thrown into {code, message, hint}. */
function describeError(err) {
  if (!err) return { code: 'UNKNOWN', message: 'Unknown error', hint: null };
  if (err instanceof OrkardchError) return { code: err.code, message: err.message, hint: err.hint };
  const code = err.code || (err.cause && err.cause.code) || err.name || 'ERROR';
  return { code: String(code), message: err.message || String(err), hint: null };
}

module.exports = { NavSignal, OrkardchError, offlineFailure, describeError, OFFLINE_HINT };
