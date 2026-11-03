'use strict';

const RULES = [
  [/(authorization\s*[:=]\s*)(bearer\s+|basic\s+)?[^\s,;"']+/gi, '$1[REDACTED]'],
  [/([?&](?:api[_-]?key|apikey|key|token|access[_-]?token|secret|password|passwd|sig|signature)=)[^&\s#"']+/gi, '$1[REDACTED]'],
  [/\b(x-subscription-token|x-api-key)(\s*[:=]\s*)[^\s,;"']+/gi, '$1$2[REDACTED]'],
  [/\b((?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|pwd)["']?\s*[=:]\s*)(["']?)[^\s,;"'&]{4,}\2/gi, '$1$2[REDACTED]$2'],
  [/\b(bearer\s+)[A-Za-z0-9\-._~+/]{12,}=*/gi, '$1[REDACTED]'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, '[REDACTED]'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/g, '[REDACTED]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED]'],
  [/\/\/([^/\s:@]+):([^/\s@]+)@/g, '//$1:[REDACTED]@'],
];
const SECRET_KEY = /^(api[_-]?key|apikey|token|access[_-]?token|secret|password|passwd|authorization|x-api-key|x-subscription-token)$/i;

function redactString(input, secrets = []) {
  let out = String(input);
  for (const s of secrets) if (typeof s === 'string' && s.length >= 4) out = out.split(s).join('[REDACTED]');
  for (const [re, rep] of RULES) out = out.replace(re, rep);
  return out;
}

function redactDeep(value, secrets = [], seen = new WeakSet()) {
  if (typeof value === 'string') return redactString(value, secrets);
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value)) return '[circular]';
  seen.add(value);
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, secrets, seen));
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = SECRET_KEY.test(k) && typeof v === 'string' && v ? '[REDACTED]' : redactDeep(v, secrets, seen);
  }
  return out;
}

function maskSecret(s) {
  if (!s) return '(not set)';
  return s.length <= 8 ? '••••' : `••••${s.slice(-4)}`;
}

module.exports = { redactString, redactDeep, maskSecret };
