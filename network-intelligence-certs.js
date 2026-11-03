'use strict';

/**
 * Search public certificate-transparency logs through crt.sh.
 * These logs list certificates that were issued, so they reveal names, not who runs them.
 */
async function ctSearch(ctx, domain, { includeSubdomains = true } = {}) {
  const q = includeSubdomains ? `%.${domain}` : domain;
  const url = `https://crt.sh/?q=${encodeURIComponent(q)}&output=json`;
  const res = await ctx.net.get(url, {
    headers: { accept: 'application/json' }, purpose: 'certificate transparency search',
    timeoutMs: Math.max(ctx.config.get('requestTimeoutMs'), 30000), maxBytes: 6 * 1024 * 1024,
  });
  const base = { source: 'crt.sh (public certificate transparency logs)', requestUrl: url, retrievedAt: res.retrievedAt, fromCache: res.fromCache };
  if (!res.ok) {
    const hint = [502, 503, 504].includes(res.status) || (res.error && res.error.kind === 'timeout')
      ? 'crt.sh is often slow or overloaded. Wait a minute and try again, or try a more specific domain.' : null;
    return { ok: false, error: { ...(res.error || {}), hint }, ...base };
  }
  let rows;
  try { rows = JSON.parse(res.body); } catch {
    return { ok: false, error: { kind: 'parse', code: 'CT_BAD_JSON', message: res.truncated ? 'The answer was too large to read completely. Try a more specific domain.' : 'crt.sh answered with something that was not valid data.' }, ...base };
  }
  if (!Array.isArray(rows)) return { ok: true, certificates: [], subdomains: [], total: 0, ...base };
  const seen = new Set();
  const certs = [];
  const subs = new Set();
  for (const r of rows) {
    if (!r || seen.has(r.id)) continue;
    seen.add(r.id);
    const nameList = String(r.name_value || '').split('\n').map((s) => s.trim().toLowerCase()).filter(Boolean);
    for (const n of [...nameList, String(r.common_name || '').toLowerCase()]) {
      const clean = n.replace(/^\*\./, '');
      if (clean && !clean.includes('@') && (clean === domain || clean.endsWith(`.${domain}`))) subs.add(clean);
    }
    certs.push({
      id: r.id, commonName: r.common_name || null, names: [...new Set(nameList)].slice(0, 30), issuer: r.issuer_name || null,
      notBefore: r.not_before || null, notAfter: r.not_after || null, loggedAt: r.entry_timestamp || null, serial: r.serial_number || null,
    });
  }
  certs.sort((a, b) => String(b.notBefore).localeCompare(String(a.notBefore)));
  return { ok: true, certificates: certs.slice(0, 500), subdomains: [...subs].sort().slice(0, 500), total: certs.length, truncated: res.truncated, ...base };
}

function issuerName(s) {
  const m = /CN=([^,]+)/.exec(s || '') || /O=([^,]+)/.exec(s || '');
  return m ? m[1].trim() : (s || 'unknown');
}

module.exports = { ctSearch, issuerName };
