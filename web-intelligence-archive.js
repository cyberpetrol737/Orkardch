'use strict';

const tsToIso = (t) => { const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(String(t)); return m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z` : null; };

function parseCdx(body) {
  const t = String(body || '').trim();
  if (!t) return [];
  const rows = JSON.parse(t);
  if (!Array.isArray(rows) || rows.length < 2) return [];
  const head = rows[0];
  return rows.slice(1).map((r) => {
    const o = Object.fromEntries(head.map((h, i) => [h, r[i]]));
    return {
      timestamp: tsToIso(o.timestamp), raw: o.timestamp, original: o.original, statusCode: o.statuscode, mimeType: o.mimetype, digest: o.digest,
      archiveUrl: `https://web.archive.org/web/${o.timestamp}/${o.original}`,
    };
  });
}

/** Public captures of a URL from the Internet Archive (Wayback Machine). Read-only; no login is bypassed. */
async function listSnapshots(ctx, url, { first = 5, last = 3, signal } = {}) {
  const base = 'https://web.archive.org/cdx/search/cdx';
  const common = `url=${encodeURIComponent(url)}&output=json&fl=timestamp,original,statuscode,mimetype,digest&collapse=digest&filter=statuscode:200`;
  const reqs = [`${base}?${common}&limit=${first}`, `${base}?${common}&limit=-${last}`];
  const out = [];
  for (const u of reqs) out.push(await ctx.net.get(u, { purpose: 'Internet Archive lookup', signal, timeoutMs: Math.max(ctx.config.get('requestTimeoutMs'), 20000) }));
  const bad = out.find((r) => !r.ok);
  if (bad) {
    return { ok: false, error: { ...(bad.error || {}), hint: bad.error && bad.error.kind === 'rate-limited' ? 'The Internet Archive asks you to slow down. Try again in a minute.' : null }, source: base, retrievedAt: bad.retrievedAt };
  }
  try {
    const seen = new Map();
    for (const r of out) for (const s of parseCdx(r.body)) seen.set(s.raw, s);
    const snapshots = [...seen.values()].sort((a, b) => String(a.raw).localeCompare(String(b.raw)));
    return {
      ok: true, snapshots, source: 'Internet Archive CDX index (web.archive.org)', requestUrl: reqs[0], retrievedAt: out[0].retrievedAt,
      note: snapshots.length ? 'Capture times come from the archive. They show when the archive saved the page, not when it was written.' : 'No captures were found. That does not prove the page never existed; it may simply not have been archived.',
    };
  } catch (e) {
    return { ok: false, error: { kind: 'parse', code: 'CDX_BAD', message: `The archive answered in an unexpected format (${e.message}).` }, source: base, retrievedAt: out[0].retrievedAt };
  }
}

module.exports = { listSnapshots, parseCdx, tsToIso };
