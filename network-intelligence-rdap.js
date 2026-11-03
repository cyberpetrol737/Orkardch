'use strict';

const vcardFn = (e) => {
  const arr = e && e.vcardArray && e.vcardArray[1];
  if (!Array.isArray(arr)) return null;
  const f = arr.find((r) => r[0] === 'fn');
  return f && f[3] ? String(f[3]) : null;
};
const eventDate = (events, action) => { const e = (events || []).find((x) => x.eventAction === action); return e ? e.eventDate : null; };
const withRole = (entities, role) => (entities || []).filter((e) => (e.roles || []).includes(role));
const names = (entities, role) => withRole(entities, role).map(vcardFn).filter(Boolean);

async function rdapFetch(ctx, kind, query) {
  const url = `https://rdap.org/${kind}/${encodeURIComponent(query)}`;
  const res = await ctx.net.getJson(url, { headers: { accept: 'application/rdap+json, application/json' }, purpose: `RDAP ${kind} lookup`, timeoutMs: Math.max(ctx.config.get('requestTimeoutMs'), 15000) });
  if (res.status === 404 || (res.json && Number(res.json.errorCode) === 404)) {
    return { ok: false, error: { kind: 'not-found', code: 'RDAP_404', message: 'The registry has no record for this.' }, source: res.finalUrl, retrievedAt: res.retrievedAt };
  }
  if (!res.ok || !res.json) return { ok: false, error: res.error || { kind: 'network', code: 'RDAP_FAILED', message: 'The registry lookup failed.' }, source: res.finalUrl || url, retrievedAt: res.retrievedAt };
  return { ok: true, json: res.json, source: res.finalUrl || url, retrievedAt: res.retrievedAt, fromCache: res.fromCache };
}

async function lookupIp(ctx, ip) {
  const r = await rdapFetch(ctx, 'ip', ip);
  if (!r.ok) return r;
  const j = r.json;
  const cidrs = (j.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`);
  return {
    ok: true, source: r.source, retrievedAt: r.retrievedAt,
    name: j.name || null, handle: j.handle || null, type: j.type || null, country: j.country || null,
    range: j.startAddress && j.endAddress ? `${j.startAddress} - ${j.endAddress}` : null, cidrs,
    parentHandle: j.parentHandle || null, status: j.status || [],
    registered: eventDate(j.events, 'registration'), lastChanged: eventDate(j.events, 'last changed'),
    organizations: [...new Set([...names(j.entities, 'registrant'), ...names(j.entities, 'administrative'), ...names(j.entities, 'technical'), ...names(j.entities, 'abuse')])].slice(0, 4),
    remarks: (j.remarks || []).flatMap((x) => x.description || []).slice(0, 2),
  };
}

async function lookupDomain(ctx, domain) {
  const r = await rdapFetch(ctx, 'domain', domain);
  if (!r.ok) return r;
  const j = r.json;
  const registrarEntity = withRole(j.entities, 'registrar')[0];
  const ianaId = registrarEntity && (registrarEntity.publicIds || []).find((p) => /iana/i.test(p.type || ''));
  const registrant = names(j.entities, 'registrant');
  return {
    ok: true, source: r.source, retrievedAt: r.retrievedAt,
    name: (j.ldhName || domain).toLowerCase(), handle: j.handle || null, status: j.status || [],
    registrar: vcardFn(registrarEntity), registrarIanaId: ianaId ? ianaId.identifier : null,
    registered: eventDate(j.events, 'registration'), expires: eventDate(j.events, 'expiration'), lastChanged: eventDate(j.events, 'last changed'),
    nameservers: (j.nameservers || []).map((n) => String(n.ldhName || '').toLowerCase()).filter(Boolean),
    dnssecSigned: j.secureDNS ? Boolean(j.secureDNS.delegationSigned) : null,
    registrant: registrant.length ? registrant : null,
    registrantNote: registrant.length ? null : 'No registrant is published. Most registries now hide it for privacy, so this is normal and not suspicious.',
  };
}

async function lookupAsn(ctx, asn) {
  const r = await rdapFetch(ctx, 'autnum', String(asn));
  if (!r.ok) return r;
  const j = r.json;
  return {
    ok: true, source: r.source, retrievedAt: r.retrievedAt, name: j.name || null, handle: j.handle || null, type: j.type || null, country: j.country || null,
    range: j.startAutnum ? `AS${j.startAutnum} - AS${j.endAutnum}` : null, registered: eventDate(j.events, 'registration'), lastChanged: eventDate(j.events, 'last changed'),
    organizations: [...new Set([...names(j.entities, 'registrant'), ...names(j.entities, 'technical'), ...names(j.entities, 'abuse')])].slice(0, 4),
  };
}

/** Approximate location from RIPEstat (run by the RIPE NCC). City and country only. */
async function lookupGeo(ctx, ip) {
  const url = `https://stat.ripe.net/data/geoloc/data.json?resource=${encodeURIComponent(ip)}`;
  const res = await ctx.net.getJson(url, { purpose: 'approximate IP location (RIPEstat)' });
  if (!res.ok || !res.json) return { ok: false, error: res.error, source: url, retrievedAt: res.retrievedAt };
  const locs = ((res.json.data && res.json.data.locations) || []).filter((l) => l.country || l.city).slice(0, 3)
    .map((l) => ({ country: l.country || null, city: l.city || null, coveredPercentage: l.covered_percentage != null ? l.covered_percentage : null }));
  return { ok: true, locations: locs, source: 'RIPEstat geolocation (stat.ripe.net)', retrievedAt: res.retrievedAt };
}

module.exports = { lookupIp, lookupDomain, lookupAsn, lookupGeo };
