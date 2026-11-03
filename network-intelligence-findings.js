'use strict';

const MODULE = 'network-intelligence';

function src(provider, url, retrievedAt) {
  return { module: MODULE, provider, url: url || null, retrievedAt: retrievedAt || null };
}
const obs = (type, value, s, extra = {}) => ({
  type, value: String(value), statementType: 'observation', source: s,
  firstObserved: s.retrievedAt || undefined, lastObserved: s.retrievedAt || undefined, ...extra,
});

function ipFindings(r) {
  const out = [obs('ip', r.ip, { module: MODULE, provider: 'local classification', retrievedAt: r.at }, {
    data: { category: r.classification.category, version: r.classification.version, public: r.classification.public },
  })];
  if (r.rdap && r.rdap.ok) {
    const s = src('RDAP', r.rdap.source, r.rdap.retrievedAt);
    if (r.rdap.name) out.push(obs('network_registration', `${r.rdap.name}${r.rdap.handle ? ` (${r.rdap.handle})` : ''}`, s, { subject: r.ip, attribute: 'network_name', data: { range: r.rdap.range, cidrs: r.rdap.cidrs, country: r.rdap.country, organizations: r.rdap.organizations } }));
  }
  if (r.origin && r.origin.ok) {
    const s = src('Team Cymru DNS', null, r.origin.retrievedAt);
    s.description = r.origin.source;
    for (const asn of r.origin.asns) out.push(obs('asn', `AS${asn}`, s, { subject: r.ip, data: { prefix: r.origin.prefix, registry: r.origin.registry, country: r.origin.country, name: r.asnName && r.asnName.name } }));
  }
  if (r.ptr && r.ptr.status === 'ok') {
    const s = src(`DNS (${r.ptr.resolver})`, null, r.ptr.retrievedAt);
    for (const rec of r.ptr.records) out.push(obs('dns_record', `PTR ${rec.value}`, s, { data: { domain: rec.value, recordType: 'PTR', queried: r.ip } }));
  }
  if (r.geo && r.geo.ok) {
    const s = src('RIPEstat', null, r.geo.retrievedAt);
    s.description = r.geo.source;
    for (const l of r.geo.locations) out.push({ ...obs('ip_location', [l.city, l.country].filter(Boolean).join(', '), s, { subject: r.ip, data: { approximate: true, coveredPercentage: l.coveredPercentage } }), statementType: 'claim' });
  }
  return out;
}

function dnsFindings(domain, results) {
  const out = [];
  for (const r of results) {
    if (r.status !== 'ok') continue;
    const s = src(`DNS (${r.resolver})`, null, r.retrievedAt);
    for (const rec of r.records) out.push(obs('dns_record', `${r.type} ${rec.value}`, s, { data: { domain, recordType: r.type, value: rec.value, ttl: rec.ttl == null ? null : rec.ttl, fields: r.type === 'A' || r.type === 'AAAA' ? { address: rec.value } : undefined } }));
  }
  return out;
}

function rdapDomainFindings(domain, rd) {
  if (!rd || !rd.ok) return [];
  const s = src('RDAP', rd.source, rd.retrievedAt);
  const out = [obs('domain', domain, s, { data: { registrar: rd.registrar, status: rd.status, nameservers: rd.nameservers } })];
  const attr = (attribute, value) => { if (value) out.push(obs('domain_registration', value, s, { subject: domain, attribute })); };
  attr('registrar', rd.registrar);
  attr('registration_date', rd.registered);
  attr('expiration_date', rd.expires);
  if (rd.registrant) attr('registrant_organization', rd.registrant.join('; '));
  return out;
}

function domainFindings(r) {
  const out = rdapDomainFindings(r.domain, r.rdap);
  if (!out.some((f) => f.type === 'domain')) out.unshift(obs('domain', r.domain, { module: MODULE, provider: 'user input', retrievedAt: r.at }));
  return [...out, ...dnsFindings(r.domain, r.dns || [])];
}

function certFindings(r) {
  const s = src('crt.sh (certificate transparency)', r.ct.requestUrl, r.ct.retrievedAt);
  const out = [obs('domain', r.domain, { module: MODULE, provider: 'user input', retrievedAt: r.ct.retrievedAt })];
  for (const c of r.ct.certificates.slice(0, 50)) {
    out.push(obs('certificate', `crt.sh #${c.id}`, s, { data: { names: c.names, commonName: c.commonName, issuer: c.issuer, notBefore: c.notBefore, notAfter: c.notAfter, loggedAt: c.loggedAt, serial: c.serial, domain: r.domain } }));
  }
  for (const sub of r.ct.subdomains.slice(0, 200)) out.push(obs('subdomain', sub, s, { data: { parent: r.domain, passive: true } }));
  if (r.live && r.live.ok && r.live.certificate) {
    const c = r.live.certificate;
    out.push(obs('certificate', `sha256:${c.sha256}`, src('live TLS connection', null, r.live.retrievedAt), { data: { names: c.altNames, commonName: c.subject, issuer: c.issuer, notBefore: c.validFrom, notAfter: c.validTo, trusted: r.live.trusted, domain: r.domain } }));
  }
  return out;
}

function asnFindings(r) {
  const out = [];
  if (r.name && r.name.ok) { const s = src('Team Cymru DNS', null, r.name.retrievedAt); s.description = r.name.source; out.push(obs('asn', `AS${r.asn}`, s, { subject: `AS${r.asn}`, attribute: 'as_name', data: { name: r.name.name, registry: r.name.registry, country: r.name.country } })); }
  if (r.rdap && r.rdap.ok) out.push(obs('asn', `AS${r.asn}`, src('RDAP', r.rdap.source, r.rdap.retrievedAt), { data: { name: r.rdap.name, country: r.rdap.country, organizations: r.rdap.organizations } }));
  return out;
}

function connectivityFindings(r) {
  const s = src('active check (authorized)', null, r.at);
  const out = [];
  if (r.http && r.http.ok) out.push(obs('connectivity_check', `${r.http.url} answered ${r.http.status} in ${r.http.totalMs} ms`, s, { data: { host: r.host, status: r.http.status, timing: r.http.timing, server: r.http.server } }));
  if (r.latency && r.latency.ok) out.push(obs('connectivity_check', `TCP ${r.host}:${r.latency.port} average ${r.latency.avgMs} ms (${r.latency.lossPercent}% lost)`, s, { data: { host: r.host, ...r.latency } }));
  if (r.tls && r.tls.ok && r.tls.certificate) out.push(obs('certificate', `sha256:${r.tls.certificate.sha256}`, s, { data: { names: r.tls.certificate.altNames, commonName: r.tls.certificate.subject, issuer: r.tls.certificate.issuer, notBefore: r.tls.certificate.validFrom, notAfter: r.tls.certificate.validTo, trusted: r.tls.trusted, domain: r.host } }));
  return out;
}

module.exports = { ipFindings, dnsFindings, domainFindings, certFindings, asnFindings, connectivityFindings };
