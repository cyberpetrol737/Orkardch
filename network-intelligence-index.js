'use strict';
const net = require('net');
const { classifyIp } = require('./network-intelligence-ip');
const { EXPLAIN, interpretTxt, TYPES, lookupOrigin, lookupAsnName } = require('./network-intelligence-dns');
const rdap = require('./network-intelligence-rdap');
const { ctSearch, issuerName } = require('./network-intelligence-certs');
const diag = require('./network-intelligence-diagnostics');
const F = require('./network-intelligence-findings');
const { saveFindings } = require('./evidence-correlator-pick');
const { classifyInput, normalizeDomain, isValidDomain, isValidHostname, parseAsn } = require('./utils-validate');
const { mapLimit } = require('./core-concurrency');
const { truncate } = require('./utils-format');

const day = (iso) => (iso ? String(iso).slice(0, 10) : null);
const ago = (iso, now) => {
  if (!iso) return null;
  const d = (now - new Date(iso).getTime()) / 86400000;
  if (!Number.isFinite(d)) return null;
  if (d < 0) return 'in the future';
  return d < 60 ? `${Math.floor(d)} days ago` : d < 730 ? `${Math.floor(d / 30)} months ago` : `${(d / 365).toFixed(1)} years ago`;
};

function failLine(ui, label, err) {
  const msg = err ? `${err.message || err.code || 'failed'}` : 'failed';
  ui.warn(`${label}: ${msg}${err && err.hint ? ` ${err.hint}` : ''}`);
}

function showSource(ui, label, source, at) {
  if (source) ui.note(`Source: ${label} - ${truncate(source, 60)} (retrieved ${at ? String(at).replace('T', ' ').slice(0, 19) : '?'} UTC)`);
}

async function afterMenu(ctx, findingsFn, methodText) {
  await ctx.ask.menu({
    title: 'What next?', step: 'network.after',
    items: [
      { key: '1', label: 'Save these findings to an investigation', run: async () => { await saveFindings(ctx, findingsFn(), { module: 'network-intelligence', method: methodText }); } },
      { key: '2', label: 'Explain these results', aliases: ['explain'], run: () => require('./mother-index').explainResults(ctx) },
    ],
  });
}

// ---------------------------------------------------------------- IP
async function ipFlow(ctx, input) {
  const ui = ctx.ui;
  const c = classifyIp(input);
  if (!c.valid) { ctx.session.setError({ code: 'MALFORMED_IP', message: c.message }); ui.warn(c.message); return; }
  ctx.session.setInput('ip', c.address);
  ui.heading(`IP address ${c.address}`);
  ui.kv('Version', `IPv${c.version}${c.mappedFrom ? ' (written in IPv4-mapped form)' : ''}`);
  ui.kv('Kind', c.description);
  if (!c.public) {
    ui.para('This is not a public internet address, so there is no public registry owner or location for it. Orkardch made no network lookups.');
    ctx.session.setResult('ip', { ip: c.address, public: false, category: c.category });
    return;
  }
  if (!ctx.requireOnline(`look up ${c.address} in public registries`)) return;
  ui.note('Asking public registries (this sends the IP address to them)...');
  const [rd, origin, ptr] = await mapLimit([
    () => rdap.lookupIp(ctx, c.address), () => lookupOrigin(ctx, c.address), () => ctx.dns.reverse(c.address),
  ], ctx.config.get('maxParallelRequests'), (f) => f());
  let asnName = null;
  if (origin && origin.ok && origin.asns[0]) asnName = await lookupAsnName(ctx, origin.asns[0]);
  if (rd && rd.ok) {
    ui.heading('Registry record (RDAP)');
    if (rd.name) ui.kv('Network', `${rd.name}${rd.handle ? ` (${rd.handle})` : ''}`);
    if (rd.range) ui.kv('Address range', rd.range);
    if (rd.cidrs && rd.cidrs.length) ui.kv('CIDR', rd.cidrs.join(', '));
    if (rd.country) ui.kv('Registered country', rd.country);
    if (rd.registered) ui.kv('Registered', day(rd.registered));
    if (rd.lastChanged) ui.kv('Last changed', day(rd.lastChanged));
    if (rd.organizations.length) ui.kv('Organizations', rd.organizations.join('; '));
    showSource(ui, 'RDAP', rd.source, rd.retrievedAt);
  } else failLine(ui, 'Registry record', rd && rd.error);
  ui.heading('Routing (who announces this address)');
  if (origin && origin.ok) {
    ui.kv('Origin AS', origin.asns.map((a) => `AS${a}`).join(', ') + (asnName && asnName.ok && asnName.name ? ` (${asnName.name})` : ''));
    if (origin.prefix) ui.kv('Announced prefix', origin.prefix);
    if (origin.registry) ui.kv('Regional registry', origin.registry);
    showSource(ui, 'Team Cymru via DNS', origin.source, origin.retrievedAt);
  } else if (origin && origin.status === 'no-data') ui.note('No routing record found: this address may not be announced on the public internet.');
  else failLine(ui, 'Routing lookup', origin && (origin.error || { message: origin.status }));
  ui.heading('Reverse DNS (PTR)');
  if (ptr.status === 'ok') ptr.records.forEach((r) => ui.kv('Name', r.value)); else if (ptr.status === 'no-data' || ptr.status === 'nxdomain') ui.note('No reverse name is set for this address. That is common and not suspicious.'); else failLine(ui, 'Reverse lookup', ptr.error);
  if (ptr.note) ui.note(ptr.note);
  let geo = null;
  if (await ctx.ask.confirm('Also ask RIPEstat for an APPROXIMATE location? (Sends this IP to RIPE NCC)', { def: false, step: 'network.ip.geo' })) {
    geo = await rdap.lookupGeo(ctx, c.address);
    ui.heading('Approximate location (RIPEstat)');
    if (geo.ok && geo.locations.length) {
      geo.locations.forEach((l) => ui.kv('Place', [l.city, l.country].filter(Boolean).join(', ') + (l.coveredPercentage != null ? ` (${Math.round(l.coveredPercentage)}% of the block)` : '')));
    } else if (geo.ok) ui.note('No location is published for this address.'); else failLine(ui, 'Location lookup', geo.error);
  }
  ui.heading('How to read this');
  ui.para('The registry names who the address block was assigned to, not who is using it right now. An IP address does not reveal a person\'s name or home address. Any location shown is approximate and often points to an internet provider, VPN, proxy, company or data centre rather than to a person.');
  const result = { ip: c.address, classification: c, rdap: rd, origin, asnName, ptr, geo, at: new Date(ctx.services.now()).toISOString() };
  ctx.session.setResult('ip', { ip: c.address, public: true, rdapOk: Boolean(rd && rd.ok), originOk: Boolean(origin && origin.ok), ptrStatus: ptr.status, geoShown: Boolean(geo && geo.ok), failed: [!(rd && rd.ok) && 'registry', !(origin && origin.ok) && 'routing'].filter(Boolean) });
  await afterMenu(ctx, () => F.ipFindings(result), `Looked up public IP ${c.address} in RDAP, Team Cymru (DNS) and reverse DNS.`);
}

// ---------------------------------------------------------------- DNS display
function showDnsResult(ctx, r) {
  const ui = ctx.ui;
  const head = ui.c('bold', r.type);
  if (r.status === 'ok') {
    ui.print(`${head} - ${r.records.length} record${r.records.length === 1 ? '' : 's'}`);
    for (const rec of r.records.slice(0, 12)) {
      ui.para(`${rec.value}${rec.ttl != null ? `  (TTL ${rec.ttl}s)` : ''}`, '    ');
      if (r.type === 'TXT') { const n = interpretTxt(rec.value); if (n) ui.note(`    ${n}`); }
    }
    if (r.records.length > 12) ui.note(`    ...and ${r.records.length - 12} more`);
    if (r.cnameChain) ui.note(`    Alias chain: ${r.cnameChain.join('; ')}`);
  } else if (r.status === 'no-data') ui.print(`${head} - none (the name exists, but has no ${r.type} record)`);
  else if (r.status === 'nxdomain') ui.print(`${head} - the name does not exist in DNS (NXDOMAIN)`);
  else ui.print(`${head} - ${ui.c('red', 'lookup FAILED')}: ${r.error ? r.error.message : 'unknown problem'} This is not the same as "no record".`);
}

function dnsSourceNote(ctx, results) {
  const resolvers = [...new Set(results.map((r) => r.resolver).filter((r) => r && r !== 'none'))];
  const at = results.map((r) => r.retrievedAt).filter(Boolean).sort()[0];
  if (resolvers.length) ctx.ui.note(`Source: DNS answers via ${resolvers.join(', ')} (retrieved ${at ? String(at).replace('T', ' ').slice(0, 19) : '?'} UTC)`);
}

async function dnsFlow(ctx, name, type) {
  const ui = ctx.ui;
  if (!ctx.requireOnline('ask DNS')) return;
  ctx.session.setInput('dns name', name);
  const isIp = net.isIP(name);
  const types = type === 'ALL' ? TYPES : [type];
  ui.heading(`DNS for ${name}`);
  ui.note(`Asking the DNS system (${ctx.config.get('dns.mode')} mode). This sends the name to a DNS resolver.`);
  const results = isIp ? [await ctx.dns.reverse(name)] : await ctx.dns.resolveMany(name, types);
  for (const r of results) showDnsResult(ctx, r);
  dnsSourceNote(ctx, results);
  const notes = [...new Set(results.map((r) => r.note).filter(Boolean))];
  notes.forEach((n) => ui.note(n));
  if (!isIp && types.length === 1) ui.note(EXPLAIN[types[0]]);
  ctx.session.setResult('dns', { name, results: results.map((r) => ({ type: r.type, status: r.status, count: r.records.length, resolver: r.resolver, error: r.error && r.error.code })) });
  await afterMenu(ctx, () => F.dnsFindings(name, results), `Looked up DNS records (${types.join(', ')}) for ${name}.`);
}

// ---------------------------------------------------------------- domain
async function domainFlow(ctx, domain) {
  const ui = ctx.ui;
  if (!ctx.requireOnline('read public records for a domain')) return;
  ctx.session.setInput('domain', domain);
  ui.heading(`Domain ${domain}`);
  ui.note('Public records only: DNS and the registry (RDAP). Nothing connects to the site itself.');
  const [rd, dns] = await Promise.all([rdap.lookupDomain(ctx, domain), ctx.dns.resolveMany(domain, ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'CNAME', 'CAA'])]);
  ui.heading('DNS records');
  if (dns.every((r) => r.status === 'nxdomain')) ui.warn('This name does not exist in DNS (NXDOMAIN). Check the spelling, or it may not be registered.');
  else for (const r of dns) showDnsResult(ctx, r);
  dnsSourceNote(ctx, dns);
  [...new Set(dns.map((r) => r.note).filter(Boolean))].forEach((n) => ui.note(n));
  ui.heading('Registration (RDAP)');
  if (rd.ok) {
    if (rd.registrar) ui.kv('Registrar', rd.registrar + (rd.registrarIanaId ? ` (IANA ${rd.registrarIanaId})` : ''));
    if (rd.registered) ui.kv('Registered', `${day(rd.registered)} (${ago(rd.registered, ctx.services.now())})`);
    if (rd.expires) ui.kv('Expires', `${day(rd.expires)}${new Date(rd.expires) < ctx.services.now() ? ' (already passed)' : ''}`);
    if (rd.lastChanged) ui.kv('Last changed', day(rd.lastChanged));
    if (rd.status.length) ui.kv('Status', rd.status.join(', '));
    if (rd.nameservers.length) ui.kv('Name servers', rd.nameservers.join(', '));
    if (rd.dnssecSigned !== null) ui.kv('DNSSEC', rd.dnssecSigned ? 'signed' : 'not signed');
    if (rd.registrant) ui.kv('Registrant', rd.registrant.join('; ')); else ui.note(rd.registrantNote);
    showSource(ui, 'RDAP', rd.source, rd.retrievedAt);
  } else if (rd.error && rd.error.kind === 'not-found') ui.note('The registry has no record for this exact name. It may be a subdomain, or an unregistered or unsupported domain ending.');
  else failLine(ui, 'Registration lookup', rd.error);
  ui.note('Tip: [4] Certificates & subdomains lists names seen in public certificate logs.');
  ctx.session.setResult('domain', { domain, dns: dns.map((r) => ({ type: r.type, status: r.status, count: r.records.length, resolver: r.resolver, error: r.error && r.error.code })), rdapOk: rd.ok, rdapNotFound: Boolean(rd.error && rd.error.kind === 'not-found'), registrar: rd.registrar || null });
  const result = { domain, rdap: rd, dns, at: new Date(ctx.services.now()).toISOString() };
  await afterMenu(ctx, () => F.domainFindings(result), `Looked up public DNS records and RDAP registration data for ${domain}.`);
}

// ---------------------------------------------------------------- certificates
async function ensureAuthorized(ctx, host) {
  if (!ctx.authorized) ctx.authorized = new Set();
  if (ctx.authorized.has(host)) return true;
  ctx.ui.warn('Active checks connect directly to the target. Only continue for systems you own or have clear permission to test.');
  const ok = await ctx.ask.confirm(`Do you own ${host} or have permission to test it?`, { def: false, step: 'network.authorize' });
  if (ok) ctx.authorized.add(host);
  return ok;
}

function showLiveCert(ctx, live) {
  const ui = ctx.ui;
  if (!live.ok) { failLine(ui, 'Live certificate', live.error); return; }
  const c = live.certificate;
  ui.heading('Live certificate (this moment)');
  ui.kv('Trusted by this phone', live.trusted ? 'yes' : `NO - ${live.trustError || 'not verified'}`);
  if (c) {
    ui.kv('Issued to', c.subject || '?'); ui.kv('Issuer', c.issuer || '?');
    ui.kv('Valid', `${day(c.validFrom)} to ${day(c.validTo)}${c.daysRemaining !== null ? (c.expired ? ' (EXPIRED)' : ` (${c.daysRemaining} days left)`) : ''}`);
    if (c.altNames.length) ui.kv('Names covered', c.altNames.slice(0, 6).join(', ') + (c.altNames.length > 6 ? ', ...' : ''));
    if (c.nameMatchesHost !== null) ui.kv('Matches the name asked', c.nameMatchesHost ? 'yes' : 'NO');
    ui.kv('SHA-256', c.sha256 || '?');
  }
  ui.kv('Protocol', `${live.protocol || '?'}${live.cipher ? `, ${live.cipher}` : ''}`);
}

async function certFlow(ctx, domain) {
  const ui = ctx.ui;
  if (!ctx.requireOnline('search certificate logs')) return;
  ctx.session.setInput('domain', domain);
  ui.heading(`Certificates for ${domain}`);
  ui.note('Searching public certificate-transparency logs through crt.sh (this can take a while).');
  const ct = ctx.prompter && ctx.prompter.cancellable ? await ctx.prompter.cancellable((signal) => ctSearchSignal(ctx, domain, signal)) : await ctSearch(ctx, domain);
  if (!ct.ok) { failLine(ui, 'Certificate search', ct.error); ctx.session.setError(ct.error); return; }
  ui.kv('Certificates found', `${ct.total}${ct.truncated ? ' (answer was cut short)' : ''}`);
  ui.kv('Names seen', String(ct.subdomains.length));
  const issuers = {};
  ct.certificates.forEach((c) => { const n = issuerName(c.issuer); issuers[n] = (issuers[n] || 0) + 1; });
  const top = Object.entries(issuers).sort((a, b) => b[1] - a[1]).slice(0, 3);
  if (top.length) ui.kv('Main issuers', top.map(([n, k]) => `${n} (${k})`).join('; '));
  ui.heading('Newest certificates');
  ct.certificates.slice(0, 5).forEach((c) => ui.para(`#${c.id}  ${day(c.notBefore)} to ${day(c.notAfter)}  ${c.commonName || ''}`, '  '));
  ui.heading('Names seen in the logs');
  ct.subdomains.slice(0, 15).forEach((s) => ui.print(`  ${s}`));
  if (ct.subdomains.length > 15) ui.note(`...and ${ct.subdomains.length - 15} more (save to an investigation to keep them all).`);
  showSource(ui, 'crt.sh', ct.requestUrl, ct.retrievedAt);
  ui.note('These logs list certificates that were ISSUED. A name may no longer exist, and the list is not complete.');
  let live = null;
  ctx.session.setResult('certificates', { domain, total: ct.total, names: ct.subdomains.length });
  await ctx.ask.menu({
    title: 'What next?', step: 'network.certs.after',
    items: [
      {
        key: '1', label: 'Check the live certificate now (connects to the site)', run: async () => {
          if (!(await ensureAuthorized(ctx, domain))) { ui.note('Skipped. No connection was made.'); return; }
          live = await diag.tlsProbe(ctx, domain, { authorized: true });
          showLiveCert(ctx, live);
        },
      },
      { key: '2', label: 'Save these findings to an investigation', run: async () => { await saveFindings(ctx, F.certFindings({ domain, ct, live }), { module: 'network-intelligence', method: `Searched certificate transparency logs (crt.sh) for ${domain}${live ? ' and read its live certificate' : ''}.` }); } },
      { key: '3', label: 'Explain these results', aliases: ['explain'], run: () => require('./mother-index').explainResults(ctx) },
    ],
  });
}

async function ctSearchSignal(ctx, domain, signal) {
  if (signal.aborted) return { ok: false, error: { message: 'Cancelled.' } };
  const p = ctSearch(ctx, domain);
  return Promise.race([p, new Promise((resolve) => signal.addEventListener('abort', () => resolve({ ok: false, error: { kind: 'aborted', message: 'Cancelled.' } }), { once: true }))]);
}

// ---------------------------------------------------------------- ASN
async function asnFlow(ctx, asn) {
  const ui = ctx.ui;
  if (!ctx.requireOnline('look up a network owner')) return;
  ctx.session.setInput('asn', `AS${asn}`);
  ui.heading(`AS${asn}`);
  ui.note('Asking Team Cymru (DNS) and the registries (RDAP).');
  const [name, rd] = await Promise.all([lookupAsnName(ctx, asn), rdap.lookupAsn(ctx, asn)]);
  if (name.ok) { ui.kv('Name', name.name || '?'); ui.kv('Country', name.country || '?'); ui.kv('Registry', name.registry || '?'); if (name.allocated) ui.kv('Allocated', name.allocated); showSource(ui, 'Team Cymru via DNS', name.source, name.retrievedAt); } else failLine(ui, 'AS name lookup', name.error || { message: name.status });
  if (rd.ok) { ui.heading('Registry record (RDAP)'); ui.kv('Name', rd.name || '?'); if (rd.country) ui.kv('Country', rd.country); if (rd.registered) ui.kv('Registered', day(rd.registered)); if (rd.organizations.length) ui.kv('Organizations', rd.organizations.join('; ')); showSource(ui, 'RDAP', rd.source, rd.retrievedAt); } else failLine(ui, 'Registry record', rd.error);
  ui.note('An AS (autonomous system) is a network run by one organisation, such as an ISP or a company. Its number is how networks identify each other on the internet.');
  ctx.session.setResult('asn', { asn, nameOk: name.ok, rdapOk: rd.ok });
  await afterMenu(ctx, () => F.asnFindings({ asn, name, rdap: rd }), `Looked up AS${asn} in Team Cymru (DNS) and RDAP.`);
}

// ---------------------------------------------------------------- connectivity
async function connectivityFlow(ctx, target) {
  const ui = ctx.ui;
  if (!ctx.requireOnline('run connectivity checks')) return;
  let host = target;
  let url = null;
  const cls = classifyInput(target);
  if (cls.kind === 'ip' || cls.kind === 'domain' || cls.kind === 'hostname') host = cls.value;
  if (/^https?:\/\//i.test(target)) url = target;
  if (!(await ensureAuthorized(ctx, host))) { ui.note('Skipped. No connection was made.'); return; }
  const port = Number(await ctx.ask.text('Port to test:', { default: '443', step: 'network.port', validate: (v) => (/^\d+$/.test(v) && Number(v) > 0 && Number(v) < 65536 ? null : 'Enter a port number from 1 to 65535.') }));
  ctx.session.setInput('host', host);
  ui.heading(`Connectivity: ${host}`);
  const result = { host, at: new Date(ctx.services.now()).toISOString() };
  if (!net.isIP(host)) {
    result.dns = await ctx.dns.resolveMany(host, ['A', 'AAAA']);
    ui.heading('1. Name lookup');
    result.dns.forEach((r) => showDnsResult(ctx, r));
  }
  ui.heading(`2. TCP connection to port ${port}`);
  result.latency = await diag.tcpLatency(ctx, host, port, { count: 4, authorized: true, timeoutMs: ctx.config.get('requestTimeoutMs') });
  if (result.latency.ok) ui.para(`${result.latency.successes}/${result.latency.attempts} connections worked. Time: min ${result.latency.minMs} ms, average ${result.latency.avgMs} ms, max ${result.latency.maxMs} ms. ${result.latency.lossPercent}% lost.`, '  ');
  else failLine(ui, 'Connection', result.latency.error);
  if (result.latency.ok && (port === 443 || url)) {
    ui.heading('3. Secure connection (TLS)');
    result.tls = await diag.tlsProbe(ctx, host, { port, authorized: true, timeoutMs: ctx.config.get('requestTimeoutMs') });
    showLiveCert(ctx, result.tls);
  }
  if (result.latency.ok) {
    const scheme = port === 443 ? 'https' : port === 80 ? 'http' : (result.tls && result.tls.ok ? 'https' : 'http');
    const probeUrl = url || `${scheme}://${host}${[80, 443].includes(port) ? '' : `:${port}`}/`;
    ui.heading(`4. Web request (${probeUrl})`);
    result.http = await diag.httpProbe(ctx, probeUrl, { authorized: true, timeoutMs: ctx.config.get('requestTimeoutMs') });
    if (result.http.ok) {
      ui.kv('Answer', `${result.http.status} ${result.http.statusText}`);
      const t = result.http.timing;
      ui.kv('Timing', [t.dnsMs != null && `name ${t.dnsMs} ms`, t.connectMs != null && `connect ${t.connectMs} ms`, t.tlsMs != null && `secure ${t.tlsMs} ms`, `first byte ${t.firstByteMs} ms`].filter(Boolean).join(', '));
      if (result.http.redirectTo) ui.kv('Redirects to', result.http.redirectTo);
      if (result.http.server) ui.kv('Server', result.http.server);
    } else failLine(ui, 'Web request', result.http.error);
  }
  ctx.session.setResult('connectivity', { host, port, tcpOk: Boolean(result.latency && result.latency.ok), tlsOk: Boolean(result.tls && result.tls.ok), tlsTrusted: Boolean(result.tls && result.tls.trusted), httpStatus: result.http && result.http.ok ? result.http.status : null, errors: [result.latency && !result.latency.ok && result.latency.error && result.latency.error.kind, result.http && !result.http.ok && result.http.error && result.http.error.kind].filter(Boolean) });
  await afterMenu(ctx, () => F.connectivityFindings(result), `Ran authorized connectivity checks against ${host}:${port}.`);
}

// ---------------------------------------------------------------- menu
const ask = (ctx, label, validate, step) => ctx.ask.text(label, { step, validate });

async function run(ctx) {
  const ui = ctx.ui;
  ui.heading('IP & Network Intelligence');
  ui.para('Look up who runs an IP address or domain, what its DNS says, and which certificates were issued for it. These use public records. Checks that connect to a target need your confirmation first.');
  if (ctx.net.offline) ui.warn('Offline mode is ON, so lookups will not run. Turn it off in Settings.');
  await ctx.ask.menu({
    step: 'network.menu',
    items: [
      { key: '1', label: 'An IP address', aliases: ['ip', 'address'], run: async () => ipFlow(ctx, await ask(ctx, 'IP address (for example 192.0.2.1):', null, 'network.ip.input')) },
      {
        key: '2', label: 'A domain or hostname', aliases: ['domain', 'hostname'], run: async () => {
          const d = normalizeDomain(await ask(ctx, 'Domain (for example example.com):', (v) => (isValidHostname(normalizeDomain(v)) ? null : 'That does not look like a domain name. Example: example.com'), 'network.domain.input'));
          return domainFlow(ctx, d);
        },
      },
      {
        key: '3', label: 'DNS records', aliases: ['dns', 'records'], run: async () => {
          const name = await ask(ctx, 'Name or IP address:', (v) => (net.isIP(v) || isValidHostname(normalizeDomain(v)) ? null : 'Enter a domain name or an IP address.'), 'network.dns.input');
          const isIp = net.isIP(name);
          const type = isIp ? 'PTR' : (await ctx.ask.text('Record type (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA) or "all":', { default: 'all', step: 'network.dns.type', validate: (v) => (['all', ...TYPES].includes(v.toUpperCase()) || v.toLowerCase() === 'all' ? null : 'Choose A, AAAA, MX, NS, TXT, CNAME, SOA, CAA or all.') })).toUpperCase();
          return dnsFlow(ctx, isIp ? name : normalizeDomain(name), type);
        },
      },
      {
        key: '4', label: 'Certificates & subdomains (public logs)', aliases: ['certificates', 'certs', 'subdomains'], run: async () => {
          const d = normalizeDomain(await ask(ctx, 'Domain you own or are authorized to assess:', (v) => (isValidDomain(normalizeDomain(v)) ? null : 'Enter a registered domain such as example.com'), 'network.certs.input'));
          return certFlow(ctx, d);
        },
      },
      {
        key: '5', label: 'A network owner (ASN)', aliases: ['asn', 'network'], run: async () => {
          const raw = await ask(ctx, 'AS number (for example AS64500):', (v) => (parseAsn(v) || parseAsn(`AS${v}`) ? null : 'Type AS followed by a number, such as AS64500.'), 'network.asn.input');
          return asnFlow(ctx, parseAsn(raw) || parseAsn(`AS${raw}`));
        },
      },
      {
        key: '6', label: 'Connectivity check (only for systems you own)', aliases: ['connectivity', 'ping', 'test'], run: async () => {
          const t = await ask(ctx, 'Host or web address to test:', (v) => (classifyInput(v).kind === 'invalid' ? 'Enter a domain, IP address or full web address.' : null), 'network.conn.input');
          return connectivityFlow(ctx, t);
        },
      },
    ],
  });
}

module.exports = { id: 'network', title: 'IP & Network Intelligence', run, ipFlow, domainFlow, dnsFlow, certFlow, asnFlow, connectivityFlow, showDnsResult };
