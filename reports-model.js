'use strict';
const { analyze, sourceSummary } = require('./evidence-correlator-analysis');
const { graphData } = require('./evidence-correlator-graph');
const { redactDeep } = require('./security-redact');
const { clone } = require('./utils-format');

function roundGps(value) {
  const parts = String(value).split(',').map((s) => Number(s.trim()));
  return parts.length === 2 && parts.every(Number.isFinite) ? `${parts[0].toFixed(2)}, ${parts[1].toFixed(2)} (rounded to about 1 km)` : '[withheld: GPS position]';
}

/**
 * Build everything a report shows. Sensitive values are withheld unless the person said otherwise,
 * and secrets are redacted last, so nothing private reaches a file by accident.
 * sensitive: { gps: 'exclude'|'round'|'include', personal: boolean, paths: boolean }
 */
function buildReportModel(inv, { analysis, sensitive = {}, secrets = [], now = Date.now, version = '1.0.0' } = {}) {
  const a = analysis || analyze(inv, { now });
  const opt = { gps: 'exclude', personal: false, paths: false, ...sensitive };
  const withheld = { gps: 0, personal: 0, paths: 0 };
  const withheldIds = new Set();
  const findings = inv.findings.map((f0) => {
    const f = clone(f0);
    if (!opt.paths && f.source && f.source.file && f.source.file.path) { delete f.source.file.path; withheld.paths++; }
    if (f.sensitive === 'gps' && opt.gps !== 'include') {
      if (opt.gps === 'round') { f.value = roundGps(f.value); f.data = null; f.note = 'GPS position rounded for sharing.'; } else { f.value = '[withheld: GPS position]'; f.data = null; f.withheld = 'gps'; withheld.gps++; withheldIds.add(f.id); }
    } else if (f.sensitive === 'personal-metadata' && !opt.personal) {
      f.value = '[withheld: personal metadata]'; f.data = null; f.withheld = 'personal'; withheld.personal++; withheldIds.add(f.id);
    } else if (f.sensitive === 'local-path' && !opt.paths) {
      f.value = '[withheld: local path]'; f.data = null; f.withheld = 'paths'; withheld.paths++; withheldIds.add(f.id);
    }
    f.investigationId = f.investigationId || inv.id;
    f.assessment = a.assessments[f.id];
    return f;
  });
  const byId = new Map(findings.map((f) => [f.id, f]));
  const contradictions = a.contradictions.map((c) => ({
    ...c, sides: c.sides.map((s) => (s.findings.some((x) => withheldIds.has(x.id)) ? { ...s, value: '[withheld]', normalized: '[withheld]' } : s)),
  }));
  const sources = new Map();
  for (const f of findings) {
    const s = f.source || {};
    const key = sourceSummary(f);
    if (!sources.has(key)) sources.set(key, { source: key, url: s.url || null, findings: 0, first: f.firstObserved, last: f.lastObserved });
    const g = sources.get(key);
    g.findings++;
    if (f.firstObserved < g.first) g.first = f.firstObserved;
    if (f.lastObserved > g.last) g.last = f.lastObserved;
  }
  const rel = a.relationships.filter((e) => byId.has(e.from) && byId.has(e.to));
  const gd = graphData({ findings }, { ...a, relationships: rel });
  const has = (pred) => findings.some(pred);
  const limitations = [
    'Findings are only as reliable as their sources. A search result or web page is a claim made by its author, not a verified fact.',
    'Confidence labels are plain categories produced by fixed rules. They are not probabilities and not scientific measurements.',
    'Several websites repeating one original report count as one source unless independence has been shown.',
    'Not finding something (a DNS record, an archive copy, a search hit) does not prove it does not exist.',
  ];
  if (has((f) => ['ip', 'network_registration', 'asn', 'ip_location'].includes(f.type))) limitations.push('IP registration country and any location are approximate. They often describe an internet provider, VPN, proxy or data centre, not a person.');
  if (has((f) => f.source && f.source.module === 'file-forensics')) limitations.push('File metadata is written by cameras and apps and can be edited or removed. Filesystem timestamps can be changed and do not prove when a file was created.');
  if (rel.some((e) => e.match === 'fuzzy')) limitations.push('Connections marked fuzzy are hints only. Similar names or handles do not show that two items are the same person or organisation.');
  if (withheld.gps || withheld.personal || withheld.paths) limitations.push(`Some sensitive details were withheld from this report (${[withheld.gps && `${withheld.gps} location`, withheld.personal && `${withheld.personal} personal-metadata`, withheld.paths && `${withheld.paths} local-path`].filter(Boolean).join(', ')}).`);
  if (!inv.methods.length && !inv.searches.length) limitations.push('No search methods were logged for this investigation, so how the evidence was gathered is not documented.');
  const last = findings.reduce((m, f) => (f.lastObserved > m ? f.lastObserved : m), '');
  if (last) limitations.push(`The most recent observation in this report is from ${last.slice(0, 10)}. Re-run key lookups to refresh them.`);
  const model = {
    title: inv.title, description: inv.description || '', investigationId: inv.id, createdAt: inv.createdAt,
    exportedAt: new Date(now()).toISOString(), generator: `Orkardch ${version}`,
    summary: { findings: findings.length, byConfidence: a.counts, contradictions: contradictions.length, connections: rel.length },
    methods: inv.methods, searches: (inv.searches || []).map((s) => ({ ranAt: s.ranAt, query: s.query, providers: s.providers, resultCount: s.resultCount })),
    findings, sources: [...sources.values()], contradictions, connections: rel.map((e) => ({ ...e, fromLabel: `${byId.get(e.from).type}: ${byId.get(e.from).value}`, toLabel: `${byId.get(e.to).type}: ${byId.get(e.to).value}` })),
    limitations, nextSteps: a.nextSteps, notes: inv.notes, graph: gd,
    privacy: { gps: opt.gps, personalMetadataIncluded: opt.personal, localPathsIncluded: opt.paths, withheld },
  };
  return redactDeep(model, secrets);
}

/** How many sensitive items does this investigation hold? Used to decide what to ask before exporting. */
function sensitiveInventory(inv) {
  const n = { gps: 0, personal: 0, paths: 0 };
  for (const f of inv.findings) {
    if (f.sensitive === 'gps') n.gps++;
    else if (f.sensitive === 'personal-metadata') n.personal++;
    if (f.source && f.source.file && f.source.file.path) n.paths++;
    if (f.sensitive === 'local-path') n.paths++;
  }
  return n;
}

module.exports = { buildReportModel, sensitiveInventory };
