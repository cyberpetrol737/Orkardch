'use strict';
const { normalizeUrl, urlHost, registrableDomain } = require('./utils-validate');
const { truncate } = require('./utils-format');

/** Plain categories. No numeric scores: a number would suggest precision that does not exist. */
const LEVELS = {
  confirmed_direct: 'Confirmed by direct observation',
  multi_independent: 'Supported by multiple independent sources',
  plausible: 'Plausible but unverified',
  conflicting: 'Conflicting evidence',
  unknown: 'Unknown',
};
const INTERNAL_MODULES = new Set(['file-forensics', 'network-intelligence', 'web-intelligence']);
const IDENTIFIER_TYPES = new Set(['email', 'phone', 'domain', 'ip', 'file_hash', 'hash', 'asn', 'username']);
const CORP_WORDS = new Set(['inc', 'incorporated', 'llc', 'ltd', 'limited', 'corp', 'corporation', 'co', 'company', 'gmbh', 'sa', 'ag', 'plc', 'srl', 'bv', 'the']);

const squash = (s) => String(s).toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/\s+/g, ' ').trim();

function normValue(type, value) {
  const v = String(value).trim();
  switch (type) {
    case 'domain': case 'subdomain': return v.toLowerCase().replace(/\.$/, '');
    case 'ip': case 'file_hash': case 'hash': case 'email': return v.toLowerCase();
    case 'url': case 'source': case 'archive_capture': return normalizeUrl(v) || v.toLowerCase();
    case 'username': case 'profile': return v.toLowerCase().replace(/^@/, '');
    default: return squash(v);
  }
}

function dateKey(v) {
  const s = String(v).trim();
  const iso = /^(\d{4})-(\d{2})-(\d{2})/.exec(s);
  if (iso) return `${iso[1]}-${iso[2]}-${iso[3]}`;
  const ex = /^(\d{4}):(\d{2}):(\d{2})/.exec(s);
  if (ex) return `${ex[1]}-${ex[2]}-${ex[3]}`;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return null;
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
const isDateAttr = (a) => /date|created|modified|published|expir|registered|founded/i.test(a || '');
const isNameAttr = (a) => /name|organi[sz]ation|registrant|registrar|owner|company|author/i.test(a || '');

function orgKey(v) {
  return squash(v).replace(/[^\p{L}\p{N} ]/gu, ' ').split(' ').filter((t) => t && !CORP_WORDS.has(t)).join(' ');
}
function compareKey(attribute, value) {
  if (isDateAttr(attribute)) { const d = dateKey(value); if (d) return d; }
  if (isNameAttr(attribute)) return orgKey(value) || squash(value);
  return squash(value);
}
function tokenSim(a, b) {
  const A = new Set(a.split(' ').filter(Boolean));
  const B = new Set(b.split(' ').filter(Boolean));
  if (!A.size || !B.size) return 0;
  let n = 0;
  for (const t of A) if (B.has(t)) n++;
  return n / (A.size + B.size - n);
}
function lev(a, b) {
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > 2) return 3;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[n];
}

/** Which independent origin does this finding come from? Same website or publisher = same origin. */
function originKey(f) {
  const s = f.source || {};
  if (s.url) { const h = urlHost(s.url); if (h) return `site:${registrableDomain(h)}`; }
  if (s.publisher) return `publisher:${squash(s.publisher)}`;
  if (s.file && s.file.sha256) return `file:${s.file.sha256}`;
  return `${s.module || 'unknown'}:${s.provider || ''}`;
}
const hasProvenance = (f) => Boolean(f.source && (f.source.url || f.source.file || f.source.description || f.source.publisher || f.source.provider));

function sourceSummary(f) {
  const s = f.source || {};
  const where = s.url || (s.file && (s.file.name || s.file.path)) || s.publisher || s.description || s.provider || s.module || 'no source recorded';
  return `${s.module || '?'}${s.provider ? ` / ${s.provider}` : ''}: ${truncate(where, 80)}`;
}

function implicitSubjectAttribute(f) {
  if (f.subject && f.attribute) return { subject: f.subject, attribute: f.attribute };
  return null;
}

function detectContradictions(findings) {
  const groups = new Map();
  for (const f of findings) {
    const sa = implicitSubjectAttribute(f);
    if (!sa) continue;
    const key = `${squash(sa.subject)}|${squash(sa.attribute)}`;
    if (!groups.has(key)) groups.set(key, { subject: sa.subject, attribute: sa.attribute, items: [] });
    groups.get(key).items.push(f);
  }
  const out = [];
  for (const g of groups.values()) {
    const sides = new Map();
    for (const f of g.items) {
      const k = compareKey(g.attribute, f.value);
      if (!sides.has(k)) sides.set(k, { value: f.value, normalized: k, findings: [] });
      sides.get(k).findings.push({ id: f.id, source: sourceSummary(f), observedAt: f.firstObserved, statementType: f.statementType });
    }
    if (sides.size < 2) continue;
    const sideList = [...sides.values()];
    const all = g.items;
    const allObs = all.every((f) => f.statementType === 'observation');
    const times = all.map((f) => new Date(f.firstObserved).getTime()).filter(Number.isFinite);
    const spread = times.length ? Math.max(...times) - Math.min(...times) : 0;
    let kind = 'conflict';
    let note = 'These sources disagree. Orkardch does not pick a side: check which one is closest to the original.';
    if (allObs && spread >= 3600000) { kind = 'changed-between-observations'; note = 'These were observed at different times, so this may be a legitimate change rather than an error. Compare the timestamps.'; }
    else if (isNameAttr(g.attribute) && sideList.length === 2 && tokenSim(sideList[0].normalized, sideList[1].normalized) >= 0.8) { kind = 'possible-variant'; note = 'These look like spelling or formatting variants of the same name. Check before treating them as a real disagreement.'; }
    out.push({ subject: g.subject, attribute: g.attribute, kind, note, sides: sideList, findingIds: all.map((f) => f.id) });
  }
  return out;
}

function discoverRelationships(findings) {
  const edges = [];
  const seen = new Set();
  const add = (from, to, relation, match, basis, caution) => {
    if (!from || !to || from === to) return;
    const k = `${from}|${to}|${relation}`;
    if (seen.has(k) || edges.length >= 1500) return;
    seen.add(k);
    edges.push({ from, to, relation, match, basis, ...(caution ? { caution } : {}) });
  };
  const byKey = new Map();
  const push = (m, k, f) => { if (!m.has(k)) m.set(k, []); m.get(k).push(f); };
  for (const f of findings) push(byKey, `${f.type}|${normValue(f.type, f.value)}`, f);

  // 1. identical values seen more than once
  for (const [k, list] of byKey) {
    if (list.length < 2) continue;
    const type = k.split('|')[0];
    if (type === 'claim') continue; // claims get the more informative "same claim" relation below
    const rel = type === 'file_hash' ? 'identical file contents (same SHA-256)' : 'same value';
    for (const other of list.slice(1)) add(list[0].id, other.id, rel, 'exact', `identical ${type} value`);
  }
  const find = (type, norm) => byKey.get(`${type}|${norm}`) || [];

  for (const f of findings) {
    const d = f.data || {};
    // 2. DNS records
    if (f.type === 'dns_record' && d.domain) {
      for (const dom of find('domain', normValue('domain', d.domain))) add(dom.id, f.id, 'has DNS record', 'structural', 'record is for this exact domain name');
      if ((d.recordType === 'A' || d.recordType === 'AAAA') && d.value) for (const ip of find('ip', normValue('ip', d.value))) add(f.id, ip.id, 'resolves to', 'exact', 'the record\'s address equals this IP');
      if (d.recordType === 'PTR' && d.queried) for (const ip of find('ip', normValue('ip', d.queried))) add(ip.id, f.id, 'has reverse DNS', 'structural', 'PTR answer for this IP');
    }
    // 3. certificates
    if (f.type === 'certificate') {
      const names = (Array.isArray(d.names) ? d.names : []).map((n) => String(n).toLowerCase());
      for (const dm of findings.filter((x) => x.type === 'domain')) {
        const n = normValue('domain', dm.value);
        if (names.includes(n)) add(f.id, dm.id, 'certificate names this domain', 'exact', 'domain appears in the certificate\'s names');
        else if (names.some((x) => x.startsWith('*.') && n.endsWith(x.slice(1)) && n.split('.').length === x.split('.').length)) add(f.id, dm.id, 'wildcard certificate covers', 'structural', 'wildcard name matches this domain', 'A wildcard covers many names; it does not mean the domain was named on purpose.');
        else if (d.domain && normValue('domain', d.domain) === n) add(f.id, dm.id, 'found in certificate logs for', 'structural', 'search was made for this domain');
      }
    }
    // 4. subdomains
    if (f.type === 'subdomain' && d.parent) for (const dm of find('domain', normValue('domain', d.parent))) add(f.id, dm.id, 'subdomain of', 'structural', 'name ends with the parent domain');
    // 5. claims made in sources
    if (f.type === 'claim' && f.source && f.source.url) {
      const u = normalizeUrl(f.source.url);
      for (const s of findings.filter((x) => x.type === 'source')) if (u && (normalizeUrl(s.value) === u || (s.data && normalizeUrl(s.data.url || '') === u))) add(f.id, s.id, 'claim made in source', 'exact', 'claim\'s source address equals this source');
    }
    // 10. subject points at another finding's value
    if (f.subject) {
      const subj = String(f.subject);
      const cand = [];
      if (subj.startsWith('file:')) cand.push(...find('file_hash', subj.slice(5).toLowerCase()));
      cand.push(...find('ip', subj.toLowerCase()), ...find('domain', subj.toLowerCase()), ...find('source', normalizeUrl(subj) || subj.toLowerCase()), ...find('asn', subj.toLowerCase()));
      for (const c of cand) add(f.id, c.id, 'is about', 'structural', 'its subject equals this finding\'s value');
    }
  }

  // 6. same claim in several sources (repeating is not corroboration by itself)
  const claimGroups = new Map();
  for (const f of findings) if (f.type === 'claim' || (f.subject && f.attribute && f.statementType === 'claim')) push(claimGroups, `${squash(f.subject || '')}|${squash(f.attribute || '')}|${compareKey(f.attribute, f.value)}`, f);
  for (const list of claimGroups.values()) {
    if (list.length < 2) continue;
    for (const o of list.slice(1)) add(list[0].id, o.id, 'same claim', 'exact', 'same subject, property and value', 'Repeating a claim is not proof. Check whether these sources are independent.');
  }

  // 7. usernames
  const names = findings.filter((f) => f.type === 'username' || f.type === 'profile').slice(0, 300);
  for (let i = 0; i < names.length; i++) {
    for (let j = i + 1; j < names.length; j++) {
      const a = normValue('username', names[i].value);
      const b = normValue('username', names[j].value);
      if (a === b) { if (names[i].source.url !== names[j].source.url) add(names[i].id, names[j].id, 'same handle text', 'exact', 'identical username text', 'The same text does not prove the same person. Many people choose the same names.'); continue; }
      const sa = a.replace(/[._-]/g, '');
      const sb = b.replace(/[._-]/g, '');
      if (sa === sb || (sa.length >= 5 && lev(sa, sb) <= 1)) add(names[i].id, names[j].id, 'similar handle', 'fuzzy', 'differs only by punctuation or one character', 'Similar names are weak hints, not links between people.');
    }
  }

  // 8. organisation names (fuzzy)
  const orgs = findings.filter((f) => f.type === 'organization' || f.type === 'organisation').slice(0, 300);
  for (let i = 0; i < orgs.length; i++) {
    for (let j = i + 1; j < orgs.length; j++) {
      const a = orgKey(orgs[i].value);
      const b = orgKey(orgs[j].value);
      if (a === b && squash(orgs[i].value) !== squash(orgs[j].value)) add(orgs[i].id, orgs[j].id, 'same name apart from company suffix', 'fuzzy', 'names match after removing Inc/Ltd/etc.', 'Different companies can share names.');
      else if (a !== b && tokenSim(a, b) >= 0.8) add(orgs[i].id, orgs[j].id, 'similar organisation name', 'fuzzy', 'most words are shared', 'Similar names are not proof of the same organisation.');
    }
  }

  // 9. shared verified identifiers
  const idMap = new Map();
  for (const f of findings.filter((x) => x.verification === 'verified-by-user')) {
    const ids = [...(Array.isArray(f.data && f.data.identifiers) ? f.data.identifiers : []), ...(IDENTIFIER_TYPES.has(f.type) ? [{ type: f.type, value: f.value }] : [])];
    for (const i of ids) if (i && i.type && i.value) push(idMap, `${i.type}|${normValue(i.type, i.value)}`, f);
  }
  for (const [k, list] of idMap) {
    if (list.length < 2) continue;
    for (const o of list.slice(1)) add(list[0].id, o.id, `shared verified ${k.split('|')[0]}`, 'exact', 'both findings were verified by you and share this identifier');
  }
  return edges;
}

function assessAll(findings, contradictions) {
  const byId = new Map(findings.map((f) => [f.id, f]));
  const conflicted = new Map();
  for (const c of contradictions) if (c.kind === 'conflict') for (const id of c.findingIds) conflicted.set(id, c);
  const claimKey = (f) => `${f.type}|${squash(f.subject || '')}|${squash(f.attribute || '')}|${f.subject ? compareKey(f.attribute, f.value) : normValue(f.type, f.value)}`;
  const groups = new Map();
  for (const f of findings) {
    if (f.statementType === 'inference') continue;
    if (f.statementType === 'observation' && INTERNAL_MODULES.has(f.source && f.source.module)) continue;
    const k = claimKey(f);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(f);
  }
  const effectiveOrigin = (f) => {
    if (f.independence && f.independence.status === 'derived') {
      const parent = f.independence.derivedFrom && byId.get(f.independence.derivedFrom);
      return parent ? originKey(parent) : `derived:${f.id}`;
    }
    return originKey(f);
  };
  const userConflicts = new Set();
  for (const f of findings) for (const ref of f.contradicting || []) if (ref.findingId && byId.has(ref.findingId)) { userConflicts.add(f.id); userConflicts.add(ref.findingId); }
  const out = {};
  for (const f of findings) {
    const reasons = [];
    let level;
    const date = String(f.firstObserved || '').slice(0, 10);
    if (!hasProvenance(f)) { level = 'unknown'; reasons.push('No record of where this came from. Add a source to make it checkable.'); }
    else if (f.verification === 'disputed') { level = 'conflicting'; reasons.push('You marked this as disputed.'); }
    else if (userConflicts.has(f.id)) { level = 'conflicting'; reasons.push('You linked evidence that contradicts this (or this contradicts another finding).'); }
    else if (conflicted.has(f.id)) { level = 'conflicting'; const c = conflicted.get(f.id); reasons.push(`Conflicts with other evidence about "${c.subject} / ${c.attribute}" (see the contradiction list).`); }
    else if (f.statementType === 'observation' && INTERNAL_MODULES.has(f.source.module)) {
      level = 'confirmed_direct';
      reasons.push(`Orkardch observed this directly on ${date} (${f.source.provider || f.source.module}). That confirms what the source returned, not that the real-world statement is true.`);
      if (f.data && f.data.selfReported) reasons.push('The value is self-reported by the file or page and can be edited by whoever made it.');
    } else if (f.statementType === 'inference') { level = 'plausible'; reasons.push('This is an inference, not something directly observed.'); }
    else {
      const members = groups.get(claimKey(f)) || [f];
      const origins = new Set(members.map(effectiveOrigin));
      const independentFlags = members.filter((m) => m.independence && m.independence.status === 'independent');
      const independentOrigins = new Set(independentFlags.map(effectiveOrigin));
      if (origins.size >= 2 && independentFlags.length >= 2 && independentOrigins.size >= 2) { level = 'multi_independent'; reasons.push(`${origins.size} different origins support this, and you confirmed at least two are independent of each other.`); }
      else if (origins.size >= 2) { level = 'plausible'; reasons.push(`${origins.size} sources repeat this, but their independence is not established. Several websites repeating one original report count as ONE source. If you checked that they are independent, mark them as independent.`); }
      else if (members.length >= 2) { level = 'plausible'; reasons.push('Repeated, but every copy comes from the same origin, so it counts as one source.'); }
      else { level = 'plausible'; reasons.push(f.source.module === 'manual' || f.source.module === 'import' ? 'Recorded by hand or imported, so Orkardch cannot verify it. A single source has not been cross-checked.' : 'A single source says this and it has not been cross-checked.'); }
    }
    if ((f.supporting || []).length) reasons.push(`${f.supporting.length} item(s) you linked as supporting evidence (they do not change the category by themselves).`);
    if (f.verification === 'verified-by-user') reasons.push('You marked this as verified (see your notes for how).');
    out[f.id] = { level, label: LEVELS[level], reasons };
  }
  return out;
}

function nextSteps(findings, analysis) {
  const steps = [];
  const lv = (l) => findings.filter((f) => analysis.assessments[f.id].level === l);
  if (analysis.contradictions.some((c) => c.kind === 'conflict')) steps.push('Resolve each contradiction: find the original or primary source (official record, registry entry, archive copy) and see which version it supports.');
  if (analysis.contradictions.some((c) => c.kind === 'changed-between-observations')) steps.push('For values that changed between observations, compare timestamps and check archives to see when and why they changed.');
  const single = lv('plausible').filter((f) => f.statementType !== 'inference');
  if (single.length) steps.push(`Seek an independent source for the ${single.length} plausible-but-unverified finding(s). Look for sources that did not copy each other.`);
  if (lv('unknown').length) steps.push(`Add a source (link, file or description) to the ${lv('unknown').length} finding(s) with unknown provenance.`);
  if (findings.some((f) => f.sensitive)) steps.push('Some findings are marked sensitive (location or personal details). Review them before sharing any export.');
  if (analysis.relationships.some((e) => e.match === 'fuzzy')) steps.push('Fuzzy matches are only hints. Confirm them with an exact, verifiable identifier before treating two items as the same.');
  if (!findings.length) steps.push('Add evidence first: run a module and save its findings, or add evidence by hand.');
  if (!steps.length) steps.push('Re-run key lookups later to check whether anything has changed.');
  return steps;
}

/** Everything the correlator can say about an investigation, computed fresh (stored evidence is never modified). */
function analyze(inv, { now = Date.now } = {}) {
  const findings = inv.findings;
  const contradictions = detectContradictions(findings);
  const relationships = discoverRelationships(findings);
  const assessments = assessAll(findings, contradictions);
  const counts = {};
  for (const f of findings) counts[assessments[f.id].level] = (counts[assessments[f.id].level] || 0) + 1;
  const result = { generatedAt: new Date(now()).toISOString(), assessments, relationships, contradictions, counts };
  result.nextSteps = nextSteps(findings, result);
  return result;
}

module.exports = { analyze, LEVELS, normValue, compareKey, originKey, detectContradictions, discoverRelationships, assessAll, sourceSummary, hasProvenance };
