'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const zlib = require('zlib');
const path = require('path');
const crypto = require('crypto');
const { makeCtx } = require('./tests-helpers-ctx');
const { analyze, detectContradictions } = require('./evidence-correlator-analysis');
const { renderTextGraph } = require('./evidence-correlator-graph');

const T0 = '2026-03-01T10:00:00.000Z';
const store = () => { const t = makeCtx(); const inv = t.ctx.store.create('Case'); return { ...t, store: t.ctx.store, inv }; };
const add = (s, inv, raws, defaults) => s.addFindings(inv.id, raws, defaults).added;
const web = (url, publisher) => ({ module: 'web-intelligence', provider: 'duckduckgo', url, publisher, retrievedAt: T0 });
const claim = (value, source, extra = {}) => ({ type: 'claim', value, statementType: 'claim', subject: 'Acme Corp', attribute: 'founding year', source, ...extra });
const levels = (a, findings) => Object.fromEntries(findings.map((f) => [f.id, a.assessments[f.id].level]));

test('records are validated with plain reasons; valid ones are kept even when others are rejected', () => {
  const t = store();
  const r = t.store.addFindings(t.inv.id, [
    { type: 'domain', value: 'example.org' }, { type: '', value: 'x' }, { type: 'claim' }, { type: 'claim', value: 'x'.repeat(5000) }, { type: 'claim', value: 'ok', statementType: 'rumour' }, 'not an object',
  ]);
  assert.equal(r.added.length, 1);
  assert.equal(r.errors.length, 5);
  assert.match(r.errors[0].message, /"type" is required/);
  assert.match(r.errors[1].message, /"value" is required/);
  assert.match(r.errors[2].message, /too long/);
  assert.match(r.errors[3].message, /statementType/);
  const f = r.added[0];
  assert.match(f.id, /^f_[a-f0-9]+$/);
  assert.equal(f.statementType, 'claim', 'unspecified kinds default to the cautious "claim"');
  assert.equal(f.verification, 'unverified');
  assert.ok(f.firstObserved && f.lastObserved);
  t.cleanup();
});

test('stored evidence is never altered by notes, verification or independence changes', () => {
  const t = store();
  const [f] = add(t.store, t.inv, [claim('Founded in 2010', web('https://a.example.com/x', 'A'))]);
  const before = JSON.parse(JSON.stringify(t.store.load(t.inv.id).findings[0]));
  t.store.addFindingNote(t.inv.id, f.id, 'checked the archive');
  t.store.setVerification(t.inv.id, f.id, 'verified-by-user', 'compared with printed brochure');
  t.store.setIndependence(t.inv.id, f.id, { status: 'independent' });
  const n = t.store.addNote(t.inv.id, 'first');
  t.store.updateNote(t.inv.id, n.id, 'edited');
  const after = t.store.load(t.inv.id);
  const g = after.findings[0];
  for (const k of ['id', 'type', 'value', 'statementType', 'subject', 'attribute', 'source', 'firstObserved', 'lastObserved', 'data']) assert.deepEqual(g[k], before[k], `${k} must be untouched`);
  assert.equal(g.verification, 'verified-by-user');
  assert.equal(g.independence.status, 'independent');
  assert.ok(g.notes.some((x) => /checked the archive/.test(x.text)) && g.notes.some((x) => /verified-by-user/.test(x.text)));
  assert.equal(after.notes[0].text, 'edited');
  assert.ok(after.notes[0].editedAt);
  assert.throws(() => t.store.setVerification(t.inv.id, f.id, 'bogus'), /must be one of/);
  t.cleanup();
});

test('import: arrays and {findings}, records are treated as claims, missing sources become Unknown, bad shapes explained', () => {
  const t = store();
  const res = t.store.importJson(t.inv.id, { findings: [
    { id: 'orig-1', type: 'claim', value: 'A says X', source: { url: 'https://a.example.com/' } }, { type: 'note', value: 'no source here' }, { value: 'missing type' },
  ] }, { filename: '/tmp/evidence.json' });
  assert.equal(res.added.length, 2);
  assert.equal(res.errors.length, 1);
  assert.equal(res.errors[0].index, 2);
  const inv = t.store.load(t.inv.id);
  assert.ok(inv.findings.every((f) => f.source.module === 'import' && f.statementType === 'claim' && f.verification === 'unverified'));
  assert.equal(inv.findings[0].data.originalId, 'orig-1');
  assert.match(inv.findings[0].source.importNote, /Imported from evidence\.json/);
  assert.ok(!inv.findings[0].id.startsWith('orig'), 'imported ids never overwrite existing evidence');
  const a = analyze(inv);
  assert.equal(a.assessments[inv.findings[0].id].level, 'plausible');
  assert.equal(a.assessments[inv.findings[1].id].level, 'unknown');
  assert.equal(t.store.importJson(t.inv.id, [{ type: 'domain', value: 'x.org' }]).added.length, 1);
  assert.throws(() => t.store.importJson(t.inv.id, { nope: 1 }), (e) => e.code === 'BAD_IMPORT' && /sample-evidence/.test(e.hint));
  t.cleanup();
});

test('deleting needs the exact word DELETE; archives are valid gzip with a matching integrity hash', () => {
  const t = store();
  add(t.store, t.inv, [{ type: 'domain', value: 'example.org' }]);
  assert.throws(() => t.store.delete(t.inv.id, {}), (e) => e.code === 'NOT_CONFIRMED');
  assert.throws(() => t.store.delete(t.inv.id, { confirm: 'delete' }), (e) => e.code === 'NOT_CONFIRMED');
  assert.ok(t.store.load(t.inv.id));
  const dir = path.join(t.home, 'out');
  const a = t.store.archive(t.inv.id, dir);
  const bundle = JSON.parse(zlib.gunzipSync(fs.readFileSync(a.file)));
  assert.equal(bundle.integrity.value, crypto.createHash('sha256').update(JSON.stringify(bundle.investigation)).digest('hex'));
  assert.equal(a.sha256, crypto.createHash('sha256').update(fs.readFileSync(a.file)).digest('hex'));
  assert.equal(t.store.delete(t.inv.id, { confirm: 'DELETE' }), true);
  assert.equal(t.store.load(t.inv.id), null);
  assert.deepEqual(t.store.list(), []);
  t.cleanup();
});

test('a damaged investigation file is reported without affecting the others', () => {
  const t = store();
  const other = t.store.create('Other');
  fs.writeFileSync(path.join(t.ctx.paths.investigationsDir, `${t.inv.id}.json`), '{ broken');
  assert.throws(() => t.store.load(t.inv.id), (e) => e.code === 'CORRUPT');
  assert.equal(t.store.load(other.id).title, 'Other');
  assert.deepEqual(t.store.list().map((x) => x.title), ['Other']);
  t.cleanup();
});

test('connections: exact and structural links are distinguished from fuzzy ones, and fuzzy ones carry a caution', () => {
  const t = store();
  const mod = { module: 'network-intelligence', provider: 'DNS', retrievedAt: T0 };
  const fs_ = add(t.store, t.inv, [
    { type: 'domain', value: 'Example.ORG', statementType: 'observation', source: mod },
    { type: 'dns_record', value: 'A 192.0.2.10', statementType: 'observation', source: mod, data: { domain: 'example.org', recordType: 'A', value: '192.0.2.10' } },
    { type: 'ip', value: '192.0.2.10', statementType: 'observation', source: mod },
    { type: 'certificate', value: 'crt.sh #1', statementType: 'observation', source: mod, data: { names: ['*.example.org', 'example.org'], domain: 'example.org' } },
    { type: 'subdomain', value: 'mail.example.org', statementType: 'observation', source: mod, data: { parent: 'example.org' } },
    { type: 'file_hash', value: 'AB'.repeat(32), statementType: 'observation', source: mod }, { type: 'file_hash', value: 'ab'.repeat(32), statementType: 'observation', source: mod },
    { type: 'username', value: 'jane_doe', source: { url: 'https://one.example/jane_doe' } }, { type: 'username', value: 'janedoe', source: { url: 'https://two.example/janedoe' } },
    { type: 'username', value: 'JANE_DOE', source: { url: 'https://three.example/jane' } },
    { type: 'organization', value: 'Acme Corp', source: { description: 'card' } }, { type: 'organization', value: 'ACME Corporation', source: { description: 'site' } }, { type: 'organization', value: 'Totally Different LLC', source: { description: 'x' } },
  ]);
  const [dom, rec, ip, cert, sub, h1, h2, u1, u2, u3, o1, o2] = fs_;
  const a = analyze(t.store.load(t.inv.id));
  const has = (from, to, rel, match) => a.relationships.some((e) => e.from === from.id && e.to === to.id && e.relation.includes(rel) && e.match === match);
  assert.ok(has(dom, rec, 'has DNS record', 'structural'));
  assert.ok(has(rec, ip, 'resolves to', 'exact'));
  assert.ok(has(cert, dom, 'certificate names this domain', 'exact'));
  assert.ok(has(sub, dom, 'subdomain of', 'structural'));
  assert.ok(has(h1, h2, 'identical file contents', 'exact'), 'matching hashes ignore letter case');
  assert.ok(has(u1, u3, 'same handle text', 'exact'));
  const fuzzy = a.relationships.filter((e) => e.match === 'fuzzy');
  assert.ok(fuzzy.some((e) => [e.from, e.to].includes(u2.id)), 'jane_doe ~ janedoe is only a fuzzy match');
  assert.ok(fuzzy.some((e) => e.from === o1.id && e.to === o2.id && /company suffix|similar/.test(e.relation)));
  assert.ok(fuzzy.every((e) => e.caution && /share|not|hint|proof/i.test(e.caution)));
  assert.ok(a.relationships.filter((e) => e.match === 'exact' && /same handle/.test(e.relation)).every((e) => /does not prove the same person/.test(e.caution)));
  assert.ok(!a.relationships.some((e) => [o1.id, o2.id].includes(e.from) && e.to === 'Totally Different LLC'));
  t.cleanup();
});

test('contradictions show both sides with their sources and never pick a winner', () => {
  const t = store();
  const f = add(t.store, t.inv, [
    claim('Founded in 2010', web('https://a.example.com/x', 'Site A')), claim('Founded in 2012', web('https://registry.example.org/acme', 'Registry')),
    { type: 'source_date', value: '2025-12-30T08:00:00Z', subject: 'https://x.test/a', attribute: 'publication_date', statementType: 'claim', source: web('https://x.test/a') },
    { type: 'source_date', value: 'December 30, 2025', subject: 'https://x.test/a', attribute: 'publication_date', statementType: 'claim', source: web('https://mirror.test/a') },
    { type: 'organization', value: 'North Star Trading Holdings Group', subject: 'example.org', attribute: 'registrant_organization', statementType: 'claim', source: web('https://a.test') },
    { type: 'organization', value: 'North Star Trading Holdings', subject: 'example.org', attribute: 'registrant_organization', statementType: 'claim', source: web('https://b.test') },
    { type: 'organization', value: 'Acme Corp', subject: 'example.net', attribute: 'registrant_organization', statementType: 'claim', source: web('https://c.test') },
    { type: 'organization', value: 'ACME Corporation', subject: 'example.net', attribute: 'registrant_organization', statementType: 'claim', source: web('https://d.test') },
    { type: 'domain_registration', value: 'Registrar One', subject: 'example.com', attribute: 'registrar', statementType: 'observation', source: { module: 'network-intelligence', provider: 'RDAP' }, firstObserved: '2026-01-01T00:00:00Z' },
    { type: 'domain_registration', value: 'Registrar Two', subject: 'example.com', attribute: 'registrar', statementType: 'observation', source: { module: 'network-intelligence', provider: 'RDAP' }, firstObserved: '2026-06-01T00:00:00Z' },
  ]);
  const inv = t.store.load(t.inv.id);
  const c = detectContradictions(inv.findings);
  const bySub = Object.fromEntries(c.map((x) => [`${x.subject}|${x.attribute}`, x]));
  const years = bySub['Acme Corp|founding year'];
  assert.equal(years.kind, 'conflict');
  assert.deepEqual(years.sides.map((s) => s.value).sort(), ['Founded in 2010', 'Founded in 2012']);
  assert.ok(years.sides.every((s) => s.findings[0].source.includes('http')));
  assert.match(years.note, /does not pick a side/);
  assert.equal(bySub['https://x.test/a|publication_date'], undefined, 'same day in two formats is not a contradiction');
  assert.equal(bySub['example.org|registrant_organization'].kind, 'possible-variant');
  assert.equal(bySub['example.net|registrant_organization'], undefined, 'Inc/Ltd/Corporation differences alone are not a contradiction');
  assert.equal(bySub['example.com|registrar'].kind, 'changed-between-observations');
  const a = analyze(inv);
  assert.equal(a.assessments[f[0].id].level, 'conflicting');
  assert.equal(a.assessments[f[1].id].level, 'conflicting');
  assert.notEqual(a.assessments[f[4].id].level, 'conflicting', 'a possible spelling variant is not treated as a real conflict');
  t.cleanup();
});

test('confidence: direct observation, single claims, unknown provenance, and NO automatic corroboration from repeats', () => {
  const t = store();
  const [obs, single, bare] = add(t.store, t.inv, [
    { type: 'file_hash', value: 'a'.repeat(64), statementType: 'observation', source: { module: 'file-forensics', provider: 'local analysis', file: { name: 'x', sha256: 'a'.repeat(64) } } },
    { type: 'claim', value: 'Solo claim', statementType: 'claim', source: web('https://solo.example.com/') }, { type: 'claim', value: 'orphan', statementType: 'claim' },
  ]);
  const a = analyze(t.store.load(t.inv.id));
  assert.equal(a.assessments[obs.id].level, 'confirmed_direct');
  assert.match(a.assessments[obs.id].reasons.join(' '), /not that the real-world statement is true/);
  assert.equal(a.assessments[single.id].level, 'plausible');
  assert.equal(a.assessments[bare.id].level, 'unknown');
  assert.ok(Object.values(a.assessments).every((x) => !/\d+\s?%|score|probability/i.test(x.label) && x.level && x.label));
  t.cleanup();
});

test('several websites repeating one claim stay "plausible" until independence is shown; copies count once', () => {
  const t = store();
  const [a1, b1, c1] = add(t.store, t.inv, [
    claim('Founded in 2010', web('https://news.example.com/x', 'News')), claim('Founded in 2010', web('https://blog.example.net/y', 'Blog')), claim('Founded in 2010', web('https://news.example.com/other', 'News again')),
  ]);
  let a = analyze(t.store.load(t.inv.id));
  assert.deepEqual(levels(a, [a1, b1, c1]), { [a1.id]: 'plausible', [b1.id]: 'plausible', [c1.id]: 'plausible' });
  assert.match(a.assessments[a1.id].reasons.join(' '), /independence is not established/);
  assert.match(a.assessments[a1.id].reasons.join(' '), /ONE source/);
  t.store.setIndependence(t.inv.id, a1.id, { status: 'independent' });
  a = analyze(t.store.load(t.inv.id));
  assert.equal(a.assessments[a1.id].level, 'plausible', 'one independent flag is not enough');
  t.store.setIndependence(t.inv.id, b1.id, { status: 'independent' });
  a = analyze(t.store.load(t.inv.id));
  assert.equal(a.assessments[a1.id].level, 'multi_independent');
  assert.equal(a.assessments[b1.id].level, 'multi_independent');
  t.store.setIndependence(t.inv.id, b1.id, { status: 'derived', derivedFrom: a1.id });
  a = analyze(t.store.load(t.inv.id));
  assert.equal(a.assessments[a1.id].level, 'plausible', 'a copy of the first source is the same origin');
  t.store.setVerification(t.inv.id, a1.id, 'verified-by-user', 'phoned the company');
  a = analyze(t.store.load(t.inv.id));
  assert.equal(a.assessments[a1.id].level, 'plausible', 'self-verification does not silently upgrade the category');
  assert.match(a.assessments[a1.id].reasons.join(' '), /marked this as verified/);
  t.store.setVerification(t.inv.id, c1.id, 'disputed', 'looks copied');
  a = analyze(t.store.load(t.inv.id));
  assert.equal(a.assessments[c1.id].level, 'conflicting');
  t.cleanup();
});

test('text graph fits the screen, marks fuzzy links and lists unconnected findings', () => {
  const t = store();
  const mod = { module: 'network-intelligence', provider: 'DNS' };
  add(t.store, t.inv, [
    { type: 'domain', value: 'a-very-long-domain-name-for-testing.example.org', statementType: 'observation', source: mod },
    { type: 'dns_record', value: 'A 192.0.2.10', statementType: 'observation', source: mod, data: { domain: 'a-very-long-domain-name-for-testing.example.org', recordType: 'A', value: '192.0.2.10' } },
    { type: 'username', value: 'jane_doe', source: { url: 'https://one.example/jane_doe' } }, { type: 'username', value: 'janedoe', source: { url: 'https://two.example/janedoe' } },
    { type: 'claim', value: 'lonely', source: { description: 'x' } },
  ]);
  const inv = t.store.load(t.inv.id);
  const lines = renderTextGraph(inv, analyze(inv), { width: 36, unicode: false });
  assert.ok(lines.every((l) => l.length <= 36), lines.filter((l) => l.length > 36).join('|'));
  const text = lines.join('\n');
  assert.match(text, /has DNS record/);
  assert.match(text, /~-> similar handle|~<- similar handle/);
  assert.match(text, /Not connected to anything yet \(1\)/);
  assert.match(text, /~ marks a fuzzy match/);
  const uni = renderTextGraph(inv, analyze(inv), { width: 40, unicode: true }).join('\n');
  assert.match(uni, /[├└]─/);
  t.cleanup();
});

test('every finding carries its investigation ID; links between findings are stored beside the evidence and drive "conflicting"', () => {
  const t = store();
  const [a, b, c] = add(t.store, t.inv, [{ type: 'claim', value: 'A says X', source: { description: 'a' } }, { type: 'claim', value: 'B says not X', source: { description: 'b' } }, { type: 'claim', value: 'C agrees with A', source: { description: 'c' } }]);
  assert.ok([a, b, c].every((f) => f.investigationId === t.inv.id));
  const before = JSON.stringify(t.store.load(t.inv.id).findings[0].value);
  t.store.addReference(t.inv.id, c.id, 'supporting', { otherFindingId: a.id, description: 'same story' });
  t.store.addReference(t.inv.id, b.id, 'contradicting', { otherFindingId: a.id, description: 'denies it' });
  const inv = t.store.load(t.inv.id);
  assert.equal(JSON.stringify(inv.findings[0].value), before);
  assert.equal(inv.findings.find((f) => f.id === c.id).supporting[0].findingId, a.id);
  const an = analyze(inv);
  assert.equal(an.assessments[a.id].level, 'conflicting');
  assert.equal(an.assessments[b.id].level, 'conflicting');
  assert.equal(an.assessments[c.id].level, 'plausible');
  assert.match(an.assessments[c.id].reasons.join(' '), /1 item\(s\) you linked as supporting/);
  assert.throws(() => t.store.addReference(t.inv.id, a.id, 'supporting', { otherFindingId: a.id }), /cannot support or contradict itself/);
  assert.throws(() => t.store.addReference(t.inv.id, a.id, 'maybe', {}), /must be "supporting" or "contradicting"/);
  t.cleanup();
});

test('differing descriptions of the same source are flagged as contradictions or changes', () => {
  const t = store();
  add(t.store, t.inv, [
    { type: 'source_description', value: 'Acme Corp - About', subject: 'https://a.example.com/about', attribute: 'source_title', statementType: 'claim', source: web('https://a.example.com/about'), firstObserved: '2026-01-01T00:00:00Z' },
    { type: 'source_description', value: 'Acme Holdings - About us', subject: 'https://a.example.com/about', attribute: 'source_title', statementType: 'claim', source: web('https://a.example.com/about'), firstObserved: '2026-06-01T00:00:00Z' },
  ]);
  const c = detectContradictions(t.store.load(t.inv.id).findings);
  assert.equal(c.length, 1);
  assert.equal(c[0].attribute, 'source_title');
  assert.equal(c[0].sides.length, 2);
  t.cleanup();
});
