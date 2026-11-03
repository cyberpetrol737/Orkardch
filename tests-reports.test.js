'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { makeCtx } = require('./tests-helpers-ctx');
const { buildReportModel, sensitiveInventory } = require('./reports-model');
const R = require('./reports-render');
const { writeReports } = require('./reports-index');

const T0 = '2026-03-01T10:00:00.000Z';
function seeded() {
  const t = makeCtx();
  const inv = t.ctx.store.create('Photo & <b>case</b>');
  const file = { name: 'p.jpg', path: '/data/data/com.termux/files/home/storage/p.jpg', sha256: 'f'.repeat(64), size: 10 };
  const base = { statementType: 'observation', source: { module: 'file-forensics', provider: 'local analysis', file, retrievedAt: T0 } };
  t.ctx.store.addFindings(inv.id, [
    { ...base, type: 'file_hash', value: 'f'.repeat(64), subject: 'p.jpg', attribute: 'sha256' },
    { ...base, type: 'file_metadata', value: '48.856700,2.350000', subject: `file:${'f'.repeat(64)}`, attribute: 'gps_position', sensitive: 'gps' },
    { ...base, type: 'file_metadata', value: 'Jane Photographer', subject: `file:${'f'.repeat(64)}`, attribute: 'author', sensitive: 'personal-metadata' },
    { type: 'claim', value: '<script>alert(1)</script> "quoted" & </script><img src=x onerror=alert(2)>', subject: 'Acme', attribute: 'founding year', source: { module: 'web-intelligence', url: 'https://a.example.com/x?a=1&b=2', description: 'api_key=SUPERSECRET123456 was in this note', retrievedAt: T0 } },
    { type: 'claim', value: '2012', subject: 'Acme', attribute: 'founding year', source: { module: 'web-intelligence', url: 'javascript:alert(3)', publisher: 'Evil' } },
  ]);
  t.ctx.store.logMethod(inv.id, { module: 'file-forensics', description: 'Inspected p.jpg' });
  t.ctx.store.addSearch(inv.id, { query: 'acme <founding>', providers: ['wikipedia'], resultCount: 3, urls: [] });
  t.ctx.store.addNote(inv.id, 'Remember to call them');
  return { ...t, inv: t.ctx.store.load(inv.id) };
}

test('by default GPS, personal metadata and local paths are withheld, and say so', () => {
  const t = seeded();
  assert.deepEqual(sensitiveInventory(t.inv), { gps: 1, personal: 1, paths: 3 });
  const m = buildReportModel(t.inv, { secrets: ['SUPERSECRET123456'] });
  const all = JSON.stringify(m);
  assert.ok(!all.includes('48.8567') && !all.includes('2.35'));
  assert.ok(!all.includes('Jane Photographer'));
  assert.ok(!all.includes('/data/data/com.termux'));
  assert.ok(all.includes('[withheld: GPS position]'));
  assert.deepEqual(m.privacy.withheld, { gps: 1, personal: 1, paths: 3 });
  assert.ok(m.limitations.some((l) => /sensitive details were withheld/.test(l)));
  assert.ok(m.findings.find((f) => f.attribute === 'sha256').source.file.sha256, 'hashes (not sensitive) are kept');
  t.cleanup();
});

test('the person can include rounded or exact GPS, personal details and paths', () => {
  const t = seeded();
  const rounded = JSON.stringify(buildReportModel(t.inv, { sensitive: { gps: 'round' } }));
  assert.ok(rounded.includes('48.86, 2.35 (rounded to about 1 km)'));
  assert.ok(!rounded.includes('48.8567'));
  const full = JSON.stringify(buildReportModel(t.inv, { sensitive: { gps: 'include', personal: true, paths: true } }));
  assert.ok(full.includes('48.856700,2.350000') && full.includes('Jane Photographer') && full.includes('/data/data/com.termux'));
  t.cleanup();
});

test('secrets are redacted from every report format', () => {
  const t = seeded();
  t.ctx.config.set('apiKeys.brave', 'BRAVE-KEY-ZZZ-999');
  t.ctx.store.addNote(t.inv.id, 'my brave key is BRAVE-KEY-ZZZ-999 oops');
  const inv = t.ctx.store.load(t.inv.id);
  const out = writeReports(t.ctx, inv, ['json', 'md', 'txt', 'html'], { gps: 'exclude' });
  assert.equal(out.length, 4);
  for (const r of out) {
    const text = fs.readFileSync(r.file, 'utf8');
    assert.ok(!text.includes('SUPERSECRET123456'), `${r.format} leaks the token`);
    assert.ok(!text.includes('BRAVE-KEY-ZZZ-999'), `${r.format} leaks the configured key`);
    assert.ok(text.includes('[REDACTED]'), `${r.format} should show the redaction`);
    assert.equal(fs.statSync(r.file).mode & 0o777, 0o600);
    assert.ok(r.file.includes(path.join('orkardch-output', 'reports')));
  }
  t.cleanup();
});

test('every report has the required sections, provenance and timestamps', () => {
  const t = seeded();
  const m = buildReportModel(t.inv, { now: () => Date.parse('2026-03-02T00:00:00Z') });
  const md = R.toMarkdown(m);
  for (const h of ['## Summary', '## Search methods used', '## Findings', '## Evidence provenance', '## Contradictions', '## Connections', '## Limitations', '## Recommended next verification steps', '## Notes']) assert.ok(md.includes(h), `missing ${h}`);
  assert.match(md, /Created 2026-/);
  assert.match(md, /exported 2026-03-02 00:00:00 UTC/);
  assert.match(md, /Confidence: \*\*/);
  assert.match(md, /Source: file-forensics via local analysis/);
  assert.match(md, /Acme \/ founding year \(conflict\)/);
  assert.match(md, /search `acme <founding>`/);
  const txt = R.toText(m);
  for (const h of ['SUMMARY', 'SEARCH METHODS USED', 'FINDINGS', 'EVIDENCE PROVENANCE', 'CONTRADICTIONS', 'LIMITATIONS', 'RECOMMENDED NEXT VERIFICATION STEPS']) assert.ok(txt.includes(h));
  assert.ok(txt.split('\n').every((l) => l.length <= 78 || !/\s/.test(l.trim())), 'text report is wrapped for a terminal');
  const json = JSON.parse(R.toJson(m));
  assert.equal(json.summary.findings, 5);
  assert.ok(json.findings.every((f) => f.assessment.label && f.source));
  assert.ok(json.nextSteps.length && json.limitations.length);
  t.cleanup();
});

test('HTML report is self-contained, escapes hostile content, blocks external loads, and adapts to dark mode', () => {
  const t = seeded();
  const html = R.toHtml(buildReportModel(t.inv, { sensitive: { gps: 'include' } }));
  assert.match(html, /<meta http-equiv="Content-Security-Policy" content="default-src 'none'/);
  assert.match(html, /<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">/);
  assert.match(html, /prefers-color-scheme:dark/);
  assert.ok(!/<script[^>]+src=|<link[^>]+href=|@import|url\(|<img|<iframe|<object/i.test(html), 'no external or embedded loads');
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(!/onerror=alert/.test(html.replace(/&lt;img src=x onerror=alert\(2\)&gt;/g, '')));
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(html.includes('Photo &amp; &lt;b&gt;case&lt;/b&gt;'));
  assert.ok(!html.includes('href="javascript:'), 'non-http links are shown as text, not made clickable');
  assert.equal((html.match(/<script/g) || []).length, 2, 'only the graph data and the small graph script');
  const data = html.match(/<script type="application\/json" id="gdata">([\s\S]*?)<\/script>/);
  assert.ok(data && JSON.parse(data[1]).nodes.length >= 1);
  assert.match(html, /<svg id="graph"/);
  assert.match(html, /Generated offline/);
  t.cleanup();
});

test('an empty investigation still produces a valid, honest report', () => {
  const t = makeCtx();
  const inv = t.ctx.store.create('Empty');
  const m = buildReportModel(t.ctx.store.load(inv.id));
  assert.equal(m.summary.findings, 0);
  assert.ok(m.limitations.some((l) => /No search methods were logged/.test(l)));
  assert.ok(m.nextSteps.some((s) => /Add evidence first/.test(s)));
  for (const f of ['toJson', 'toMarkdown', 'toText', 'toHtml']) assert.ok(R[f](m).length > 100);
  assert.match(R.toHtml(m), /no graph to draw/);
  t.cleanup();
});
