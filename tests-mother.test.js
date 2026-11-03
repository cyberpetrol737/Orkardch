'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { makeCtx } = require('./tests-helpers-ctx');
const mother = require('./mother-index');
const { LESSONS, GLOSSARY, BASICS } = require('./mother-lessons');
const { explainError } = require('./mother-errors');
const { explainResult } = require('./mother-explain');
const { NavSignal } = require('./core-errors');

const FIELDS = ['what', 'input', 'source', 'howTo', 'normal', 'errors', 'cannot', 'save'];

test('Mother greets with the required welcome', () => {
  assert.equal(mother.WELCOME, "Hi! I'm Mother. I'll help you understand Orkardch. You don't need to memorize commands. Pick something you want to learn, and I'll explain it one small step at a time.");
});

test('every lesson covers all nine teaching points in simple language', () => {
  assert.deepEqual(LESSONS.map((l) => l.id), ['forensics', 'web', 'network', 'correlator', 'reports', 'settings']);
  for (const l of LESSONS) {
    for (const f of FIELDS) assert.ok(Array.isArray(l[f]) && l[f].length > 0 && l[f].every((x) => (typeof x === 'string' ? x.length > 10 : x.when && x.meaning && x.fix)), `${l.id}.${f}`);
    assert.match(l.back, /menu/i, `${l.id} explains how to return to the main menu`);
    const ex = l.example();
    assert.ok(ex.intro && ex.lines.length, `${l.id} has an example`);
    const text = [...l.what, ...l.normal, ...l.cannot].join(' ');
    const longWords = text.split(/\s+/).filter((w) => w.replace(/[^a-z]/gi, '').length > 14);
    assert.ok(longWords.length <= 2, `${l.id} uses too many long words: ${longWords}`);
  }
  assert.ok(BASICS.some((b) => /Ctrl\+C/.test(b)) && BASICS.some((b) => /\?/.test(b)));
});

test('the required examples are taught the simple way', () => {
  const all = JSON.stringify(LESSONS.map((l) => [l.example(), l.normal, l.cannot]));
  assert.match(all, /A hash is like a digital fingerprint for a file\. If the file's contents change, its fingerprint will usually change too/);
  assert.match(all, /DNS is like the internet's address book\. It helps a computer find the server for a website/);
  assert.match(all, /One person saying something is a clue\. Two independent sources agreeing can be stronger evidence\. But we still need to check where the information came from/);
  const fp = LESSONS[0].example().lines.join('\n');
  assert.ok(fp.includes('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'), 'live SHA-256 of "hello"');
  assert.ok(GLOSSARY.length >= 15 && GLOSSARY.every(([t, d]) => t && d.length > 20));
});

test('every question the app can ask has context help (no prompt leaves the person stranded)', () => {
  // every source file (not the tests) in the project folder
  const files = fs.readdirSync(__dirname).filter((f) => f.endsWith('.js') && !f.startsWith('tests-')).map((f) => path.join(__dirname, f));
  const steps = new Set();
  for (const f of files) for (const m of fs.readFileSync(f, 'utf8').matchAll(/step(?::|\s*=)\s*'([a-z][\w.-]*)'/g)) steps.add(m[1]);
  assert.ok(steps.size > 60);
  const missing = [...steps].filter((s) => !mother.stepHelp(s));
  assert.deepEqual(missing, []);
});

test('errors are explained plainly, and unknown errors still get honest guidance', () => {
  const cases = { FILE_NOT_FOUND: /not found/i, EACCES: /Permission denied/, OFFLINE_MODE: /Offline mode/, MALFORMED: /valid IP/, HTTP_404: /not found/i, BLOCKED: /bot protection/i, 'rate-limited': /rate limit/i, CERT_HAS_EXPIRED: /expired/i, ENOTFOUND: /could not be found/i, ECONNREFUSED: /refused/i, EJSON: /JSON/, NOT_CONFIRMED: /Not confirmed/, EXIT_3: /TunnelR stopped/, TIMEOUT: /No answer/, NOT_AUTHORIZED: /Active check/ };
  for (const [code, re] of Object.entries(cases)) {
    const e = explainError({ code, message: 'x' });
    assert.match(e.title, re, code);
    assert.ok(e.meaning.length > 20 && e.fix.length >= 1, code);
  }
  const unknown = explainError({ code: 'WEIRD', message: 'something odd happened' });
  assert.match(unknown.meaning, /something odd happened/);
  assert.ok(unknown.fix.length >= 2);
  assert.equal(explainError(null), null);
});

test('every kind of result can be explained from what the session recorded', () => {
  const samples = {
    'file-inspection': { name: 'a.jpg', type: 'JPEG image', extensionMatches: false, size: 5, hashes: ['sha256', 'md5'], metadataSupported: true, hasExif: true, hasGps: true, gpsShown: false, hasDocFields: false, noMetadataFound: false },
    'file-comparison': { sameContent: false, sizeSame: true, typeSame: true, different: 2, same: 5 }, 'baseline-check': { status: 'changed', sizeChanged: true, name: 'x' },
    'search-results': { query: 'solar', resultCount: 4, providers: [{ id: 'wikipedia', status: 'ok', count: 4 }, { id: 'gdelt', status: 'error', count: 0, error: 'rate-limited' }] },
    'source-record': { title: 't', status: 'fetch-failed', hasPublished: false, excerpts: 0, uncertainty: 2 }, pages: { opened: 1, failed: 1, query: 'q' }, archive: { url: 'u', captures: 2, first: '2010-01-01T00:00:00Z', last: '2020-01-01T00:00:00Z' },
    'source-comparison': { overlap: 0.4, basis: 'titles', sameUrl: false, sameSite: true },
    ip: { ip: '8.8.8.8', public: true, rdapOk: true, originOk: false, ptrStatus: 'no-data', geoShown: true }, dns: { name: 'example.com', results: [{ type: 'A', status: 'ok', count: 1 }, { type: 'AAAA', status: 'no-data', count: 0 }, { type: 'MX', status: 'failed', count: 0, error: 'ETIMEOUT' }] },
    domain: { domain: 'example.com', rdapOk: false, rdapNotFound: true, registrar: null, dns: [] }, certificates: { domain: 'example.com', total: 3, names: 5 }, asn: { asn: 64500, nameOk: true, rdapOk: false },
    connectivity: { host: 'h', port: 443, tcpOk: true, tlsOk: true, tlsTrusted: false, httpStatus: 301 },
    'findings-review': { total: 3, conflicts: 1 }, 'sources-review': { sources: 2 }, import: { added: 3, skipped: 1 },
    analysis: { counts: {}, contradictions: 1, exact: 2, structural: 1, fuzzy: 1, findings: 6 }, graph: { edges: 3, nodes: 5 }, report: { formats: ['md'], files: 1, withheld: { gps: 1, personal: 0, paths: 0 }, findings: 4 },
    tunnelr: { connected: true, hasReadme: true, launchOptions: 2, risks: 3, dirty: 1 }, 'tunnelr-run': { mode: 'foreground', ok: false, exitCode: 2, spawnError: null }, 'tunnelr-status': { running: true, known: true },
  };
  for (const [kind, data] of Object.entries(samples)) {
    const lines = explainResult({ kind, data });
    assert.ok(Array.isArray(lines) && lines.length >= 1 && lines.every((l) => typeof l === 'string' && l.length > 10), kind);
  }
  assert.equal(explainResult(null), null);
  assert.equal(explainResult({ kind: 'nope', data: {} }), null);
  assert.match(explainResult({ kind: 'dns', data: samples.dns }).join(' '), /FAILED.*different from "none exists"/);
  assert.match(explainResult({ kind: 'ip', data: samples.ip }).join(' '), /approximate/);
});

test('context help uses the current screen, the inputs given, the last result and the last error', async () => {
  const t = makeCtx();
  const { ctx } = t;
  ctx.session.enter('forensics', 'Image & File Forensics');
  ctx.session.setStep('forensics.path');
  ctx.session.setInput('file name', 'photo.jpg');
  ctx.session.setOptions(['Inspect a file', 'Compare two files']);
  ctx.session.setResult('file-inspection', { name: 'photo.jpg', type: 'JPEG image', extensionMatches: true, size: 9, hashes: ['sha256'], metadataSupported: true, hasExif: true, hasGps: false, gpsShown: false, hasDocFields: false, noMetadataFound: false });
  ctx.session.setError({ code: 'FILE_NOT_FOUND', message: 'I could not find "x".' });
  await mother.contextHelp(ctx);
  const out = t.output();
  assert.match(out, /You are in: Image & File Forensics/);
  assert.match(out, /I need the address \(path\) of a file/);
  assert.match(out, /file name: photo\.jpg/);
  assert.match(out, /1\) Inspect a file; 2\) Compare two files/);
  assert.match(out, /About your latest result/);
  assert.match(out, /About that error: File or folder not found/);
  t.cleanup();
  const t2 = makeCtx();
  t2.ctx.session.enter('web', 'Public Web Intelligence');
  t2.ctx.session.setError({ code: 'FILE_NOT_FOUND', message: 'old error from another tool' });
  t2.ctx.session.lastError.module = 'forensics';
  await mother.contextHelp(t2.ctx);
  assert.ok(!/About that error/.test(t2.output()), 'errors from other tools are not shown as if they were current');
  t2.cleanup();
});

test('the lesson menu offers the six choices and each one teaches; 6 returns to the main menu', async () => {
  const t = makeCtx({ inputs: ['1', '1', '2', '3', '4', '5', '6'] });
  await assert.rejects(() => mother.run(t.ctx), (e) => e instanceof NavSignal && e.kind === 'menu');
  const out = t.output();
  for (const label of ['Show me what this tool does.', 'Teach me how to use it.', 'Show me an example.', 'Explain these results.', 'Help me fix an error.', 'Back to the main menu.']) assert.ok(out.includes(label), label);
  for (const heading of ['What it does', 'Where the information comes from', 'What you give it', 'How to run it, step by step', 'Saving or exporting', 'An example', 'What a normal result looks like', 'What results from this tool cannot prove', 'Common errors']) assert.ok(out.includes(heading), heading);
  assert.match(out, /You have no recent result from this tool/);
  t.cleanup();
});

test('TunnelR lesson: not connected says it will not guess; connected is built only from the inspected files', async () => {
  const t = makeCtx({ env: { PATH: process.env.PATH } });
  const lesson0 = await mother.tunnelrLesson(t.ctx);
  assert.match(lesson0.what.join(' '), /will not guess/);
  assert.match(lesson0.example().lines.join(' '), /Connect TunnelR first/);
  const dir = path.join(t.home, 'TunnelR');
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'README.md'), '# Gizmo Router\n\nGizmo Router forwards widgets between two toy networks for testing purposes only.\n');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'gizmo', description: 'A toy widget forwarder', scripts: { start: 'node gizmo.js', lint: 'echo lint' }, dependencies: { 'missing-lib': '^1' } }));
  fs.writeFileSync(path.join(dir, 'gizmo.js'), 'console.log(1)\n');
  require('./tunnelr-adapter').saveConfig(t.ctx, { path: dir });
  t.ctx._tunnelrInfo = null;
  const lesson = await mother.tunnelrLesson(t.ctx);
  const text = JSON.stringify([lesson.what, lesson.howTo, lesson.errors, lesson.example()]);
  assert.match(text, /Gizmo Router forwards widgets/);
  assert.match(text, /A toy widget forwarder/);
  assert.match(text, /start, lint/);
  assert.match(text, /npm run start/);
  assert.match(text, /missing-lib/);
  for (const invented of ['VPN', 'proxy', 'SOCKS', 'encrypt', 'tunnel server', 'OSINT']) assert.ok(!new RegExp(invented, 'i').test(text), `must not invent "${invented}"`);
  for (const f of FIELDS) assert.ok(lesson[f] && lesson[f].length, `tunnelr.${f}`);
  t.cleanup();
});
