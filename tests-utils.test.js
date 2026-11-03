'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { formatBytes, formatDuration, truncate, wrapText, slugify } = require('./utils-format');
const V = require('./utils-validate');
const { redactString, redactDeep, maskSecret } = require('./security-redact');

test('formatBytes / duration / truncate / slugify', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(1536), '1.50 KB');
  assert.equal(formatBytes(5 * 1024 * 1024), '5.00 MB');
  assert.equal(formatBytes(-1), 'unknown');
  assert.equal(formatDuration(250), '250 ms');
  assert.equal(truncate('abcdefghij', 5), 'abcd…');
  assert.equal(slugify('My Case: Photo #1!'), 'my-case-photo-1');
  assert.equal(slugify('***'), 'untitled');
});

test('wrapText wraps words but keeps long tokens (paths, hashes) intact for copying', () => {
  const lines = wrapText('one two three four five six seven', 12);
  assert.ok(lines.every((l) => l.length <= 12));
  const hash = 'a'.repeat(64);
  assert.deepEqual(wrapText(`x ${hash} y`, 20), ['x', hash, 'y']);
});

test('domain and URL validation', () => {
  assert.ok(V.isValidDomain('example.com'));
  assert.ok(V.isValidDomain('sub.example.co.uk'));
  assert.ok(!V.isValidDomain('localhost'));
  assert.ok(!V.isValidDomain('-bad.example.com'));
  assert.ok(!V.isValidDomain('exa mple.com'));
  assert.equal(V.normalizeDomain('https://User@Example.COM:8080/path?x=1'), 'example.com');
  assert.equal(V.normalizeDomain('bücher.example'), 'xn--bcher-kva.example');
  assert.equal(V.parseAsn('AS15169'), 15169);
  assert.equal(V.parseAsn('15169'), null);
  assert.equal(V.classifyInput('8.8.8.8').kind, 'ip');
  assert.equal(V.classifyInput('https://example.com/a').kind, 'domain');
  assert.equal(V.classifyInput('AS64500').kind, 'asn');
  assert.equal(V.classifyInput('not a domain!').kind, 'invalid');
  assert.equal(V.classifyInput('').kind, 'empty');
});

test('URL normalisation drops tracking params and fragments; dedupe key ignores scheme and www', () => {
  assert.equal(V.normalizeUrl('https://Example.com/a?utm_source=x&b=2&a=1#frag'), 'https://example.com/a?a=1&b=2');
  assert.equal(V.normalizeUrl('ftp://x'), null);
  assert.equal(V.dedupeKey('http://www.example.com/a/'), V.dedupeKey('https://example.com/a/'));
  assert.equal(V.registrableDomain('news.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(V.registrableDomain('a.b.example.com'), 'example.com');
});

test('redaction removes keys, tokens and URL credentials from strings and objects', () => {
  const secret = 'sk-test-ABCDEFGHIJKLMNOPQRSTUV';
  assert.ok(!redactString(`Authorization: Bearer ${secret}`).includes(secret));
  assert.equal(redactString('https://x.test/?q=1&api_key=SECRET123&z=2'), 'https://x.test/?q=1&api_key=[REDACTED]&z=2');
  assert.ok(redactString('https://user:hunter2@host.test/').includes('[REDACTED]'));
  assert.ok(!redactString('my key is abcd1234efgh', ['abcd1234efgh']).includes('abcd1234efgh'));
  const out = redactDeep({ apiKey: 'x', nested: { token: 'y', note: 'ok', arr: ['Bearer abcdefghijklmnopqrstuv'] } });
  assert.equal(out.apiKey, '[REDACTED]');
  assert.equal(out.nested.token, '[REDACTED]');
  assert.equal(out.nested.note, 'ok');
  assert.ok(!JSON.stringify(out).includes('abcdefghijklmnopqrstuv'));
  assert.equal(maskSecret(''), '(not set)');
  assert.equal(maskSecret('abcdefghijkl'), '••••ijkl');
});
