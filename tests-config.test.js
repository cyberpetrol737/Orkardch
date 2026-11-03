'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const F = require('./tests-helpers-fixtures');
const { resolvePaths } = require('./core-paths');
const { Config, DEFAULTS } = require('./core-config');

const mk = () => { const home = F.tempDir(); return { home, config: new Config({ paths: resolvePaths({ HOME: home }) }).load() }; };

test('defaults need no API key and no paid service', () => {
  const { home, config } = mk();
  assert.equal(config.get('apiKeys.brave'), '');
  assert.equal(config.get('offline'), false);
  assert.equal(config.get('dns.mode'), 'auto');
  assert.equal(config.outputDir(), path.join(home, 'orkardch-output'));
  F.rmrf(home);
});

test('validation rejects bad values with plain messages and keeps the old value', () => {
  const { home, config } = mk();
  assert.match(config.set('maxParallelRequests', 99).error, /from 1 to 8/);
  assert.match(config.set('reportFormat', 'pdf').error, /Choose one of/);
  assert.match(config.set('dns.servers', 'not-an-ip').error, /IP addresses/);
  assert.match(config.set('nonsense', 1).error, /Unknown setting/);
  assert.equal(config.get('maxParallelRequests'), DEFAULTS.maxParallelRequests);
  assert.ok(config.set('offline', 'on').ok);
  assert.equal(config.get('offline'), true);
  F.rmrf(home);
});

test('save is atomic, private (0600) and round-trips; invalid saved values fall back to defaults', () => {
  const { home, config } = mk();
  config.set('cacheTtlMinutes', 5);
  config.set('apiKeys.brave', 'abcd1234');
  config.save();
  const file = config.paths.configFile;
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(path.dirname(file)).filter((f) => f.endsWith('.tmp')), []);
  const again = new Config({ paths: config.paths }).load();
  assert.equal(again.get('cacheTtlMinutes'), 5);
  assert.deepEqual(again.secrets(), ['abcd1234']);
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  raw.requestTimeoutMs = 'banana';
  raw.color = 'rainbow';
  fs.writeFileSync(file, JSON.stringify(raw));
  const bad = new Config({ paths: config.paths }).load();
  assert.equal(bad.get('requestTimeoutMs'), DEFAULTS.requestTimeoutMs);
  assert.equal(bad.warnings.length, 2);
  fs.writeFileSync(file, '{ not json');
  const broken = new Config({ paths: config.paths }).load();
  assert.equal(broken.get('cacheTtlMinutes'), DEFAULTS.cacheTtlMinutes);
  assert.match(broken.warnings[0], /could not be read/);
  F.rmrf(home);
});

test('command-line overrides apply for the session but are never saved', () => {
  const { home, config } = mk();
  config.override('offline', true);
  assert.equal(config.get('offline'), true);
  config.save();
  const again = new Config({ paths: config.paths }).load();
  assert.equal(again.get('offline'), false);
  F.rmrf(home);
});
