'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const F = require('./tests-helpers-fixtures');
const { hashFile } = require('./file-forensics-hashing');

test('known hash vectors (SHA-256, SHA-1, MD5) and legacy warnings', async () => {
  const d = F.tempDir();
  const f = path.join(d, 'abc.txt');
  fs.writeFileSync(f, 'abc');
  const r = await hashFile(f, ['sha256', 'sha1', 'md5']);
  assert.equal(r.digests.sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(r.digests.sha1, 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.equal(r.digests.md5, '900150983cd24fb0d6963f7d28e17f72');
  assert.ok(r.notes.some((n) => /MD5.*broken/i.test(n)));
  assert.ok(r.notes.some((n) => /SHA-1.*deprecated/i.test(n)));
  const only = await hashFile(f);
  assert.deepEqual(Object.keys(only.digests), ['sha256']);
  assert.deepEqual(only.notes, []);
  F.rmrf(d);
});

test('empty file and missing file', async () => {
  const d = F.tempDir();
  const f = path.join(d, 'empty');
  fs.writeFileSync(f, '');
  assert.equal((await hashFile(f)).digests.sha256, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  await assert.rejects(() => hashFile(path.join(d, 'nope')), { code: 'ENOENT' });
  F.rmrf(d);
});

test('a large file is hashed in a stream without loading it into memory', async () => {
  const d = F.tempDir();
  const f = path.join(d, 'big.bin');
  const size = 160 * 1024 * 1024;
  const fd = fs.openSync(f, 'w');
  fs.ftruncateSync(fd, size);
  fs.closeSync(fd);
  const expected = (() => { const h = crypto.createHash('sha256'); const z = Buffer.alloc(1024 * 1024); for (let i = 0; i < 160; i++) h.update(z); return h.digest('hex'); })();
  if (global.gc) global.gc();
  const before = process.memoryUsage().rss;
  let progress = 0;
  const r = await hashFile(f, ['sha256'], { onProgress: (done) => { progress = done; } });
  const growth = process.memoryUsage().rss - before;
  assert.equal(r.digests.sha256, expected);
  assert.equal(progress, size);
  assert.equal(r.bytesRead, size);
  assert.ok(growth < 96 * 1024 * 1024, `RSS grew by ${(growth / 1048576).toFixed(0)} MB while hashing 160 MB`);
  F.rmrf(d);
});

test('hashing never modifies the file', async () => {
  const d = F.tempDir();
  const f = path.join(d, 'keep.bin');
  fs.writeFileSync(f, crypto.randomBytes(10000));
  const before = { st: fs.statSync(f), data: fs.readFileSync(f) };
  await hashFile(f, ['sha256', 'md5']);
  const after = { st: fs.statSync(f), data: fs.readFileSync(f) };
  assert.equal(after.st.mtimeMs, before.st.mtimeMs);
  assert.equal(after.st.size, before.st.size);
  assert.ok(before.data.equals(after.data));
  F.rmrf(d);
});

test('cancelling stops hashing with a clear error', async () => {
  const d = F.tempDir();
  const f = path.join(d, 'x.bin');
  fs.writeFileSync(f, Buffer.alloc(5 * 1024 * 1024));
  const ctrl = new AbortController();
  ctrl.abort();
  await assert.rejects(() => hashFile(f, ['sha256'], { signal: ctrl.signal }), { code: 'ABORTED' });
  F.rmrf(d);
});
