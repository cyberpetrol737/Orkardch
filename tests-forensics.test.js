'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const F = require('./tests-helpers-fixtures');
const { inspectFile } = require('./file-forensics-inspect');
const { detectType } = require('./file-forensics-filetype');
const { parseTiff, bufReader } = require('./file-forensics-tiff');
const { compareInspections } = require('./file-forensics-compare');
const { describeInspection, sectionsToText } = require('./file-forensics-describe');
const { sanitizeInspection, sensitiveInventory } = require('./file-forensics-export');
const { inspectionFindings } = require('./file-forensics-findings');
const { verifyBaseline } = require('./file-forensics-baseline');
const { openZip, readEntry } = require('./file-forensics-zip');

const w = (dir, name, buf) => { const p = path.join(dir, name); fs.writeFileSync(p, buf); return p; };

test('file type comes from the contents, not the name', async () => {
  const d = F.tempDir();
  const r = detectType(w(d, 'looks-like.png', F.buildJpeg({})));
  assert.equal(r.mime, 'image/jpeg');
  assert.equal(r.extensionMatches, false);
  assert.match(r.note, /Renamed files are common/);
  assert.equal(detectType(w(d, 'a.pdf', F.buildPdf())).mime, 'application/pdf');
  assert.equal(detectType(w(d, 'a.docx', F.buildDocx())).mime, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
  assert.equal(detectType(w(d, 'a.odt', F.buildOdt())).description, 'OpenDocument text');
  assert.equal(detectType(w(d, 'n.txt', 'plain words\n')).mime, 'text/plain');
  const unknown = detectType(w(d, 'blob.bin', crypto.randomBytes(300)));
  assert.equal(unknown.mime, 'application/octet-stream');
  assert.match(unknown.note, /does not mean the file is damaged/);
  F.rmrf(d);
});

test('JPEG: camera, lens-free fields, dates, orientation, dimensions and GPS are read; nothing invented', async () => {
  const d = F.tempDir();
  const r = await inspectFile(w(d, 'p.jpg', F.buildJpeg({ tiff: F.SAMPLE_EXIF(), comment: 'a comment' })), { algorithms: ['sha256'] });
  const m = r.metadata;
  assert.equal(m.supported, true);
  assert.deepEqual(m.dimensions, { width: 640, height: 480 });
  assert.equal(m.exif.camera.make, 'TestCam');
  assert.equal(m.exif.camera.model, 'Model X1');
  assert.equal(m.exif.software, 'PhotoEditor 3.2');
  assert.equal(m.exif.image.orientation.value, 6);
  assert.match(m.exif.image.orientation.description, /90/);
  assert.equal(m.exif.dates.captured.iso, '2024-05-01T10:20:30+02:00');
  assert.equal(m.exif.dates.captured.timezone, '+02:00');
  assert.equal(m.exif.dates.modified.iso, '2024-05-02T08:00:00');
  assert.match(m.exif.dates.modified.timezone, /not recorded/);
  assert.equal(m.exif.settings.exposureTime, '1/250 s');
  assert.equal(m.exif.settings.aperture, 'f/2.8');
  assert.equal(m.exif.settings.iso, 200);
  assert.ok(Math.abs(m.exif.gps.latitude - 48.85667) < 1e-4);
  assert.ok(Math.abs(m.exif.gps.longitude - 2.35) < 1e-4);
  assert.equal(m.comments[0], 'a comment');
  assert.equal(m.exif.artist, undefined, 'absent fields stay absent');
  assert.equal(m.exif.owner, undefined);
  F.rmrf(d);
});

test('JPEG without EXIF says so honestly; corrupt EXIF does not crash', async () => {
  const d = F.tempDir();
  const plain = await inspectFile(w(d, 'plain.jpg', F.buildJpeg({})));
  assert.equal(plain.metadata.exif, null);
  assert.match(plain.metadata.notes.join(' '), /No embedded camera or editing metadata/);
  assert.deepEqual(plain.metadata.dimensions, { width: 640, height: 480 });
  const tiff = F.SAMPLE_EXIF();
  const corrupt = Buffer.concat([tiff.subarray(0, 40), Buffer.alloc(10, 0xff)]);
  const r = await inspectFile(w(d, 'bad.jpg', F.buildJpeg({ tiff: corrupt })));
  assert.equal(r.metadata.supported, true);
  for (const junk of [Buffer.alloc(0), Buffer.from('II*\0'), Buffer.from('II*\0\x08\0\0\0\xff\xff', 'latin1'), crypto.randomBytes(200)]) {
    const t = parseTiff(bufReader(junk), 0);
    assert.ok(t.ok === false || Array.isArray(t.warnings));
  }
  const trunc = F.buildJpeg({ tiff: tiff }).subarray(0, 60);
  const tr = await inspectFile(w(d, 'trunc.jpg', trunc));
  assert.ok(tr.hashes.digests.sha256);
  F.rmrf(d);
});

test('big-endian EXIF and invalid GPS values are handled', () => {
  const t = F.buildTiff({ le: false, ifd0: [{ tag: 0x010f, type: 2, value: 'BigEndianCam' }], gps: [
    { tag: 1, type: 2, value: 'S' }, { tag: 2, type: 5, value: [F.rat(95), F.rat(0), F.rat(0)] }, { tag: 3, type: 2, value: 'W' }, { tag: 4, type: 5, value: [F.rat(10), F.rat(0), F.rat(0)] },
  ] });
  const parsed = parseTiff(bufReader(t), 0);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.byteOrder, 'big-endian');
  const { summarizeExif } = require('./file-forensics-tiff');
  const s = summarizeExif(parsed);
  assert.equal(s.camera.make, 'BigEndianCam');
  assert.equal(s.gps.present, true);
  assert.equal(s.gps.valid, false, 'latitude 95 is out of range');
});

test('PNG: size, text chunks, last-modified time and embedded EXIF', async () => {
  const d = F.tempDir();
  const r = await inspectFile(w(d, 'a.png', F.buildPng({ width: 8, height: 6, texts: { Software: 'GIMP 2.10', Author: 'Zed' }, time: [2024, 5, 4, 3, 2, 1], tiff: F.SAMPLE_EXIF() })));
  assert.deepEqual(r.metadata.dimensions, { width: 8, height: 6 });
  assert.equal(r.metadata.textChunks.Software, 'GIMP 2.10');
  assert.equal(r.metadata.embeddedDates.pngLastModified.iso, '2024-05-04T03:02:01Z');
  assert.equal(r.metadata.exif.camera.model, 'Model X1');
  F.rmrf(d);
});

test('PDF: title, author, producer, dates with timezone, version, page count; encrypted PDFs are not decoded', async () => {
  const d = F.tempDir();
  const r = await inspectFile(w(d, 'a.pdf', F.buildPdf()));
  const m = r.metadata;
  assert.equal(m.fields.title, 'Quarterly Report');
  assert.equal(m.fields.author, 'Jane Doe');
  assert.equal(m.fields.producer, 'Orkardch Test Writer');
  assert.equal(m.embeddedDates.created.iso, '2024-05-01T10:20:30+02:00');
  assert.equal(m.embeddedDates.modified.timezone, 'UTC');
  assert.equal(m.structure.pdfVersion, '1.4');
  assert.equal(m.structure.pages, 1);
  const enc = await inspectFile(w(d, 'e.pdf', F.buildPdf({ encrypted: true })));
  assert.equal(enc.metadata.structure.encrypted, true);
  assert.equal(enc.metadata.fields.author, undefined);
  assert.match(enc.metadata.notes.join(' '), /encrypted/);
  const none = await inspectFile(w(d, 'n.pdf', Buffer.from('%PDF-1.7\n%%EOF\n')));
  assert.match(none.metadata.notes.join(' '), /No readable document information/);
  F.rmrf(d);
});

test('Office documents: properties, macro presence (not executed), ODF, and timezone-less dates stay as recorded', async () => {
  const d = F.tempDir();
  const r = await inspectFile(w(d, 'm.docx', F.buildDocx({ macro: true })));
  const m = r.metadata;
  assert.equal(m.fields.author, 'Jane Doe');
  assert.equal(m.fields.lastModifiedBy, 'John Roe');
  assert.equal(m.fields.application, 'Microsoft Office Word 16.0000'.split(' 16')[0]);
  assert.equal(m.embeddedDates.created.iso, '2024-05-01T10:20:30.000Z');
  assert.equal(m.structure.hasMacros, true);
  assert.match(m.notes.join(' '), /did not read or run it/);
  const odt = await inspectFile(w(d, 'o.odt', F.buildOdt()));
  assert.equal(odt.metadata.fields.author, 'Ann Lee');
  assert.equal(odt.metadata.embeddedDates.created.iso, '2023-01-02T03:04:05');
  assert.equal(odt.metadata.embeddedDates.created.timezone, 'not recorded');
  F.rmrf(d);
});

test('ZIP safety: damaged archives and decompression bombs are refused, not expanded', () => {
  const d = F.tempDir();
  const bomb = w(d, 'bomb.zip', F.buildZip([{ name: 'big.xml', data: Buffer.alloc(30 * 1024 * 1024) }]));
  const z = openZip(bomb);
  assert.equal(z.ok, true);
  const r = readEntry(bomb, z.entries[0], { limit: 1024 * 1024 });
  assert.equal(r.ok, false);
  assert.match(r.reason, /larger than/);
  const liar = F.buildZip([{ name: 'x', data: Buffer.alloc(5 * 1024 * 1024) }]);
  const z2 = openZip(w(d, 'liar.zip', liar));
  z2.entries[0].uncompSize = 10;
  const r2 = readEntry(path.join(d, 'liar.zip'), z2.entries[0], { limit: 1024 * 1024 });
  assert.equal(r2.ok, false, 'a lying size field must not defeat the output cap');
  assert.equal(openZip(w(d, 'junk.zip', crypto.randomBytes(500))).ok, false);
  assert.equal(openZip(w(d, 'tiny.zip', 'PK')).ok, false);
  F.rmrf(d);
});

test('inspection never modifies the source file or creates files next to it', async () => {
  const d = F.tempDir();
  const files = [w(d, 'a.jpg', F.buildJpeg({ tiff: F.SAMPLE_EXIF() })), w(d, 'b.pdf', F.buildPdf()), w(d, 'c.docx', F.buildDocx())];
  const snap = () => fs.readdirSync(d).sort().map((n) => { const p = path.join(d, n); const s = fs.statSync(p); return `${n}:${s.size}:${s.mtimeMs}:${crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')}`; });
  const before = snap();
  for (const f of files) await inspectFile(f, { algorithms: ['sha256', 'sha1', 'md5'] });
  assert.deepEqual(snap(), before);
  F.rmrf(d);
});

test('friendly errors for missing files, folders and unreadable paths', async () => {
  const d = F.tempDir();
  await assert.rejects(() => inspectFile(path.join(d, 'missing.jpg')), (e) => e.code === 'FILE_NOT_FOUND' && /termux-setup-storage/.test(e.hint));
  await assert.rejects(() => inspectFile(d), (e) => e.code === 'IS_DIRECTORY');
  F.rmrf(d);
});

test('comparison: identical contents with different names, and different contents', async () => {
  const d = F.tempDir();
  const a = await inspectFile(w(d, 'one.jpg', F.buildJpeg({ tiff: F.SAMPLE_EXIF() })));
  const b = await inspectFile(w(d, 'two.jpg', F.buildJpeg({ tiff: F.SAMPLE_EXIF() })));
  const same = compareInspections(a, b);
  assert.equal(same.sameContent, true);
  assert.equal(same.metadata.different.length, 0);
  const c = await inspectFile(w(d, 'three.jpg', F.buildJpeg({ tiff: F.buildTiff({ ifd0: [{ tag: 0x010f, type: 2, value: 'Other' }] }) })));
  const diff = compareInspections(a, c);
  assert.equal(diff.sameContent, false);
  assert.ok(diff.metadata.different.some((x) => x.key === 'exif.camera.make' && x.a === 'TestCam' && x.b === 'Other'));
  assert.match(diff.explanation, /not identical/);
  F.rmrf(d);
});

test('export withholds GPS, folder path and personal details unless the person says yes', async () => {
  const d = F.tempDir();
  const tiff = F.buildTiff({ ifd0: [{ tag: 0x013b, type: 2, value: 'Jane Photographer' }], exif: [{ tag: 0xa431, type: 2, value: 'SN-12345' }], gps: [
    { tag: 1, type: 2, value: 'N' }, { tag: 2, type: 5, value: [F.rat(48), F.rat(51), F.rat(24)] }, { tag: 3, type: 2, value: 'E' }, { tag: 4, type: 5, value: [F.rat(2), F.rat(21), F.rat(0)] },
  ] });
  const r = await inspectFile(w(d, 'g.jpg', F.buildJpeg({ tiff })));
  assert.deepEqual(sensitiveInventory(r), { gps: true, personal: true });
  const safe = JSON.stringify(sanitizeInspection(r));
  assert.ok(!/48\.8|2\.35|Jane Photographer|SN-12345/.test(safe));
  assert.ok(!safe.includes(d));
  assert.match(safe, /withheld/);
  const rounded = sanitizeInspection(r, { gps: 'rounded' });
  assert.equal(rounded.metadata.exif.gps.latitude, 48.86);
  const exact = sanitizeInspection(r, { gps: 'show', includePath: true, includePersonal: true });
  assert.ok(Math.abs(exact.metadata.exif.gps.latitude - 48.8567) < 1e-3);
  assert.equal(exact.path, r.path);
  assert.equal(exact.metadata.exif.artist, 'Jane Photographer');
  const screen = sectionsToText(describeInspection(r, { gps: 'hide' }));
  assert.ok(!/48\.8/.test(screen));
  assert.match(screen, /hidden/);
  F.rmrf(d);
});

test('findings carry provenance and flag sensitive items; GPS is only saved on request', async () => {
  const d = F.tempDir();
  const r = await inspectFile(w(d, 'g.jpg', F.buildJpeg({ tiff: F.SAMPLE_EXIF() })));
  const without = inspectionFindings(r);
  assert.ok(without.every((f) => f.source.file.sha256 === r.hashes.digests.sha256 && f.statementType === 'observation'));
  assert.ok(!without.some((f) => f.attribute === 'gps_position'));
  const withGps = inspectionFindings(r, { includeGps: true });
  const g = withGps.find((f) => f.attribute === 'gps_position');
  assert.equal(g.sensitive, 'gps');
  assert.ok(withGps.some((f) => f.attribute === 'camera' && f.value === 'TestCam Model X1'));
  F.rmrf(d);
});

test('baselines: unchanged, changed, and missing files are told apart', async () => {
  const d = F.tempDir();
  const f = w(d, 'doc.txt', 'version one');
  const r = await inspectFile(f);
  const entry = { path: f, sha256: r.hashes.digests.sha256, size: r.size, fileModifiedAtSave: r.filesystem.modified };
  assert.equal((await verifyBaseline(entry)).status, 'match');
  fs.writeFileSync(f, 'version two!');
  const changed = await verifyBaseline(entry);
  assert.equal(changed.status, 'changed');
  assert.equal(changed.sizeChanged, true);
  fs.unlinkSync(f);
  assert.equal((await verifyBaseline(entry)).status, 'missing');
  F.rmrf(d);
});

test('an empty file is reported as empty, hashed correctly, and does not crash any reader', async () => {
  const d = F.tempDir();
  const r = await inspectFile(w(d, 'nothing.jpg', ''));
  assert.equal(r.size, 0);
  assert.equal(r.type.description, 'Empty file (0 bytes)');
  assert.equal(r.hashes.digests.sha256, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(r.metadata.supported, false);
  F.rmrf(d);
});
