'use strict';
// Builders for small, harmless, synthetic test files. Nothing here is a real photo or document.
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c; }
  return t;
})();
function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function tempDir(prefix = 'orkardch-test-') { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }
function rmrf(dir) { fs.rmSync(dir, { recursive: true, force: true }); }

/** Build a TIFF/EXIF block. Entry: {tag, type, value}; types 2 ASCII, 3 SHORT, 4 LONG, 5 RATIONAL([[n,d],...]), 7 raw Buffer. */
function buildTiff({ ifd0 = [], exif = [], gps = [], le = true } = {}) {
  const w16 = (b, o, v) => (le ? b.writeUInt16LE(v, o) : b.writeUInt16BE(v, o));
  const w32 = (b, o, v) => (le ? b.writeUInt32LE(v, o) : b.writeUInt32BE(v, o));
  const size = { 2: 1, 3: 2, 4: 4, 5: 8, 7: 1 };
  const enc = (e) => {
    if (e.type === 2) return Buffer.from(`${e.value}\0`, 'latin1');
    if (e.type === 7) return Buffer.from(e.value);
    const arr = [].concat(e.value);
    const b = Buffer.alloc(arr.length * size[e.type]);
    arr.forEach((v, i) => {
      if (e.type === 3) w16(b, i * 2, v);
      else if (e.type === 4) w32(b, i * 4, v);
      else { w32(b, i * 8, v[0]); w32(b, i * 8 + 4, v[1]); }
    });
    return b;
  };
  const lists = { ifd0: ifd0.map((e) => ({ ...e })), exif: exif.map((e) => ({ ...e })), gps: gps.map((e) => ({ ...e })) };
  if (exif.length) lists.ifd0.push({ tag: 0x8769, type: 4, value: 0, ptr: 'exif' });
  if (gps.length) lists.ifd0.push({ tag: 0x8825, type: 4, value: 0, ptr: 'gps' });
  for (const k of Object.keys(lists)) lists[k].sort((a, b) => a.tag - b.tag);
  const ifdSize = (l) => 2 + l.length * 12 + 4;
  const off = { ifd0: 8 };
  off.exif = off.ifd0 + ifdSize(lists.ifd0);
  off.gps = off.exif + (exif.length ? ifdSize(lists.exif) : 0);
  let dataPos = off.gps + (gps.length ? ifdSize(lists.gps) : 0);
  const chunks = [];
  for (const k of ['ifd0', 'exif', 'gps']) {
    for (const e of lists[k]) {
      if (e.ptr) { e.bytes = Buffer.alloc(4); w32(e.bytes, 0, off[e.ptr]); e.count = 1; continue; }
      e.bytes = enc(e);
      e.count = e.type === 2 || e.type === 7 ? e.bytes.length : e.bytes.length / size[e.type];
      if (e.bytes.length > 4) { e.dataOffset = dataPos; chunks.push(e.bytes); dataPos += e.bytes.length + (e.bytes.length & 1); if (e.bytes.length & 1) chunks.push(Buffer.alloc(1)); }
    }
  }
  const out = Buffer.alloc(dataPos);
  out.write(le ? 'II' : 'MM', 0, 'latin1');
  w16(out, 2, 42);
  w32(out, 4, 8);
  for (const k of ['ifd0', 'exif', 'gps']) {
    if (!lists[k].length) continue;
    let p = off[k];
    w16(out, p, lists[k].length); p += 2;
    for (const e of lists[k]) {
      w16(out, p, e.tag); w16(out, p + 2, e.ptr ? 4 : e.type); w32(out, p + 4, e.count);
      if (e.dataOffset !== undefined) w32(out, p + 8, e.dataOffset); else e.bytes.copy(out, p + 8);
      p += 12;
    }
  }
  Buffer.concat(chunks).copy(out, off.gps + (gps.length ? ifdSize(lists.gps) : 0));
  return out;
}

const rat = (n, d = 1) => [n, d];
const SAMPLE_EXIF = () => buildTiff({
  ifd0: [
    { tag: 0x010f, type: 2, value: 'TestCam' }, { tag: 0x0110, type: 2, value: 'Model X1' }, { tag: 0x0112, type: 3, value: 6 },
    { tag: 0x0131, type: 2, value: 'PhotoEditor 3.2' }, { tag: 0x0132, type: 2, value: '2024:05:02 08:00:00' },
  ],
  exif: [
    { tag: 0x829a, type: 5, value: [rat(1, 250)] }, { tag: 0x829d, type: 5, value: [rat(28, 10)] }, { tag: 0x8827, type: 3, value: 200 },
    { tag: 0x9003, type: 2, value: '2024:05:01 10:20:30' }, { tag: 0x9011, type: 2, value: '+02:00' }, { tag: 0xa002, type: 4, value: 640 }, { tag: 0xa003, type: 4, value: 480 },
  ],
  gps: [
    { tag: 1, type: 2, value: 'N' }, { tag: 2, type: 5, value: [rat(48), rat(51), rat(2400, 100)] },
    { tag: 3, type: 2, value: 'E' }, { tag: 4, type: 5, value: [rat(2), rat(21), rat(0)] },
  ],
});

function buildJpeg({ tiff = null, width = 640, height = 480, comment = null } = {}) {
  const parts = [Buffer.from([0xff, 0xd8])];
  if (tiff) {
    const body = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff]);
    const hdr = Buffer.from([0xff, 0xe1, 0, 0]); hdr.writeUInt16BE(body.length + 2, 2);
    parts.push(hdr, body);
  }
  if (comment) { const c = Buffer.from(comment); const h = Buffer.from([0xff, 0xfe, 0, 0]); h.writeUInt16BE(c.length + 2, 2); parts.push(h, c); }
  const sof = Buffer.from([0xff, 0xc0, 0, 0x11, 8, 0, 0, 0, 0, 3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
  sof.writeUInt16BE(height, 5); sof.writeUInt16BE(width, 7);
  parts.push(sof, Buffer.from([0xff, 0xda, 0, 12, 3, 1, 0, 2, 0x11, 3, 0x11, 0, 0x3f, 0, 0x12, 0x34, 0xff, 0xd9]));
  return Buffer.concat(parts);
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function buildPng({ width = 4, height = 3, texts = {}, tiff = null, time = null } = {}) {
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4); ihdr[8] = 8; ihdr[9] = 2;
  const chunks = [Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), pngChunk('IHDR', ihdr)];
  for (const [k, v] of Object.entries(texts)) chunks.push(pngChunk('tEXt', Buffer.concat([Buffer.from(k, 'latin1'), Buffer.from([0]), Buffer.from(v, 'latin1')])));
  if (tiff) chunks.push(pngChunk('eXIf', tiff));
  if (time) { const t = Buffer.alloc(7); t.writeUInt16BE(time[0], 0); t[2] = time[1]; t[3] = time[2]; t[4] = time[3]; t[5] = time[4]; t[6] = time[5]; chunks.push(pngChunk('tIME', t)); }
  chunks.push(pngChunk('IDAT', zlib.deflateSync(Buffer.alloc(height * (1 + width * 3)))), pngChunk('IEND', Buffer.alloc(0)));
  return Buffer.concat(chunks);
}

function buildPdf({ title = 'Quarterly Report', author = 'Jane Doe', producer = 'Orkardch Test Writer', encrypted = false } = {}) {
  const lines = [
    '%PDF-1.4', '1 0 obj', '<< /Type /Catalog /Pages 2 0 R >>', 'endobj', '2 0 obj', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>', 'endobj',
    '3 0 obj', '<< /Type /Page /Parent 2 0 R >>', 'endobj', '4 0 obj',
    `<< /Title (${title}) /Author (${author}) /Producer (${producer}) /CreationDate (D:20240501102030+02'00') /ModDate (D:20240502000000Z) >>`,
    'endobj', 'trailer', `<< /Root 1 0 R /Info 4 0 R /Size 5${encrypted ? ' /Encrypt 9 0 R' : ''} >>`, '%%EOF', '',
  ];
  return Buffer.from(lines.join('\n'), 'latin1');
}

/** Minimal ZIP writer. entries: [{name, data(Buffer|string), store?}] */
function buildZip(entries) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, 'utf8');
    const raw = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data);
    const method = e.store ? 0 : 8;
    const data = method === 8 ? zlib.deflateRawSync(raw) : raw;
    const crc = crc32(raw);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x800, 6); lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(name.length, 26);
    locals.push(lh, name, data);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x800, 8); ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(offset, 42);
    central.push(ch, name);
    offset += 30 + name.length + data.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

function buildDocx({ author = 'Jane Doe', title = 'Sample Memo', macro = false } = {}) {
  const core = `<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="x" xmlns:dc="y" xmlns:dcterms="z"><dc:title>${title}</dc:title><dc:creator>${author}</dc:creator><cp:lastModifiedBy>John Roe</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">2024-05-01T10:20:30Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2024-05-03T09:00:00Z</dcterms:modified></cp:coreProperties>`;
  const app = '<?xml version="1.0"?><Properties><Application>Microsoft Office Word</Application><AppVersion>16.0000</AppVersion><Company>Example Co</Company><Pages>2</Pages></Properties>';
  const entries = [
    { name: '[Content_Types].xml', data: '<Types/>' }, { name: 'word/document.xml', data: '<w:document/>' },
    { name: 'docProps/core.xml', data: core }, { name: 'docProps/app.xml', data: app }, { name: 'word/media/image1.png', data: 'x' },
  ];
  if (macro) entries.push({ name: 'word/vbaProject.bin', data: 'x' });
  return buildZip(entries);
}

function buildOdt() {
  const meta = '<office:document-meta><office:meta><meta:generator>LibreOffice/7</meta:generator><dc:title>ODF Title</dc:title><meta:initial-creator>Ann Lee</meta:initial-creator><meta:creation-date>2023-01-02T03:04:05</meta:creation-date><dc:date>2023-02-03T04:05:06</dc:date><meta:document-statistic meta:page-count="3" meta:word-count="120"/></office:meta></office:document-meta>';
  return buildZip([{ name: 'mimetype', data: 'application/vnd.oasis.opendocument.text', store: true }, { name: 'meta.xml', data: meta }, { name: 'content.xml', data: '<x/>' }]);
}

module.exports = { crc32, tempDir, rmrf, buildTiff, SAMPLE_EXIF, buildJpeg, buildPng, buildPdf, buildZip, buildDocx, buildOdt, rat };
