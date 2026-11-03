'use strict';
const fs = require('fs');

const TYPES = {
  1: { size: 1, name: 'BYTE' }, 2: { size: 1, name: 'ASCII' }, 3: { size: 2, name: 'SHORT' }, 4: { size: 4, name: 'LONG' },
  5: { size: 8, name: 'RATIONAL' }, 6: { size: 1, name: 'SBYTE' }, 7: { size: 1, name: 'UNDEFINED' }, 8: { size: 2, name: 'SSHORT' },
  9: { size: 4, name: 'SLONG' }, 10: { size: 8, name: 'SRATIONAL' }, 11: { size: 4, name: 'FLOAT' }, 12: { size: 8, name: 'DOUBLE' },
};
const MAX_IFD_ENTRIES = 512;
const MAX_VALUE_BYTES = 65536;

const bufReader = (buf) => ({ size: buf.length, read: (o, l) => (o < 0 || l < 0 || o + l > buf.length ? null : buf.subarray(o, o + l)) });
function fdReader(fd, size) {
  return {
    size,
    read: (o, l) => {
      if (o < 0 || l < 0 || o + l > size || l > 16 * 1024 * 1024) return null;
      const b = Buffer.alloc(l);
      return fs.readSync(fd, b, 0, l, o) === l ? b : null;
    },
  };
}

function decodeValue(type, count, data, le) {
  const u16 = (o) => (le ? data.readUInt16LE(o) : data.readUInt16BE(o));
  const i16 = (o) => (le ? data.readInt16LE(o) : data.readInt16BE(o));
  const u32 = (o) => (le ? data.readUInt32LE(o) : data.readUInt32BE(o));
  const i32 = (o) => (le ? data.readInt32LE(o) : data.readInt32BE(o));
  const arr = [];
  const n = Math.min(count, 64);
  switch (TYPES[type].name) {
    case 'ASCII': return data.toString('utf8', 0, count).replace(/\0[\s\S]*$/, '').trim();
    case 'UNDEFINED': return Buffer.from(data.subarray(0, Math.min(count, MAX_VALUE_BYTES)));
    case 'BYTE': for (let i = 0; i < n; i++) arr.push(data[i]); break;
    case 'SBYTE': for (let i = 0; i < n; i++) arr.push(data.readInt8(i)); break;
    case 'SHORT': for (let i = 0; i < n; i++) arr.push(u16(i * 2)); break;
    case 'SSHORT': for (let i = 0; i < n; i++) arr.push(i16(i * 2)); break;
    case 'LONG': for (let i = 0; i < n; i++) arr.push(u32(i * 4)); break;
    case 'SLONG': for (let i = 0; i < n; i++) arr.push(i32(i * 4)); break;
    case 'FLOAT': for (let i = 0; i < n; i++) arr.push(le ? data.readFloatLE(i * 4) : data.readFloatBE(i * 4)); break;
    case 'DOUBLE': for (let i = 0; i < n; i++) arr.push(le ? data.readDoubleLE(i * 8) : data.readDoubleBE(i * 8)); break;
    case 'RATIONAL': for (let i = 0; i < n; i++) { const d = u32(i * 8 + 4); arr.push(d === 0 ? null : u32(i * 8) / d); } break;
    case 'SRATIONAL': for (let i = 0; i < n; i++) { const d = i32(i * 8 + 4); arr.push(d === 0 ? null : i32(i * 8) / d); } break;
    default: return null;
  }
  return arr.length === 1 ? arr[0] : arr;
}

/** Parse a TIFF structure (also the body of JPEG/PNG/WebP EXIF). Every read is bounds-checked. */
function parseTiff(reader, base = 0) {
  const fail = (reason) => ({ ok: false, reason });
  const hdr = reader.read(base, 8);
  if (!hdr) return fail('too short to hold a TIFF header');
  const le = hdr[0] === 0x49 && hdr[1] === 0x49;
  const be = hdr[0] === 0x4d && hdr[1] === 0x4d;
  if (!le && !be) return fail('no TIFF byte-order mark');
  const u16 = (b, o) => (le ? b.readUInt16LE(o) : b.readUInt16BE(o));
  const u32 = (b, o) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
  if (u16(hdr, 2) !== 42) return fail('bad TIFF magic number');
  const out = { ok: true, ifd0: {}, exif: {}, gps: {}, warnings: [], byteOrder: le ? 'little-endian' : 'big-endian' };
  const warn = (m) => { if (out.warnings.length < 10) out.warnings.push(m); };

  const readIfd = (offset, into, depth) => {
    const cb = reader.read(base + offset, 2);
    if (!cb) { warn(`directory at offset ${offset} lies outside the data`); return; }
    const count = u16(cb, 0);
    if (count > MAX_IFD_ENTRIES) { warn(`directory has an implausible ${count} entries; skipped`); return; }
    const ents = reader.read(base + offset + 2, count * 12);
    if (!ents) { warn('directory entries are cut off'); return; }
    for (let i = 0; i < count; i++) {
      const tag = u16(ents, i * 12);
      const type = u16(ents, i * 12 + 2);
      const cnt = u32(ents, i * 12 + 4);
      const t = TYPES[type];
      if (!t || cnt === 0) continue;
      const total = t.size * cnt;
      if (total > MAX_VALUE_BYTES * 4) { warn(`tag 0x${tag.toString(16)} is too large to read; skipped`); continue; }
      let data;
      if (total <= 4) data = ents.subarray(i * 12 + 8, i * 12 + 8 + total);
      else {
        data = reader.read(base + u32(ents, i * 12 + 8), Math.min(total, MAX_VALUE_BYTES));
        if (!data) { warn(`tag 0x${tag.toString(16)} points outside the data`); continue; }
      }
      try { into[tag] = decodeValue(type, Math.min(cnt, Math.floor(data.length / t.size) || cnt), data, le); } catch { warn(`tag 0x${tag.toString(16)} could not be decoded`); }
    }
    if (depth === 0) {
      if (typeof into[0x8769] === 'number') readIfd(into[0x8769], out.exif, 1);
      if (typeof into[0x8825] === 'number') readIfd(into[0x8825], out.gps, 1);
    }
  };
  readIfd(u32(hdr, 4), out.ifd0, 0);
  return out;
}

const ORIENTATION = {
  1: 'Normal', 2: 'Mirrored horizontally', 3: 'Rotated 180°', 4: 'Mirrored vertically',
  5: 'Mirrored horizontally, rotated 270° clockwise', 6: 'Rotated 90° clockwise', 7: 'Mirrored horizontally, rotated 90° clockwise', 8: 'Rotated 270° clockwise',
};

function exifDate(raw, offset) {
  if (typeof raw !== 'string' || !raw) return null;
  const m = /^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/.exec(raw);
  if (!m || m[1] === '0000' || m[2] === '00' || m[3] === '00') return { raw, iso: null, note: 'Not a valid date (cameras write zeros when the clock was unset).' };
  const local = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}`;
  const off = typeof offset === 'string' && /^[+-]\d{2}:\d{2}$/.test(offset) ? offset : null;
  const iso = off ? local + off : local;
  if (Number.isNaN(new Date(iso).getTime())) return { raw, iso: null, note: 'Not a valid calendar date.' };
  return { raw, iso, timezone: off || 'not recorded (camera local time)' };
}

function dms(v, ref) {
  if (!Array.isArray(v) || v.length < 3 || v.some((x) => typeof x !== 'number' || !Number.isFinite(x))) return null;
  const val = v[0] + v[1] / 60 + v[2] / 3600;
  return /^[SW]/i.test(ref || '') ? -val : val;
}

const text = (v) => (typeof v === 'string' && v ? v : null);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);

function userComment(buf) {
  if (!Buffer.isBuffer(buf) || buf.length <= 8) return null;
  const prefix = buf.toString('latin1', 0, 8);
  const body = buf.subarray(8);
  const s = prefix.startsWith('UNICODE') ? body.toString('utf16le') : body.toString('utf8');
  return s.replace(/\0+$/, '').trim() || null;
}

/** Turn raw tags into plain, labelled fields. Missing fields stay missing; nothing is invented. */
function summarizeExif(t) {
  const i = t.ifd0;
  const e = t.exif;
  const g = t.gps;
  const out = { camera: {}, settings: {}, dates: {}, image: {}, other: {}, warnings: t.warnings };
  Object.assign(out.camera, {
    make: text(i[0x010f]), model: text(i[0x0110]), lensMake: text(e[0xa433]), lensModel: text(e[0xa434]),
  });
  out.software = text(i[0x0131]);
  out.artist = text(i[0x013b]);
  out.copyright = text(i[0x8298]);
  out.imageDescription = text(i[0x010e]);
  out.owner = text(e[0xa430]);
  out.bodySerial = text(e[0xa431]);
  out.lensSerial = text(e[0xa435]);
  const off = text(e[0x9011]) || text(e[0x9010]);
  out.dates.captured = exifDate(text(e[0x9003]), text(e[0x9011]));
  out.dates.digitized = exifDate(text(e[0x9004]), text(e[0x9012]));
  out.dates.modified = exifDate(text(i[0x0132]), text(e[0x9010]));
  void off;
  const o = num(i[0x0112]);
  if (o) out.image.orientation = { value: o, description: ORIENTATION[o] || 'Unknown value' };
  out.image.width = num(e[0xa002]) || num(i[0x0100]);
  out.image.height = num(e[0xa003]) || num(i[0x0101]);
  const et = num(e[0x829a]);
  Object.assign(out.settings, {
    exposureTime: et ? (et >= 1 ? `${et} s` : `1/${Math.round(1 / et)} s`) : null,
    aperture: num(e[0x829d]) ? `f/${Number(e[0x829d]).toFixed(1)}` : null,
    iso: num(Array.isArray(e[0x8827]) ? e[0x8827][0] : e[0x8827]),
    focalLengthMm: num(e[0x920a]),
    flash: num(e[0x9209]) !== null ? (e[0x9209] & 1 ? 'Fired' : 'Did not fire') : null,
  });
  const comment = userComment(e[0x9286]);
  if (comment) out.other.userComment = comment.slice(0, 500);
  if (Buffer.isBuffer(e[0x927c])) out.other.makerNote = `present (${e[0x927c].length} bytes, not decoded)`;
  if (Object.keys(g).length) {
    const lat = dms(g[2], g[1]);
    const lon = dms(g[4], g[3]);
    const valid = lat !== null && lon !== null && Math.abs(lat) <= 90 && Math.abs(lon) <= 180;
    const gps = { present: true, valid, notes: [] };
    if (valid) { gps.latitude = lat; gps.longitude = lon; if (lat === 0 && lon === 0) gps.notes.push('Coordinates are exactly 0,0, which usually means "no GPS fix", not a real location.'); }
    else gps.notes.push('GPS tags exist but the coordinates are missing or out of range.');
    if (num(g[6]) !== null) gps.altitudeMeters = (g[5] === 1 ? -1 : 1) * g[6];
    const date = text(g[0x1d]);
    if (date && Array.isArray(g[7]) && g[7].length === 3) {
      const iso = `${date.replace(/:/g, '-')}T${g[7].map((n) => String(Math.floor(n)).padStart(2, '0')).join(':')}Z`;
      if (!Number.isNaN(new Date(iso).getTime())) gps.timestampUtc = iso;
    }
    out.gps = gps;
  }
  for (const k of Object.keys(out.camera)) if (!out.camera[k]) delete out.camera[k];
  for (const k of Object.keys(out.settings)) if (out.settings[k] === null) delete out.settings[k];
  for (const k of ['software', 'artist', 'copyright', 'imageDescription', 'owner', 'bodySerial', 'lensSerial']) if (!out[k]) delete out[k];
  for (const k of Object.keys(out.dates)) if (!out.dates[k]) delete out.dates[k];
  return out;
}

module.exports = { parseTiff, summarizeExif, bufReader, fdReader, exifDate };
