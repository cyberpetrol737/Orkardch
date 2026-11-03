'use strict';
const fs = require('fs');
const zlib = require('zlib');

const EOCD = 0x06054b50;
const CEN = 0x02014b50;
const LOC = 0x04034b50;

function readAt(fd, pos, len) {
  if (len <= 0) return Buffer.alloc(0);
  const buf = Buffer.alloc(len);
  const n = fs.readSync(fd, buf, 0, len, pos);
  return n === len ? buf : buf.subarray(0, n);
}

/** Read only the ZIP central directory (the file list). Never loads the whole archive. */
function openZip(file, { maxEntries = 20000 } = {}) {
  const fd = fs.openSync(file, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    if (size < 22) return { ok: false, reason: 'file is too small to be a ZIP archive' };
    const tailLen = Math.min(size, 65557);
    const tail = readAt(fd, size - tailLen, tailLen);
    let eocd = -1;
    for (let i = tail.length - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === EOCD) { eocd = i; break; }
    }
    if (eocd < 0) return { ok: false, reason: 'no ZIP end-of-archive record found' };
    const total = tail.readUInt16LE(eocd + 10);
    const cdSize = tail.readUInt32LE(eocd + 12);
    const cdOffset = tail.readUInt32LE(eocd + 16);
    if (total === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) return { ok: false, reason: 'ZIP64 archives are not supported yet' };
    if (cdSize > 32 * 1024 * 1024 || cdOffset + cdSize > size) return { ok: false, reason: 'the ZIP file list looks damaged' };
    const cd = readAt(fd, cdOffset, cdSize);
    const entries = [];
    let p = 0;
    while (p + 46 <= cd.length && entries.length < maxEntries) {
      if (cd.readUInt32LE(p) !== CEN) break;
      const flags = cd.readUInt16LE(p + 8);
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      entries.push({
        name: cd.toString(flags & 0x800 ? 'utf8' : 'latin1', p + 46, p + 46 + nameLen),
        method: cd.readUInt16LE(p + 10), compSize: cd.readUInt32LE(p + 20), uncompSize: cd.readUInt32LE(p + 24),
        offset: cd.readUInt32LE(p + 42), encrypted: Boolean(flags & 1),
      });
      p += 46 + nameLen + extraLen + commentLen;
    }
    return { ok: true, size, entries, truncated: entries.length < total };
  } finally {
    fs.closeSync(fd);
  }
}

/** Read one entry, refusing anything that expands beyond `limit` bytes (zip-bomb guard). */
function readEntry(file, entry, { limit = 2 * 1024 * 1024 } = {}) {
  if (entry.encrypted) return { ok: false, reason: 'this part is encrypted' };
  if (entry.uncompSize > limit) return { ok: false, reason: `this part is larger than ${limit} bytes` };
  if (entry.compSize > limit * 2) return { ok: false, reason: 'this part is too large to read safely' };
  const fd = fs.openSync(file, 'r');
  try {
    const hdr = readAt(fd, entry.offset, 30);
    if (hdr.length < 30 || hdr.readUInt32LE(0) !== LOC) return { ok: false, reason: 'damaged ZIP entry header' };
    const dataPos = entry.offset + 30 + hdr.readUInt16LE(26) + hdr.readUInt16LE(28);
    const data = readAt(fd, dataPos, entry.compSize);
    if (entry.method === 0) return { ok: true, data };
    if (entry.method === 8) {
      try { return { ok: true, data: zlib.inflateRawSync(data, { maxOutputLength: limit }) }; } catch (e) { return { ok: false, reason: `could not decompress (${e.code || e.message})` }; }
    }
    return { ok: false, reason: `unsupported compression method ${entry.method}` };
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = { openZip, readEntry };
