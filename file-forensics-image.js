'use strict';
const fs = require('fs');
const zlib = require('zlib');
const { parseTiff, summarizeExif, bufReader, fdReader } = require('./file-forensics-tiff');

function readAt(fd, pos, len) {
  if (len <= 0) return Buffer.alloc(0);
  const b = Buffer.alloc(len);
  const n = fs.readSync(fd, b, 0, len, pos);
  return n === len ? b : b.subarray(0, n);
}
const isSof = (m) => m >= 0xc0 && m <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(m);

function walkJpeg(fd, size) {
  const out = { width: null, height: null, exifBuf: null, xmpText: null, comments: [], progressive: false, notes: [] };
  let pos = 2;
  for (let guard = 0; pos + 4 <= size && guard < 5000; guard++) {
    const h = readAt(fd, pos, 4);
    if (h.length < 4) break;
    if (h[0] !== 0xff) { out.notes.push('Unexpected bytes between JPEG segments; reading stopped early.'); break; }
    const m = h[1];
    if (m === 0xff) { pos += 1; continue; }
    if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { pos += 2; continue; }
    if (m === 0xd9 || m === 0xda) break;
    const len = h.readUInt16BE(2);
    if (len < 2) break;
    const start = pos + 4;
    const dataLen = len - 2;
    if (m === 0xe1 && dataLen >= 6 && dataLen <= 200000) {
      const seg = readAt(fd, start, dataLen);
      if (seg.toString('latin1', 0, 6) === 'Exif\0\0') { if (!out.exifBuf) out.exifBuf = seg.subarray(6); }
      else if (seg.toString('latin1', 0, 29) === 'http://ns.adobe.com/xap/1.0/\0') out.xmpText = seg.toString('utf8', 29);
    } else if (m === 0xfe && dataLen <= 4096) {
      out.comments.push(readAt(fd, start, dataLen).toString('utf8').replace(/\0+$/, ''));
    } else if (isSof(m) && dataLen >= 6) {
      const sof = readAt(fd, start, 6);
      out.height = sof.readUInt16BE(1);
      out.width = sof.readUInt16BE(3);
      out.progressive = m === 0xc2;
    }
    pos = start + dataLen;
  }
  return out;
}

function walkPng(fd, size) {
  const out = { width: null, height: null, exifBuf: null, xmpText: null, text: {}, modified: null, notes: [] };
  let pos = 8;
  for (let guard = 0; pos + 12 <= size && guard < 100000; guard++) {
    const h = readAt(fd, pos, 8);
    if (h.length < 8) break;
    const len = h.readUInt32BE(0);
    const type = h.toString('latin1', 4, 8);
    const dp = pos + 8;
    if (len > size) { out.notes.push('A PNG chunk claims to be larger than the file; reading stopped.'); break; }
    if (type === 'IHDR' && len >= 13) { const d = readAt(fd, dp, 13); out.width = d.readUInt32BE(0); out.height = d.readUInt32BE(4); }
    else if (type === 'eXIf' && len <= 1 << 20) out.exifBuf = readAt(fd, dp, len);
    else if (type === 'tIME' && len === 7) {
      const d = readAt(fd, dp, 7);
      const iso = `${String(d.readUInt16BE(0)).padStart(4, '0')}-${String(d[2]).padStart(2, '0')}-${String(d[3]).padStart(2, '0')}T${String(d[4]).padStart(2, '0')}:${String(d[5]).padStart(2, '0')}:${String(d[6]).padStart(2, '0')}Z`;
      if (!Number.isNaN(new Date(iso).getTime())) out.modified = iso;
    } else if ((type === 'tEXt' || type === 'zTXt' || type === 'iTXt') && len <= 262144) {
      const d = readAt(fd, dp, len);
      const z = d.indexOf(0);
      if (z > 0 && Object.keys(out.text).length < 20) {
        const key = d.toString('latin1', 0, z);
        let val = null;
        try {
          if (type === 'tEXt') val = d.toString('latin1', z + 1);
          else if (type === 'zTXt') val = zlib.inflateSync(d.subarray(z + 2), { maxOutputLength: 262144 }).toString('latin1');
          else {
            const compressed = d[z + 1] === 1;
            let p = z + 3;
            p = d.indexOf(0, p) + 1;
            p = d.indexOf(0, p) + 1;
            const body = d.subarray(p);
            val = (compressed ? zlib.inflateSync(body, { maxOutputLength: 262144 }) : body).toString('utf8');
          }
        } catch { val = null; }
        if (val !== null) { if (key === 'XML:com.adobe.xmp') out.xmpText = val; else out.text[key] = val.slice(0, 500); }
      }
    } else if (type === 'IEND') break;
    pos = dp + len + 4;
  }
  return out;
}

function walkWebp(fd, size) {
  const out = { width: null, height: null, exifBuf: null, xmpText: null, notes: [] };
  let pos = 12;
  for (let guard = 0; pos + 8 <= size && guard < 1000; guard++) {
    const h = readAt(fd, pos, 8);
    if (h.length < 8) break;
    const cc = h.toString('latin1', 0, 4);
    const len = h.readUInt32LE(4);
    const dp = pos + 8;
    if (cc === 'VP8X' && len >= 10) { const d = readAt(fd, dp, 10); out.width = 1 + d.readUIntLE(4, 3); out.height = 1 + d.readUIntLE(7, 3); }
    else if (cc === 'VP8 ' && len >= 10) { const d = readAt(fd, dp, 10); if (d[3] === 0x9d && d[4] === 0x01 && d[5] === 0x2a) { out.width = d.readUInt16LE(6) & 0x3fff; out.height = d.readUInt16LE(8) & 0x3fff; } }
    else if (cc === 'VP8L' && len >= 5) { const d = readAt(fd, dp, 5); if (d[0] === 0x2f) { const bits = d.readUInt32LE(1); out.width = (bits & 0x3fff) + 1; out.height = ((bits >> 14) & 0x3fff) + 1; } }
    else if (cc === 'EXIF' && len <= 1 << 20) { const d = readAt(fd, dp, len); out.exifBuf = d.toString('latin1', 0, 6) === 'Exif\0\0' ? d.subarray(6) : d; }
    else if (cc === 'XMP ' && len <= 200000) out.xmpText = readAt(fd, dp, len).toString('utf8');
    pos = dp + len + (len & 1);
  }
  return out;
}

function xmpFields(xml) {
  if (!xml) return null;
  const pick = (name) => {
    const a = new RegExp(`${name}="([^"]*)"`, 'i').exec(xml);
    if (a) return a[1];
    const b = new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, 'i').exec(xml);
    return b ? b[1].replace(/<[^>]+>/g, '').trim() || null : null;
  };
  const out = {};
  for (const [k, n] of [['creatorTool', 'xmp:CreatorTool'], ['createDate', 'xmp:CreateDate'], ['modifyDate', 'xmp:ModifyDate'], ['creator', 'dc:creator']]) {
    const v = pick(n);
    if (v) out[k] = v.slice(0, 200);
  }
  return Object.keys(out).length ? out : null;
}

/** Read dimensions and embedded metadata. Only headers and metadata blocks are read, never the pixels. */
function inspectImage(file, type) {
  const fd = fs.openSync(file, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const notes = [];
    let w = { width: null, height: null, exifBuf: null, xmpText: null };
    let tiff = null;
    const mime = type.mime;
    if (mime === 'image/jpeg') w = walkJpeg(fd, size);
    else if (mime === 'image/png') w = walkPng(fd, size);
    else if (mime === 'image/webp') w = walkWebp(fd, size);
    else if (mime === 'image/gif') { const d = readAt(fd, 0, 10); if (d.length >= 10) { w.width = d.readUInt16LE(6); w.height = d.readUInt16LE(8); } }
    else if (mime === 'image/bmp') { const d = readAt(fd, 0, 26); if (d.length >= 26) { w.width = Math.abs(d.readInt32LE(18)); w.height = Math.abs(d.readInt32LE(22)); } }
    else if (mime === 'image/tiff') tiff = parseTiff(fdReader(fd, size), 0);
    else if (mime === 'image/heic') return { kind: 'image', supported: false, reason: 'HEIC/HEIF metadata reading is not supported in this version. Convert a copy to JPEG to inspect it.' };
    if (w.exifBuf && !tiff) tiff = parseTiff(bufReader(w.exifBuf), 0);
    if (w.notes) notes.push(...w.notes);
    const result = { kind: 'image', supported: true, format: type.description, dimensions: null, exif: null, xmp: xmpFields(w.xmpText), notes };
    if (tiff && tiff.ok) result.exif = summarizeExif(tiff);
    else if (tiff && !tiff.ok) notes.push(`Embedded EXIF block could not be read: ${tiff.reason}.`);
    const width = w.width || (result.exif && result.exif.image.width) || null;
    const height = w.height || (result.exif && result.exif.image.height) || null;
    if (width && height) result.dimensions = { width, height };
    if (w.comments && w.comments.length) result.comments = w.comments.slice(0, 5);
    if (w.text && Object.keys(w.text).length) result.textChunks = w.text;
    if (w.modified) result.embeddedDates = { pngLastModified: { raw: w.modified, iso: w.modified } };
    if (w.progressive) result.progressive = true;
    if (!result.exif && !result.xmp && !result.textChunks && !(result.comments && result.comments.length)) {
      notes.push('No embedded camera or editing metadata was found. Many apps and websites strip it, so its absence does not mean anything by itself.');
    }
    return result;
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = { inspectImage };
