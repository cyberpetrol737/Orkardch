'use strict';
const fs = require('fs');

const FULL_SCAN_LIMIT = 24 * 1024 * 1024;
const EDGE = 2 * 1024 * 1024;
const KEYS = ['Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer', 'CreationDate', 'ModDate'];

function decodeString(tok) {
  let bytes;
  if (tok[0] === '(') {
    const inner = tok.slice(1, -1);
    const out = [];
    for (let i = 0; i < inner.length; i++) {
      const ch = inner[i];
      if (ch !== '\\') { out.push(inner.charCodeAt(i) & 0xff); continue; }
      const n = inner[++i];
      if (n === undefined) break;
      const map = { n: 10, r: 13, t: 9, b: 8, f: 12, '(': 40, ')': 41, '\\': 92 };
      if (n in map) out.push(map[n]);
      else if (/[0-7]/.test(n)) {
        let oct = n;
        while (oct.length < 3 && /[0-7]/.test(inner[i + 1] || '')) oct += inner[++i];
        out.push(parseInt(oct, 8) & 0xff);
      } else if (n === '\r') { if (inner[i + 1] === '\n') i++; } else if (n !== '\n') out.push(n.charCodeAt(0) & 0xff);
    }
    bytes = Buffer.from(out);
  } else {
    let hex = tok.slice(1, -1).replace(/\s+/g, '');
    if (hex.length % 2) hex += '0';
    bytes = Buffer.from(hex, 'hex');
  }
  if (bytes[0] === 0xfe && bytes[1] === 0xff) { const sw = Buffer.from(bytes.subarray(2)); sw.swap16(); return sw.toString('utf16le'); }
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return bytes.toString('utf8', 3);
  return bytes.toString('latin1');
}

function parsePdfDate(s) {
  const m = /^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Zz+-])?(?:(\d{2})'?(\d{2})?'?)?/.exec(String(s).trim());
  if (!m) return { raw: s, iso: null, note: 'Not in the standard PDF date format.' };
  const [, Y, Mo = '01', D = '01', H = '00', Mi = '00', S = '00', tz, th = '00', tm = '00'] = m;
  let iso = `${Y}-${Mo}-${D}T${H}:${Mi}:${S}`;
  let timezone = 'not recorded';
  if (tz === 'Z' || tz === 'z') { iso += 'Z'; timezone = 'UTC'; } else if (tz === '+' || tz === '-') { iso += `${tz}${th}:${tm}`; timezone = `${tz}${th}:${tm}`; }
  return Number.isNaN(new Date(iso).getTime()) ? { raw: s, iso: null, note: 'Not a valid calendar date.' } : { raw: s, iso, timezone };
}

function readRegions(file, size) {
  const fd = fs.openSync(file, 'r');
  try {
    const read = (pos, len) => { const b = Buffer.alloc(len); const n = fs.readSync(fd, b, 0, len, pos); return b.subarray(0, n); };
    if (size <= FULL_SCAN_LIMIT) return { regions: [read(0, size)], partial: false };
    return { regions: [read(0, EDGE), read(size - EDGE, EDGE)], partial: true };
  } finally {
    fs.closeSync(fd);
  }
}

const STR = String.raw`(\((?:[^()\\]|\\[\s\S]|\((?:[^()\\]|\\[\s\S])*\))*\)|<[0-9A-Fa-f\s]*>)`;

function parseInfoDict(text) {
  const out = {};
  for (const key of KEYS) {
    const m = new RegExp(`/${key}\\s*${STR}`).exec(text);
    if (m) out[key] = decodeString(m[1]);
  }
  return out;
}

function inspectPdf(file) {
  const size = fs.statSync(file).size;
  const { regions, partial } = readRegions(file, size);
  const notes = [];
  let version = null;
  let encrypted = false;
  let infoRef = null;
  let pages = 0;
  let xmp = null;
  const candidates = [];
  const seenPages = new Set();
  regions.forEach((buf, idx) => {
    const s = buf.toString('latin1');
    if (idx === 0) { const v = /%PDF-(\d\.\d)/.exec(s.slice(0, 1024)); if (v) version = v[1]; }
    if (/\/Encrypt\b/.test(s)) encrypted = true;
    const refs = [...s.matchAll(/\/Info\s+(\d+)\s+(\d+)\s+R/g)];
    if (refs.length) infoRef = Number(refs[refs.length - 1][1]);
    for (const m of s.matchAll(/\/Type\s*\/Page(?![A-Za-z])/g)) seenPages.add(`${idx}:${m.index}`);
    if (!xmp) {
      const a = s.indexOf('<x:xmpmeta');
      const b = a >= 0 ? s.indexOf('</x:xmpmeta>', a) : -1;
      if (a >= 0 && b > a && b - a < 200000) xmp = s.slice(a, b + 12);
    }
    for (const m of s.matchAll(/(\d+)\s+(\d+)\s+obj\b([\s\S]{0,6000}?)endobj/g)) {
      const body = m[3];
      const hits = KEYS.filter((k) => body.includes(`/${k}`)).length;
      if (hits >= 2 && !/\/Type\s*\/(Page|Pages|Catalog|Font|XObject)\b/.test(body)) {
        candidates.push({ num: Number(m[1]), body: body.split('stream')[0] });
      }
    }
  });
  pages = seenPages.size;
  const chosen = candidates.find((c) => c.num === infoRef) || (infoRef === null ? candidates[candidates.length - 1] : null);
  let fields = {};
  const embeddedDates = {};
  if (encrypted) {
    notes.push('This PDF is encrypted, so its metadata strings are scrambled and were not decoded.');
  } else if (chosen) {
    const info = parseInfoDict(chosen.body);
    for (const [k, v] of Object.entries(info)) {
      if (k === 'CreationDate') embeddedDates.created = parsePdfDate(v);
      else if (k === 'ModDate') embeddedDates.modified = parsePdfDate(v);
      else if (v.trim()) fields[k[0].toLowerCase() + k.slice(1)] = v.trim().slice(0, 500);
    }
    if (infoRef === null) notes.push('The document information object could not be tied to the file trailer, so the nearest match was used. Treat it as less certain.');
  } else {
    notes.push('No readable document information dictionary was found. It may be stored in a compressed object stream, which this version does not unpack, or the file may have none.');
  }
  if (xmp && !encrypted) {
    const grab = (name) => { const m = new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, 'i').exec(xmp); return m ? m[1].replace(/<[^>]+>/g, '').trim() || null : null; };
    const attrs = (name) => { const m = new RegExp(`${name}="([^"]*)"`, 'i').exec(xmp); return m ? m[1] : null; };
    const tool = attrs('xmp:CreatorTool') || grab('xmp:CreatorTool');
    const xc = attrs('xmp:CreateDate') || grab('xmp:CreateDate');
    const xm = attrs('xmp:ModifyDate') || grab('xmp:ModifyDate');
    if (tool) fields.xmpCreatorTool = tool.slice(0, 200);
    if (xc) embeddedDates.xmpCreated = { raw: xc, iso: Number.isNaN(new Date(xc).getTime()) ? null : new Date(xc).toISOString() };
    if (xm) embeddedDates.xmpModified = { raw: xm, iso: Number.isNaN(new Date(xm).getTime()) ? null : new Date(xm).toISOString() };
  }
  if (partial) notes.push('Large file: only the first and last 2 MB were scanned, so the page count is unknown and some metadata could be missed.');
  return {
    kind: 'document', supported: true, format: 'PDF', fields, embeddedDates,
    structure: { pdfVersion: version, pages: partial ? null : pages, pagesNote: partial ? 'unknown (partial scan)' : 'counted by page markers; approximate', encrypted },
    notes,
  };
}

module.exports = { inspectPdf, parsePdfDate, decodeString };
