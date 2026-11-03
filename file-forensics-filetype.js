'use strict';
const fs = require('fs');
const path = require('path');
const { openZip, readEntry } = require('./file-forensics-zip');

const ascii = (b, from, to) => b.toString('latin1', from, to);
const starts = (b, sig, at = 0) => sig.every((v, i) => b[at + i] === v);

// Signatures checked in order. This is a built-in list (not exhaustive); unknown means "not recognised".
const SIGNATURES = [
  { mime: 'image/jpeg', description: 'JPEG image', ext: ['jpg', 'jpeg', 'jpe'], test: (b) => starts(b, [0xff, 0xd8, 0xff]) },
  { mime: 'image/png', description: 'PNG image', ext: ['png'], test: (b) => starts(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  { mime: 'image/gif', description: 'GIF image', ext: ['gif'], test: (b) => ['GIF87a', 'GIF89a'].includes(ascii(b, 0, 6)) },
  { mime: 'image/webp', description: 'WebP image', ext: ['webp'], test: (b) => ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 12) === 'WEBP' },
  { mime: 'image/tiff', description: 'TIFF image', ext: ['tif', 'tiff'], test: (b) => (starts(b, [0x49, 0x49, 0x2a, 0x00]) || starts(b, [0x4d, 0x4d, 0x00, 0x2a])) },
  { mime: 'image/bmp', description: 'BMP image', ext: ['bmp'], test: (b) => ascii(b, 0, 2) === 'BM' && b.length > 14 && b.readUInt32LE(10) < 1e7 },
  { mime: 'image/heic', description: 'HEIC/HEIF image', ext: ['heic', 'heif'], test: (b) => ascii(b, 4, 8) === 'ftyp' && ['heic', 'heix', 'hevc', 'hevx', 'mif1', 'msf1', 'heim', 'heis'].includes(ascii(b, 8, 12)) },
  { mime: 'application/pdf', description: 'PDF document', ext: ['pdf'], test: (b) => b.subarray(0, 1024).includes('%PDF-') },
  { mime: 'application/zip', description: 'ZIP archive', ext: ['zip'], test: (b) => starts(b, [0x50, 0x4b, 0x03, 0x04]) || starts(b, [0x50, 0x4b, 0x05, 0x06]) },
  { mime: 'application/gzip', description: 'GZIP compressed data', ext: ['gz', 'tgz'], test: (b) => starts(b, [0x1f, 0x8b]) },
  { mime: 'application/x-7z-compressed', description: '7-Zip archive', ext: ['7z'], test: (b) => starts(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
  { mime: 'application/vnd.rar', description: 'RAR archive', ext: ['rar'], test: (b) => ascii(b, 0, 6) === 'Rar!\x1a\x07' },
  { mime: 'application/x-bzip2', description: 'BZIP2 compressed data', ext: ['bz2'], test: (b) => ascii(b, 0, 3) === 'BZh' },
  { mime: 'application/x-xz', description: 'XZ compressed data', ext: ['xz'], test: (b) => starts(b, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) },
  { mime: 'application/x-ole-storage', description: 'Legacy Microsoft Office / OLE file', ext: ['doc', 'xls', 'ppt', 'msg'], test: (b) => starts(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) },
  { mime: 'application/rtf', description: 'Rich Text Format document', ext: ['rtf'], test: (b) => ascii(b, 0, 5) === '{\\rtf' },
  { mime: 'application/vnd.sqlite3', description: 'SQLite database', ext: ['sqlite', 'db', 'sqlite3'], test: (b) => ascii(b, 0, 15) === 'SQLite format 3' },
  { mime: 'audio/mpeg', description: 'MP3 audio', ext: ['mp3'], test: (b) => ascii(b, 0, 3) === 'ID3' || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0 && (b[1] & 0x06) !== 0) },
  { mime: 'audio/flac', description: 'FLAC audio', ext: ['flac'], test: (b) => ascii(b, 0, 4) === 'fLaC' },
  { mime: 'audio/ogg', description: 'Ogg container', ext: ['ogg', 'oga', 'opus'], test: (b) => ascii(b, 0, 4) === 'OggS' },
  { mime: 'audio/wav', description: 'WAV audio', ext: ['wav'], test: (b) => ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 12) === 'WAVE' },
  { mime: 'video/x-msvideo', description: 'AVI video', ext: ['avi'], test: (b) => ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 12) === 'AVI ' },
  { mime: 'video/x-matroska', description: 'Matroska/WebM video', ext: ['mkv', 'webm'], test: (b) => starts(b, [0x1a, 0x45, 0xdf, 0xa3]) },
  { mime: 'video/mp4', description: 'MP4/QuickTime media', ext: ['mp4', 'm4a', 'm4v', 'mov', '3gp'], test: (b) => ascii(b, 4, 8) === 'ftyp' },
  { mime: 'application/x-elf', description: 'ELF executable', ext: ['so', 'elf', 'bin', 'o'], test: (b) => starts(b, [0x7f, 0x45, 0x4c, 0x46]) },
  { mime: 'application/vnd.android.dex', description: 'Android DEX code', ext: ['dex'], test: (b) => ascii(b, 0, 4) === 'dex\n' },
];

const OOXML = { word: ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'Word document (OOXML)'], xl: ['xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Excel workbook (OOXML)'], ppt: ['pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'PowerPoint presentation (OOXML)'] };
const ODF = { 'application/vnd.oasis.opendocument.text': ['odt', 'OpenDocument text'], 'application/vnd.oasis.opendocument.spreadsheet': ['ods', 'OpenDocument spreadsheet'], 'application/vnd.oasis.opendocument.presentation': ['odp', 'OpenDocument presentation'] };

function refineZip(file) {
  const z = openZip(file);
  if (!z.ok) return null;
  const names = z.entries.map((e) => e.name);
  if (names.includes('[Content_Types].xml')) {
    for (const [dir, [ext, mime, description]] of Object.entries(OOXML)) {
      if (names.some((n) => n.startsWith(`${dir}/`))) return { mime, description, ext: [ext], family: 'office-ooxml', zipEntries: names.length };
    }
  }
  const mt = z.entries.find((e) => e.name === 'mimetype');
  if (mt) {
    const r = readEntry(file, mt, { limit: 256 });
    const m = r.ok ? r.data.toString('utf8').trim() : '';
    if (ODF[m]) return { mime: m, description: ODF[m][1], ext: [ODF[m][0]], family: 'office-odf', zipEntries: names.length };
    if (m === 'application/epub+zip') return { mime: m, description: 'EPUB e-book', ext: ['epub'], family: 'zip', zipEntries: names.length };
  }
  if (names.includes('AndroidManifest.xml') && names.some((n) => n.endsWith('.dex'))) return { mime: 'application/vnd.android.package-archive', description: 'Android app package (APK)', ext: ['apk'], family: 'zip', zipEntries: names.length };
  if (names.includes('META-INF/MANIFEST.MF')) return { mime: 'application/java-archive', description: 'Java archive (JAR)', ext: ['jar'], family: 'zip', zipEntries: names.length };
  return { mime: 'application/zip', description: 'ZIP archive', ext: ['zip'], family: 'zip', zipEntries: names.length };
}

function looksLikeText(buf) {
  if (!buf.length) return true;
  if (buf.includes(0)) return false;
  let slice = buf;
  for (let cut = 0; cut < 4; cut++) {
    try { new TextDecoder('utf-8', { fatal: true }).decode(slice.subarray(0, slice.length - cut)); return true; } catch { /* try trimming a split character */ }
  }
  return false;
}

/** Identify a file by its first bytes (not by its name). */
function detectType(file) {
  const fd = fs.openSync(file, 'r');
  let head;
  try {
    const buf = Buffer.alloc(4096);
    const n = fs.readSync(fd, buf, 0, 4096, 0);
    head = buf.subarray(0, n);
  } finally {
    fs.closeSync(fd);
  }
  const ext = path.extname(file).replace(/^\./, '').toLowerCase();
  let found = null;
  if (head.length === 0) {
    return { mime: 'application/x-empty', description: 'Empty file (0 bytes)', ext: [], family: 'empty', confidence: 'file size', extension: ext || null, extensionMatches: null, note: 'The file contains no data at all.' };
  }
  for (const sig of SIGNATURES) {
    let ok = false;
    try { ok = head.length >= 2 && sig.test(head); } catch { ok = false; }
    if (ok) { found = { mime: sig.mime, description: sig.description, ext: sig.ext, family: sig.mime.split('/')[0], confidence: 'file signature' }; break; }
  }
  if (found && found.mime === 'application/zip') {
    const refined = refineZip(file);
    if (refined) found = { ...found, ...refined };
  }
  if (!found && looksLikeText(head)) {
    const t = head.toString('utf8').trimStart().slice(0, 200).toLowerCase();
    const sub = t.startsWith('<?xml') ? ['application/xml', 'XML text', ['xml']]
      : (t.startsWith('<!doctype html') || t.startsWith('<html')) ? ['text/html', 'HTML text', ['html', 'htm']]
        : (/^[{[]/.test(t)) ? ['text/plain', 'Text that may be JSON', ['json', 'txt']]
          : ['text/plain', 'Plain text', ['txt', 'md', 'log', 'csv', 'json', 'js', 'py', 'sh']];
    found = { mime: sub[0], description: sub[1], ext: sub[2], family: 'text', confidence: 'text heuristic' };
  }
  if (!found) found = { mime: 'application/octet-stream', description: 'Unrecognised binary data', ext: [], family: 'unknown', confidence: 'none' };
  const hasExt = Boolean(ext);
  const matches = found.ext.length && hasExt ? found.ext.includes(ext) : null;
  let note = null;
  if (matches === false) note = `The name ends in .${ext}, but the contents look like ${found.description}. Renamed files are common and do not prove anything by themselves.`;
  if (found.family === 'unknown') note = 'Orkardch only recognises a built-in list of common formats. "Unrecognised" does not mean the file is damaged or suspicious.';
  return { ...found, extension: ext || null, extensionMatches: matches, note };
}

module.exports = { detectType, looksLikeText };
