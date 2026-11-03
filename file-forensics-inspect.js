'use strict';
const fs = require('fs');
const path = require('path');
const { OrkardchError } = require('./core-errors');
const { detectType } = require('./file-forensics-filetype');
const { hashFile } = require('./file-forensics-hashing');
const { inspectImage } = require('./file-forensics-image');
const { inspectPdf } = require('./file-forensics-pdf');
const { inspectOffice } = require('./file-forensics-office');

function fsError(err, file) {
  const map = {
    ENOENT: ['FILE_NOT_FOUND', `I could not find "${file}".`, 'Check the spelling. In Termux, phone storage lives under ~/storage/shared after you run: termux-setup-storage'],
    EACCES: ['PERMISSION_DENIED', `Android would not let Orkardch read "${file}".`, 'Run termux-setup-storage and allow storage access, or copy the file into the Termux home folder.'],
    EPERM: ['PERMISSION_DENIED', `Not allowed to read "${file}".`, 'Run termux-setup-storage and allow storage access.'],
    EISDIR: ['IS_DIRECTORY', `"${file}" is a folder, not a file.`, 'Choose a file inside it.'],
    ELOOP: ['BAD_LINK', `"${file}" is a link that loops back on itself.`, null],
    ENAMETOOLONG: ['BAD_PATH', 'That path is too long.', null],
  };
  const m = map[err.code] || ['FILE_ERROR', `Could not open "${file}": ${err.message}`, null];
  return new OrkardchError(m[0], m[1], { hint: m[2], cause: err });
}

function metadataFor(file, type) {
  try {
    if (type.mime.startsWith('image/')) return inspectImage(file, type);
    if (type.mime === 'application/pdf') return inspectPdf(file);
    if (type.family === 'office-ooxml' || type.family === 'office-odf') return inspectOffice(file, type);
    return { kind: 'none', supported: false, reason: `Orkardch has no metadata reader for ${type.description} yet. The type, hashes and filesystem details above still apply.` };
  } catch (err) {
    return { kind: 'error', supported: false, reason: `The metadata reader failed (${err.code || err.message}). The file may be damaged or unusual.` };
  }
}

const iso = (ms) => (ms > 0 ? new Date(ms).toISOString() : null);

/**
 * Inspect one local file. Reads only; the source file is never modified.
 * Filesystem timestamps are reported separately from metadata embedded in the file.
 */
async function inspectFile(file, { algorithms = ['sha256'], onProgress, signal, now = Date.now } = {}) {
  const abs = path.resolve(file);
  let st;
  try { st = fs.statSync(abs); } catch (e) { throw fsError(e, file); }
  if (st.isDirectory()) throw fsError({ code: 'EISDIR' }, file);
  if (!st.isFile()) throw new OrkardchError('NOT_A_FILE', `"${file}" is not a regular file (it may be a device or socket).`);
  let type;
  let hashes;
  try {
    type = detectType(abs);
    hashes = await hashFile(abs, algorithms, { onProgress, signal });
  } catch (e) {
    if (e instanceof OrkardchError) throw e;
    throw fsError(e, file);
  }
  const metadata = metadataFor(abs, type);
  return {
    inspectedAt: new Date(now()).toISOString(),
    path: abs, name: path.basename(abs), extension: type.extension, size: st.size,
    filesystem: {
      modified: iso(st.mtimeMs), accessed: iso(st.atimeMs), changed: iso(st.ctimeMs), created: iso(st.birthtimeMs),
      note: 'These come from the phone\'s filesystem, not from the file itself. Copying, downloading or editing a file changes them, and they can be set to any value, so they do not prove when a file was originally created.',
    },
    type, hashes, metadata,
  };
}

module.exports = { inspectFile, fsError };
