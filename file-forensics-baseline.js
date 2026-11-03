'use strict';
const fs = require('fs');
const { hashFile } = require('./file-forensics-hashing');

/** Re-hash a file and compare with a saved fingerprint. */
async function verifyBaseline(entry, { onProgress, now = Date.now } = {}) {
  const checkedAt = new Date(now()).toISOString();
  let st;
  try { st = fs.statSync(entry.path); } catch (e) {
    return { status: e.code === 'ENOENT' ? 'missing' : 'unreadable', expected: entry.sha256, actual: null, checkedAt, detail: e.code === 'ENOENT' ? 'The file is no longer at its saved location (moved, renamed or deleted).' : `The file could not be opened (${e.code}).` };
  }
  let h;
  try { h = await hashFile(entry.path, ['sha256'], { onProgress }); } catch (e) {
    return { status: 'unreadable', expected: entry.sha256, actual: null, checkedAt, detail: `The file could not be read (${e.code || e.message}).` };
  }
  const actual = h.digests.sha256;
  const match = actual === entry.sha256;
  return {
    status: match ? 'match' : 'changed', expected: entry.sha256, actual, checkedAt,
    sizeBefore: entry.size, sizeNow: st.size, sizeChanged: st.size !== entry.size,
    mtimeChanged: entry.fileModifiedAtSave ? new Date(st.mtimeMs).toISOString() !== entry.fileModifiedAtSave : null,
    detail: match
      ? 'The contents are identical to when the fingerprint was saved.'
      : 'The contents are different from when the fingerprint was saved. The file was edited, replaced, damaged, or is a different file with the same name.',
    notes: h.notes,
  };
}

module.exports = { verifyBaseline };
