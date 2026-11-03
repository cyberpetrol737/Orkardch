'use strict';
const fs = require('fs');
const path = require('path');

/** Write a file atomically (temp file + rename). Never leaves a half-written file behind. */
function writeFileAtomic(file, content, { mode = 0o600, dirMode = 0o700 } = {}) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: dirMode });
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  const fd = fs.openSync(tmp, 'w', mode);
  try {
    fs.writeFileSync(fd, content);
    try { fs.fsyncSync(fd); } catch { /* some Android filesystems cannot fsync */ }
  } catch (err) {
    fs.closeSync(fd);
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    throw err;
  }
  fs.closeSync(fd);
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    throw err;
  }
}

function writeJsonAtomic(file, data, opts) {
  writeFileAtomic(file, `${JSON.stringify(data, null, 2)}\n`, opts);
}

/** Read JSON without throwing: {ok, value} | {ok:false, missing, error}. */
function readJsonSafe(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    return { ok: false, missing: err.code === 'ENOENT', error: err.message, code: err.code };
  }
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (err) {
    return { ok: false, missing: false, error: `Invalid JSON: ${err.message}`, code: 'EJSON' };
  }
}

module.exports = { writeFileAtomic, writeJsonAtomic, readJsonSafe };
