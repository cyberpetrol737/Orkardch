'use strict';
const fs = require('fs');
const crypto = require('crypto');
const { OrkardchError } = require('./core-errors');

const LEGACY = {
  md5: 'MD5 is broken for security: two different files can be crafted to share one MD5. Use it only to match older checksums.',
  sha1: 'SHA-1 is deprecated for security: collisions have been demonstrated. Use it only for compatibility.',
};
const SUPPORTED = ['sha256', 'sha1', 'md5'];

/**
 * Hash a file in a single streaming pass (64-256 KB at a time), so a huge file never sits in RAM.
 * Returns hex digests plus notes about weak algorithms or a file that changed while it was read.
 */
async function hashFile(file, algorithms = ['sha256'], { onProgress, signal, highWaterMark = 256 * 1024 } = {}) {
  const algos = [...new Set(algorithms)].filter((a) => SUPPORTED.includes(a));
  if (!algos.length) algos.push('sha256');
  const hashers = [];
  const unavailable = [];
  for (const a of algos) {
    try { hashers.push([a, crypto.createHash(a)]); } catch { unavailable.push(a); }
  }
  const before = fs.statSync(file);
  let read = 0;
  const stream = fs.createReadStream(file, { highWaterMark });
  try {
    for await (const chunk of stream) {
      for (const [, h] of hashers) h.update(chunk);
      read += chunk.length;
      if (onProgress) onProgress(read, before.size);
      if (signal && signal.aborted) throw new OrkardchError('ABORTED', 'Hashing was cancelled.');
    }
  } finally {
    stream.destroy();
  }
  const after = fs.statSync(file);
  const digests = {};
  for (const [a, h] of hashers) digests[a] = h.digest('hex');
  const notes = [];
  for (const a of algos) if (LEGACY[a] && digests[a]) notes.push(`${a.toUpperCase()}: ${LEGACY[a]}`);
  for (const a of unavailable) notes.push(`${a.toUpperCase()} is not available in this Node.js build.`);
  if (after.size !== before.size || after.mtimeMs !== before.mtimeMs) notes.push('The file changed while it was being read, so this hash may not match any single version of it.');
  return { digests, bytesRead: read, size: before.size, notes, legacy: algos.filter((a) => LEGACY[a]) };
}

module.exports = { hashFile, LEGACY, SUPPORTED };
