'use strict';

function flatten(obj, prefix = '', out = {}) {
  if (obj === null || obj === undefined) return out;
  if (Array.isArray(obj)) { obj.forEach((v, i) => flatten(v, `${prefix}[${i}]`, out)); return out; }
  if (typeof obj === 'object' && !Buffer.isBuffer(obj)) {
    for (const [k, v] of Object.entries(obj)) flatten(v, prefix ? `${prefix}.${k}` : k, out);
    return out;
  }
  out[prefix] = obj;
  return out;
}

const EXPLANATORY = /(^|\.)(raw|note|notes|warnings|supported|reason|pagesNote)(\.|\[|$)/;

/** Compare two metadata objects field by field. */
function diffMetadata(a, b) {
  const fa = flatten(a);
  const fb = flatten(b);
  const keys = [...new Set([...Object.keys(fa), ...Object.keys(fb)])].filter((k) => !EXPLANATORY.test(k)).sort();
  const out = { same: [], different: [], onlyA: [], onlyB: [] };
  for (const k of keys) {
    const inA = k in fa;
    const inB = k in fb;
    if (inA && inB) (String(fa[k]) === String(fb[k]) ? out.same : out.different).push(...(String(fa[k]) === String(fb[k]) ? [k] : [{ key: k, a: fa[k], b: fb[k] }]));
    else if (inA) out.onlyA.push({ key: k, value: fa[k] });
    else out.onlyB.push({ key: k, value: fb[k] });
  }
  return out;
}

function compareInspections(a, b) {
  const sameContent = a.hashes.digests.sha256 === b.hashes.digests.sha256;
  const extra = [];
  for (const algo of ['sha1', 'md5']) {
    if (a.hashes.digests[algo] && b.hashes.digests[algo]) extra.push({ algo, same: a.hashes.digests[algo] === b.hashes.digests[algo] });
  }
  const fs = {};
  for (const k of ['modified', 'accessed', 'changed', 'created']) fs[k] = { a: a.filesystem[k], b: b.filesystem[k], same: a.filesystem[k] === b.filesystem[k] };
  return {
    sameContent,
    sha256: { a: a.hashes.digests.sha256, b: b.hashes.digests.sha256 },
    legacyHashes: extra,
    size: { a: a.size, b: b.size, same: a.size === b.size },
    type: { a: a.type.mime, b: b.type.mime, same: a.type.mime === b.type.mime },
    metadata: diffMetadata(a.metadata, b.metadata),
    filesystem: fs,
    explanation: sameContent
      ? 'The SHA-256 fingerprints match, so the two files have identical contents (even if their names or dates differ).'
      : 'The SHA-256 fingerprints differ, so the contents are not identical. Even a one-byte change produces a different fingerprint.',
  };
}

module.exports = { flatten, diffMetadata, compareInspections };
