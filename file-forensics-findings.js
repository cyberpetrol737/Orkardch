'use strict';

/** Convert an inspection into evidence records. Everything here was directly observed by this app. */
function inspectionFindings(res, { includeGps = false } = {}) {
  const sha = res.hashes.digests.sha256;
  const subject = `file:${sha}`;
  const file = { name: res.name, path: res.path, sha256: sha, size: res.size };
  const base = {
    statementType: 'observation',
    source: { module: 'file-forensics', provider: 'local analysis', file, retrievedAt: res.inspectedAt },
    firstObserved: res.inspectedAt, lastObserved: res.inspectedAt,
  };
  const out = [{
    ...base, type: 'file_hash', value: sha, subject: res.name, attribute: 'sha256',
    data: { size: res.size, mime: res.type.mime, md5: res.hashes.digests.md5 || null, sha1: res.hashes.digests.sha1 || null },
  }, { ...base, type: 'file_type', value: `${res.type.description} (${res.type.mime})`, subject, attribute: 'file_type' }];
  const meta = (attribute, value, extra = {}) => { if (value) out.push({ ...base, type: 'file_metadata', value: String(value), subject, attribute, data: { selfReported: true }, ...extra }); };
  const m = res.metadata;
  const date = (d) => (d ? (d.iso || d.raw) : null);
  if (m.supported && m.kind === 'image' && m.exif) {
    const e = m.exif;
    meta('camera', [e.camera.make, e.camera.model].filter(Boolean).join(' '));
    meta('software', e.software);
    meta('capture_date', date(e.dates.captured));
    meta('metadata_modified_date', date(e.dates.modified));
    meta('author', e.artist, { sensitive: 'personal-metadata' });
    meta('device_owner', e.owner, { sensitive: 'personal-metadata' });
    meta('device_serial', e.bodySerial, { sensitive: 'personal-metadata' });
    if (includeGps && e.gps && e.gps.valid) meta('gps_position', `${e.gps.latitude.toFixed(6)},${e.gps.longitude.toFixed(6)}`, { sensitive: 'gps' });
  } else if (m.supported && m.kind === 'image' && m.xmp) {
    meta('software', m.xmp.creatorTool);
  }
  if (m.supported && m.kind === 'document') {
    const f = m.fields || {};
    const d = m.embeddedDates || {};
    meta('title', f.title);
    meta('author', f.author, { sensitive: 'personal-metadata' });
    meta('last_modified_by', f.lastModifiedBy, { sensitive: 'personal-metadata' });
    meta('organization', f.company, { sensitive: 'personal-metadata' });
    meta('software', f.application || f.producer || f.creator || f.xmpCreatorTool);
    meta('document_created_date', date(d.created || d.xmpCreated));
    meta('document_modified_date', date(d.modified || d.xmpModified));
  }
  return out;
}

module.exports = { inspectionFindings };
