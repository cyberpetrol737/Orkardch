'use strict';
const { clone } = require('./utils-format');
const { WITHHELD } = require('./file-forensics-describe');

/**
 * Prepare an inspection result for writing to a file. Sensitive parts are removed unless the
 * person said yes: exact GPS, the full local path, and names/serials found inside the file.
 */
function sanitizeInspection(res, { gps = 'hide', includePath = false, includePersonal = false } = {}) {
  const r = clone(res);
  if (!includePath) r.path = WITHHELD;
  const m = r.metadata;
  if (m && m.exif) {
    const e = m.exif;
    if (e.gps && e.gps.present) {
      if (gps === 'rounded' && e.gps.valid) { e.gps.latitude = Number(e.gps.latitude.toFixed(2)); e.gps.longitude = Number(e.gps.longitude.toFixed(2)); e.gps.note = 'rounded to about 1 km for sharing'; delete e.gps.timestampUtc; delete e.gps.altitudeMeters; }
      else if (gps !== 'show') { r.metadata.exif.gps = { present: true, withheld: true }; }
    }
    if (!includePersonal) for (const k of ['artist', 'owner', 'bodySerial', 'lensSerial']) if (e[k]) e[k] = WITHHELD;
  }
  if (m && m.fields && !includePersonal) for (const k of ['author', 'lastModifiedBy', 'company']) if (m.fields[k]) m.fields[k] = WITHHELD;
  if (m && m.xmp && m.xmp.creator && !includePersonal) m.xmp.creator = WITHHELD;
  if (m && m.textChunks && !includePersonal) for (const k of Object.keys(m.textChunks)) if (/author|artist|owner|creator/i.test(k)) m.textChunks[k] = WITHHELD;
  r.exportNotice = 'Created by Orkardch. Sensitive parts were removed unless the person exporting chose to include them.';
  return r;
}

/** Which sensitive things does this result contain? Used to decide what to ask before exporting. */
function sensitiveInventory(res) {
  const m = res.metadata || {};
  const e = m.exif;
  const personal = Boolean(
    (e && (e.artist || e.owner || e.bodySerial || e.lensSerial))
    || (m.fields && (m.fields.author || m.fields.lastModifiedBy || m.fields.company))
    || (m.xmp && m.xmp.creator)
    || (m.textChunks && Object.keys(m.textChunks).some((k) => /author|artist|owner|creator/i.test(k))),
  );
  return { gps: Boolean(e && e.gps && e.gps.present && e.gps.valid), personal };
}

module.exports = { sanitizeInspection, sensitiveInventory };
