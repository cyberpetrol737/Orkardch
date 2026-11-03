'use strict';
const { formatBytes } = require('./utils-format');

const WITHHELD = '[withheld]';

function fmtDate(d) {
  if (!d) return null;
  if (!d.iso) return `${d.raw} (${d.note || 'could not be read as a date'})`;
  const iso = d.iso.replace('T', ' ').replace(/\.000Z$/, 'Z');
  return d.timezone && !/^[+-]\d|^UTC$/.test(d.timezone) ? `${iso} [timezone ${d.timezone}]` : iso;
}

function gpsText(gps, mode) {
  if (!gps || !gps.present) return null;
  if (gps.withheld) return 'present, withheld from this file';
  if (!gps.valid) return `present but unusable (${gps.notes.join(' ') || 'values out of range'})`;
  if (mode === 'show') return `${gps.latitude.toFixed(6)}, ${gps.longitude.toFixed(6)}${gps.notes.length ? ` (${gps.notes.join(' ')})` : ''}`;
  if (mode === 'rounded') return `${gps.latitude.toFixed(2)}, ${gps.longitude.toFixed(2)} (rounded to about 1 km)`;
  return 'present, hidden (you chose not to show it)';
}

const personal = (v, on) => (v ? (on ? v : WITHHELD) : null);

function imageRows(m, o) {
  const rows = [];
  const add = (l, v) => { if (v !== null && v !== undefined && v !== '') rows.push([l, v]); };
  if (m.dimensions) add('Size in pixels', `${m.dimensions.width} × ${m.dimensions.height}`);
  const e = m.exif;
  if (e) {
    add('Camera', [e.camera.make, e.camera.model].filter(Boolean).join(' '));
    add('Lens', [e.camera.lensMake, e.camera.lensModel].filter(Boolean).join(' '));
    if (e.image.orientation) add('Orientation', `${e.image.orientation.description} (${e.image.orientation.value})`);
    add('Taken (camera clock)', fmtDate(e.dates.captured));
    add('Digitized', fmtDate(e.dates.digitized));
    add('Metadata last changed', fmtDate(e.dates.modified));
    add('Software', e.software);
    const s = e.settings;
    add('Exposure', [s.exposureTime, s.aperture, s.iso ? `ISO ${s.iso}` : null, s.focalLengthMm ? `${s.focalLengthMm} mm` : null].filter(Boolean).join(', '));
    add('Flash', s.flash);
    add('Artist', personal(e.artist, o.includePersonal));
    add('Owner name', personal(e.owner, o.includePersonal));
    add('Copyright', e.copyright);
    add('Description', e.imageDescription);
    add('Body serial no.', personal(e.bodySerial, o.includePersonal));
    add('Lens serial no.', personal(e.lensSerial, o.includePersonal));
    add('Comment', e.other.userComment);
    add('Maker note', e.other.makerNote);
    if (e.gps) add('GPS', gpsText(e.gps, o.gps));
    if (e.gps && e.gps.timestampUtc && o.gps === 'show') add('GPS time (UTC)', e.gps.timestampUtc);
  }
  if (m.xmp) {
    add('XMP tool', m.xmp.creatorTool); add('XMP created', m.xmp.createDate); add('XMP modified', m.xmp.modifyDate);
    add('XMP creator', personal(m.xmp.creator, o.includePersonal));
  }
  if (m.textChunks) for (const [k, v] of Object.entries(m.textChunks)) add(`PNG text: ${k}`, /author|artist|owner|creator/i.test(k) ? personal(v, o.includePersonal) : v);
  if (m.embeddedDates && m.embeddedDates.pngLastModified) add('PNG last modified', m.embeddedDates.pngLastModified.iso);
  if (m.comments) m.comments.forEach((c, i) => add(`JPEG comment ${i + 1}`, c));
  return rows;
}

function docRows(m, o) {
  const rows = [];
  const add = (l, v) => { if (v !== null && v !== undefined && v !== '') rows.push([l, v]); };
  const f = m.fields || {};
  add('Format', m.format);
  add('Title', f.title); add('Subject', f.subject);
  add('Author', personal(f.author, o.includePersonal));
  add('Last saved by', personal(f.lastModifiedBy, o.includePersonal));
  add('Company', personal(f.company, o.includePersonal));
  const d = m.embeddedDates || {};
  add('Created (inside file)', fmtDate(d.created)); add('Modified (inside file)', fmtDate(d.modified)); add('Last printed', fmtDate(d.lastPrinted));
  add('XMP created', fmtDate(d.xmpCreated)); add('XMP modified', fmtDate(d.xmpModified));
  add('Application', [f.application, f.applicationVersion].filter(Boolean).join(' '));
  add('Producer', f.producer); add('Creator tool', f.creator || f.xmpCreatorTool);
  add('Keywords', f.keywords); add('Revision', f.revision); add('Editing time', f.editingMinutes ? `${f.editingMinutes} min` : null);
  add('Pages', f.pages); add('Words', f.words);
  const s = m.structure || {};
  if (s.pdfVersion) add('PDF version', s.pdfVersion);
  if (s.pages !== undefined && s.pages !== null && !f.pages) add('Pages (approx.)', s.pages);
  if (s.encrypted) add('Encrypted', 'yes');
  if (s.parts !== undefined) add('Parts / images / embedded', `${s.parts} / ${s.mediaFiles} / ${s.embeddedObjects}`);
  if (s.hasMacros) add('Macros', 'a VBA macro part exists (not read or run)');
  return rows;
}

/** Turn an inspection into labelled sections that both the screen and the export file use. */
function describeInspection(res, opts = {}) {
  const o = { gps: 'hide', includePath: true, includePersonal: true, ...opts };
  const sections = [];
  const t = res.type;
  const file = {
    title: 'File',
    rows: [
      ['Name', res.name],
      ['Type', `${t.description} (${t.mime}), found by ${t.confidence}`],
      ['Size', `${formatBytes(res.size)} (${res.size.toLocaleString('en-US')} bytes)`],
    ],
    notes: [],
  };
  if (t.extensionMatches === true) file.rows.push(['Name fits type', `yes (.${t.extension})`]);
  if (t.note) file.notes.push(t.note);
  file.rows.push(['Location', o.includePath ? res.path : '[withheld]']);
  sections.push(file);

  const labels = { sha256: 'SHA-256', sha1: 'SHA-1 (legacy)', md5: 'MD5 (legacy)' };
  sections.push({
    title: 'Fingerprints (hashes)',
    rows: Object.entries(res.hashes.digests).map(([k, v]) => [labels[k] || k, v]),
    notes: ['A hash is a fingerprint of the contents. If even one byte changes, the fingerprint changes.', ...res.hashes.notes],
  });

  const fs = res.filesystem;
  const fsRows = [['Modified', fs.modified], ['Accessed', fs.accessed], ['Status changed', fs.changed]];
  if (fs.created) fsRows.push(['Created (if the phone tracks it)', fs.created]);
  sections.push({ title: 'Phone filesystem times', rows: fsRows.filter((r) => r[1]), notes: [fs.note] });

  const m = res.metadata;
  if (!m.supported) {
    sections.push({ title: 'Details inside the file', rows: [], notes: [m.reason] });
  } else {
    const rows = m.kind === 'image' ? imageRows(m, o) : docRows(m, o);
    sections.push({ title: 'Details inside the file (self-reported, can be edited)', rows, notes: [...(m.notes || []), ...((m.exif && m.exif.warnings) || [])] });
  }
  return sections;
}

function sectionsToText(sections, title = 'Orkardch file inspection') {
  const out = [title, '='.repeat(title.length), ''];
  for (const s of sections) {
    out.push(s.title, '-'.repeat(s.title.length));
    for (const [k, v] of s.rows) out.push(`${k}: ${v}`);
    for (const n of s.notes || []) out.push(`Note: ${n}`);
    out.push('');
  }
  return out.join('\n');
}

module.exports = { describeInspection, sectionsToText, gpsText, WITHHELD, fmtDate };
