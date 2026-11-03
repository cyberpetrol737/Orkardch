'use strict';
const { openZip, readEntry } = require('./file-forensics-zip');

function decodeXml(s) {
  return String(s)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (m, n) => { try { return String.fromCodePoint(Number(n)); } catch { return m; } })
    .replace(/&#x([0-9a-f]+);/gi, (m, n) => { try { return String.fromCodePoint(parseInt(n, 16)); } catch { return m; } })
    .replace(/&amp;/g, '&');
}
function tag(xml, name) {
  const m = new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i').exec(xml);
  const v = m ? decodeXml(m[1]).trim() : '';
  return v || null;
}
function attr(xml, el, name) {
  const m = new RegExp(`<${el}\\s[^>]*?${name}="([^"]*)"`, 'i').exec(xml);
  return m ? decodeXml(m[1]) : null;
}
/** Keep dates as recorded. Only convert when the file states a timezone; never guess the phone's. */
function dateInfo(raw) {
  if (!raw) return null;
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?)(Z|[+-]\d{2}:?\d{2})?$/.exec(raw.trim());
  if (!m || Number.isNaN(new Date(raw).getTime())) return { raw, iso: null, note: 'Not in a recognised date format.' };
  if (m[2]) return { raw, iso: new Date(raw).toISOString(), timezone: m[2] === 'Z' ? 'UTC' : m[2] };
  return { raw, iso: m[1], timezone: 'not recorded' };
}
function compact(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) if (v !== null && v !== undefined && v !== '') out[k] = v;
  return out;
}

/** Read document properties from OOXML (docx/xlsx/pptx) and OpenDocument (odt/ods/odp) files. */
function inspectOffice(file, type) {
  const z = openZip(file);
  if (!z.ok) return { kind: 'document', supported: false, reason: `Could not read the document container: ${z.reason}.` };
  const get = (name) => {
    const e = z.entries.find((x) => x.name === name);
    if (!e) return { ok: false, reason: 'not present' };
    const r = readEntry(file, e);
    return r.ok ? { ok: true, text: r.data.toString('utf8') } : r;
  };
  const names = z.entries.map((e) => e.name);
  const notes = [];
  const structure = {
    parts: names.length,
    mediaFiles: names.filter((n) => /\/media\//i.test(n) || /^Pictures\//i.test(n)).length,
    embeddedObjects: names.filter((n) => /\/embeddings\//i.test(n) || /^Object \d+\//i.test(n)).length,
    hasMacros: names.some((n) => /vbaProject\.bin$/i.test(n)),
    encryptedParts: z.entries.filter((e) => e.encrypted).length,
  };
  if (z.truncated) notes.push('The part list was cut short; counts may be too low.');
  if (structure.hasMacros) notes.push('The file contains a VBA macro project part. Orkardch only reports that it exists; it did not read or run it.');
  if (structure.encryptedParts) notes.push('Some parts are encrypted and were not read.');

  const fields = {};
  const embeddedDates = {};
  let format = type.family === 'office-odf' ? 'OpenDocument' : 'Office Open XML';
  if (type.family === 'office-ooxml') {
    const core = get('docProps/core.xml');
    const app = get('docProps/app.xml');
    if (core.ok) {
      Object.assign(fields, compact({
        title: tag(core.text, 'dc:title'), subject: tag(core.text, 'dc:subject'), author: tag(core.text, 'dc:creator'),
        lastModifiedBy: tag(core.text, 'cp:lastModifiedBy'), keywords: tag(core.text, 'cp:keywords'),
        description: tag(core.text, 'dc:description'), category: tag(core.text, 'cp:category'), revision: tag(core.text, 'cp:revision'),
      }));
      embeddedDates.created = dateInfo(tag(core.text, 'dcterms:created'));
      embeddedDates.modified = dateInfo(tag(core.text, 'dcterms:modified'));
      embeddedDates.lastPrinted = dateInfo(tag(core.text, 'cp:lastPrinted'));
    } else notes.push(`docProps/core.xml: ${core.reason}.`);
    if (app.ok) {
      Object.assign(fields, compact({
        application: tag(app.text, 'Application'), applicationVersion: tag(app.text, 'AppVersion'), company: tag(app.text, 'Company'),
        template: tag(app.text, 'Template'), editingMinutes: tag(app.text, 'TotalTime'), pages: tag(app.text, 'Pages'), words: tag(app.text, 'Words'),
      }));
    } else notes.push(`docProps/app.xml: ${app.reason}.`);
  } else {
    const meta = get('meta.xml');
    if (meta.ok) {
      Object.assign(fields, compact({
        title: tag(meta.text, 'dc:title'), subject: tag(meta.text, 'dc:subject'), description: tag(meta.text, 'dc:description'),
        keywords: tag(meta.text, 'meta:keyword'), author: tag(meta.text, 'meta:initial-creator'), lastModifiedBy: tag(meta.text, 'dc:creator'),
        application: tag(meta.text, 'meta:generator'), editingCycles: tag(meta.text, 'meta:editing-cycles'), editingDuration: tag(meta.text, 'meta:editing-duration'),
        pages: attr(meta.text, 'meta:document-statistic', 'meta:page-count'), words: attr(meta.text, 'meta:document-statistic', 'meta:word-count'),
      }));
      embeddedDates.created = dateInfo(tag(meta.text, 'meta:creation-date'));
      embeddedDates.modified = dateInfo(tag(meta.text, 'dc:date'));
    } else notes.push(`meta.xml: ${meta.reason}.`);
  }
  for (const k of Object.keys(embeddedDates)) if (!embeddedDates[k]) delete embeddedDates[k];
  if (!Object.keys(fields).length && !Object.keys(embeddedDates).length) notes.push('No document properties were found. They may have been removed, or the file may not store any.');
  return { kind: 'document', supported: true, format, fields, embeddedDates, structure, notes };
}

module.exports = { inspectOffice, decodeXml, tag };
