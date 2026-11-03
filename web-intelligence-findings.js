'use strict';
const { normalizeUrl } = require('./utils-validate');
const { publicRecord } = require('./web-intelligence-sources');

const sourceRef = (rec) => ({
  module: 'web-intelligence', provider: rec.foundBy.map((f) => f.provider).filter((v, i, a) => a.indexOf(v) === i).join(', '),
  url: rec.url, publisher: rec.publisher || null, retrievedAt: rec.dates.retrieved || null,
});

/** A saved source is an observation (we saw it listed/fetched). What the page says is recorded separately as claims. */
function sourceFindings(rec) {
  const url = rec.canonicalUrl || rec.url;
  const source = sourceRef(rec);
  const out = [{
    type: 'source', value: url, statementType: 'observation', source,
    firstObserved: rec.dates.retrieved || undefined, lastObserved: rec.dates.retrieved || undefined,
    data: publicRecord(rec),
  }];
  const pub = rec.dates.published;
  if (pub) {
    out.push({
      type: 'source_date', value: pub.value, attribute: 'publication_date', subject: normalizeUrl(url) || url, statementType: 'claim', source,
      firstObserved: rec.dates.retrieved || undefined, data: { basis: pub.basis, selfReported: true },
    });
  }
  const subject = normalizeUrl(url) || url;
  const describe = (attribute, value) => { if (value) out.push({ type: 'source_description', value: String(value).slice(0, 300), attribute, subject, statementType: 'claim', source, firstObserved: rec.dates.retrieved || undefined, data: { selfReported: true } }); };
  if (rec.status === 'fetched') { describe('source_title', rec.pageTitle); describe('source_publisher', rec.pagePublisher); }
  return out;
}

/** A claim typed in by the person, attributed to the source it came from. */
function claimFinding({ subject, attribute, value, rec }) {
  return {
    type: 'claim', value, subject: subject || null, attribute: attribute || null, statementType: 'claim', source: sourceRef(rec),
    firstObserved: rec.dates.retrieved || undefined, data: { quotedFromSource: true, sourceTitle: rec.title },
  };
}

function archiveFindings(url, snaps, retrievedAt) {
  return snaps.map((s) => ({
    type: 'archive_capture', value: s.archiveUrl, statementType: 'observation', subject: normalizeUrl(url) || url, attribute: null,
    source: { module: 'web-intelligence', provider: 'Internet Archive (Wayback Machine)', url: s.archiveUrl, retrievedAt },
    firstObserved: s.timestamp || undefined, data: { captured: s.timestamp, original: s.original, statusCode: s.statusCode, mimeType: s.mimeType, digest: s.digest, note: 'Capture time is when the archive saved the page.' },
  }));
}

module.exports = { sourceFindings, claimFinding, archiveFindings };
