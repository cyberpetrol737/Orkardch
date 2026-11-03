'use strict';

const NAMED = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '-', mdash: '-', hellip: '...', rsquo: "'", lsquo: "'",
  rdquo: '"', ldquo: '"', copy: '(c)', reg: '(R)', trade: '(TM)', laquo: '"', raquo: '"', middot: '.', bull: '*',
};

function decodeHtml(s) {
  return String(s)
    .replace(/&#(\d+);/g, (m, n) => { try { return String.fromCodePoint(Number(n)); } catch { return m; } })
    .replace(/&#x([0-9a-f]+);/gi, (m, n) => { try { return String.fromCodePoint(parseInt(n, 16)); } catch { return m; } })
    .replace(/&([a-z]+);/gi, (m, n) => (NAMED[n.toLowerCase()] !== undefined ? NAMED[n.toLowerCase()] : m));
}

/** Remove tags and decode entities. Input is treated as untrusted text, never executed. */
function htmlToText(html) {
  return decodeHtml(String(html).replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
}

function parseAttrs(str) {
  const out = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
  let m;
  while ((m = re.exec(str))) out[m[1].toLowerCase()] = decodeHtml(m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4]);
  return out;
}

module.exports = { decodeHtml, htmlToText, parseAttrs };
