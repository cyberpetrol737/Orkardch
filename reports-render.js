'use strict';
const { wrapText } = require('./utils-format');

const day = (v) => (v ? String(v).replace('T', ' ').replace(/\.\d+Z$/, 'Z').replace(/Z$/, ' UTC') : '?');
const LABEL = { confirmed_direct: 'Confirmed by direct observation', multi_independent: 'Supported by multiple independent sources', plausible: 'Plausible but unverified', conflicting: 'Conflicting evidence', unknown: 'Unknown' };
const KIND = { observation: 'observation', claim: 'claim by a source', inference: 'inference' };

const code = (s) => { const t = String(s).replace(/\s+/g, ' '); const f = t.includes('`') ? '``' : '`'; return `${f}${/^`|`$/.test(t) ? ` ${t} ` : t}${f}`; };
const provLine = (f) => {
  const s = f.source || {};
  const bits = [`${s.module || '?'}${s.provider ? ` via ${s.provider}` : ''}`];
  if (s.url) bits.push(s.url);
  if (s.publisher) bits.push(`publisher: ${s.publisher}`);
  if (s.file) bits.push(`file: ${s.file.name || '?'}${s.file.sha256 ? ` (SHA-256 ${s.file.sha256})` : ''}${s.file.path ? ` at ${s.file.path}` : ''}`);
  if (s.description) bits.push(s.description);
  if (s.importNote) bits.push(s.importNote);
  if (s.retrievedAt) bits.push(`retrieved ${day(s.retrievedAt)}`);
  return bits.join(' | ');
};

function toJson(m) { return `${JSON.stringify(m, null, 2)}\n`; }

function toMarkdown(m) {
  const o = [`# ${m.title}`, '', `*Created ${day(m.createdAt)} - exported ${day(m.exportedAt)} - ${m.generator}*`, ''];
  if (m.description) o.push(m.description, '');
  o.push('## Summary', '', `- Findings: ${m.summary.findings}`, `- Contradictions: ${m.summary.contradictions}`, `- Connections: ${m.summary.connections}`);
  for (const [k, n] of Object.entries(m.summary.byConfidence)) o.push(`- ${LABEL[k]}: ${n}`);
  o.push('', '## Search methods used', '');
  if (!m.methods.length && !m.searches.length) o.push('_No methods were logged._');
  m.methods.forEach((x) => o.push(`- ${day(x.at)} - ${x.module}: ${x.description}`));
  m.searches.forEach((s) => o.push(`- ${day(s.ranAt)} - search ${code(s.query)} (${(s.providers || []).join(', ') || 'no provider'}; ${s.resultCount} results)`));
  o.push('', '## Findings', '');
  m.findings.forEach((f, i) => {
    o.push(`### ${i + 1}. ${f.type}: ${code(f.value)}`, '', `- Kind: ${KIND[f.statementType]}`);
    if (f.subject) o.push(`- About: ${f.subject}${f.attribute ? ` / ${f.attribute}` : ''}`);
    o.push(`- Confidence: **${f.assessment.label}**`);
    f.assessment.reasons.forEach((r) => o.push(`  - ${r}`));
    o.push(`- Source: ${provLine(f)}`, `- First seen ${day(f.firstObserved)}, last seen ${day(f.lastObserved)}; verification: ${f.verification}`);
    for (const r of f.supporting || []) o.push(`- Supporting: ${r.description || r.findingId || r.url}`);
    for (const r of f.contradicting || []) o.push(`- Contradicting: ${r.description || r.findingId || r.url}`);
    if (f.notes.length) f.notes.forEach((n) => o.push(`- Note (${day(n.at)}): ${n.text}`));
    o.push('');
  });
  o.push('## Evidence provenance (where findings came from)', '');
  m.sources.forEach((s) => o.push(`- ${s.source} - ${s.findings} finding(s), ${day(s.first)} to ${day(s.last)}`));
  o.push('', '## Contradictions', '');
  if (!m.contradictions.length) o.push('_None found._');
  m.contradictions.forEach((c) => {
    o.push(`### ${c.subject} / ${c.attribute} (${c.kind})`, '');
    c.sides.forEach((s) => o.push(`- ${code(s.value)} - ${s.findings.map((x) => x.source).join('; ')}`));
    o.push('', `_${c.note}_`, '');
  });
  o.push('', '## Connections', '');
  if (!m.connections.length) o.push('_None found._');
  m.connections.forEach((e) => o.push(`- ${e.match === 'fuzzy' ? '(fuzzy) ' : ''}${code(e.fromLabel)} -> ${e.relation} -> ${code(e.toLabel)} [${e.match}]${e.caution ? ` - ${e.caution}` : ''}`));
  o.push('', '## Limitations', '', ...m.limitations.map((l) => `- ${l}`), '', '## Recommended next verification steps', '', ...m.nextSteps.map((s, i) => `${i + 1}. ${s}`));
  if (m.notes.length) { o.push('', '## Notes', ''); m.notes.forEach((n) => o.push(`- ${day(n.at)}: ${n.text}`)); }
  return `${o.join('\n')}\n`;
}

function toText(m, width = 78) {
  const o = [];
  const h = (t) => { o.push('', t, '-'.repeat(t.length)); };
  const p = (t, ind = '') => o.push(...wrapText(t, width, ind));
  o.push(...wrapText(m.title, width), '='.repeat(Math.min(width, m.title.length)));
  p(`Created ${day(m.createdAt)} | exported ${day(m.exportedAt)} | ${m.generator}`);
  if (m.description) p(m.description);
  h('SUMMARY');
  o.push(`Findings: ${m.summary.findings}`, `Contradictions: ${m.summary.contradictions}`, `Connections: ${m.summary.connections}`);
  for (const [k, n] of Object.entries(m.summary.byConfidence)) o.push(`${LABEL[k]}: ${n}`);
  h('SEARCH METHODS USED');
  if (!m.methods.length && !m.searches.length) o.push('No methods were logged.');
  m.methods.forEach((x) => p(`${day(x.at)} - ${x.module}: ${x.description}`, '  '));
  m.searches.forEach((s) => p(`${day(s.ranAt)} - search "${s.query}" (${(s.providers || []).join(', ') || 'no provider'}; ${s.resultCount} results)`, '  '));
  h('FINDINGS');
  m.findings.forEach((f, i) => {
    p(`${i + 1}. ${f.type}: ${f.value}`);
    p(`Kind: ${KIND[f.statementType]}${f.subject ? ` | about: ${f.subject}${f.attribute ? ` / ${f.attribute}` : ''}` : ''}`, '   ');
    p(`Confidence: ${f.assessment.label}`, '   ');
    f.assessment.reasons.forEach((r) => p(`- ${r}`, '     '));
    p(`Source: ${provLine(f)}`, '   ');
    for (const r of f.supporting || []) p(`Supporting: ${r.description || r.findingId || r.url}`, '   ');
    for (const r of f.contradicting || []) p(`Contradicting: ${r.description || r.findingId || r.url}`, '   ');
    p(`First seen ${day(f.firstObserved)}; last seen ${day(f.lastObserved)}; verification: ${f.verification}`, '   ');
    f.notes.forEach((n) => p(`Note (${day(n.at)}): ${n.text}`, '   '));
    o.push('');
  });
  h('EVIDENCE PROVENANCE');
  m.sources.forEach((s) => p(`${s.source} - ${s.findings} finding(s), ${day(s.first)} to ${day(s.last)}`, '  '));
  h('CONTRADICTIONS');
  if (!m.contradictions.length) o.push('None found.');
  m.contradictions.forEach((c) => { p(`${c.subject} / ${c.attribute} (${c.kind})`); c.sides.forEach((s) => p(`"${s.value}" - ${s.findings.map((x) => x.source).join('; ')}`, '   ')); p(c.note, '   '); });
  h('CONNECTIONS');
  if (!m.connections.length) o.push('None found.');
  m.connections.forEach((e) => p(`${e.match === 'fuzzy' ? '(fuzzy) ' : ''}${e.fromLabel} -> ${e.relation} -> ${e.toLabel} [${e.match}]${e.caution ? ` - ${e.caution}` : ''}`, '  '));
  h('LIMITATIONS');
  m.limitations.forEach((l) => p(`- ${l}`));
  h('RECOMMENDED NEXT VERIFICATION STEPS');
  m.nextSteps.forEach((s, i) => p(`${i + 1}. ${s}`));
  if (m.notes.length) { h('NOTES'); m.notes.forEach((n) => p(`${day(n.at)}: ${n.text}`)); }
  return `${o.join('\n')}\n`;
}

// ------------------------------------------------------------------ HTML
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const link = (u) => (/^https?:\/\//i.test(u || '') ? `<a href="${esc(u)}" rel="noopener noreferrer">${esc(u)}</a>` : esc(u || ''));
const jsonForScript = (o) => JSON.stringify(o).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
const COLORS = { confirmed_direct: 'var(--ok)', multi_independent: 'var(--info)', plausible: 'var(--warn)', conflicting: 'var(--bad)', unknown: 'var(--unk)' };

function svgGraph(g) {
  if (!g.nodes.length) return '<p class="muted">No connections were found, so there is no graph to draw.</p>';
  const W = 640;
  const R = Math.min(250, 40 + g.nodes.length * 12);
  const cx = W / 2;
  const cy = W / 2;
  const pos = new Map();
  g.nodes.forEach((n, i) => { const a = (2 * Math.PI * i) / g.nodes.length - Math.PI / 2; pos.set(n.id, [cx + R * Math.cos(a), cy + R * Math.sin(a)]); });
  const edges = g.edges.map((e, i) => { const a = pos.get(e.from); const b = pos.get(e.to); return `<line class="edge ${e.match}" data-e="${i}" data-a="${esc(e.from)}" data-b="${esc(e.to)}" x1="${a[0].toFixed(1)}" y1="${a[1].toFixed(1)}" x2="${b[0].toFixed(1)}" y2="${b[1].toFixed(1)}"><title>${esc(e.relation)} (${e.match})</title></line>`; }).join('');
  const nodes = g.nodes.map((n, i) => { const [x, y] = pos.get(n.id); const left = x < cx; return `<g class="node" data-n="${i}" tabindex="0"><circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="9" fill="${COLORS[n.level]}"/><text x="${(x + (left ? -14 : 14)).toFixed(1)}" y="${(y + 4).toFixed(1)}" text-anchor="${left ? 'end' : 'start'}">${esc(n.label.slice(0, 22))}</text><title>${esc(n.type)}: ${esc(n.label)}</title></g>`; }).join('');
  return `<svg id="graph" viewBox="0 0 ${W} ${W}" role="img" aria-label="Relationship graph">${edges}${nodes}</svg><div id="detail" class="muted">Tap a dot to see what it is connected to. Dashed lines are fuzzy matches (similar, not identical).</div><script type="application/json" id="gdata">${jsonForScript(g)}</script>`;
}

const CSS = `:root{--bg:#f3f0e8;--panel:#fffdf7;--ink:#1c2420;--muted:#59665f;--line:#d8d1c0;--accent:#0e5a4b;--ok:#1d7a3c;--info:#1c5fa6;--warn:#98640a;--bad:#b0261d;--unk:#6a7280}
@media (prefers-color-scheme:dark){:root{--bg:#0d1310;--panel:#141c18;--ink:#e3eae5;--muted:#98a79f;--line:#26322c;--accent:#5fdfb4;--ok:#4ac177;--info:#6aa9f0;--warn:#e1a73a;--bad:#f0746b;--unk:#9aa3b0}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:max(16px,env(safe-area-inset-top)) max(14px,env(safe-area-inset-right)) max(24px,env(safe-area-inset-bottom)) max(14px,env(safe-area-inset-left))}
main{max-width:860px;margin:0 auto}
h1{font:700 1.7rem/1.2 ui-monospace,"SF Mono",Menlo,Consolas,monospace;margin:.2em 0;letter-spacing:-.01em}
h2{font:700 .95rem ui-monospace,"SF Mono",Menlo,Consolas,monospace;text-transform:uppercase;letter-spacing:.08em;color:var(--accent);border-bottom:1px solid var(--line);padding-bottom:.3em;margin:2em 0 .8em}
.meta,.muted{color:var(--muted);font-size:.9rem}.chips{display:flex;flex-wrap:wrap;gap:8px;margin:.8em 0}
.chip{border:1px solid var(--line);background:var(--panel);border-radius:999px;padding:.2em .8em;font-size:.85rem}
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--unk);border-radius:8px;padding:.7em .9em;margin:.7em 0;overflow-wrap:anywhere}
.card h3{margin:0 0 .3em;font:600 1rem ui-monospace,"SF Mono",Menlo,Consolas,monospace}
.badge{display:inline-block;font-size:.78rem;font-weight:600;border-radius:4px;padding:.05em .5em;color:#fff}
.conf-confirmed_direct{border-left-color:var(--ok)}.conf-multi_independent{border-left-color:var(--info)}.conf-plausible{border-left-color:var(--warn)}.conf-conflicting{border-left-color:var(--bad)}
.bg-confirmed_direct{background:var(--ok)}.bg-multi_independent{background:var(--info)}.bg-plausible{background:var(--warn)}.bg-conflicting{background:var(--bad)}.bg-unknown{background:var(--unk)}
.sides{display:grid;grid-template-columns:1fr;gap:8px}@media(min-width:640px){.sides{grid-template-columns:1fr 1fr}}
.side{border:1px dashed var(--line);border-radius:6px;padding:.5em .7em}
ul{padding-left:1.2em}li{margin:.25em 0}code{font:.88em ui-monospace,Menlo,Consolas,monospace;background:var(--bg);padding:.1em .3em;border-radius:4px;overflow-wrap:anywhere}
a{color:var(--accent)}svg{width:100%;height:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px}
.edge{stroke:var(--muted);stroke-width:1.2;opacity:.55}.edge.fuzzy{stroke-dasharray:5 4}.edge.on{stroke:var(--accent);stroke-width:2.5;opacity:1}
.node text{font:11px ui-monospace,Menlo,monospace;fill:var(--ink)}.node{cursor:pointer}.node:focus circle,.node.on circle{stroke:var(--accent);stroke-width:3}
footer{margin-top:2.5em;font-size:.85rem;color:var(--muted);border-top:1px solid var(--line);padding-top:1em}
@media print{body{background:#fff;color:#000}.card{break-inside:avoid}}`;

const SCRIPT = `(function(){var el=document.getElementById('gdata');if(!el)return;var g=JSON.parse(el.textContent),svg=document.getElementById('graph'),d=document.getElementById('detail');
function pick(i){var n=g.nodes[i],t=svg.querySelectorAll('.node'),k;for(k=0;k<t.length;k++)t[k].classList.remove('on');t[i].classList.add('on');
var es=svg.querySelectorAll('.edge'),rel=[];for(k=0;k<es.length;k++){var e=g.edges[k],on=e.from===n.id||e.to===n.id;es[k].classList.toggle('on',on);if(on){var o=g.nodes.filter(function(x){return x.id===(e.from===n.id?e.to:e.from)})[0];rel.push((e.match==='fuzzy'?'~ ':'')+e.relation+': '+(o?o.type+' '+o.label:'?'))}}
d.textContent=n.type+': '+n.label+(rel.length?'  |  '+rel.join('  |  '):'  |  no links');}
svg.addEventListener('click',function(ev){var g2=ev.target.closest('.node');if(g2)pick(+g2.getAttribute('data-n'))});
svg.addEventListener('keydown',function(ev){if(ev.key==='Enter'){var g2=ev.target.closest('.node');if(g2)pick(+g2.getAttribute('data-n'))}});})();`;

function toHtml(m) {
  const conf = Object.entries(m.summary.byConfidence).map(([k, n]) => `<span class="chip"><span class="badge bg-${k}">${n}</span> ${esc(LABEL[k])}</span>`).join('');
  const findings = m.findings.map((f, i) => `<article class="card conf-${f.assessment.level}"><h3>${i + 1}. ${esc(f.type)}: ${esc(f.value)}</h3>
<p><span class="badge bg-${f.assessment.level}">${esc(f.assessment.label)}</span> <span class="muted">${esc(KIND[f.statementType])}${f.subject ? ` - about ${esc(f.subject)}${f.attribute ? ` / ${esc(f.attribute)}` : ''}` : ''}</span></p>
<ul>${f.assessment.reasons.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>
<p class="muted"><strong>Source:</strong> ${esc(f.source.module || '?')}${f.source.provider ? ` via ${esc(f.source.provider)}` : ''}${f.source.url ? ` - ${link(f.source.url)}` : ''}${f.source.publisher ? ` - ${esc(f.source.publisher)}` : ''}${f.source.file ? ` - file ${esc(f.source.file.name || '?')}${f.source.file.sha256 ? ` (SHA-256 <code>${esc(f.source.file.sha256)}</code>)` : ''}${f.source.file.path ? ` at ${esc(f.source.file.path)}` : ''}` : ''}${f.source.description ? ` - ${esc(f.source.description)}` : ''}${f.source.importNote ? ` - ${esc(f.source.importNote)}` : ''}${f.source.retrievedAt ? ` - retrieved ${esc(day(f.source.retrievedAt))}` : ''}</p>
${(f.supporting || []).map((r) => `<p class="meta">Supporting: ${esc(r.description || r.findingId || r.url)}</p>`).join('')}${(f.contradicting || []).map((r) => `<p class="meta">Contradicting: ${esc(r.description || r.findingId || r.url)}</p>`).join('')}<p class="meta">First seen ${esc(day(f.firstObserved))} - last seen ${esc(day(f.lastObserved))} - verification: ${esc(f.verification)}</p>${f.notes.map((n) => `<p class="meta">Note (${esc(day(n.at))}): ${esc(n.text)}</p>`).join('')}</article>`).join('');
  const contradictions = m.contradictions.length ? m.contradictions.map((c) => `<article class="card conf-conflicting"><h3>${esc(c.subject)} / ${esc(c.attribute)} <span class="badge bg-conflicting">${esc(c.kind)}</span></h3><div class="sides">${c.sides.map((s) => `<div class="side"><strong>${esc(s.value)}</strong><br><span class="muted">${s.findings.map((x) => esc(x.source)).join('<br>')}</span></div>`).join('')}</div><p class="muted">${esc(c.note)}</p></article>`).join('') : '<p class="muted">None found.</p>';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>${esc(m.title)} - Orkardch report</title><style>${CSS}</style></head><body><main>
<p class="meta">ORKARDCH INVESTIGATION REPORT</p><h1>${esc(m.title)}</h1>
<p class="meta">Created ${esc(day(m.createdAt))} - exported ${esc(day(m.exportedAt))} - ${esc(m.generator)}</p>${m.description ? `<p>${esc(m.description)}</p>` : ''}
<h2>Summary</h2><div class="chips"><span class="chip">${m.summary.findings} findings</span><span class="chip">${m.summary.contradictions} contradictions</span><span class="chip">${m.summary.connections} connections</span>${conf}</div>
<h2>Search methods used</h2>${m.methods.length || m.searches.length ? `<ul>${m.methods.map((x) => `<li>${esc(day(x.at))} - ${esc(x.module)}: ${esc(x.description)}</li>`).join('')}${m.searches.map((s) => `<li>${esc(day(s.ranAt))} - search <code>${esc(s.query)}</code> (${esc((s.providers || []).join(', ') || 'no provider')}; ${s.resultCount} results)</li>`).join('')}</ul>` : '<p class="muted">No methods were logged.</p>'}
<h2>Findings</h2>${findings || '<p class="muted">No findings.</p>'}
<h2>Evidence provenance</h2><ul>${m.sources.map((s) => `<li>${esc(s.source)} - ${s.findings} finding(s), ${esc(day(s.first))} to ${esc(day(s.last))}</li>`).join('')}</ul>
<h2>Contradictions</h2>${contradictions}
<h2>Connections</h2>${m.connections.length ? `<ul>${m.connections.map((e) => `<li>${e.match === 'fuzzy' ? '<em>(fuzzy)</em> ' : ''}<code>${esc(e.fromLabel)}</code> &rarr; ${esc(e.relation)} &rarr; <code>${esc(e.toLabel)}</code> <span class="muted">[${esc(e.match)}]${e.caution ? ` ${esc(e.caution)}` : ''}</span></li>`).join('')}</ul>` : '<p class="muted">None found.</p>'}
<h2>Relationship graph</h2>${svgGraph(m.graph)}
<h2>Limitations</h2><ul>${m.limitations.map((l) => `<li>${esc(l)}</li>`).join('')}</ul>
<h2>Recommended next verification steps</h2><ol>${m.nextSteps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>
${m.notes.length ? `<h2>Notes</h2><ul>${m.notes.map((n) => `<li>${esc(day(n.at))}: ${esc(n.text)}</li>`).join('')}</ul>` : ''}
<footer>Generated offline by ${esc(m.generator)}. This file is self-contained and makes no network requests. Sensitive details are withheld unless the exporter chose to include them.</footer>
</main><script>${SCRIPT}</script></body></html>
`;
}

const RENDERERS = { json: [toJson, 'json'], md: [toMarkdown, 'md'], txt: [toText, 'txt'], html: [toHtml, 'html'] };

module.exports = { toJson, toMarkdown, toText, toHtml, RENDERERS, esc };
