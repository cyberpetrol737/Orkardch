'use strict';
const { truncate, wrapText } = require('./utils-format');

function label(f, max) { return truncate(`${f.type}: ${f.value}`, max); }

/** A text relationship graph that fits a phone screen. Fuzzy links are marked with "~". */
function renderTextGraph(inv, analysis, { width = 40, unicode = true, maxRoots = 8 } = {}) {
  const byId = new Map(inv.findings.map((f) => [f.id, f]));
  const adj = new Map();
  for (const e of analysis.relationships) {
    if (!byId.has(e.from) || !byId.has(e.to)) continue;
    if (!adj.has(e.from)) adj.set(e.from, []);
    if (!adj.has(e.to)) adj.set(e.to, []);
    adj.get(e.from).push({ other: e.to, edge: e, dir: 'out' });
    adj.get(e.to).push({ other: e.from, edge: e, dir: 'in' });
  }
  const [T, L, V, S] = unicode ? ['├─ ', '└─ ', '│  ', '   '] : ['|- ', '`- ', '|  ', '   '];
  const lines = [];
  const used = new Set();
  const roots = [...adj.keys()].sort((a, b) => adj.get(b).length - adj.get(a).length);
  let rootCount = 0;
  for (const root of roots) {
    if (used.has(root)) continue;
    if (rootCount++ >= maxRoots) { lines.push(...wrapText('... more connected groups not shown (export a report to see all).', width)); break; }
    used.add(root);
    lines.push(label(byId.get(root), width));
    const walk = (id, prefix, depth) => {
      const kids = (adj.get(id) || []).filter((n) => !used.has(n.other));
      const shown = kids.slice(0, 6);
      shown.forEach((k, i) => {
        if (used.has(k.other)) return;
        used.add(k.other);
        const last = i === shown.length - 1 && kids.length <= 6;
        const arrow = k.dir === 'out' ? '->' : '<-';
        const mark = k.edge.match === 'fuzzy' ? '~' : '';
        lines.push(truncate(`${prefix}${last ? L : T}${mark}${arrow} ${k.edge.relation}`, width));
        lines.push(truncate(`${prefix}${last ? S : V}   ${label(byId.get(k.other), width - prefix.length - 6)}`, width));
        if (depth < 3) walk(k.other, `${prefix}${last ? S : V}   `, depth + 1);
      });
      if (kids.length > 6) lines.push(truncate(`${prefix}${L}... and ${kids.length - 6} more`, width));
    };
    walk(root, '', 1);
    lines.push('');
  }
  const lonely = inv.findings.filter((f) => !adj.has(f.id));
  if (lonely.length) {
    lines.push(...wrapText(`Not connected to anything yet (${lonely.length}):`, width));
    lonely.slice(0, 8).forEach((f) => lines.push(truncate(`  ${label(f, width - 2)}`, width)));
    if (lonely.length > 8) lines.push(`  ... and ${lonely.length - 8} more`);
  }
  if (analysis.relationships.some((e) => e.match === 'fuzzy')) lines.push('', ...wrapText('~ marks a fuzzy match (similar, not identical).', width));
  return lines;
}

/** Nodes and edges for the HTML report's interactive graph. */
function graphData(inv, analysis, { maxNodes = 80 } = {}) {
  const linked = new Set();
  for (const e of analysis.relationships) { linked.add(e.from); linked.add(e.to); }
  const nodes = inv.findings.filter((f) => linked.has(f.id)).slice(0, maxNodes).map((f) => ({
    id: f.id, type: f.type, label: truncate(f.value, 40), level: analysis.assessments[f.id].level,
  }));
  const ids = new Set(nodes.map((n) => n.id));
  const edges = analysis.relationships.filter((e) => ids.has(e.from) && ids.has(e.to)).map((e) => ({ from: e.from, to: e.to, relation: e.relation, match: e.match }));
  return { nodes, edges };
}

module.exports = { renderTextGraph, graphData };
