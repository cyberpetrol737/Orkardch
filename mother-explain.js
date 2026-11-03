'use strict';

/** Explain the most recent result in plain words, using what the session recorded. */
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

const EXPLAINERS = {
  'file-inspection': (d) => [
    `I looked inside "${d.name}". It is ${d.type}${d.extensionMatches === false ? ', but its name suggests something else (renamed files are common and prove nothing alone)' : ''}.`,
    `The SHA-256 fingerprint is like a name tag made from the contents. ${d.hashes.length > 1 ? 'You also asked for older fingerprints; those are only for matching old checksums.' : 'If the file changes even slightly, the tag changes.'}`,
    d.metadataSupported
      ? (d.hasExif || d.hasDocFields ? 'It carries hidden notes (metadata). They were written by a camera or program and anyone can edit them, so they are claims, not proof.' : d.noMetadataFound ? 'No hidden notes were found. Many apps strip them, so this proves nothing.' : 'No hidden notes were found.')
      : 'This kind of file has no metadata reader yet, so only the type, fingerprint and phone dates are shown.',
    d.hasGps ? (d.gpsShown ? 'It contains GPS coordinates, which you chose to view. They show where it was probably taken, not who was there.' : 'It contains GPS coordinates. I kept them hidden because you said no.') : null,
    'The "phone filesystem times" are kept by your phone. Copying or downloading a file changes them, so they do not prove when the file was made.',
  ],
  'file-comparison': (d) => [
    d.sameContent ? 'The two files have identical contents. Names and phone dates can still differ.' : 'The two files are not identical.',
    d.sizeSame ? 'Their sizes match.' : 'Their sizes differ.',
    `${plural(d.different, 'detail')} inside the files differ and ${plural(d.same, 'detail')} match.`,
    'Matching fingerprints are strong proof of identical bytes. They say nothing about who made the file.',
  ],
  'baseline-check': (d) => [
    d.status === 'match' ? `"${d.name}" is unchanged since you saved its fingerprint.` : d.status === 'changed' ? `"${d.name}" is different now. It was edited, replaced, damaged, or it is another file with the same name.` : `I could not check "${d.name}" (${d.status}).`,
    d.sizeChanged ? 'Its size changed too.' : null,
  ],
  'search-results': (d) => {
    const ok = d.providers.filter((p) => p.status === 'ok');
    const bad = d.providers.filter((p) => p.status === 'error');
    return [
      `You searched for "${d.query}". ${ok.length} source${ok.length === 1 ? '' : 's'} answered and gave ${plural(d.resultCount, 'result')} after removing duplicates.`,
      bad.length ? `${bad.map((p) => p.id).join(', ')} could not answer (${bad.map((p) => p.error).filter(Boolean).join(', ')}). That is normal for free sources. Nothing was made up to fill the gap.` : null,
      'A search result is a pointer, not a fact. Open one to see who published it and when. "Date unknown" simply means none was available.',
    ];
  },
  'source-record': (d) => [
    d.status === 'fetched' ? 'I opened the page and read what it says about itself.' : d.status === 'fetch-failed' ? 'I could not open the page, so I kept the link and the reason. I did not pretend to know what is on it.' : 'This result is only listed; I have not opened the page.',
    d.hasPublished ? 'The published date is what the page says about itself. It is a claim.' : 'No publication date was found. I did not guess one.',
    d.excerpts ? `${plural(d.excerpts, 'short excerpt')} show where your words appear on the page.` : null,
    d.uncertainty ? `There ${d.uncertainty === 1 ? 'is 1 caution' : `are ${d.uncertainty} cautions`} listed under "Things to be careful about". Please read them.` : null,
  ],
  pages: (d) => [`I tried to open pages for "${d.query}": ${d.opened} worked and ${d.failed} did not. A failed page keeps its link and the reason.`],
  archive: (d) => [
    d.captures ? `The Internet Archive saved ${plural(d.captures, 'copy', 'copies')} of this address, from ${String(d.first).slice(0, 10)} to ${String(d.last).slice(0, 10)}. The times are when the archive saved it, not when it was written.`.replace('copys', 'copies') : 'The archive has no saved copy of this address. That does not mean the page never existed.',
  ],
  'source-comparison': (d) => [
    `I compared them using ${d.basis}. About ${Math.round(d.overlap * 100)}% of their main words are shared.`,
    d.sameUrl ? 'These are the same address, so it is one source, not two.' : d.sameSite ? 'Both are from the same website, so they are not independent.' : null,
    'Shared words are a hint, not a verdict. Read both to decide which is better.',
  ],
  ip: (d) => (!d.public ? ['This address is private or reserved, so it has no public owner or location to look up. No lookups were made.'] : [
    d.rdapOk ? 'The registry (RDAP) says who this block of addresses was assigned to. That is the owner of the block, not necessarily who is using it now.' : 'The registry lookup did not work this time. That is a failed lookup, not proof there is no owner.',
    d.originOk ? 'The routing record shows which network (AS) announces this address to the internet.' : 'No routing record was returned.',
    d.ptrStatus === 'ok' ? 'A reverse-DNS name exists. The address owner chooses it, so it is a hint.' : 'No reverse-DNS name was found, which is common.',
    d.geoShown ? 'Any location is approximate and often points to an internet provider, VPN or data centre, not to a person.' : 'I did not look up a location.',
  ]),
  dns: (d) => [
    `I asked DNS (the internet's address book) about ${d.name}.`,
    ...d.results.map((r) => `- ${r.type}: ${r.status === 'ok' ? `${plural(r.count, 'record')}` : r.status === 'no-data' ? 'none exists (the name is real, it just has no such record)' : r.status === 'nxdomain' ? 'the name does not exist' : `the lookup FAILED${r.error ? ` (${r.error})` : ''} - that is different from "none exists"`}`),
  ],
  domain: (d) => [
    `I read the public records for ${d.domain}: DNS and the registry.`,
    d.rdapOk ? `The registry says the registrar is ${d.registrar || 'not listed'}. Owner names are usually hidden for privacy, which is normal.` : d.rdapNotFound ? 'The registry has no record for this exact name, which can happen for subdomains.' : 'The registry lookup failed this time.',
    'DNS records tell computers where to send web visitors and email. They do not show who is behind the domain.',
  ],
  certificates: (d) => [
    `Public certificate logs list ${plural(d.total, 'certificate')} for ${d.domain}, naming ${plural(d.names, 'name')}.`,
    'These show certificates that were issued. Some names may no longer exist, and the list is not complete.',
    'Seeing a name here does not prove who runs it.',
  ],
  asn: (d) => [`AS${d.asn} is a network run by one organisation, such as an internet provider.`, d.nameOk ? 'Its name comes from Team Cymru.' : 'The name lookup did not return anything.'],
  connectivity: (d) => [
    d.tcpOk ? `I could open a connection to ${d.host}:${d.port}.` : `I could not open a connection to ${d.host}:${d.port}. The host may be down, the port closed, or a firewall may be in the way.`,
    d.tlsOk ? (d.tlsTrusted ? 'The secure certificate is trusted by this phone.' : 'The secure certificate was NOT trusted by this phone. See the reason above.') : null,
    d.httpStatus ? `The web server answered with status ${d.httpStatus}. 200 means OK, 3xx a redirect, 4xx a problem with the request, 5xx a problem on the server.` : null,
  ],
  'findings-review': (d) => [`This investigation has ${plural(d.total, 'finding')} here${d.conflicts ? `, and ${d.conflicts} of them are in conflict with other evidence` : ''}.`, 'Open one to see exactly where it came from.'],
  'sources-review': (d) => [`The findings come from ${plural(d.sources, 'distinct source')}. Counting sources, not findings, is what matters for trust.`],
  import: (d) => [`${plural(d.added, 'record')} imported${d.skipped ? `, ${d.skipped} skipped because they were missing a type or value` : ''}. Imported items are treated as claims because Orkardch did not observe them itself.`],
  analysis: (d) => [
    `I checked ${plural(d.findings, 'finding')}.`,
    d.contradictions ? `There ${d.contradictions === 1 ? 'is 1 contradiction' : `are ${d.contradictions} contradictions`}. I show both sides and do not pick one for you.` : 'No contradictions were found. That only means no two findings share a subject and property with different values.',
    `Connections: ${d.exact} exact (identical values), ${d.structural} structural (built from known fields), ${d.fuzzy} fuzzy (only similar, treat as hints).`,
    'Confidence is shown in words, not percentages. Several sites repeating one original report count as one source until you mark them independent.',
  ],
  graph: (d) => [`The graph draws ${plural(d.edges, 'connection')} between ${plural(d.nodes, 'finding')}. A "~" marks a fuzzy connection. Lines show that two findings are related, not that anything is proven.`],
  report: (d) => [`I wrote ${plural(d.files, 'report file')} from ${plural(d.findings, 'finding')}.`, (d.withheld.gps + d.withheld.personal + d.withheld.paths) ? 'Some sensitive details were left out on purpose, and the report says so.' : 'No sensitive details needed to be left out.', 'The report works offline and never contains your API keys.'],
  tunnelr: (d) => (d.connected ? [
    d.hasReadme ? 'I read TunnelR\'s own README to describe it.' : 'TunnelR has no README, so I only know what its project files show.',
    `I found ${plural(d.launchOptions, 'way')} to start it.`,
    d.risks ? `I flagged ${plural(d.risks, 'pattern')} in the code worth reviewing. These are prompts to look closer, not verdicts.` : 'I did not flag risky-looking patterns in the files I scanned.',
    d.dirty ? `Your TunnelR repository has ${plural(d.dirty, 'uncommitted change')}. I did not touch them.` : null,
  ] : ['TunnelR is not connected yet. Open it from the main menu and point me to its folder.']),
  'tunnelr-run': (d) => (d.stoppedByUser ? ['TunnelR was ended with a stop signal (for example you pressed Ctrl+C). That is a normal way to stop a program and not an error in TunnelR.'] : [d.ok ? 'TunnelR started or finished normally.' : d.spawnError ? 'TunnelR could not be started at all. The reason is shown above, unchanged.' : `TunnelR stopped with a problem${d.exitCode != null ? ` (exit code ${d.exitCode})` : ''}. Its own messages are shown unchanged, because they explain it best.`]),
  'tunnelr-status': (d) => [d.known ? (d.running ? 'TunnelR is running in the background.' : 'The background TunnelR is not running any more.') : 'I have not started TunnelR in the background.'],
};

function explainResult(result) {
  if (!result) return null;
  const f = EXPLAINERS[result.kind];
  return f ? f(result.data).filter(Boolean) : null;
}

module.exports = { explainResult, EXPLAINERS };
