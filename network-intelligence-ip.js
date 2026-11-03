'use strict';
const net = require('net');

function list(cidrs, family) {
  const bl = new net.BlockList();
  for (const [addr, prefix] of cidrs) bl.addSubnet(addr, prefix, family);
  return bl;
}

const V4 = [
  ['this-network', 'Reserved for "this network" (0.0.0.0/8)', [['0.0.0.0', 8]]],
  ['private', 'Private network address (RFC 1918): used inside homes, offices and phones, not on the public internet', [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16]]],
  ['shared-cgnat', 'Carrier-grade NAT shared space: used by mobile and ISP networks, not unique to one customer', [['100.64.0.0', 10]]],
  ['loopback', 'Loopback: this device talking to itself', [['127.0.0.0', 8]]],
  ['link-local', 'Link-local: automatically assigned, only valid on the local link', [['169.254.0.0', 16]]],
  ['ietf-protocol', 'Reserved for internet protocol assignments', [['192.0.0.0', 24]]],
  ['documentation', 'Documentation range: reserved for examples, never assigned to real networks', [['192.0.2.0', 24], ['198.51.100.0', 24], ['203.0.113.0', 24]]],
  ['benchmarking', 'Reserved for network benchmarking', [['198.18.0.0', 15]]],
  ['multicast', 'Multicast: one-to-many delivery, not a single host', [['224.0.0.0', 4]]],
  ['reserved', 'Reserved for future use (includes the broadcast address)', [['240.0.0.0', 4]]],
].map(([c, d, l]) => ({ category: c, description: d, bl: list(l, 'ipv4') }));

const V6 = [
  ['unspecified', 'The unspecified address (::)', [['::', 128]]],
  ['loopback', 'Loopback: this device talking to itself', [['::1', 128]]],
  ['unique-local', 'Private (unique local) address: used inside local networks', [['fc00::', 7]]],
  ['link-local', 'Link-local: only valid on the local link', [['fe80::', 10]]],
  ['multicast', 'Multicast: one-to-many delivery, not a single host', [['ff00::', 8]]],
  ['documentation', 'Documentation range: reserved for examples', [['2001:db8::', 32]]],
  ['discard', 'Discard-only range', [['100::', 64]]],
].map(([c, d, l]) => ({ category: c, description: d, bl: list(l, 'ipv6') }));

const GLOBAL6 = list([['2000::', 3]], 'ipv6');

function expandIpv6(addr) {
  let a = String(addr).toLowerCase();
  const m = /(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (m) {
    const o = m[1].split('.').map(Number);
    a = `${a.slice(0, -m[1].length)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const [head, tail] = a.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined ? (tail ? tail.split(':') : []) : [];
  const groups = tail === undefined ? h : [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t];
  return groups.map((g) => parseInt(g, 16));
}

function mappedV4(s) {
  const g = expandIpv6(s);
  if (g.length === 8 && g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
  return null;
}

/** Validate and classify an IP address. Never throws. */
function classifyIp(input) {
  let s = String(input == null ? '' : input).trim().replace(/^\[|\]$/g, '');
  const z = s.indexOf('%');
  if (z >= 0) s = s.slice(0, z);
  const version = net.isIP(s);
  if (!version) {
    return { valid: false, input, error: 'MALFORMED', message: 'That is not a valid IP address. IPv4 looks like 192.0.2.1 (four numbers up to 255). IPv6 looks like 2001:db8::1.' };
  }
  if (version === 6) {
    const v4 = mappedV4(s);
    if (v4) return { ...classifyIp(v4), input, mappedFrom: s, note: 'This is an IPv4 address written in IPv6 form.' };
  }
  const tables = version === 4 ? V4 : V6;
  const hit = tables.find((t) => t.bl.check(s, version === 4 ? 'ipv4' : 'ipv6'));
  if (hit) return { valid: true, input, address: s, version, category: hit.category, description: hit.description, public: false };
  if (version === 6 && !GLOBAL6.check(s, 'ipv6')) {
    return { valid: true, input, address: s, version, category: 'reserved', description: 'Not in the range used for public internet addresses', public: false };
  }
  const g = version === 6 ? expandIpv6(s) : null;
  if (g && ((g[0] === 0x2001 && g[1] === 0) || g[0] === 0x2002)) {
    return { valid: true, input, address: s, version, category: 'transition', description: 'IPv6 transition tunnel address (Teredo or 6to4): the real network behind it may differ', public: true };
  }
  return { valid: true, input, address: s, version, category: 'public', description: 'Public internet address', public: true };
}

function ptrName(ip) {
  const c = classifyIp(ip);
  if (!c.valid) return null;
  if (c.version === 4) return `${c.address.split('.').reverse().join('.')}.in-addr.arpa`;
  const nibbles = expandIpv6(c.address).map((g) => g.toString(16).padStart(4, '0')).join('').split('').reverse().join('.');
  return `${nibbles}.ip6.arpa`;
}

function cymruOriginName(ip) {
  const c = classifyIp(ip);
  if (!c.valid) return null;
  if (c.version === 4) return `${c.address.split('.').reverse().join('.')}.origin.asn.cymru.com`;
  const nibbles = expandIpv6(c.address).map((g) => g.toString(16).padStart(4, '0')).join('').split('').reverse().join('.');
  return `${nibbles}.origin6.asn.cymru.com`;
}

module.exports = { classifyIp, ptrName, cymruOriginName, expandIpv6 };
