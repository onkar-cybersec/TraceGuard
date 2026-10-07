/**
 * IP utility for classifying IPv4 and IPv6 addresses.
 * Excludes private, loopback, link-local, multicast, documentation, and reserved ranges.
 */

// Convert IPv4 string to 32-bit unsigned number
export function parseIpv4ToUint32(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;

  let acc = 0;
  for (let i = 0; i < 4; i++) {
    const part = parts[i];
    if (!/^\d{1,3}$/.test(part)) return null;
    const num = parseInt(part, 10);
    if (num < 0 || num > 255) return null;
    // Disallow leading zeros for non-zero numbers to avoid octal ambiguity
    if (part.length > 1 && part.startsWith('0')) return null;
    acc = ((acc << 8) | num) >>> 0;
  }
  return acc >>> 0;
}

// Convert 32-bit IPv4 uint to dotted-quad string
export function uint32ToIpv4(val: number): string {
  return [
    (val >>> 24) & 255,
    (val >>> 16) & 255,
    (val >>> 8) & 255,
    val & 255,
  ].join('.');
}

// Check if uint32 IPv4 falls into CIDR (network uint32, prefix bits)
function inIpv4Cidr(ipNum: number, network: number, prefix: number): boolean {
  if (prefix === 0) return true;
  const mask = ((0xffffffff << (32 - prefix)) >>> 0);
  return (ipNum & mask) === (network & mask);
}

// IPv4 Non-public CIDR definitions
const IPV4_NON_PUBLIC: Array<{ network: string; prefix: number; reason: string }> = [
  { network: '0.0.0.0', prefix: 8, reason: 'Current network' },
  { network: '10.0.0.0', prefix: 8, reason: 'Private (RFC 1918)' },
  { network: '100.64.0.0', prefix: 10, reason: 'Carrier-grade NAT (RFC 6598)' },
  { network: '127.0.0.0', prefix: 8, reason: 'Loopback' },
  { network: '169.254.0.0', prefix: 16, reason: 'Link-Local' },
  { network: '172.16.0.0', prefix: 12, reason: 'Private (RFC 1918)' },
  { network: '192.0.0.0', prefix: 24, reason: 'IETF Protocol Assignments' },
  { network: '192.0.2.0', prefix: 24, reason: 'Documentation TEST-NET-1 (RFC 5737)' },
  { network: '192.88.99.0', prefix: 24, reason: '6to4 Anycast' },
  { network: '192.168.0.0', prefix: 16, reason: 'Private (RFC 1918)' },
  { network: '198.18.0.0', prefix: 15, reason: 'Benchmarking (RFC 2544)' },
  { network: '198.51.100.0', prefix: 24, reason: 'Documentation TEST-NET-2 (RFC 5737)' },
  { network: '203.0.113.0', prefix: 24, reason: 'Documentation TEST-NET-3 (RFC 5737)' },
  { network: '224.0.0.0', prefix: 4, reason: 'Multicast' },
  { network: '240.0.0.0', prefix: 4, reason: 'Reserved (Class E)' },
  { network: '255.255.255.255', prefix: 32, reason: 'Limited Broadcast' },
];

const COMPILED_IPV4_NON_PUBLIC = IPV4_NON_PUBLIC.map((entry) => ({
  num: parseIpv4ToUint32(entry.network)!,
  prefix: entry.prefix,
  reason: entry.reason,
}));

/**
 * Expand and parse IPv6 address into 8 16-bit blocks (big-endian).
 * Returns number[8] or null if invalid.
 */
export function parseIpv6(ip: string): number[] | null {
  const clean = ip.trim().toLowerCase();

  // Handle IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1)
  if (clean.includes('.')) {
    const lastColon = clean.lastIndexOf(':');
    if (lastColon === -1) return null;
    const v6Prefix = clean.slice(0, lastColon);
    const v4Part = clean.slice(lastColon + 1);
    const v4Num = parseIpv4ToUint32(v4Part);
    if (v4Num === null) return null;

    const highV4 = (v4Num >>> 16) & 0xffff;
    const lowV4 = v4Num & 0xffff;

    // Convert prefix to 6 blocks
    const fullPrefix = v6Prefix + `:${highV4.toString(16)}:${lowV4.toString(16)}`;
    return parseIpv6(fullPrefix);
  }

  const parts = clean.split('::');
  if (parts.length > 2) return null; // Only one '::' allowed

  let leftBlocks: number[] = [];
  if (parts[0]) {
    const rawLeft = parts[0].split(':');
    for (const b of rawLeft) {
      if (!/^[0-9a-f]{1,4}$/.test(b)) return null;
      leftBlocks.push(parseInt(b, 16));
    }
  }

  let rightBlocks: number[] = [];
  if (parts.length === 2 && parts[1]) {
    const rawRight = parts[1].split(':');
    for (const b of rawRight) {
      if (!/^[0-9a-f]{1,4}$/.test(b)) return null;
      rightBlocks.push(parseInt(b, 16));
    }
  }

  if (parts.length === 1) {
    if (leftBlocks.length !== 8) return null;
    return leftBlocks;
  }

  const missing = 8 - (leftBlocks.length + rightBlocks.length);
  if (missing < 0) return null;

  const middle = new Array(missing).fill(0);
  return [...leftBlocks, ...middle, ...rightBlocks];
}

/**
 * Validate if string is a syntactically valid IPv4 or IPv6 address.
 */
export function isValidIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();
  if (trimmed.includes('.')) {
    return parseIpv4ToUint32(trimmed) !== null;
  }
  return parseIpv6(trimmed) !== null;
}

/**
 * Determine if an IPv4 address is considered a Public IP.
 */
export function isPublicIpv4(ip: string): boolean {
  const num = parseIpv4ToUint32(ip);
  if (num === null) return false;

  for (const entry of COMPILED_IPV4_NON_PUBLIC) {
    if (inIpv4Cidr(num, entry.num, entry.prefix)) {
      return false;
    }
  }
  return true;
}

/**
 * Determine if an IPv6 address is considered a Public IP.
 * Excludes loopback (::1), unspecified (::), unique local (fc00::/7),
 * link-local (fe80::/10), multicast (ff00::/8), documentation (2001:db8::/32),
 * discard prefix (100::/64), and IPv4-mapped private IPs.
 */
export function isPublicIpv6(ip: string): boolean {
  const blocks = parseIpv6(ip);
  if (blocks === null) return false;

  // 1. Unspecified ::/128
  if (blocks.every((b) => b === 0)) return false;

  // 2. Loopback ::1/128
  if (blocks.slice(0, 7).every((b) => b === 0) && blocks[7] === 1) return false;

  // 3. IPv4-mapped ::ffff:0:0/96
  if (
    blocks.slice(0, 5).every((b) => b === 0) &&
    blocks[5] === 0xffff
  ) {
    const v4Num = ((blocks[6] << 16) | blocks[7]) >>> 0;
    const v4Str = uint32ToIpv4(v4Num);
    return isPublicIpv4(v4Str);
  }

  // 4. Unique Local Address fc00::/7 (covers fc00::/8 and fd00::/8)
  // First 7 bits: 0b1111110x => 0xfc00 to 0xfdff
  if ((blocks[0] & 0xfe00) === 0xfc00) return false;

  // 5. Link-Local Unicast fe80::/10
  // First 10 bits: 0b1111111010 => 0xfe80
  if ((blocks[0] & 0xffc0) === 0xfe80) return false;

  // 6. Multicast ff00::/8
  // First 8 bits: 0b11111111 => 0xff00
  if ((blocks[0] & 0xff00) === 0xff00) return false;

  // 7. Documentation prefix 2001:db8::/32
  if (blocks[0] === 0x2001 && blocks[1] === 0x0db8) return false;

  // 8. Discard prefix 100::/64
  if (blocks[0] === 0x0100 && blocks[1] === 0 && blocks[2] === 0 && blocks[3] === 0) return false;

  // 9. Benchmarking 2001:2::/48
  if (blocks[0] === 0x2001 && blocks[1] === 0x0002) return false;

  return true;
}

/**
 * Universal public IP classification for TraceGuard (TG004).
 */
export function isPublicIp(ip: string | undefined): boolean {
  if (!ip) return false;
  const clean = ip.trim();
  if (clean.includes('.')) {
    return isPublicIpv4(clean);
  }
  return isPublicIpv6(clean);
}
