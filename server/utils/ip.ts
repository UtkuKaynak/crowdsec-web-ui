import { isIP } from 'node:net';

export type IpVersion = 4 | 6;

/**
 * Returns the IP version (4 or 6) for a bare address, or null if it is not a
 * valid IP. Thin wrapper over node's isIP that narrows the return type.
 */
export function getIpVersion(value: string): IpVersion | null {
  const version = isIP(value);
  if (version === 4) return 4;
  if (version === 6) return 6;
  return null;
}

/**
 * Validates an IP address or CIDR range (e.g. "1.2.3.4" or "1.2.3.0/24").
 */
export function isValidIpOrCidr(value: string): boolean {
  const [address, prefix, extra] = value.split('/');
  const version = isIP(address || '');
  if (version === 0 || extra !== undefined) {
    return false;
  }
  if (prefix === undefined) {
    return true;
  }
  if (!/^\d+$/.test(prefix)) {
    return false;
  }
  const numericPrefix = Number(prefix);
  const maxPrefix = version === 4 ? 32 : 128;
  return Number.isInteger(numericPrefix) && numericPrefix >= 0 && numericPrefix <= maxPrefix;
}

/**
 * Returns true when the given IP (a bare address, not a range) falls inside the
 * supplied CIDR. Both IPv4 and IPv6 are supported; mismatched versions are false.
 */
export function cidrContainsIp(cidr: string, value: string): boolean {
  const [networkAddress, prefixText] = cidr.split('/');
  const version = isIP(networkAddress || '');
  if (version === 0 || isIP(value) !== version) {
    return false;
  }
  const ipVersion: IpVersion = version === 4 ? 4 : 6;
  const prefix = Number(prefixText);
  const bits = ipVersion === 4 ? 32 : 128;
  const network = parseIpAddress(networkAddress || '', ipVersion);
  const address = parseIpAddress(value, ipVersion);
  if (network === null || address === null || !Number.isInteger(prefix) || prefix < 0 || prefix > bits) {
    return false;
  }

  const hostBits = BigInt(bits - prefix);
  const mask = hostBits === BigInt(bits)
    ? 0n
    : ((1n << BigInt(bits)) - 1n) ^ ((1n << hostBits) - 1n);
  return (network & mask) === (address & mask);
}

/**
 * Computes the network CIDR a bare IP belongs to, used to cluster related
 * addresses. Defaults: /24 for IPv4, /64 for IPv6 (the common allocation unit).
 * Returns null for invalid input or ranges.
 */
export function ipToNetworkCidr(value: string, ipv4Prefix = 24, ipv6Prefix = 64): string | null {
  if (value.includes('/')) {
    return null;
  }
  const version = getIpVersion(value);
  if (version === null) {
    return null;
  }
  const bits = version === 4 ? 32 : 128;
  const prefix = version === 4 ? ipv4Prefix : ipv6Prefix;
  if (prefix < 0 || prefix > bits) {
    return null;
  }
  const address = parseIpAddress(value, version);
  if (address === null) {
    return null;
  }
  const hostBits = BigInt(bits - prefix);
  const mask = hostBits === BigInt(bits)
    ? 0n
    : ((1n << BigInt(bits)) - 1n) ^ ((1n << hostBits) - 1n);
  const network = address & mask;
  return `${formatIpAddress(network, version)}/${prefix}`;
}

export function parseIpAddress(value: string, version: IpVersion): bigint | null {
  return version === 4 ? parseIpv4Address(value) : parseIpv6Address(value);
}

function parseIpv4Address(value: string): bigint | null {
  const parts = value.split('.');
  if (parts.length !== 4) {
    return null;
  }
  let result = 0n;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return null;
    }
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      return null;
    }
    result = (result << 8n) + BigInt(octet);
  }
  return result;
}

function parseIpv6Address(value: string): bigint | null {
  const normalized = value.toLowerCase();
  const [leftText, rightText, extraText] = normalized.split('::');
  if (extraText !== undefined) {
    return null;
  }

  const leftParts = splitIpv6Parts(leftText || '');
  const rightParts = rightText === undefined ? [] : splitIpv6Parts(rightText || '');
  if (!leftParts || !rightParts) {
    return null;
  }

  const missingParts = 8 - leftParts.length - rightParts.length;
  if (rightText === undefined ? missingParts !== 0 : missingParts < 1) {
    return null;
  }

  const parts = [...leftParts, ...Array.from({ length: missingParts }, () => 0), ...rightParts];
  if (parts.length !== 8) {
    return null;
  }

  return parts.reduce((result, part) => (result << 16n) + BigInt(part), 0n);
}

function splitIpv6Parts(value: string): number[] | null {
  if (!value) {
    return [];
  }
  const parts = value.split(':');
  const parsed: number[] = [];
  for (const part of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(part)) {
      return null;
    }
    parsed.push(Number.parseInt(part, 16));
  }
  return parsed;
}

function formatIpAddress(value: bigint, version: IpVersion): string {
  if (version === 4) {
    const octets = [];
    for (let shift = 24n; shift >= 0n; shift -= 8n) {
      octets.push(Number((value >> shift) & 0xffn));
    }
    return octets.join('.');
  }

  const groups: string[] = [];
  for (let shift = 112n; shift >= 0n; shift -= 16n) {
    groups.push(Number((value >> shift) & 0xffffn).toString(16));
  }
  return groups.join(':');
}
