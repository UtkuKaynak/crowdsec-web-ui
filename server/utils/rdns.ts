import { promises as dns } from 'node:dns';
import { getIpVersion } from './ip';

/**
 * Best-effort reverse DNS (PTR) lookups with a small in-memory TTL cache.
 * Used to enrich the investigation view; failures resolve to null rather than
 * throwing so a missing/blocked PTR never breaks the response.
 */

const DEFAULT_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const MAX_ENTRIES = 5000;

export interface RdnsResult {
  /** The first PTR name, or null if none/failed. */
  ptr: string | null;
  /**
   * Forward-confirmed rDNS: true when the PTR name resolves back to the original
   * IP. null when there is no PTR (nothing to confirm).
   */
  confirmed: boolean | null;
}

interface CacheEntry {
  value: RdnsResult;
  expiresAt: number;
}

export interface RdnsResolver {
  resolve(ip: string): Promise<string | null>;
  resolveConfirmed(ip: string): Promise<RdnsResult>;
}

type LookupFn = (ip: string) => Promise<string[]>;
type ForwardFn = (name: string) => Promise<string[]>;

async function defaultForward(name: string): Promise<string[]> {
  const results = await Promise.allSettled([dns.resolve4(name), dns.resolve6(name)]);
  return results.flatMap((r) => (r.status === 'fulfilled' ? r.value : []));
}

export function createRdnsResolver(options: {
  ttlMs?: number;
  now?: () => number;
  lookup?: LookupFn;
  forward?: ForwardFn;
} = {}): RdnsResolver {
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  const now = options.now ?? (() => Date.now());
  const lookup = options.lookup ?? ((ip: string) => dns.reverse(ip));
  const forward = options.forward ?? defaultForward;
  const cache = new Map<string, CacheEntry>();

  async function resolveConfirmed(ip: string): Promise<RdnsResult> {
    if (getIpVersion(ip) === null) {
      return { ptr: null, confirmed: null };
    }

    const cached = cache.get(ip);
    if (cached && cached.expiresAt > now()) {
      return cached.value;
    }

    let result: RdnsResult = { ptr: null, confirmed: null };
    try {
      const names = await lookup(ip);
      const ptr = names.find((name) => name && name.trim()) ?? null;
      if (ptr) {
        let confirmed = false;
        try {
          const forwardIps = await forward(ptr);
          confirmed = forwardIps.includes(ip);
        } catch {
          confirmed = false;
        }
        result = { ptr, confirmed };
      }
    } catch {
      result = { ptr: null, confirmed: null };
    }

    if (cache.size >= MAX_ENTRIES) {
      const oldestKey = cache.keys().next().value;
      if (oldestKey !== undefined) {
        cache.delete(oldestKey);
      }
    }
    cache.set(ip, { value: result, expiresAt: now() + ttlMs });
    return result;
  }

  return {
    resolveConfirmed,
    async resolve(ip: string): Promise<string | null> {
      return (await resolveConfirmed(ip)).ptr;
    },
  };
}
