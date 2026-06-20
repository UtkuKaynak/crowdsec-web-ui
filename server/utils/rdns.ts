import { promises as dns } from 'node:dns';
import { getIpVersion } from './ip';

/**
 * Best-effort reverse DNS (PTR) lookups with a small in-memory TTL cache.
 * Used to enrich the investigation view; failures resolve to null rather than
 * throwing so a missing/blocked PTR never breaks the response.
 */

const DEFAULT_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const MAX_ENTRIES = 5000;

interface CacheEntry {
  value: string | null;
  expiresAt: number;
}

export interface RdnsResolver {
  resolve(ip: string): Promise<string | null>;
}

type LookupFn = (ip: string) => Promise<string[]>;

export function createRdnsResolver(options: {
  ttlMs?: number;
  now?: () => number;
  lookup?: LookupFn;
} = {}): RdnsResolver {
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  const now = options.now ?? (() => Date.now());
  const lookup = options.lookup ?? ((ip: string) => dns.reverse(ip));
  const cache = new Map<string, CacheEntry>();

  return {
    async resolve(ip: string): Promise<string | null> {
      if (getIpVersion(ip) === null) {
        return null;
      }

      const cached = cache.get(ip);
      if (cached && cached.expiresAt > now()) {
        return cached.value;
      }

      let value: string | null = null;
      try {
        const names = await lookup(ip);
        value = names.find((name) => name && name.trim()) ?? null;
      } catch {
        value = null;
      }

      if (cache.size >= MAX_ENTRIES) {
        // Cheap eviction: drop the oldest insertion.
        const oldestKey = cache.keys().next().value;
        if (oldestKey !== undefined) {
          cache.delete(oldestKey);
        }
      }
      cache.set(ip, { value, expiresAt: now() + ttlMs });
      return value;
    },
  };
}
