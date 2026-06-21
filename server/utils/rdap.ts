import { getIpVersion } from './ip';

/**
 * Best-effort RDAP (whois successor) lookups for an IP — network name and abuse
 * contact. RDAP is a free, key-less HTTP API; rdap.org redirects to the owning
 * RIR. All failures resolve to null so a slow/blocked lookup never breaks the
 * response. Results are cached in-memory with a TTL.
 *
 * Note: this is an outbound request that discloses the queried IP to a third
 * party, so it can be disabled via config (IP_RDAP_ENABLED=false).
 */

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_ENTRIES = 5000;
const RDAP_BASE = 'https://rdap.org/ip/';

export interface WhoisResult {
  name: string | null;
  handle: string | null;
  abuseEmail: string | null;
}

interface CacheEntry {
  value: WhoisResult | null;
  expiresAt: number;
}

type FetchLike = (url: string, init?: { signal?: AbortSignal }) => Promise<{ ok: boolean; json: () => Promise<unknown> }>;

export interface RdapResolver {
  lookup(ip: string): Promise<WhoisResult | null>;
  lookupAutnum(asn: string): Promise<WhoisResult | null>;
}

export function createRdapResolver(options: {
  enabled?: boolean;
  ttlMs?: number;
  timeoutMs?: number;
  now?: () => number;
  fetchImpl?: FetchLike;
} = {}): RdapResolver {
  const enabled = options.enabled ?? true;
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const now = options.now ?? (() => Date.now());
  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  const cache = new Map<string, CacheEntry>();

  async function fetchCached(cacheKey: string, url: string): Promise<WhoisResult | null> {
    if (!enabled || typeof fetchImpl !== 'function') {
      return null;
    }
    const cached = cache.get(cacheKey);
    if (cached && cached.expiresAt > now()) {
      return cached.value;
    }

    let value: WhoisResult | null = null;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(url, { signal: controller.signal });
      if (response.ok) {
        value = parseRdap(await response.json());
      }
    } catch {
      value = null;
    } finally {
      clearTimeout(timer);
    }

    if (cache.size >= MAX_ENTRIES) {
      const oldestKey = cache.keys().next().value;
      if (oldestKey !== undefined) {
        cache.delete(oldestKey);
      }
    }
    cache.set(cacheKey, { value, expiresAt: now() + ttlMs });
    return value;
  }

  return {
    async lookup(ip: string): Promise<WhoisResult | null> {
      if (getIpVersion(ip) === null) {
        return null;
      }
      return fetchCached(`ip:${ip}`, `${RDAP_BASE}${encodeURIComponent(ip)}`);
    },
    async lookupAutnum(asn: string): Promise<WhoisResult | null> {
      if (!/^\d+$/.test(asn)) {
        return null;
      }
      return fetchCached(`as:${asn}`, `https://rdap.org/autnum/${encodeURIComponent(asn)}`);
    },
  };
}

interface RdapEntity {
  roles?: unknown;
  vcardArray?: unknown;
  entities?: RdapEntity[];
}

function parseRdap(payload: unknown): WhoisResult {
  const data = (payload ?? {}) as { name?: unknown; handle?: unknown; entities?: RdapEntity[] };
  const name = typeof data.name === 'string' && data.name ? data.name : null;
  const handle = typeof data.handle === 'string' && data.handle ? data.handle : null;
  const abuseEmail = findAbuseEmail(Array.isArray(data.entities) ? data.entities : []);
  return { name, handle, abuseEmail };
}

function findAbuseEmail(entities: RdapEntity[]): string | null {
  for (const entity of entities) {
    const roles = Array.isArray(entity.roles) ? entity.roles.map((r) => String(r)) : [];
    if (roles.includes('abuse')) {
      const email = extractVcardEmail(entity.vcardArray);
      if (email) return email;
    }
    if (Array.isArray(entity.entities)) {
      const nested = findAbuseEmail(entity.entities);
      if (nested) return nested;
    }
  }
  return null;
}

function extractVcardEmail(vcardArray: unknown): string | null {
  // vcardArray = ['vcard', [ ['email', {...}, 'text', 'abuse@example.com'], ... ]]
  if (!Array.isArray(vcardArray) || vcardArray.length < 2 || !Array.isArray(vcardArray[1])) {
    return null;
  }
  for (const field of vcardArray[1] as unknown[]) {
    if (Array.isArray(field) && field[0] === 'email' && typeof field[3] === 'string' && field[3]) {
      return field[3];
    }
  }
  return null;
}
