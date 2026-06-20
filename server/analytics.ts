import type { CrowdsecDatabase } from './database';
import { getIpVersion, ipToNetworkCidr } from './utils/ip';

/**
 * Local analytics computed directly from the SQLite cache (alerts + decisions).
 * No CrowdSec LAPI calls — these read the history the UI already keeps.
 *
 * This module is the foundation for the investigation/incident features:
 * IP history, related-IP discovery (same /24 or ASN), and blocklist
 * cross-referencing. It exposes a thin class that wraps the shared db handle.
 */

const COMMUNITY_BLOCKLIST_ORIGINS = new Set(['lists', 'CAPI', 'cscli-import']);

export interface ScenarioActivity {
  scenario: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
}

export interface RelatedIp {
  ip: string;
  alertCount: number;
  lastSeen: string;
  /** Whether this neighbour currently has an active (non-expired) decision. */
  active: boolean;
}

export interface IpHistory {
  ip: string;
  firstSeen: string | null;
  lastSeen: string | null;
  alertCount: number;
  timesBanned: number;
  activeDecisions: number;
  asNumber: string | null;
  cn: string | null;
  cidr24: string | null;
  scenarios: ScenarioActivity[];
}

export interface BlocklistMembership {
  origin: string;
  scenario: string | null;
  lastSeen: string;
}

export interface IpDecision {
  id: string;
  type: string;
  origin: string;
  scenario: string | null;
  created_at: string;
  stop_at: string;
  duration: string | null;
  expired: boolean;
}

export interface ActivityPoint {
  day: string;
  count: number;
}

export interface NetworkAggregate {
  key: string;
  ipCount: number;
  alertCount: number;
}

interface SqlRow {
  [column: string]: unknown;
}

export class Analytics {
  private readonly db: CrowdsecDatabase['db'];

  constructor(database: CrowdsecDatabase) {
    this.db = database.db;
  }

  /**
   * Full local history for a single IP: when first/last seen, how many alerts,
   * how many times banned, and the scenarios that fired against it over time.
   */
  getIpHistory(ip: string): IpHistory {
    const nowIso = new Date().toISOString();

    const alertAgg = this.db
      .query(
        `SELECT
           COUNT(*) AS alertCount,
           MIN(created_at) AS firstSeen,
           MAX(created_at) AS lastSeen,
           MAX(as_number) AS asNumber,
           MAX(cn) AS cn
         FROM alerts
         WHERE source_ip = $ip`,
      )
      .get({ $ip: ip }) as SqlRow | undefined;

    const decisionAgg = this.db
      .query(
        `SELECT
           COUNT(*) AS timesBanned,
           SUM(CASE WHEN stop_at > $now THEN 1 ELSE 0 END) AS activeDecisions
         FROM decisions
         WHERE value = $ip`,
      )
      .get({ $ip: ip, $now: nowIso }) as SqlRow | undefined;

    const scenarioRows = this.db
      .query(
        `SELECT
           scenario AS scenario,
           COUNT(*) AS count,
           MIN(created_at) AS firstSeen,
           MAX(created_at) AS lastSeen
         FROM alerts
         WHERE source_ip = $ip AND scenario IS NOT NULL AND scenario <> ''
         GROUP BY scenario
         ORDER BY lastSeen DESC`,
      )
      .all({ $ip: ip }) as SqlRow[];

    return {
      ip,
      firstSeen: (alertAgg?.firstSeen as string) ?? null,
      lastSeen: (alertAgg?.lastSeen as string) ?? null,
      alertCount: Number(alertAgg?.alertCount ?? 0),
      timesBanned: Number(decisionAgg?.timesBanned ?? 0),
      activeDecisions: Number(decisionAgg?.activeDecisions ?? 0),
      asNumber: (alertAgg?.asNumber as string) ?? null,
      cn: (alertAgg?.cn as string) ?? null,
      cidr24: ipToNetworkCidr(ip),
      scenarios: scenarioRows.map((row) => ({
        scenario: String(row.scenario),
        count: Number(row.count ?? 0),
        firstSeen: String(row.firstSeen),
        lastSeen: String(row.lastSeen),
      })),
    };
  }

  /**
   * Other IPs we have seen in the same /24 (or /64 for IPv6) and/or the same
   * ASN — the coordinated-infrastructure signal. The seed IP is excluded.
   */
  getRelatedIps(ip: string, options: { asNumber?: string | null; limit?: number } = {}): {
    sameSubnet: RelatedIp[];
    sameAsn: RelatedIp[];
  } {
    const limit = options.limit ?? 50;
    const cidr = ipToNetworkCidr(ip);
    const version = getIpVersion(ip);

    const sameSubnet: RelatedIp[] = [];
    if (cidr && version !== null) {
      // Constrain candidates with a cheap prefix match in SQL, then verify
      // exact subnet membership in JS to keep correctness for IPv6/edge cases.
      const prefixSeed = version === 4 ? ip.slice(0, ip.lastIndexOf('.') + 1) : null;
      const rows = prefixSeed
        ? (this.db
            .query(
              `SELECT source_ip AS ip, COUNT(*) AS alertCount, MAX(created_at) AS lastSeen
               FROM alerts
               WHERE source_ip <> $ip AND source_ip LIKE $prefix
               GROUP BY source_ip
               ORDER BY lastSeen DESC
               LIMIT $limit`,
            )
            .all({ $ip: ip, $prefix: `${prefixSeed}%`, $limit: limit }) as SqlRow[])
        : [];
      for (const row of rows) {
        const candidate = String(row.ip);
        if (ipToNetworkCidr(candidate) === cidr) {
          sameSubnet.push(this.toRelatedIp(row));
        }
      }
    }

    const sameAsn: RelatedIp[] = [];
    const asNumber = options.asNumber ?? null;
    if (asNumber) {
      const rows = this.db
        .query(
          `SELECT source_ip AS ip, COUNT(*) AS alertCount, MAX(created_at) AS lastSeen
           FROM alerts
           WHERE as_number = $asNumber AND source_ip <> $ip AND source_ip IS NOT NULL
           GROUP BY source_ip
           ORDER BY lastSeen DESC
           LIMIT $limit`,
        )
        .all({ $asNumber: asNumber, $ip: ip, $limit: limit }) as SqlRow[];
      for (const row of rows) {
        sameAsn.push(this.toRelatedIp(row));
      }
    }

    return { sameSubnet, sameAsn };
  }

  /**
   * Whether the IP currently appears in any subscribed blocklist / CAPI feed,
   * derived from decisions whose origin is a list source rather than a local
   * scenario. Helps answer "is this a known-bad address elsewhere?".
   */
  getBlocklistMemberships(ip: string): BlocklistMembership[] {
    const nowIso = new Date().toISOString();
    const rows = this.db
      .query(
        `SELECT origin, scenario, MAX(created_at) AS lastSeen
         FROM decisions
         WHERE value = $ip AND stop_at > $now
         GROUP BY origin, scenario
         ORDER BY lastSeen DESC`,
      )
      .all({ $ip: ip, $now: nowIso }) as SqlRow[];

    return rows
      .filter((row) => {
        const origin = String(row.origin ?? '');
        return COMMUNITY_BLOCKLIST_ORIGINS.has(origin) || origin === 'lists';
      })
      .map((row) => ({
        origin: String(row.origin ?? ''),
        scenario: (row.scenario as string) ?? null,
        lastSeen: String(row.lastSeen),
      }));
  }

  /** All decisions (active + expired) recorded against the IP, newest first. */
  getIpDecisions(ip: string): IpDecision[] {
    const nowIso = new Date().toISOString();
    const rows = this.db
      .query(
        `SELECT id, type, origin, scenario, created_at, stop_at, raw_data
         FROM decisions
         WHERE value = $ip
         ORDER BY stop_at DESC`,
      )
      .all({ $ip: ip }) as SqlRow[];

    return rows.map((row) => {
      let duration: string | null = null;
      try {
        const raw = JSON.parse(String(row.raw_data ?? '{}')) as { duration?: unknown };
        if (raw.duration != null && raw.duration !== '') {
          duration = String(raw.duration);
        }
      } catch {
        duration = null;
      }
      const stopAt = String(row.stop_at ?? '');
      return {
        id: String(row.id ?? ''),
        type: String(row.type ?? ''),
        origin: String(row.origin ?? ''),
        scenario: (row.scenario as string) ?? null,
        created_at: String(row.created_at ?? ''),
        stop_at: stopAt,
        duration,
        expired: stopAt !== '' && stopAt <= nowIso,
      };
    });
  }

  /** Alerts-per-day counts for the IP (UTC days), oldest first. */
  getActivitySeries(ip: string): ActivityPoint[] {
    const rows = this.db
      .query(
        `SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS count
         FROM alerts
         WHERE source_ip = $ip
         GROUP BY day
         ORDER BY day ASC`,
      )
      .all({ $ip: ip }) as SqlRow[];
    return rows.map((row) => ({ day: String(row.day), count: Number(row.count ?? 0) }));
  }

  /** Distinct IPs and total alerts seen in the IP's /24 (or /64 for IPv6). */
  getSubnetAggregate(ip: string): NetworkAggregate | null {
    const cidr = ipToNetworkCidr(ip);
    const version = getIpVersion(ip);
    if (!cidr || version !== 4) {
      // IPv4 prefix-match keeps this cheap; skip aggregate for IPv6.
      return cidr ? { key: cidr, ipCount: 0, alertCount: 0 } : null;
    }
    const prefix = ip.slice(0, ip.lastIndexOf('.') + 1);
    const rows = this.db
      .query(
        `SELECT source_ip AS ip, COUNT(*) AS alertCount
         FROM alerts
         WHERE source_ip LIKE $prefix
         GROUP BY source_ip`,
      )
      .all({ $prefix: `${prefix}%` }) as SqlRow[];

    let ipCount = 0;
    let alertCount = 0;
    for (const row of rows) {
      if (ipToNetworkCidr(String(row.ip)) === cidr) {
        ipCount += 1;
        alertCount += Number(row.alertCount ?? 0);
      }
    }
    return { key: cidr, ipCount, alertCount };
  }

  /** Distinct IPs and total alerts seen for an ASN. */
  getAsnAggregate(asNumber: string | null): NetworkAggregate | null {
    if (!asNumber) {
      return null;
    }
    const row = this.db
      .query(
        `SELECT COUNT(DISTINCT source_ip) AS ipCount, COUNT(*) AS alertCount
         FROM alerts
         WHERE as_number = $asNumber`,
      )
      .get({ $asNumber: asNumber }) as SqlRow | undefined;
    return {
      key: `AS${asNumber}`,
      ipCount: Number(row?.ipCount ?? 0),
      alertCount: Number(row?.alertCount ?? 0),
    };
  }

  private toRelatedIp(row: SqlRow): RelatedIp {
    const ip = String(row.ip);
    const nowIso = new Date().toISOString();
    const activeRow = this.db
      .query('SELECT 1 AS hit FROM decisions WHERE value = $ip AND stop_at > $now LIMIT 1')
      .get({ $ip: ip, $now: nowIso }) as SqlRow | undefined;
    return {
      ip,
      alertCount: Number(row.alertCount ?? 0),
      lastSeen: String(row.lastSeen),
      active: Boolean(activeRow?.hit),
    };
  }
}
