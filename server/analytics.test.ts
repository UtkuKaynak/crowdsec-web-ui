import { afterEach, describe, expect, test } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import path from 'path';
import { tmpdir } from 'os';
import { CrowdsecDatabase } from './database';
import { Analytics } from './analytics';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

function createDb(): CrowdsecDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), 'crowdsec-analytics-'));
  tempDirs.push(dir);
  return new CrowdsecDatabase({ dbPath: path.join(dir, 'test.db') });
}

function insertAlert(db: CrowdsecDatabase, params: { id: number; ip: string; scenario: string; createdAt: string; asn?: string; cn?: string }): void {
  db.insertAlert({
    $id: params.id,
    $uuid: `alert-${params.id}`,
    $created_at: params.createdAt,
    $scenario: params.scenario,
    $source_ip: params.ip,
    $as_number: params.asn,
    $cn: params.cn,
    $message: 'test',
    $raw_data: JSON.stringify({ id: params.id, source: { value: params.ip, as_number: params.asn, cn: params.cn } }),
  });
}

describe('Analytics.getIncidents', () => {
  const nowMs = Date.parse('2026-01-10T00:00:00.000Z');
  const hoursAgo = (h: number) => new Date(nowMs - h * 3_600_000).toISOString();
  const daysAgo = (d: number) => new Date(nowMs - d * 86_400_000).toISOString();

  test('clusters by scenario and /24, computes baseline, isNew, and active bans', () => {
    const db = createDb();
    const analytics = new Analytics(db);

    // Two IPs in the same /24 + scenario, inside the 24h window.
    insertAlert(db, { id: 1, ip: '1.2.3.10', scenario: 'crowdsecurity/ssh-bf', createdAt: hoursAgo(1), asn: '64500', cn: 'US' });
    insertAlert(db, { id: 2, ip: '1.2.3.11', scenario: 'crowdsecurity/ssh-bf', createdAt: hoursAgo(2), asn: '64500', cn: 'US' });
    // Different /24, same scenario → separate incident.
    insertAlert(db, { id: 3, ip: '9.9.9.9', scenario: 'crowdsecurity/ssh-bf', createdAt: hoursAgo(3), asn: '64501', cn: 'FR' });
    // Brand-new scenario in the window (no baseline) → isNew.
    insertAlert(db, { id: 4, ip: '5.5.5.5', scenario: 'crowdsecurity/http-probing', createdAt: hoursAgo(1) });
    // Baseline alert for ssh-bf (older than the window, within baseline period).
    insertAlert(db, { id: 5, ip: '1.2.3.99', scenario: 'crowdsecurity/ssh-bf', createdAt: daysAgo(2) });

    // Active ban on one IP of the /24 cluster.
    db.insertDecision({
      $id: 'dec-1', $uuid: 'dec-1', $alert_id: 1,
      $created_at: hoursAgo(1), $stop_at: new Date(nowMs + 3_600_000).toISOString(),
      $value: '1.2.3.10', $type: 'ban', $origin: 'crowdsec', $scenario: 'crowdsecurity/ssh-bf',
      $raw_data: JSON.stringify({ duration: '4h' }),
    });

    const result = analytics.getIncidents({ windowHours: 24, baselineDays: 7, nowMs, lastViewedAt: null });

    expect(result.totalAlerts).toBe(4); // baseline alert (id 5) is outside the window

    const subnetIncident = result.incidents.find((i) => i.scenario === 'crowdsecurity/ssh-bf' && i.cidr === '1.2.3.0/24');
    expect(subnetIncident).toBeDefined();
    expect(subnetIncident!.ipCount).toBe(2);
    expect(subnetIncident!.alertCount).toBe(2);
    expect(subnetIncident!.activeBans).toBe(1);
    expect(subnetIncident!.isNew).toBe(false); // ssh-bf has a baseline alert
    expect(subnetIncident!.ratioVsBaseline).not.toBeNull();

    const newScenario = result.incidents.find((i) => i.scenario === 'crowdsecurity/http-probing');
    expect(newScenario).toBeDefined();
    expect(newScenario!.isNew).toBe(true); // no baseline

    db.close();
  });

  test('flags incidents new since last view', () => {
    const db = createDb();
    const analytics = new Analytics(db);
    insertAlert(db, { id: 1, ip: '1.2.3.10', scenario: 'crowdsecurity/ssh-bf', createdAt: hoursAgo(1) });

    const seen = analytics.getIncidents({ windowHours: 24, nowMs, lastViewedAt: hoursAgo(0) });
    expect(seen.incidents[0].isNewSinceLastView).toBe(false);

    const fresh = analytics.getIncidents({ windowHours: 24, nowMs, lastViewedAt: hoursAgo(2) });
    expect(fresh.incidents[0].isNewSinceLastView).toBe(true);

    db.close();
  });
});

describe('Analytics.getAllowlistConflicts', () => {
  // getAllowlistConflicts uses the real current time, so the ban must end in the real future.
  const future = new Date(Date.now() + 3_600_000).toISOString();

  function activeDecision(db: CrowdsecDatabase, id: string, value: string): void {
    db.insertDecision({
      $id: id, $uuid: id, $alert_id: 0,
      $created_at: '2026-01-09T00:00:00.000Z', $stop_at: future,
      $value: value, $type: 'ban', $origin: 'crowdsec', $scenario: 'crowdsecurity/ssh-bf',
      $raw_data: JSON.stringify({ duration: '4h' }),
    });
  }

  test('flags active bans whose IP is in an allowlist (exact or CIDR)', () => {
    const db = createDb();
    const analytics = new Analytics(db);

    activeDecision(db, 'd1', '10.0.0.5');     // inside an allowlisted /24
    activeDecision(db, 'd2', '1.2.3.4');      // exact allowlisted IP
    activeDecision(db, 'd3', '203.0.113.7');  // not allowlisted

    const conflicts = analytics.getAllowlistConflicts([
      { value: '10.0.0.0/24', allowlist: 'office' },
      { value: '1.2.3.4', allowlist: 'monitors' },
    ]);

    const byValue = new Map(conflicts.map((c) => [c.value, c]));
    expect(byValue.get('10.0.0.5')?.matchedAllowlist).toBe('office');
    expect(byValue.get('1.2.3.4')?.matchedValue).toBe('1.2.3.4');
    expect(byValue.has('203.0.113.7')).toBe(false);
    expect(conflicts).toHaveLength(2);

    db.close();
  });
});

describe('Analytics network overviews', () => {
  test('getAsnOverview and getSubnetOverview aggregate IPs and scenarios', () => {
    const db = createDb();
    const analytics = new Analytics(db);
    const insert = (id: number, ip: string, scenario: string, asn: string) => db.insertAlert({
      $id: id, $uuid: `a${id}`, $created_at: '2026-01-09T00:00:00.000Z',
      $scenario: scenario, $source_ip: ip, $as_number: asn, $cn: 'US', $message: 'x', $raw_data: '{}',
    });

    insert(1, '1.2.3.10', 'crowdsecurity/ssh-bf', '64500');
    insert(2, '1.2.3.10', 'crowdsecurity/ssh-bf', '64500'); // same IP again
    insert(3, '1.2.3.11', 'crowdsecurity/http-probing', '64500'); // same /24 + ASN
    insert(4, '9.9.9.9', 'crowdsecurity/ssh-bf', '64500'); // same ASN, different /24

    const asn = analytics.getAsnOverview('64500');
    expect(asn.kind).toBe('asn');
    expect(asn.ipCount).toBe(3);            // .10, .11, 9.9.9.9
    expect(asn.alertCount).toBe(4);
    expect(asn.ips[0].ip).toBe('1.2.3.10'); // most alerts first

    const subnet = analytics.getSubnetOverview('1.2.3.0/24');
    expect(subnet).not.toBeNull();
    expect(subnet!.kind).toBe('subnet');
    expect(subnet!.ipCount).toBe(2);        // .10 and .11 only
    expect(subnet!.alertCount).toBe(3);
    expect(subnet!.scenarios.map((s) => s.scenario).sort()).toEqual(['crowdsecurity/http-probing', 'crowdsecurity/ssh-bf']);

    expect(analytics.getSubnetOverview('not-a-cidr')).toBeNull();

    db.close();
  });
});

describe('Analytics insights', () => {
  const future = new Date(Date.now() + 3_600_000).toISOString();
  const past = new Date(Date.now() - 3_600_000).toISOString();

  function decision(db: CrowdsecDatabase, id: string, value: string, origin: string, stopAt: string): void {
    db.insertDecision({
      $id: id, $uuid: id, $alert_id: 0, $created_at: '2026-01-09T00:00:00.000Z', $stop_at: stopAt,
      $value: value, $type: 'ban', $origin: origin, $scenario: 'crowdsecurity/ssh-bf', $raw_data: '{}',
    });
  }

  test('getRepeatOffenders surfaces IPs banned multiple times', () => {
    const db = createDb();
    const analytics = new Analytics(db);
    decision(db, 'a1', '1.2.3.4', 'crowdsec', past);    // banned twice
    decision(db, 'a2', '1.2.3.4', 'crowdsec', future);
    decision(db, 'b1', '5.6.7.8', 'crowdsec', future);  // banned once
    db.insertAlert({ $id: 1, $uuid: 'al1', $created_at: '2026-01-09T00:00:00.000Z', $scenario: 's', $source_ip: '1.2.3.4', $as_number: '64500', $cn: 'US', $message: 'x', $raw_data: '{}' });

    const offenders = analytics.getRepeatOffenders(2, 100);
    expect(offenders).toHaveLength(1);
    expect(offenders[0]).toMatchObject({ ip: '1.2.3.4', banCount: 2, active: true, asn: '64500', cn: 'US' });

    db.close();
  });

  test('getBlocklistOverlap counts local vs community and their intersection', () => {
    const db = createDb();
    const analytics = new Analytics(db);
    decision(db, 'l1', '1.1.1.1', 'crowdsec', future);  // local only
    decision(db, 'c1', '2.2.2.2', 'lists', future);     // community only
    decision(db, 'l3', '3.3.3.3', 'crowdsec', future);  // both
    decision(db, 'c3', '3.3.3.3', 'CAPI', future);

    const overlap = analytics.getBlocklistOverlap();
    expect(overlap.localIps).toBe(2);       // 1.1.1.1, 3.3.3.3
    expect(overlap.communityIps).toBe(2);   // 2.2.2.2, 3.3.3.3
    expect(overlap.overlap).toBe(1);        // 3.3.3.3
    expect(overlap.overlapIps).toContain('3.3.3.3');

    db.close();
  });
});
