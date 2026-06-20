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

describe('Analytics.getKnownGoodHits', () => {
  // getKnownGoodHits uses the real current time, so the ban must end in the real future.
  const future = new Date(Date.now() + 3_600_000).toISOString();

  function activeDecision(db: CrowdsecDatabase, id: string, value: string): void {
    db.insertDecision({
      $id: id, $uuid: id, $alert_id: 0,
      $created_at: '2026-01-09T00:00:00.000Z', $stop_at: future,
      $value: value, $type: 'ban', $origin: 'crowdsec', $scenario: 'crowdsecurity/ssh-bf',
      $raw_data: JSON.stringify({ duration: '4h' }),
    });
  }

  test('matches active bans against known-good CIDRs and ASNs', () => {
    const db = createDb();
    const analytics = new Analytics(db);

    activeDecision(db, 'd1', '10.0.0.5');   // inside a known-good /24
    activeDecision(db, 'd2', '8.8.8.8');    // belongs to a known-good ASN
    activeDecision(db, 'd3', '203.0.113.7'); // not known-good

    // 8.8.8.8 needs an alert row so its ASN can be resolved.
    db.insertAlert({
      $id: 1, $uuid: 'a1', $created_at: '2026-01-09T00:00:00.000Z',
      $scenario: 'crowdsecurity/ssh-bf', $source_ip: '8.8.8.8', $as_number: '15169', $cn: 'US',
      $message: 'x', $raw_data: '{}',
    });

    const hits = analytics.getKnownGoodHits([
      { value: '10.0.0.0/24', kind: 'cidr', label: 'office VPN' },
      { value: '15169', kind: 'asn', label: 'Google' },
    ]);

    const byValue = new Map(hits.map((h) => [h.value, h]));
    expect(byValue.get('10.0.0.5')?.matchedLabel).toBe('office VPN');
    expect(byValue.get('8.8.8.8')?.matchedKind).toBe('asn');
    expect(byValue.has('203.0.113.7')).toBe(false);
    expect(hits).toHaveLength(2);

    db.close();
  });
});
