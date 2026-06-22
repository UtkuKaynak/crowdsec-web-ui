import { describe, expect, test } from 'vitest';
import {
  computeCounterDelta,
  DEFAULT_METRIC_MAPPINGS,
  MetricsClient,
  parsePrometheusText,
  sampleKey,
  selectCounterSamples,
  type MetricsFetch,
} from './metrics';

describe('parsePrometheusText', () => {
  test('parses labelled and unlabelled samples and skips comments', () => {
    const text = [
      '# HELP cs_node_hits_ok_total Total events successfully exited node.',
      '# TYPE cs_node_hits_ok_total counter',
      'cs_node_hits_ok_total{acquis_type="apache2",name="child-crowdsecurity/apache2-logs",source="/var/log/virtualmin/dtaki.com_access_log",stage="s01-parse",type="file"} 6358',
      'cs_lapi_requests_total 42',
      '',
    ].join('\n');

    const samples = parsePrometheusText(text);
    expect(samples).toHaveLength(2);

    expect(samples[0]).toEqual({
      name: 'cs_node_hits_ok_total',
      labels: {
        acquis_type: 'apache2',
        name: 'child-crowdsecurity/apache2-logs',
        source: '/var/log/virtualmin/dtaki.com_access_log',
        stage: 's01-parse',
        type: 'file',
      },
      value: 6358,
    });
    expect(samples[1]).toEqual({ name: 'cs_lapi_requests_total', labels: {}, value: 42 });
  });

  test('handles escaped label values and an ignored trailing timestamp', () => {
    const text = 'cs_thing{path="a\\\\b",msg="line\\nbreak",q="\\""} 1.5 1700000000000';
    const [sample] = parsePrometheusText(text);
    expect(sample.labels).toEqual({ path: 'a\\b', msg: 'line\nbreak', q: '"' });
    expect(sample.value).toBe(1.5);
  });

  test('parses special float values and scientific notation', () => {
    const samples = parsePrometheusText(
      ['m_a 1.5e+03', 'm_b +Inf', 'm_c -Inf', 'm_d NaN'].join('\n'),
    );
    expect(samples[0].value).toBe(1500);
    expect(samples[1].value).toBe(Number.POSITIVE_INFINITY);
    expect(samples[2].value).toBe(Number.NEGATIVE_INFINITY);
    expect(Number.isNaN(samples[3].value)).toBe(true);
  });

  test('skips malformed lines without throwing', () => {
    const samples = parsePrometheusText(
      ['garbage-without-value', 'cs_ok{a="b"} 7', 'cs_bad{unterminated 9'].join('\n'),
    );
    expect(samples).toEqual([{ name: 'cs_ok', labels: { a: 'b' }, value: 7 }]);
  });

  test('handles a label value containing a comma and an equals sign', () => {
    const [sample] = parsePrometheusText('cs_x{reason="a,b=c"} 3');
    expect(sample.labels.reason).toBe('a,b=c');
    expect(sample.value).toBe(3);
  });
});

describe('computeCounterDelta', () => {
  test('first observation establishes a baseline (delta 0)', () => {
    expect(computeCounterDelta(undefined, 100)).toBe(0);
  });

  test('normal increase returns the difference', () => {
    expect(computeCounterDelta(100, 175)).toBe(75);
  });

  test('counter reset (decrease) returns the current value', () => {
    expect(computeCounterDelta(1_000_000, 12)).toBe(12);
  });

  test('non-finite inputs are treated as no-delta', () => {
    expect(computeCounterDelta(Number.POSITIVE_INFINITY, 5)).toBe(0);
    expect(computeCounterDelta(5, Number.NaN)).toBe(0);
  });
});

describe('sampleKey', () => {
  test('is stable regardless of label order', () => {
    const a = sampleKey({ name: 'm', labels: { b: '2', a: '1' } });
    const b = sampleKey({ name: 'm', labels: { a: '1', b: '2' } });
    expect(a).toBe(b);
    expect(a).toBe('m{a=1,b=2}');
  });

  test('distinguishes different label sets', () => {
    expect(sampleKey({ name: 'm', labels: { a: '1' } }))
      .not.toBe(sampleKey({ name: 'm', labels: { a: '2' } }));
  });
});

describe('selectCounterSamples', () => {
  test('maps known counters to (metric, dimension) and ignores the rest', () => {
    const samples = parsePrometheusText([
      'cs_parser_hits_ok_total{acquis_type="apache2",source="/var/log/a_access_log",type="file"} 100',
      'cs_parser_hits_ko_total{source="/var/log/maillog",type="file"} 8665',
      'cs_bucket_overflowed_total{name="crowdsecurity/http-bf"} 12',
      'cs_unrelated_total{foo="bar"} 9',
      'cs_parser_hits_ok_total{source=""} 5',
    ].join('\n'));

    const counters = selectCounterSamples(samples, DEFAULT_METRIC_MAPPINGS);
    expect(counters).toEqual([
      { seriesKey: sampleKey(samples[0]), metric: 'parser_ok', dimension: '/var/log/a_access_log', rawValue: 100 },
      { seriesKey: sampleKey(samples[1]), metric: 'parser_ko', dimension: '/var/log/maillog', rawValue: 8665 },
      { seriesKey: sampleKey(samples[2]), metric: 'bucket_overflow', dimension: 'crowdsecurity/http-bf', rawValue: 12 },
    ]);
  });
});

describe('MetricsClient', () => {
  const okFetch = (body: string): MetricsFetch => async () => ({
    ok: true,
    status: 200,
    text: async () => body,
  });

  test('scrape parses the body and updates status', async () => {
    const client = new MetricsClient({
      metricsUrl: 'http://127.0.0.1:6060/metrics',
      fetchImpl: okFetch('cs_node_hits_ok_total{source="x"} 5'),
    });

    const samples = await client.scrape();
    expect(samples).toHaveLength(1);

    const status = client.getStatus();
    expect(status.isConnected).toBe(true);
    expect(status.sampleCount).toBe(1);
    expect(status.lastError).toBeNull();
    expect(status.lastScrapeAt).not.toBeNull();
  });

  test('scrape throws and records error on non-2xx', async () => {
    const client = new MetricsClient({
      metricsUrl: 'http://127.0.0.1:6060/metrics',
      fetchImpl: async () => ({ ok: false, status: 503, text: async () => '' }),
    });

    await expect(client.scrape()).rejects.toThrow('HTTP 503');
    const status = client.getStatus();
    expect(status.isConnected).toBe(false);
    expect(status.lastError).toContain('503');
  });
});
