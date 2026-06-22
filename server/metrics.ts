import { fetch as undiciFetch } from 'undici';

/**
 * Read-only ingestion of the CrowdSec Prometheus metrics endpoint
 * (default `http://127.0.0.1:6060/metrics`). This is a *second* channel beyond
 * LAPI: it powers the observability dashboards (per-source throughput, attacks
 * per scenario, parser coverage). It is optional — when the endpoint is unset or
 * unreachable, the rest of the app is unaffected (graceful absence).
 *
 * The endpoint is unauthenticated and expected to be loopback-only; on the
 * reference deploy the web-ui container shares the host network namespace, so it
 * reaches `127.0.0.1:6060` exactly as it reaches LAPI on `127.0.0.1:8081`.
 */

export interface MetricSample {
  name: string;
  labels: Record<string, string>;
  value: number;
}

export interface MetricCounterSample {
  seriesKey: string;
  metric: string;
  dimension: string;
  rawValue: number;
}

/** Maps a CrowdSec Prometheus counter to a logical metric id + dimension label. */
export interface MetricMapping {
  prom: string;
  metric: string;
  label: string;
}

/**
 * The CrowdSec counters the observability dashboards ingest. Kept deliberately
 * small — per-source throughput, per-source parser failures, per-scenario
 * overflows. Adding a panel = adding a mapping here.
 */
export const DEFAULT_METRIC_MAPPINGS: MetricMapping[] = [
  { prom: 'cs_parser_hits_ok_total', metric: 'parser_ok', label: 'source' },
  { prom: 'cs_parser_hits_ko_total', metric: 'parser_ko', label: 'source' },
  { prom: 'cs_bucket_overflowed_total', metric: 'bucket_overflow', label: 'name' },
];

/**
 * Project raw Prometheus samples onto the logical (metric, dimension) counters
 * the storage layer tracks. `seriesKey` keeps the full sample identity so deltas
 * stay correct even when several raw series collapse onto one dimension.
 */
export function selectCounterSamples(samples: MetricSample[], mappings: MetricMapping[]): MetricCounterSample[] {
  const byName = new Map<string, MetricMapping>();
  for (const mapping of mappings) {
    byName.set(mapping.prom, mapping);
  }

  const result: MetricCounterSample[] = [];
  for (const sample of samples) {
    const mapping = byName.get(sample.name);
    if (!mapping) continue;
    const dimension = sample.labels[mapping.label];
    if (!dimension) continue;
    if (!Number.isFinite(sample.value)) continue;
    result.push({
      seriesKey: sampleKey(sample),
      metric: mapping.metric,
      dimension,
      rawValue: sample.value,
    });
  }
  return result;
}

export type MetricsFetch = (input: string | URL, init?: { signal?: AbortSignal }) => Promise<{
  ok: boolean;
  status: number;
  text: () => Promise<string>;
}>;

export interface MetricsClientOptions {
  metricsUrl: string;
  requestTimeoutMs?: number;
  fetchImpl?: MetricsFetch;
}

export interface MetricsStatus {
  isConnected: boolean;
  lastScrapeAt: string | null;
  lastError: string | null;
  sampleCount: number;
}

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Parse the Prometheus text exposition format into flat samples. Handles
 * `# HELP`/`# TYPE` comment lines, labelled and unlabelled samples, escaped
 * label values (`\\`, `\"`, `\n`), and an optional trailing timestamp (ignored).
 * Unparseable lines are skipped rather than throwing — a metrics feed should
 * never crash ingestion.
 */
export function parsePrometheusText(text: string): MetricSample[] {
  const samples: MetricSample[] = [];

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }

    const sample = parseSampleLine(line);
    if (sample) {
      samples.push(sample);
    }
  }

  return samples;
}

function parseSampleLine(line: string): MetricSample | null {
  const braceIndex = line.indexOf('{');
  const spaceIndex = line.indexOf(' ');

  let name: string;
  let labels: Record<string, string> = {};
  let rest: string;

  if (braceIndex !== -1 && (spaceIndex === -1 || braceIndex < spaceIndex)) {
    name = line.slice(0, braceIndex).trim();
    const closeIndex = findLabelClose(line, braceIndex);
    if (closeIndex === -1) {
      return null;
    }
    labels = parseLabels(line.slice(braceIndex + 1, closeIndex));
    rest = line.slice(closeIndex + 1).trim();
  } else {
    const splitAt = spaceIndex === -1 ? line.length : spaceIndex;
    name = line.slice(0, splitAt).trim();
    rest = line.slice(splitAt).trim();
  }

  if (!isValidMetricName(name)) {
    return null;
  }

  // `rest` is `value [timestamp]`; take the first token as the value.
  const valueToken = rest.split(/\s+/)[0];
  const value = parseMetricValue(valueToken);
  if (value === null) {
    return null;
  }

  return { name, labels, value };
}

function findLabelClose(line: string, openIndex: number): number {
  let inQuote = false;
  for (let i = openIndex + 1; i < line.length; i += 1) {
    const char = line[i];
    if (inQuote) {
      if (char === '\\') {
        i += 1; // skip the escaped character
      } else if (char === '"') {
        inQuote = false;
      }
    } else if (char === '"') {
      inQuote = true;
    } else if (char === '}') {
      return i;
    }
  }
  return -1;
}

function parseLabels(segment: string): Record<string, string> {
  const labels: Record<string, string> = {};
  let i = 0;
  const len = segment.length;

  while (i < len) {
    // Skip separators / whitespace.
    while (i < len && (segment[i] === ',' || segment[i] === ' ')) {
      i += 1;
    }
    if (i >= len) break;

    const eqIndex = segment.indexOf('=', i);
    if (eqIndex === -1) break;
    const key = segment.slice(i, eqIndex).trim();

    let j = eqIndex + 1;
    while (j < len && segment[j] === ' ') j += 1;
    if (segment[j] !== '"') break; // malformed; bail
    j += 1;

    let value = '';
    while (j < len) {
      const char = segment[j];
      if (char === '\\') {
        const next = segment[j + 1];
        if (next === 'n') value += '\n';
        else if (next === '"') value += '"';
        else if (next === '\\') value += '\\';
        else value += next ?? '';
        j += 2;
        continue;
      }
      if (char === '"') {
        j += 1;
        break;
      }
      value += char;
      j += 1;
    }

    if (key) {
      labels[key] = value;
    }
    i = j;
  }

  return labels;
}

function isValidMetricName(name: string): boolean {
  return /^[a-zA-Z_:][a-zA-Z0-9_:]*$/.test(name);
}

function parseMetricValue(token: string | undefined): number | null {
  if (!token) return null;
  if (token === '+Inf') return Number.POSITIVE_INFINITY;
  if (token === '-Inf') return Number.NEGATIVE_INFINITY;
  if (token === 'NaN') return Number.NaN;
  const value = Number(token);
  return Number.isNaN(value) ? null : value;
}

/**
 * Reset-aware counter delta — the same logic Prometheus `rate()`/`increase()`
 * use. The first observation establishes a baseline (delta 0). A decrease means
 * the counter reset (engine *restart* — not `reload`, which preserves counters),
 * so the increase since the reset is the current value itself.
 */
export function computeCounterDelta(previous: number | undefined, current: number): number {
  if (previous === undefined || !Number.isFinite(previous)) {
    return 0;
  }
  if (!Number.isFinite(current)) {
    return 0;
  }
  if (current >= previous) {
    return current - previous;
  }
  return current; // counter reset
}

/** Stable key for a sample identity (name + sorted labels), for delta tracking. */
export function sampleKey(sample: Pick<MetricSample, 'name' | 'labels'>): string {
  const entries = Object.entries(sample.labels).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const labelStr = entries.map(([k, v]) => `${k}=${v}`).join(',');
  return `${sample.name}{${labelStr}}`;
}

export class MetricsClient {
  private readonly metricsUrl: string;
  private readonly requestTimeoutMs: number;
  private readonly fetchImpl: MetricsFetch;
  private readonly status: MetricsStatus = {
    isConnected: false,
    lastScrapeAt: null,
    lastError: null,
    sampleCount: 0,
  };

  constructor(options: MetricsClientOptions) {
    this.metricsUrl = options.metricsUrl;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetchImpl ?? (undiciFetch as unknown as MetricsFetch);
  }

  getStatus(): MetricsStatus {
    return { ...this.status };
  }

  async scrape(): Promise<MetricSample[]> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    try {
      const response = await this.fetchImpl(this.metricsUrl, { signal: controller.signal });
      if (!response.ok) {
        throw new Error(`Metrics endpoint returned HTTP ${response.status}`);
      }
      const text = await response.text();
      const samples = parsePrometheusText(text);
      this.status.isConnected = true;
      this.status.lastScrapeAt = new Date().toISOString();
      this.status.lastError = null;
      this.status.sampleCount = samples.length;
      return samples;
    } catch (error: unknown) {
      this.status.isConnected = false;
      this.status.lastError = error instanceof Error ? error.message : String(error);
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
}
