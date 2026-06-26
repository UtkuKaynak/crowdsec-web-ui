import type { MetricsResolution } from '../types';

export type ChartViewMode = 'total' | 'rate';

export interface ChartRow {
    ts: string;
    label: string;
    [key: string]: number | string;
}

/** Minutes covered by one bucket at each rollup resolution. */
export const bucketMinutes = (resolution: MetricsResolution): number =>
    resolution === 'minute' ? 1 : resolution === 'hour' ? 60 : 1440;

/**
 * Cap on rendered points per chart. Minute resolution over 24h is ~1440 buckets;
 * times several stacked series that is tens of thousands of SVG nodes re-rendered
 * on every refresh, which makes the page progressively unresponsive. Aggregating
 * to a bounded number of points keeps rendering cheap without losing the shape.
 */
const MAX_CHART_POINTS = 240;

/**
 * Downsample (sum-preserving) raw count rows to at most MAX_CHART_POINTS, then
 * apply the view: `total` keeps summed counts, `rate` divides by the minutes the
 * (possibly aggregated) bucket spans → messages/min.
 */
export function finalizeRows(
    rows: ChartRow[],
    keys: string[],
    resolution: MetricsResolution,
    view: ChartViewMode,
): ChartRow[] {
    const minutesPerBucket = bucketMinutes(resolution);

    if (rows.length <= MAX_CHART_POINTS) {
        if (view === 'total') return rows;
        return rows.map((row) => {
            const scaled: ChartRow = { ts: row.ts, label: row.label };
            for (const key of keys) scaled[key] = ((row[key] as number) ?? 0) / minutesPerBucket;
            return scaled;
        });
    }

    const groupSize = Math.ceil(rows.length / MAX_CHART_POINTS);
    const out: ChartRow[] = [];
    for (let i = 0; i < rows.length; i += groupSize) {
        const group = rows.slice(i, i + groupSize);
        const spanMinutes = group.length * minutesPerBucket;
        const row: ChartRow = { ts: group[0].ts, label: group[0].label };
        for (const key of keys) {
            let sum = 0;
            for (const member of group) sum += (member[key] as number) || 0;
            row[key] = view === 'rate' ? sum / spanMinutes : sum;
        }
        out.push(row);
    }
    return out;
}
