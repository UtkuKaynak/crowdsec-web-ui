import { describe, expect, it } from 'vitest';
import { bucketMinutes, finalizeRows, type ChartRow } from './chartUtils';

const rows = (n: number, perRow: number): ChartRow[] =>
    Array.from({ length: n }, (_, i) => ({ ts: `t${i}`, label: `l${i}`, a: perRow }));

describe('finalizeRows', () => {
    it('passes through totals unchanged when under the cap', () => {
        const out = finalizeRows(rows(3, 5), ['a'], 'minute', 'total');
        expect(out.map((r) => r.a)).toEqual([5, 5, 5]);
    });

    it('rate mode divides counts by the bucket minutes', () => {
        // hour buckets = 60 min, so 120 count → 2/min
        const out = finalizeRows([{ ts: 't', label: 'l', a: 120 }], ['a'], 'hour', 'rate');
        expect(out[0].a).toBe(2);
    });

    it('downsamples (sum-preserving) when over the cap', () => {
        // 480 minute-buckets of 1 each → capped to <=240 groups, group size 2, each = 2
        const out = finalizeRows(rows(480, 1), ['a'], 'minute', 'total');
        expect(out.length).toBe(240);
        expect(out.every((r) => r.a === 2)).toBe(true);
        // total is preserved
        expect(out.reduce((s, r) => s + (r.a as number), 0)).toBe(480);
    });

    it('downsampled rate divides by the aggregated span minutes', () => {
        // 480 minute-buckets of 3 → group size 2 (span 2 min), each group sum 6 → 6/2 = 3/min
        const out = finalizeRows(rows(480, 3), ['a'], 'minute', 'rate');
        expect(out.length).toBe(240);
        expect(out.every((r) => r.a === 3)).toBe(true);
    });

    it('bucketMinutes maps resolutions', () => {
        expect(bucketMinutes('minute')).toBe(1);
        expect(bucketMinutes('hour')).toBe(60);
        expect(bucketMinutes('day')).toBe(1440);
    });
});
