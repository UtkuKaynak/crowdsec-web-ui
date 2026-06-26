import { useCallback, useEffect, useMemo, useState } from 'react';
import {
    BarChart,
    Bar,
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
} from 'recharts';
import { Activity, AlertCircle, AlertTriangle, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { fetchMetricsOverview } from '../lib/api';
import { useRefresh } from '../contexts/useRefresh';
import { useI18n } from '../lib/i18n';
import { finalizeRows, type ChartViewMode as ViewMode } from '../lib/chartUtils';
import type { MetricsOverviewResponse, MetricSeries, MetricsResolution } from '../types';

type RangeOption = '24h' | '7d' | '30d' | '90d' | '365d' | '730d';

const RANGE_OPTIONS: RangeOption[] = ['24h', '7d', '30d', '90d', '365d', '730d'];
const MAX_CHART_LINES = 6;
const SERIES_COLORS = ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#3b82f6', '#8b5cf6'];

const formatValue = (value: number, view: ViewMode) =>
    view === 'rate' ? value.toLocaleString(undefined, { maximumFractionDigits: 2 }) : Math.round(value).toLocaleString();

interface PanelMeta {
    metric: string;
    titleKey: string;
    helpKey: string;
    icon: typeof Activity;
    chart: 'bars' | 'lines';
}

const PANELS: PanelMeta[] = [
    // Volume-by-source → stacked bars (total + composition). Attack events → lines (per-scenario spikes).
    { metric: 'parser_ok', titleKey: 'pages.metrics.trafficTitle', helpKey: 'pages.metrics.trafficHelp', icon: Activity, chart: 'bars' },
    { metric: 'bucket_overflow', titleKey: 'pages.metrics.attacksTitle', helpKey: 'pages.metrics.attacksHelp', icon: ShieldAlert, chart: 'lines' },
    { metric: 'parser_ko', titleKey: 'pages.metrics.coverageTitle', helpKey: 'pages.metrics.coverageHelp', icon: AlertTriangle, chart: 'bars' },
];

const formatCount = (value: number) => Math.round(value).toLocaleString();

/** A source path → readable label (the Virtualmin per-vhost log → domain). */
function prettifyDimension(dimension: string): string {
    if (dimension.startsWith('/')) {
        const base = dimension.split('/').pop() || dimension;
        return base.replace(/_access_log$|_error_log$|\.log$/, '');
    }
    return dimension;
}

function formatBucket(ts: string, resolution: MetricsResolution): string {
    const date = new Date(ts);
    if (Number.isNaN(date.getTime())) return ts;
    if (resolution === 'minute') {
        return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    }
    if (resolution === 'hour') {
        return date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit' });
    }
    return date.toLocaleDateString(undefined, { year: '2-digit', month: 'short', day: 'numeric' });
}

interface ChartRow {
    ts: string;
    label: string;
    [dimension: string]: number | string;
}

function buildChartRows(series: MetricSeries, dimensions: string[], resolution: MetricsResolution): ChartRow[] {
    const byTs = new Map<string, ChartRow>();
    const keep = new Set(dimensions);
    for (const entry of series.dimensions) {
        if (!keep.has(entry.dimension)) continue;
        for (const point of entry.points) {
            let row = byTs.get(point.ts);
            if (!row) {
                row = { ts: point.ts, label: formatBucket(point.ts, resolution) };
                byTs.set(point.ts, row);
            }
            row[entry.dimension] = point.value;
        }
    }
    const rows = Array.from(byTs.values()).sort((left, right) => left.ts.localeCompare(right.ts));
    // Fill gaps with 0 so the lines stay continuous.
    for (const row of rows) {
        for (const dimension of dimensions) {
            if (typeof row[dimension] !== 'number') row[dimension] = 0;
        }
    }
    return rows;
}

interface MetricsTooltipEntry {
    name?: string;
    value?: number | string;
    color?: string;
}

function MetricsTooltip({ active, payload, label, view }: { active?: boolean; payload?: readonly MetricsTooltipEntry[]; label?: string; view: ViewMode }) {
    if (!active || !payload || payload.length === 0) return null;
    const sorted = [...payload].sort((a, b) => Number(b.value ?? 0) - Number(a.value ?? 0));
    return (
        <div className="bg-white dark:bg-gray-800 p-3 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg max-w-xs">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">{label}</p>
            {sorted.map((entry, index) => (
                <div key={index} className="flex items-center justify-between gap-3 text-xs mb-1 last:mb-0">
                    <span className="flex items-center gap-1.5 truncate" style={{ color: entry.color }}>
                        <span className="inline-block w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: entry.color }} />
                        <span className="truncate">{prettifyDimension(entry.name || '')}</span>
                    </span>
                    <span className="font-mono text-gray-700 dark:text-gray-200">{formatValue(Number(entry.value ?? 0), view)}</span>
                </div>
            ))}
        </div>
    );
}

function MetricPanel({ meta, series, resolution, view }: { meta: PanelMeta; series: MetricSeries | undefined; resolution: MetricsResolution; view: ViewMode }) {
    const { t } = useI18n();
    const Icon = meta.icon;

    const topDimensions = useMemo(
        () => (series?.dimensions ?? []).slice(0, MAX_CHART_LINES).map((entry) => entry.dimension),
        [series],
    );
    const rows = useMemo(
        () => finalizeRows(series ? buildChartRows(series, topDimensions, resolution) : [], topDimensions, resolution, view),
        [series, topDimensions, resolution, view],
    );

    const hasData = (series?.dimensions.length ?? 0) > 0;

    return (
        <Card className="flex flex-col">
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <Icon className="w-5 h-5 text-primary-600 dark:text-primary-400" />
                    {t(meta.titleKey)}
                </CardTitle>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{t(meta.helpKey)}</p>
            </CardHeader>
            <CardContent>
                {!hasData ? (
                    <div className="h-[260px] flex items-center justify-center text-sm text-gray-400 dark:text-gray-500">
                        {t('pages.metrics.noSeriesData')}
                    </div>
                ) : (
                    <div className="flex flex-col lg:flex-row gap-4">
                        <div className="flex-1 min-w-0 h-[260px]">
                            <ResponsiveContainer width="100%" height="100%">
                                {meta.chart === 'bars' ? (
                                    <BarChart data={rows} margin={{ top: 8, right: 16, left: 4, bottom: 0 }}>
                                        <CartesianGrid strokeDasharray="3 3" opacity={0.2} vertical={false} />
                                        <XAxis dataKey="label" stroke="#888888" fontSize={11} tickLine={false} axisLine={false} minTickGap={24} />
                                        <YAxis stroke="#888888" fontSize={11} tickLine={false} axisLine={false} width={48} tickFormatter={(v) => formatValue(v, view)} allowDecimals={view === 'rate'} />
                                        <Tooltip content={<MetricsTooltip view={view} />} cursor={{ fill: 'currentColor', opacity: 0.06 }} />
                                        {topDimensions.map((dimension, index) => (
                                            <Bar key={dimension} dataKey={dimension} name={dimension} stackId="1"
                                                fill={SERIES_COLORS[index % SERIES_COLORS.length]} isAnimationActive={false} />
                                        ))}
                                    </BarChart>
                                ) : (
                                    <LineChart data={rows} margin={{ top: 8, right: 16, left: 4, bottom: 0 }}>
                                        <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                                        <XAxis dataKey="label" stroke="#888888" fontSize={11} tickLine={false} axisLine={false} minTickGap={32} />
                                        <YAxis stroke="#888888" fontSize={11} tickLine={false} axisLine={false} width={48} tickFormatter={(v) => formatValue(v, view)} allowDecimals={view === 'rate'} />
                                        <Tooltip content={<MetricsTooltip view={view} />} />
                                        {topDimensions.map((dimension, index) => (
                                            <Line
                                                key={dimension}
                                                type="linear"
                                                dataKey={dimension}
                                                name={dimension}
                                                stroke={SERIES_COLORS[index % SERIES_COLORS.length]}
                                                strokeWidth={1.5}
                                                dot={false}
                                                isAnimationActive={false}
                                            />
                                        ))}
                                    </LineChart>
                                )}
                            </ResponsiveContainer>
                        </div>
                        <div className="lg:w-56 flex-shrink-0">
                            <table className="w-full text-sm">
                                <tbody>
                                    {series?.dimensions.map((entry, index) => (
                                        <tr key={entry.dimension} className="border-b border-gray-100 dark:border-gray-700/50 last:border-0">
                                            <td className="py-1.5 pr-2">
                                                <span className="flex items-center gap-1.5 min-w-0">
                                                    <span
                                                        className="inline-block w-2 h-2 rounded-full flex-shrink-0"
                                                        style={{ backgroundColor: index < MAX_CHART_LINES ? SERIES_COLORS[index % SERIES_COLORS.length] : '#9ca3af' }}
                                                    />
                                                    <span className="truncate text-gray-700 dark:text-gray-300" title={entry.dimension}>
                                                        {prettifyDimension(entry.dimension)}
                                                    </span>
                                                </span>
                                            </td>
                                            <td className="py-1.5 text-right font-mono text-gray-600 dark:text-gray-300">{formatCount(entry.total)}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}

export function Metrics() {
    const { t } = useI18n();
    const { refreshSignal } = useRefresh();
    const [range, setRange] = useState<RangeOption>('24h');
    const [view, setView] = useState<ViewMode>('total');
    const [data, setData] = useState<MetricsOverviewResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const load = useCallback(async (selectedRange: RangeOption) => {
        setLoading(true);
        setError(null);
        try {
            setData(await fetchMetricsOverview(selectedRange));
        } catch (err) {
            setError(err instanceof Error ? err.message : t('pages.metrics.loadError'));
        } finally {
            setLoading(false);
        }
    }, [t]);

    useEffect(() => {
        const id = window.setTimeout(() => { void load(range); }, 0);
        return () => window.clearTimeout(id);
    }, [load, range, refreshSignal]);

    const seriesByMetric = useMemo(() => {
        const map = new Map<string, MetricSeries>();
        for (const series of data?.series ?? []) map.set(series.metric, series);
        return map;
    }, [data]);

    const status = data?.status ?? null;

    return (
        <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-sm text-gray-500 dark:text-gray-400">{t('pages.metrics.description')}</p>
                <div className="flex items-center gap-2">
                    <div className="flex p-1 bg-gray-100 dark:bg-gray-800 rounded-lg" role="group" aria-label={t('pages.metrics.viewAria')}>
                        {(['total', 'rate'] as ViewMode[]).map((option) => (
                            <button key={option} type="button" onClick={() => setView(option)}
                                className={`px-3 py-1 text-xs font-medium rounded-md transition-all ${view === option ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 shadow-sm' : 'text-gray-500 hover:text-gray-900 dark:hover:text-gray-300'}`}>
                                {t(`pages.metrics.view.${option}`)}
                            </button>
                        ))}
                    </div>
                    <div className="flex p-1 bg-gray-100 dark:bg-gray-800 rounded-lg" role="group" aria-label={t('pages.metrics.rangeAria')}>
                        {RANGE_OPTIONS.map((option) => (
                            <button
                                key={option}
                                type="button"
                                onClick={() => setRange(option)}
                                className={`px-3 py-1 text-xs font-medium rounded-md transition-all ${range === option
                                    ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 shadow-sm'
                                    : 'text-gray-500 hover:text-gray-900 dark:hover:text-gray-300'}`}
                            >
                                {t(`pages.metrics.range.${option}`)}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {error && (
                <div role="alert" className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 flex items-center gap-2 text-red-700 dark:text-red-300">
                    <AlertCircle size={16} />{error}
                </div>
            )}

            {data && !data.enabled && (
                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-md p-4 text-sm text-blue-800 dark:text-blue-200">
                    <p className="font-medium mb-1">{t('pages.metrics.disabledTitle')}</p>
                    <p className="text-blue-700 dark:text-blue-300">{t('pages.metrics.disabledHelp')}</p>
                </div>
            )}

            {data && data.enabled && !data.available && !loading && (
                <div className="bg-gray-50 dark:bg-gray-900/40 border border-gray-200 dark:border-gray-700 rounded-md p-4 text-sm text-gray-600 dark:text-gray-400">
                    <p>{t('pages.metrics.waitingData')}</p>
                    {status?.lastError && (
                        <p className="mt-1 font-mono text-xs text-red-600 dark:text-red-400">{status.lastError}</p>
                    )}
                </div>
            )}

            {data && data.enabled && (
                <div className="space-y-6">
                    {PANELS.map((panel) => (
                        <MetricPanel key={panel.metric} meta={panel} series={seriesByMetric.get(panel.metric)} resolution={data.resolution} view={view} />
                    ))}
                </div>
            )}

            {status && (
                <p className="text-xs text-gray-400 dark:text-gray-500">
                    {status.isConnected
                        ? t('pages.metrics.statusConnected', {
                            time: status.lastScrapeAt ? new Date(status.lastScrapeAt).toLocaleTimeString() : '—',
                            samples: status.sampleCount,
                        })
                        : t('pages.metrics.statusDisconnected')}
                </p>
            )}
        </div>
    );
}

export default Metrics;
