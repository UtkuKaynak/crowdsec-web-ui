import { useCallback, useEffect, useMemo, useState } from 'react';
import {
    AreaChart,
    Area,
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
} from 'recharts';
import { AlertCircle, Mailbox, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { fetchMetricsOverview } from '../lib/api';
import { useRefresh } from '../contexts/useRefresh';
import { useI18n } from '../lib/i18n';
import type { MetricsOverviewResponse, MetricSeries, MetricsResolution } from '../types';

type RangeOption = '24h' | '7d' | '30d' | '90d' | '365d' | '730d';

const RANGE_OPTIONS: RangeOption[] = ['24h', '7d', '30d', '90d', '365d', '730d'];
const MAIL_SCENARIO_RE = /postfix|dovecot|smtp|sasl|mail|imap|exim/i;
const CATEGORY_COLORS: Record<string, string> = {
    received: '#3b82f6',
    sent: '#10b981',
    delivered: '#10b981',
    rejected: '#ef4444',
    bounced: '#f59e0b',
    deferred: '#eab308',
    spam: '#a855f7',
    'auth-fail': '#ec4899',
};
// Headline categories first (mailgraph order), then the rest.
const CATEGORY_ORDER = ['received', 'sent', 'rejected', 'bounced', 'deferred', 'spam', 'auth-fail'];
const FALLBACK_COLORS = ['#6366f1', '#3b82f6', '#14b8a6', '#8b5cf6', '#f97316'];
const prettyCategory = (category: string) => category.charAt(0).toUpperCase() + category.slice(1).replace(/-/g, ' ');
const orderCategories = (categories: string[]) =>
    [...categories].sort((a, b) => {
        const ai = CATEGORY_ORDER.indexOf(a); const bi = CATEGORY_ORDER.indexOf(b);
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    });
const ATTACK_COLORS = ['#ef4444', '#f59e0b', '#6366f1', '#a855f7', '#3b82f6', '#14b8a6'];

const formatCount = (value: number) => Math.round(value).toLocaleString();
const mailCategory = (dimension: string) => dimension.replace(/^mail\//, '');

function formatBucket(ts: string, resolution: MetricsResolution): string {
    const date = new Date(ts);
    if (Number.isNaN(date.getTime())) return ts;
    if (resolution === 'minute') return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    if (resolution === 'hour') return date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit' });
    return date.toLocaleDateString(undefined, { year: '2-digit', month: 'short', day: 'numeric' });
}

interface ChartRow {
    ts: string;
    label: string;
    [key: string]: number | string;
}

function pivot(dimensions: MetricSeries['dimensions'], keys: string[], keyOf: (dimension: string) => string, resolution: MetricsResolution): ChartRow[] {
    const byTs = new Map<string, ChartRow>();
    for (const entry of dimensions) {
        const key = keyOf(entry.dimension);
        if (!keys.includes(key)) continue;
        for (const point of entry.points) {
            let row = byTs.get(point.ts);
            if (!row) {
                row = { ts: point.ts, label: formatBucket(point.ts, resolution) };
                byTs.set(point.ts, row);
            }
            row[key] = ((row[key] as number) ?? 0) + point.value;
        }
    }
    const rows = Array.from(byTs.values()).sort((a, b) => a.ts.localeCompare(b.ts));
    for (const row of rows) for (const key of keys) if (typeof row[key] !== 'number') row[key] = 0;
    return rows;
}

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name?: string; value?: number | string; color?: string }>; label?: string }) {
    if (!active || !payload || payload.length === 0) return null;
    const sorted = [...payload].sort((a, b) => Number(b.value ?? 0) - Number(a.value ?? 0));
    return (
        <div className="bg-white dark:bg-gray-800 p-3 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg max-w-xs">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">{label}</p>
            {sorted.map((entry, index) => (
                <div key={index} className="flex items-center justify-between gap-3 text-xs mb-1 last:mb-0">
                    <span className="flex items-center gap-1.5 truncate" style={{ color: entry.color }}>
                        <span className="inline-block w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: entry.color }} />
                        <span className="truncate">{entry.name}</span>
                    </span>
                    <span className="font-mono text-gray-700 dark:text-gray-200">{formatCount(Number(entry.value ?? 0))}</span>
                </div>
            ))}
        </div>
    );
}

const categoryColor = (category: string, index: number) => CATEGORY_COLORS[category] ?? FALLBACK_COLORS[index % FALLBACK_COLORS.length];

function MailFlowPanel({ series, resolution }: { series: MetricSeries | undefined; resolution: MetricsResolution }) {
    const { t } = useI18n();

    const categories = useMemo(() => {
        const set = new Set<string>();
        for (const entry of series?.dimensions ?? []) set.add(mailCategory(entry.dimension));
        return orderCategories(Array.from(set));
    }, [series]);

    const totals = useMemo(() => {
        const map = new Map<string, number>();
        for (const entry of series?.dimensions ?? []) {
            const category = mailCategory(entry.dimension);
            map.set(category, (map.get(category) ?? 0) + entry.total);
        }
        return map;
    }, [series]);

    const rows = useMemo(
        () => pivot(series?.dimensions ?? [], categories, mailCategory, resolution),
        [series, categories, resolution],
    );

    return (
        <Card className="flex flex-col">
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <Mailbox className="w-5 h-5 text-primary-600 dark:text-primary-400" />
                    {t('pages.mail.flowTitle')}
                </CardTitle>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{t('pages.mail.flowHelp')}</p>
            </CardHeader>
            <CardContent>
                {categories.length === 0 ? (
                    <div className="h-[260px] flex items-center justify-center text-center text-sm text-gray-400 dark:text-gray-500 px-6">{t('pages.mail.volumeEmpty')}</div>
                ) : (
                    <>
                        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2 mb-4">
                            {categories.map((category, index) => (
                                <div key={category} className="bg-gray-50 dark:bg-gray-900/40 rounded-lg border border-gray-200 dark:border-gray-700 px-3 py-2">
                                    <div className="flex items-center gap-1.5 text-xs text-gray-500 dark:text-gray-400">
                                        <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: categoryColor(category, index) }} />
                                        {prettyCategory(category)}
                                    </div>
                                    <div className="text-lg font-bold text-gray-900 dark:text-gray-100">{formatCount(totals.get(category) ?? 0)}</div>
                                </div>
                            ))}
                        </div>
                        <div className="h-[240px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={rows} margin={{ top: 8, right: 16, left: 4, bottom: 0 }}>
                                    <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                                    <XAxis dataKey="label" stroke="#888888" fontSize={11} tickLine={false} axisLine={false} minTickGap={32} />
                                    <YAxis stroke="#888888" fontSize={11} tickLine={false} axisLine={false} width={48} tickFormatter={formatCount} />
                                    <Tooltip content={<ChartTooltip />} />
                                    {categories.map((category, index) => (
                                        <Area key={category} type="monotone" dataKey={category} name={prettyCategory(category)} stackId="1"
                                            stroke={categoryColor(category, index)} fill={categoryColor(category, index)} fillOpacity={0.5} isAnimationActive={false} />
                                    ))}
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </>
                )}
            </CardContent>
        </Card>
    );
}

function AttacksPanel({ series, resolution }: { series: MetricSeries | undefined; resolution: MetricsResolution }) {
    const { t } = useI18n();
    const mailScenarios = useMemo(
        () => (series?.dimensions ?? []).filter((entry) => MAIL_SCENARIO_RE.test(entry.dimension)).slice(0, 6),
        [series],
    );
    const names = useMemo(() => mailScenarios.map((entry) => entry.dimension), [mailScenarios]);
    const rows = useMemo(
        () => pivot(mailScenarios, names, (dimension) => dimension, resolution),
        [mailScenarios, names, resolution],
    );

    return (
        <Card className="flex flex-col">
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <ShieldAlert className="w-5 h-5 text-primary-600 dark:text-primary-400" />
                    {t('pages.mail.attacksTitle')}
                </CardTitle>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{t('pages.mail.attacksHelp')}</p>
            </CardHeader>
            <CardContent>
                {names.length === 0 ? (
                    <div className="h-[240px] flex items-center justify-center text-sm text-gray-400 dark:text-gray-500">{t('pages.mail.noAttacks')}</div>
                ) : (
                    <div className="flex flex-col lg:flex-row gap-4">
                        <div className="flex-1 min-w-0 h-[240px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <LineChart data={rows} margin={{ top: 8, right: 16, left: 4, bottom: 0 }}>
                                    <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                                    <XAxis dataKey="label" stroke="#888888" fontSize={11} tickLine={false} axisLine={false} minTickGap={32} />
                                    <YAxis stroke="#888888" fontSize={11} tickLine={false} axisLine={false} width={48} tickFormatter={formatCount} />
                                    <Tooltip content={<ChartTooltip />} />
                                    {names.map((name, index) => (
                                        <Line key={name} type="monotone" dataKey={name} name={name} stroke={ATTACK_COLORS[index % ATTACK_COLORS.length]} strokeWidth={1.5} dot={false} isAnimationActive={false} />
                                    ))}
                                </LineChart>
                            </ResponsiveContainer>
                        </div>
                        <div className="lg:w-56 flex-shrink-0">
                            <table className="w-full text-sm">
                                <tbody>
                                    {mailScenarios.map((entry, index) => (
                                        <tr key={entry.dimension} className="border-b border-gray-100 dark:border-gray-700/50 last:border-0">
                                            <td className="py-1.5 pr-2">
                                                <span className="flex items-center gap-1.5 min-w-0">
                                                    <span className="inline-block w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: ATTACK_COLORS[index % ATTACK_COLORS.length] }} />
                                                    <span className="truncate text-gray-700 dark:text-gray-300" title={entry.dimension}>{entry.dimension}</span>
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

export function Mail() {
    const { t } = useI18n();
    const { refreshSignal } = useRefresh();
    const [range, setRange] = useState<RangeOption>('24h');
    const [data, setData] = useState<MetricsOverviewResponse | null>(null);
    const [error, setError] = useState<string | null>(null);

    const load = useCallback(async (selectedRange: RangeOption) => {
        setError(null);
        try {
            setData(await fetchMetricsOverview(selectedRange));
        } catch (err) {
            setError(err instanceof Error ? err.message : t('pages.mail.loadError'));
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

    const mailFlow = seriesByMetric.get('mail_flow');
    const attacks = seriesByMetric.get('bucket_overflow');
    const resolution = data?.resolution ?? 'minute';

    return (
        <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-sm text-gray-500 dark:text-gray-400">{t('pages.mail.description')}</p>
                <div className="flex p-1 bg-gray-100 dark:bg-gray-800 rounded-lg" role="group" aria-label={t('pages.mail.rangeAria')}>
                    {RANGE_OPTIONS.map((option) => (
                        <button key={option} type="button" onClick={() => setRange(option)}
                            className={`px-3 py-1 text-xs font-medium rounded-md transition-all ${range === option ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 shadow-sm' : 'text-gray-500 hover:text-gray-900 dark:hover:text-gray-300'}`}>
                            {t(`pages.mail.range.${option}`)}
                        </button>
                    ))}
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

            <AttacksPanel series={attacks} resolution={resolution} />
            <MailFlowPanel series={mailFlow} resolution={resolution} />
        </div>
    );
}

export default Mail;
