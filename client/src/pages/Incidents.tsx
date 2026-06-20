import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertCircle, ArrowUpRight, Ban, CheckCheck, Flame, TrendingUp } from 'lucide-react';
import { fetchIncidents, markIncidentsSeen } from '../lib/api';
import { useRefresh } from '../contexts/useRefresh';
import { Badge } from '../components/ui/Badge';
import { ScenarioName } from '../components/ScenarioName';
import { getCountryName } from '../lib/utils';
import { useI18n } from '../lib/i18n';
import type { IncidentItem, IncidentsResponse } from '../types';

const WINDOWS = ['24h', '48h', '7d', '30d'];

function relativeTime(iso: string, t: ReturnType<typeof useI18n>['t']): string {
    const diffMs = Date.now() - new Date(iso).getTime();
    if (Number.isNaN(diffMs)) return '—';
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return t('pages.incidents.justNow');
    if (mins < 60) return t('pages.incidents.minsAgo', { count: mins });
    const hours = Math.floor(mins / 60);
    if (hours < 24) return t('pages.incidents.hoursAgo', { count: hours });
    return t('pages.incidents.daysAgo', { count: Math.floor(hours / 24) });
}

function alertsLink(incident: IncidentItem): string {
    const q = `scenario:"${incident.scenario}" ip:"${incident.cidr}"`;
    return `/alerts?q=${encodeURIComponent(q)}`;
}

export function Incidents() {
    const { t } = useI18n();
    const { refreshSignal } = useRefresh();
    const [range, setRange] = useState('24h');
    const [data, setData] = useState<IncidentsResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const load = useCallback(async (win: string) => {
        setLoading(true);
        setError(null);
        try {
            setData(await fetchIncidents(win));
        } catch (err) {
            setError(err instanceof Error ? err.message : t('pages.incidents.loadError'));
        } finally {
            setLoading(false);
        }
    }, [t]);

    useEffect(() => {
        const timeoutId = window.setTimeout(() => { void load(range); }, 0);
        return () => window.clearTimeout(timeoutId);
    }, [load, range, refreshSignal]);

    const handleMarkSeen = async () => {
        try {
            await markIncidentsSeen();
            await load(range);
        } catch {
            // best-effort; ignore
        }
    };

    const incidents = data?.incidents ?? [];
    const hasNewSinceVisit = incidents.some((i) => i.isNewSinceLastView);

    return (
        <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-sm text-gray-500 dark:text-gray-400">{t('pages.incidents.description')}</p>
                <div className="flex items-center gap-2">
                    <select
                        value={range}
                        onChange={(e) => setRange(e.target.value)}
                        className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-200 text-sm rounded-md px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-primary-500 cursor-pointer"
                    >
                        {WINDOWS.map((w) => (
                            <option key={w} value={w}>{t('pages.incidents.windowLabel', { window: w })}</option>
                        ))}
                    </select>
                    {hasNewSinceVisit && (
                        <button
                            type="button"
                            onClick={handleMarkSeen}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium bg-primary-50 dark:bg-primary-900/20 text-primary-600 dark:text-primary-400 hover:bg-primary-100 dark:hover:bg-primary-900/40 transition-colors"
                        >
                            <CheckCheck size={16} />
                            {t('pages.incidents.markSeen')}
                        </button>
                    )}
                </div>
            </div>

            {error && (
                <div role="alert" className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 flex items-center gap-2 text-red-700 dark:text-red-300">
                    <AlertCircle size={16} />{error}
                </div>
            )}

            {data && !loading && (
                <p className="text-sm text-gray-500 dark:text-gray-400">
                    {t('pages.incidents.summary', { incidents: incidents.length, alerts: data.totalAlerts, window: range })}
                </p>
            )}

            {loading ? (
                <div className="text-center text-gray-500 dark:text-gray-400 py-12">{t('common.loading')}</div>
            ) : incidents.length === 0 ? (
                <div className="flex flex-col items-center gap-3 py-16 text-gray-500 dark:text-gray-400">
                    <Flame size={32} className="opacity-60" />
                    <span className="text-sm">{t('pages.incidents.empty')}</span>
                </div>
            ) : (
                <div className="space-y-3">
                    {incidents.map((incident) => {
                        const ratio = incident.ratioVsBaseline;
                        const showRatio = ratio != null && ratio >= 1.5 && !incident.isNew;
                        return (
                            <div
                                key={incident.key}
                                className={`bg-white dark:bg-gray-800 rounded-xl shadow-sm border p-4 ${incident.isNewSinceLastView
                                    ? 'border-primary-300 dark:border-primary-700 ring-1 ring-primary-200 dark:ring-primary-900'
                                    : 'border-gray-200 dark:border-gray-700'}`}
                            >
                                <div className="flex flex-wrap items-start justify-between gap-3">
                                    <div className="min-w-0">
                                        <div className="flex flex-wrap items-center gap-2 mb-1">
                                            <ScenarioName name={incident.scenario} showLink />
                                            {incident.isNew && (
                                                <Badge variant="info" className="flex items-center gap-1"><Flame size={10} />{t('pages.incidents.newScenario')}</Badge>
                                            )}
                                            {showRatio && (
                                                <Badge variant="danger" className="flex items-center gap-1">
                                                    <TrendingUp size={10} />{t('pages.incidents.ratio', { ratio: ratio!.toFixed(1) })}
                                                </Badge>
                                            )}
                                            {incident.isNewSinceLastView && (
                                                <Badge variant="warning">{t('pages.incidents.newSinceVisit')}</Badge>
                                            )}
                                        </div>
                                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-gray-500 dark:text-gray-400">
                                            <span className="font-mono text-gray-700 dark:text-gray-300">{incident.cidr}</span>
                                            {incident.country && (
                                                <span className="inline-flex items-center gap-1">
                                                    <span className={`fi fi-${incident.country.toLowerCase()}`} />{getCountryName(incident.country)}
                                                </span>
                                            )}
                                            {incident.asn && <span>AS{incident.asn}</span>}
                                            <span>{relativeTime(incident.lastSeen, t)}</span>
                                        </div>
                                    </div>
                                    <Link
                                        to={alertsLink(incident)}
                                        className="inline-flex items-center gap-1 text-sm text-primary-600 dark:text-primary-400 hover:underline flex-shrink-0"
                                    >
                                        {t('pages.incidents.viewAlerts')}<ArrowUpRight size={14} />
                                    </Link>
                                </div>

                                <div className="flex flex-wrap items-center gap-4 mt-3 text-sm">
                                    <span className="text-gray-700 dark:text-gray-200"><span className="font-semibold">{incident.alertCount}</span> {t('pages.incidents.alerts')}</span>
                                    <span className="text-gray-700 dark:text-gray-200"><span className="font-semibold">{incident.ipCount}</span> {t('pages.incidents.ips')}</span>
                                    {incident.activeBans > 0 && (
                                        <span className="inline-flex items-center gap-1 text-red-600 dark:text-red-400">
                                            <Ban size={13} /><span className="font-semibold">{incident.activeBans}</span> {t('pages.incidents.activeBans')}
                                        </span>
                                    )}
                                </div>

                                {incident.topIps.length > 0 && (
                                    <div className="flex flex-wrap gap-1.5 mt-2">
                                        {incident.topIps.map((top) => (
                                            <Link
                                                key={top.ip}
                                                to={`/ip/${encodeURIComponent(top.ip)}`}
                                                className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono bg-gray-100 dark:bg-gray-700/50 text-primary-600 dark:text-primary-400 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                                            >
                                                {top.ip}<span className="text-gray-400">×{top.count}</span>
                                            </Link>
                                        ))}
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}

export default Incidents;
