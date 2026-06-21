import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertCircle, ArrowUpRight, CheckCheck, Download, Flame, TrendingUp } from 'lucide-react';
import { fetchIncidents, markIncidentsSeen } from '../lib/api';
import { useRefresh } from '../contexts/useRefresh';
import { Badge } from '../components/ui/Badge';
import { ScenarioName } from '../components/ScenarioName';
import { getCountryName } from '../lib/utils';
import { exportCsv } from '../lib/csv';
import { useI18n } from '../lib/i18n';
import type { IncidentItem, IncidentsResponse } from '../types';

const WINDOWS = ['24h', '48h', '7d', '30d'];
const DEFAULT_MIN_ALERTS = 10;

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
    const [minAlerts, setMinAlerts] = useState(DEFAULT_MIN_ALERTS);
    const [data, setData] = useState<IncidentsResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const load = useCallback(async (win: string, min: number) => {
        setLoading(true);
        setError(null);
        try {
            setData(await fetchIncidents(win, min));
        } catch (err) {
            setError(err instanceof Error ? err.message : t('pages.incidents.loadError'));
        } finally {
            setLoading(false);
        }
    }, [t]);

    useEffect(() => {
        const timeoutId = window.setTimeout(() => { void load(range, minAlerts); }, 0);
        return () => window.clearTimeout(timeoutId);
    }, [load, range, minAlerts, refreshSignal]);

    const handleMarkSeen = async () => {
        try {
            await markIncidentsSeen();
            await load(range, minAlerts);
        } catch {
            // best-effort; ignore
        }
    };

    const incidents = data?.incidents ?? [];
    const hasNewSinceVisit = incidents.some((i) => i.isNewSinceLastView);

    const handleExport = () => {
        exportCsv(`incidents-${range}`, incidents, [
            { key: 'scenario', label: 'Scenario' },
            { key: 'cidr', label: 'Subnet' },
            { key: 'asn', label: 'ASN' },
            { key: 'country', label: 'Country' },
            { key: 'ipCount', label: 'IPs' },
            { key: 'alertCount', label: 'Alerts' },
            { key: 'activeBans', label: 'Active bans' },
            { key: 'firstSeen', label: 'First seen' },
            { key: 'lastSeen', label: 'Last seen' },
            { key: 'isNew', label: 'New scenario' },
            { key: 'ratioVsBaseline', label: 'Ratio vs baseline', value: (i) => i.ratioVsBaseline?.toFixed(2) ?? '' },
        ]);
    };

    return (
        <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-sm text-gray-500 dark:text-gray-400">{t('pages.incidents.description')}</p>
                <div className="flex flex-wrap items-center gap-2">
                    <label className="flex items-center gap-1.5 text-sm text-gray-500 dark:text-gray-400">
                        {t('pages.incidents.minAlerts')}
                        <input
                            type="number"
                            min={1}
                            value={minAlerts}
                            onChange={(e) => setMinAlerts(Math.max(1, Number.parseInt(e.target.value, 10) || 1))}
                            className="w-16 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-200 text-sm rounded-md px-2 py-1.5"
                        />
                    </label>
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
                            <CheckCheck size={16} />{t('pages.incidents.markSeen')}
                        </button>
                    )}
                    <button
                        type="button"
                        onClick={handleExport}
                        disabled={incidents.length === 0}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium border border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <Download size={16} />{t('common.exportCsv')}
                    </button>
                </div>
            </div>

            {error && (
                <div role="alert" className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 flex items-center gap-2 text-red-700 dark:text-red-300">
                    <AlertCircle size={16} />{error}
                </div>
            )}

            {data && !loading && (
                <p className="text-sm text-gray-500 dark:text-gray-400">
                    {t('pages.incidents.summaryFiltered', { incidents: incidents.length, min: minAlerts, alerts: data.totalAlerts, window: range })}
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
                <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-x-auto">
                    <table className="w-full text-left text-sm">
                        <thead className="bg-gray-50 dark:bg-gray-900/50 text-xs uppercase tracking-wider text-gray-500 dark:text-gray-400">
                            <tr>
                                <th className="px-4 py-3 font-semibold">{t('pages.incidents.colScenario')}</th>
                                <th className="px-4 py-3 font-semibold">{t('pages.incidents.colSubnet')}</th>
                                <th className="px-4 py-3 font-semibold">{t('pages.incidents.colAsn')}</th>
                                <th className="px-4 py-3 font-semibold text-right">{t('pages.incidents.alerts')}</th>
                                <th className="px-4 py-3 font-semibold text-right">{t('pages.incidents.ips')}</th>
                                <th className="px-4 py-3 font-semibold text-right">{t('pages.incidents.colBans')}</th>
                                <th className="px-4 py-3 font-semibold">{t('pages.incidents.colLastSeen')}</th>
                                <th className="px-4 py-3"></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100 dark:divide-gray-700/50">
                            {incidents.map((incident) => {
                                const ratio = incident.ratioVsBaseline;
                                const showRatio = ratio != null && ratio >= 1.5 && !incident.isNew;
                                return (
                                    <tr key={incident.key} className={`hover:bg-gray-50 dark:hover:bg-gray-700/30 ${incident.isNewSinceLastView ? 'bg-primary-50/40 dark:bg-primary-900/10' : ''}`}>
                                        <td className="px-4 py-3">
                                            <div className="flex flex-wrap items-center gap-2">
                                                <ScenarioName name={incident.scenario} showLink />
                                                {incident.isNew && <Badge variant="info" className="flex items-center gap-1"><Flame size={10} />{t('pages.incidents.newScenario')}</Badge>}
                                                {showRatio && <Badge variant="danger" className="flex items-center gap-1"><TrendingUp size={10} />{t('pages.incidents.ratio', { ratio: ratio!.toFixed(1) })}</Badge>}
                                                {incident.isNewSinceLastView && <Badge variant="warning">{t('pages.incidents.newSinceVisit')}</Badge>}
                                            </div>
                                        </td>
                                        <td className="px-4 py-3 font-mono text-gray-700 dark:text-gray-300 whitespace-nowrap">
                                            <Link to={`/subnet/${encodeURIComponent(incident.cidr.replace(/\//g, '_'))}`} className="text-primary-600 dark:text-primary-400 hover:underline">{incident.cidr}</Link>
                                            {incident.country && <span className={`fi fi-${incident.country.toLowerCase()} ml-2`} title={getCountryName(incident.country) ?? undefined} />}
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap text-gray-600 dark:text-gray-300">
                                            {incident.asn ? <Link to={`/asn/${encodeURIComponent(incident.asn)}`} className="text-primary-600 dark:text-primary-400 hover:underline">AS{incident.asn}</Link> : '—'}
                                        </td>
                                        <td className="px-4 py-3 text-right font-semibold text-gray-800 dark:text-gray-200">{incident.alertCount}</td>
                                        <td className="px-4 py-3 text-right text-gray-700 dark:text-gray-300">{incident.ipCount}</td>
                                        <td className="px-4 py-3 text-right">
                                            {incident.activeBans > 0 ? <span className="text-red-600 dark:text-red-400 font-semibold">{incident.activeBans}</span> : <span className="text-gray-400">0</span>}
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap text-gray-500 dark:text-gray-400">{relativeTime(incident.lastSeen, t)}</td>
                                        <td className="px-4 py-3 whitespace-nowrap text-right">
                                            <Link to={alertsLink(incident)} className="inline-flex items-center gap-1 text-primary-600 dark:text-primary-400 hover:underline">
                                                {t('pages.incidents.viewAlerts')}<ArrowUpRight size={13} />
                                            </Link>
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

export default Incidents;
