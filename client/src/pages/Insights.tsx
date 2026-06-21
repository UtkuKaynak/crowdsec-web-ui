import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertCircle, Ban, Download, Layers, Repeat } from 'lucide-react';
import { fetchBlocklistOverlap, fetchRepeatOffenders } from '../lib/api';
import { useRefresh } from '../contexts/useRefresh';
import { Badge } from '../components/ui/Badge';
import { getCountryName } from '../lib/utils';
import { exportCsv } from '../lib/csv';
import { useI18n } from '../lib/i18n';
import type { BlocklistOverlapResponse, RepeatOffendersResponse } from '../types';

function formatWhen(value: string | null): string {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function Insights() {
    const { t } = useI18n();
    const { refreshSignal } = useRefresh();
    const [minBans, setMinBans] = useState(2);
    const [offenders, setOffenders] = useState<RepeatOffendersResponse | null>(null);
    const [overlap, setOverlap] = useState<BlocklistOverlapResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const load = useCallback(async (min: number) => {
        setLoading(true);
        setError(null);
        try {
            const [ro, ov] = await Promise.all([fetchRepeatOffenders(min), fetchBlocklistOverlap()]);
            setOffenders(ro);
            setOverlap(ov);
        } catch (err) {
            setError(err instanceof Error ? err.message : t('pages.insights.loadError'));
        } finally {
            setLoading(false);
        }
    }, [t]);

    useEffect(() => {
        const id = window.setTimeout(() => { void load(minBans); }, 0);
        return () => window.clearTimeout(id);
    }, [load, minBans, refreshSignal]);

    const list = offenders?.offenders ?? [];

    const exportOffenders = () => {
        exportCsv('repeat-offenders', list, [
            { key: 'ip', label: 'IP' },
            { key: 'banCount', label: 'Bans' },
            { key: 'firstBan', label: 'First ban' },
            { key: 'lastBan', label: 'Last ban' },
            { key: 'active', label: 'Active' },
            { key: 'asn', label: 'ASN' },
            { key: 'cn', label: 'Country' },
        ]);
    };

    return (
        <div className="space-y-6">
            <p className="text-sm text-gray-500 dark:text-gray-400">{t('pages.insights.description')}</p>

            {error && (
                <div role="alert" className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 flex items-center gap-2 text-red-700 dark:text-red-300">
                    <AlertCircle size={16} />{error}
                </div>
            )}

            {/* Blocklist overlap */}
            <section>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-1 flex items-center gap-2"><Layers size={18} />{t('pages.insights.overlapTitle')}</h3>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">{t('pages.insights.overlapHelp')}</p>
                {loading ? (
                    <div className="text-sm text-gray-500 dark:text-gray-400">{t('common.loading')}</div>
                ) : overlap ? (
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                        {[
                            { label: t('pages.insights.activeTotal'), value: overlap.activeTotal },
                            { label: t('pages.insights.localIps'), value: overlap.localIps },
                            { label: t('pages.insights.communityIps'), value: overlap.communityIps },
                            { label: t('pages.insights.overlap'), value: overlap.overlap },
                        ].map((s) => (
                            <div key={s.label} className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 px-4 py-3">
                                <div className="text-xs text-gray-400 dark:text-gray-500">{s.label}</div>
                                <div className="text-xl font-bold text-gray-900 dark:text-gray-100">{s.value}</div>
                            </div>
                        ))}
                        {overlap.byOrigin.length > 0 && (
                            <div className="col-span-2 sm:col-span-4 flex flex-wrap gap-1.5 mt-1">
                                {overlap.byOrigin.map((o) => (
                                    <Badge key={o.origin} variant="secondary">{o.origin}: {o.count}</Badge>
                                ))}
                            </div>
                        )}
                    </div>
                ) : null}
            </section>

            {/* Repeat offenders */}
            <section>
                <div className="flex flex-wrap items-center justify-between gap-3 mb-1">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2"><Repeat size={18} />{t('pages.insights.repeatTitle')}</h3>
                    <div className="flex items-center gap-2">
                        <label className="flex items-center gap-1.5 text-sm text-gray-500 dark:text-gray-400">
                            {t('pages.insights.minBans')}
                            <input type="number" min={2} value={minBans} onChange={(e) => setMinBans(Math.max(2, Number.parseInt(e.target.value, 10) || 2))}
                                className="w-16 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-200 text-sm rounded-md px-2 py-1.5" />
                        </label>
                        <button type="button" onClick={exportOffenders} disabled={list.length === 0} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium border border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50 disabled:opacity-40">
                            <Download size={16} />{t('common.exportCsv')}
                        </button>
                    </div>
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">{t('pages.insights.repeatHelp')}</p>

                {loading ? (
                    <div className="text-sm text-gray-500 dark:text-gray-400">{t('common.loading')}</div>
                ) : list.length === 0 ? (
                    <div className="bg-gray-50 dark:bg-gray-900/40 border border-gray-200 dark:border-gray-700 rounded-lg p-4 text-sm text-gray-500 dark:text-gray-400">{t('pages.insights.repeatEmpty')}</div>
                ) : (
                    <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-x-auto">
                        <table className="w-full text-left text-sm">
                            <thead className="bg-gray-50 dark:bg-gray-900/50 text-xs uppercase tracking-wider text-gray-500 dark:text-gray-400">
                                <tr>
                                    <th className="px-4 py-3 font-semibold">{t('pages.insights.colIp')}</th>
                                    <th className="px-4 py-3 font-semibold text-right">{t('pages.insights.colBans')}</th>
                                    <th className="px-4 py-3 font-semibold">{t('pages.insights.colAsn')}</th>
                                    <th className="px-4 py-3 font-semibold">{t('pages.insights.colCountry')}</th>
                                    <th className="px-4 py-3 font-semibold">{t('pages.insights.colLastBan')}</th>
                                    <th className="px-4 py-3 font-semibold">{t('pages.insights.colStatus')}</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-100 dark:divide-gray-700/50">
                                {list.map((o) => (
                                    <tr key={o.ip} className="hover:bg-gray-50 dark:hover:bg-gray-700/30">
                                        <td className="px-4 py-2 font-mono"><Link to={`/ip/${encodeURIComponent(o.ip)}`} className="text-primary-600 dark:text-primary-400 hover:underline">{o.ip}</Link></td>
                                        <td className="px-4 py-2 text-right font-semibold text-gray-800 dark:text-gray-200">{o.banCount}</td>
                                        <td className="px-4 py-2 text-gray-600 dark:text-gray-300">{o.asn ? <Link to={`/asn/${encodeURIComponent(o.asn)}`} className="text-primary-600 dark:text-primary-400 hover:underline">AS{o.asn}</Link> : '—'}</td>
                                        <td className="px-4 py-2 text-gray-600 dark:text-gray-300">{o.cn ? <span className="inline-flex items-center gap-1.5"><span className={`fi fi-${o.cn.toLowerCase()}`} />{getCountryName(o.cn) ?? o.cn}</span> : '—'}</td>
                                        <td className="px-4 py-2 whitespace-nowrap text-gray-500 dark:text-gray-400">{formatWhen(o.lastBan)}</td>
                                        <td className="px-4 py-2">{o.active ? <Badge variant="danger" className="inline-flex items-center gap-1"><Ban size={10} />{t('pages.insights.active')}</Badge> : <span className="text-gray-400 text-xs">{t('pages.insights.expired')}</span>}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>
        </div>
    );
}

export default Insights;
