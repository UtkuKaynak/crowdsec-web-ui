import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { AlertCircle, ArrowLeft, ArrowUpRight, Ban, Check, Copy, Download, Network, ShieldBan } from 'lucide-react';
import { addDecision, bulkAddDecisions, fetchAsnOverview, fetchSubnetOverview } from '../lib/api';
import { Badge } from '../components/ui/Badge';
import { Modal } from '../components/ui/Modal';
import { getCountryName } from '../lib/utils';
import { exportCsv } from '../lib/csv';
import { useI18n } from '../lib/i18n';
import type { NetworkOverviewResponse } from '../types';

interface NetworkOverviewProps {
    kind: 'asn' | 'subnet';
}

function formatWhen(value: string | null | undefined): string {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export function NetworkOverview({ kind }: NetworkOverviewProps) {
    const { t } = useI18n();
    const navigate = useNavigate();
    const params = useParams();
    // Subnet CIDRs use '_' for '/' in the URL to avoid path-segment issues.
    const key = kind === 'asn' ? (params.asn ?? '') : (params.cidr ?? '').replace(/_/g, '/');

    const [data, setData] = useState<NetworkOverviewResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const [banOpen, setBanOpen] = useState(false);
    const [banDuration, setBanDuration] = useState('4h');
    const [banSubmitting, setBanSubmitting] = useState(false);
    const [copied, setCopied] = useState(false);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            setData(kind === 'asn' ? await fetchAsnOverview(key) : await fetchSubnetOverview(key));
        } catch (err) {
            setError(err instanceof Error ? err.message : t('pages.network.loadError'));
        } finally {
            setLoading(false);
        }
    }, [kind, key, t]);

    useEffect(() => {
        const id = window.setTimeout(() => { void load(); }, 0);
        return () => window.clearTimeout(id);
    }, [load]);

    const handleExport = () => {
        if (!data) return;
        exportCsv(`${kind}-${data.key}`, data.ips, [
            { key: 'ip', label: 'IP' },
            { key: 'alertCount', label: 'Alerts' },
            { key: 'lastSeen', label: 'Last seen' },
            { key: 'active', label: 'Active ban' },
            { key: 'cn', label: 'Country' },
            { key: 'asn', label: 'ASN' },
        ]);
    };

    const allowlistCmd = `cscli allowlists add crowdsec-web-ui ${key}`;
    const copyAllowlist = async () => {
        try {
            await navigator.clipboard.writeText(allowlistCmd);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
        } catch { /* clipboard unavailable */ }
    };

    const confirmBan = async () => {
        if (!data) return;
        setBanSubmitting(true);
        setError(null);
        try {
            if (kind === 'subnet') {
                await addDecision({ ip: data.key, scope: 'range', duration: banDuration, reason: `manual (subnet ${data.key})` });
            } else {
                await bulkAddDecisions(data.ips.map((i) => i.ip), { duration: banDuration, reason: `manual (AS${key})` });
            }
            setBanOpen(false);
            await load();
        } catch (err) {
            setError(err instanceof Error ? err.message : t('pages.network.banError'));
        } finally {
            setBanSubmitting(false);
        }
    };

    const maxActivity = data ? Math.max(1, ...data.activity.map((a) => a.count)) : 1;

    return (
        <div className="space-y-4">
            <button type="button" onClick={() => navigate(-1)} className="inline-flex items-center gap-1 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 transition-colors cursor-pointer">
                <ArrowLeft size={16} />{t('common.back')}
            </button>

            {error && (
                <div role="alert" className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 flex items-center gap-2 text-red-700 dark:text-red-300">
                    <AlertCircle size={16} />{error}
                </div>
            )}

            {loading ? (
                <div className="text-center text-gray-500 dark:text-gray-400 py-12">{t('common.loading')}</div>
            ) : data ? (
                <>
                    <div className="p-4 bg-gray-50 dark:bg-gray-900/50 rounded-lg border border-gray-100 dark:border-gray-700/50">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                                <span className="font-mono text-lg font-bold text-gray-900 dark:text-white inline-flex items-center gap-2"><Network size={18} />{data.key}</span>
                                {kind === 'asn' && (
                                    <a href={`https://bgp.he.net/AS${encodeURIComponent(key)}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-primary-600 dark:hover:text-primary-400">
                                        bgp.he.net<ArrowUpRight size={12} />
                                    </a>
                                )}
                            </div>
                            <div className="flex flex-wrap items-center gap-2">
                                {kind === 'subnet' && (
                                    <button type="button" onClick={copyAllowlist} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium border border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                                        {copied ? <Check size={15} /> : <Copy size={15} />}{t('pages.network.copyAllowlist')}
                                    </button>
                                )}
                                {data.ips.length > 0 && (
                                    <button type="button" onClick={() => setBanOpen(true)} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium bg-red-600 text-white hover:bg-red-700">
                                        <ShieldBan size={15} />
                                        {kind === 'subnet' ? t('pages.network.banSubnet') : t('pages.network.banAsn', { count: data.ips.length })}
                                    </button>
                                )}
                            </div>
                        </div>

                        {data.whois && (data.whois.name || data.whois.abuseEmail) && (
                            <div className="mt-2 text-xs text-gray-600 dark:text-gray-300 flex flex-wrap gap-x-4 gap-y-0.5">
                                {data.whois.name && <span><span className="text-gray-400">{t('pages.network.owner')}:</span> {data.whois.name}</span>}
                                {data.whois.abuseEmail && <span><span className="text-gray-400">{t('pages.network.abuse')}:</span> <a href={`mailto:${data.whois.abuseEmail}`} className="text-primary-600 dark:text-primary-400 hover:underline">{data.whois.abuseEmail}</a></span>}
                            </div>
                        )}

                        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 mt-3 text-xs">
                            {[
                                { label: t('pages.network.ips'), value: String(data.ipCount) },
                                { label: t('pages.network.alerts'), value: String(data.alertCount) },
                                { label: t('pages.network.activeBans'), value: String(data.activeBans) },
                                { label: t('pages.network.firstSeen'), value: formatWhen(data.firstSeen) },
                                { label: t('pages.network.lastSeen'), value: formatWhen(data.lastSeen) },
                            ].map((s) => (
                                <div key={s.label} className="bg-white dark:bg-gray-950 rounded border border-gray-200 dark:border-gray-800 px-3 py-1.5">
                                    <div className="text-gray-400 dark:text-gray-500">{s.label}</div>
                                    <div className="font-medium text-gray-800 dark:text-gray-200">{s.value}</div>
                                </div>
                            ))}
                        </div>

                        {data.countries.length > 0 && (
                            <div className="mt-3 flex flex-wrap items-center gap-1.5">
                                <span className="text-xs text-gray-400 dark:text-gray-500">{t('pages.network.countries')}:</span>
                                {data.countries.slice(0, 12).map((c) => (
                                    <span key={c.cn} className="inline-flex items-center gap-1 text-xs text-gray-600 dark:text-gray-300">
                                        <span className={`fi fi-${c.cn.toLowerCase()}`} />{c.cn} <span className="text-gray-400">{c.count}</span>
                                    </span>
                                ))}
                            </div>
                        )}

                        {data.activity.length > 0 && (
                            <div className="mt-3">
                                <div className="text-xs text-gray-400 dark:text-gray-500 mb-1">{t('pages.network.activity')}</div>
                                <div className="flex items-end gap-0.5 h-12 bg-white dark:bg-gray-950 rounded border border-gray-200 dark:border-gray-800 px-2 py-1">
                                    {data.activity.slice(-60).map((p) => (
                                        <div key={p.day} className="flex-1 min-w-[2px] bg-primary-400 dark:bg-primary-500 rounded-sm" style={{ height: `${Math.max(8, (p.count / maxActivity) * 100)}%` }} title={`${p.day}: ${p.count}`} />
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>

                    {data.scenarios.length > 0 && (
                        <div>
                            <h3 className="text-sm font-semibold text-gray-500 dark:text-gray-400 mb-1">{t('pages.network.scenarios')}</h3>
                            <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 divide-y divide-gray-100 dark:divide-gray-700/50">
                                {data.scenarios.map((s) => (
                                    <div key={s.scenario} className="grid grid-cols-[1fr_auto] gap-2 px-4 py-2 text-sm">
                                        <span className="font-mono truncate text-gray-700 dark:text-gray-300" title={s.scenario}>{s.scenario}</span>
                                        <span className="text-gray-400">{t('pages.network.alertsCount', { count: s.count })}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    <div>
                        <div className="flex items-center justify-between mb-1">
                            <h3 className="text-sm font-semibold text-gray-500 dark:text-gray-400">{t('pages.network.ipsTitle', { count: data.ips.length })}</h3>
                            <button type="button" onClick={handleExport} disabled={data.ips.length === 0} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium border border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50 disabled:opacity-40">
                                <Download size={16} />{t('common.exportCsv')}
                            </button>
                        </div>
                        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-x-auto">
                            <table className="w-full text-left text-sm">
                                <thead className="bg-gray-50 dark:bg-gray-900/50 text-xs uppercase tracking-wider text-gray-500 dark:text-gray-400">
                                    <tr>
                                        <th className="px-4 py-3 font-semibold">{t('pages.network.colIp')}</th>
                                        <th className="px-4 py-3 font-semibold text-right">{t('pages.network.alerts')}</th>
                                        <th className="px-4 py-3 font-semibold">{t('pages.network.colCountry')}</th>
                                        {kind === 'subnet' && <th className="px-4 py-3 font-semibold">{t('pages.network.colAsn')}</th>}
                                        <th className="px-4 py-3 font-semibold">{t('pages.network.lastSeen')}</th>
                                        <th className="px-4 py-3 font-semibold">{t('pages.network.colStatus')}</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-100 dark:divide-gray-700/50">
                                    {data.ips.map((ip) => (
                                        <tr key={ip.ip} className="hover:bg-gray-50 dark:hover:bg-gray-700/30">
                                            <td className="px-4 py-2 font-mono">
                                                <Link to={`/ip/${encodeURIComponent(ip.ip)}`} className="text-primary-600 dark:text-primary-400 hover:underline">{ip.ip}</Link>
                                            </td>
                                            <td className="px-4 py-2 text-right text-gray-700 dark:text-gray-300">{ip.alertCount}</td>
                                            <td className="px-4 py-2 text-gray-600 dark:text-gray-300">
                                                {ip.cn ? <span className="inline-flex items-center gap-1.5"><span className={`fi fi-${ip.cn.toLowerCase()}`} />{getCountryName(ip.cn) ?? ip.cn}</span> : '—'}
                                            </td>
                                            {kind === 'subnet' && <td className="px-4 py-2 text-gray-600 dark:text-gray-300">{ip.asn ? `AS${ip.asn}` : '—'}</td>}
                                            <td className="px-4 py-2 whitespace-nowrap text-gray-500 dark:text-gray-400">{formatWhen(ip.lastSeen)}</td>
                                            <td className="px-4 py-2">
                                                {ip.active ? <Badge variant="danger" className="inline-flex items-center gap-1"><Ban size={10} />{t('pages.network.banned')}</Badge> : <span className="text-gray-400 text-xs">—</span>}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </>
            ) : null}

            <Modal isOpen={banOpen} onClose={() => !banSubmitting && setBanOpen(false)} title={t('pages.network.banTitle')} maxWidth="max-w-md">
                <div className="p-6 space-y-4">
                    <p className="text-sm text-gray-700 dark:text-gray-300">
                        {kind === 'subnet'
                            ? t('pages.network.banSubnetConfirm', { cidr: data?.key ?? key })
                            : t('pages.network.banAsnConfirm', { count: data?.ips.length ?? 0, asn: key })}
                    </p>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('pages.decisions.duration')}</label>
                        <input
                            type="text"
                            value={banDuration}
                            onChange={(e) => setBanDuration(e.target.value)}
                            placeholder="4h"
                            className="block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 sm:text-sm"
                        />
                    </div>
                    <div className="flex justify-end gap-3">
                        <button type="button" onClick={() => setBanOpen(false)} disabled={banSubmitting} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50">
                            {t('common.cancel')}
                        </button>
                        <button type="button" onClick={confirmBan} disabled={banSubmitting} className="inline-flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-md hover:bg-red-700 disabled:opacity-50">
                            <ShieldBan size={15} />{banSubmitting ? t('pages.network.banning') : t('pages.network.banConfirm')}
                        </button>
                    </div>
                </div>
            </Modal>
        </div>
    );
}

export default NetworkOverview;
