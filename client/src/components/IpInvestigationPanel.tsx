import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertCircle, ArrowUpRight, Ban, CheckCircle2, Network, ShieldAlert } from 'lucide-react';
import { fetchIpInvestigation } from '../lib/api';
import { getCountryName } from '../lib/utils';
import { Badge } from './ui/Badge';
import { useI18n } from '../lib/i18n';
import type { IpInvestigationResponse, IpRelatedItem } from '../types';

interface IpInvestigationPanelProps {
    ip: string;
}

const QUICK_LINKS: Array<{ label: string; href: (ip: string) => string }> = [
    { label: 'CrowdSec CTI', href: (ip) => `https://app.crowdsec.net/cti/${encodeURIComponent(ip)}` },
    { label: 'AbuseIPDB', href: (ip) => `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}` },
    { label: 'Shodan', href: (ip) => `https://www.shodan.io/host/${encodeURIComponent(ip)}` },
    { label: 'VirusTotal', href: (ip) => `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}` },
    { label: 'GreyNoise', href: (ip) => `https://viz.greynoise.io/ip/${encodeURIComponent(ip)}` },
];

function formatWhen(value: string | null | undefined): string {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
}

function formatRemaining(stopAt: string): string {
    const ms = new Date(stopAt).getTime() - Date.now();
    if (Number.isNaN(ms) || ms <= 0) return '';
    const mins = Math.floor(ms / 60000);
    const days = Math.floor(mins / 1440);
    const hours = Math.floor((mins % 1440) / 60);
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${mins % 60}m`;
    return `${mins}m`;
}

export function IpInvestigationPanel({ ip }: IpInvestigationPanelProps) {
    const { t } = useI18n();
    const [data, setData] = useState<IpInvestigationResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const load = useCallback(async (targetIp: string) => {
        setLoading(true);
        setError(null);
        try {
            setData(await fetchIpInvestigation(targetIp));
        } catch (err) {
            setError(err instanceof Error ? err.message : t('components.ipInvestigation.loadError'));
            setData(null);
        } finally {
            setLoading(false);
        }
    }, [t]);

    useEffect(() => {
        const timeoutId = window.setTimeout(() => { void load(ip); }, 0);
        return () => window.clearTimeout(timeoutId);
    }, [load, ip]);

    const renderRelated = (items: IpRelatedItem[]) => (
        <div className="bg-white dark:bg-gray-950 rounded border border-gray-200 dark:border-gray-800 divide-y divide-gray-100 dark:divide-gray-800">
            {items.map((item) => (
                <Link
                    key={item.ip}
                    to={`/ip/${encodeURIComponent(item.ip)}`}
                    className="grid grid-cols-[1fr_auto] items-center gap-2 px-3 py-1.5 text-xs hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
                    title={t('components.ipInvestigation.drillIn')}
                >
                    <span className="font-mono truncate text-primary-600 dark:text-primary-400">{item.ip}</span>
                    <span className="flex items-center gap-2 flex-shrink-0">
                        <span className="text-gray-400">{t('components.ipInvestigation.alertsCount', { count: item.alertCount })}</span>
                        {item.active && (
                            <Badge variant="danger" className="flex items-center gap-1"><Ban size={10} />{t('common.active')}</Badge>
                        )}
                    </span>
                </Link>
            ))}
        </div>
    );

    const maxActivity = data ? Math.max(1, ...data.activity.map((a) => a.count)) : 1;

    return (
        <div className="p-4 bg-gray-50 dark:bg-gray-900/50 rounded-lg border border-gray-100 dark:border-gray-700/50">
            <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider flex items-center gap-2 mb-3">
                <Network size={14} />
                {t('components.ipInvestigation.title')}
            </h4>

            {loading ? (
                <div className="text-sm text-gray-500 dark:text-gray-400 py-2">{t('common.loading')}</div>
            ) : error ? (
                <div className="text-sm text-red-600 dark:text-red-400 flex items-center gap-2 py-2"><AlertCircle size={14} />{error}</div>
            ) : data ? (
                <div className="space-y-3">
                    {/* Identity */}
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
                        <span className="font-mono font-bold text-gray-900 dark:text-white">{data.ip}</span>
                        {data.cn && (
                            <span className="inline-flex items-center gap-1.5 text-gray-600 dark:text-gray-300">
                                <span className={`fi fi-${data.cn.toLowerCase()}`} />{getCountryName(data.cn)}
                            </span>
                        )}
                        {data.asNumber && (
                            <Link to={`/asn/${encodeURIComponent(data.asNumber)}`} className="text-primary-600 dark:text-primary-400 hover:underline">
                                AS{data.asNumber}
                            </Link>
                        )}
                        {data.cidr24 && (
                            <Link to={`/subnet/${encodeURIComponent(data.cidr24.replace(/\//g, '_'))}`} className="font-mono text-primary-600 dark:text-primary-400 hover:underline">
                                {data.cidr24}
                            </Link>
                        )}
                        {data.rdns && (
                            <span className="inline-flex items-center gap-1 text-gray-500 dark:text-gray-400 truncate">
                                {data.rdns}
                                {data.rdnsConfirmed === true && (
                                    <span title={t('components.ipInvestigation.rdnsConfirmed')}><CheckCircle2 size={12} className="text-green-500" /></span>
                                )}
                                {data.rdnsConfirmed === false && (
                                    <span title={t('components.ipInvestigation.rdnsUnconfirmed')}><AlertCircle size={12} className="text-amber-500" /></span>
                                )}
                            </span>
                        )}
                    </div>

                    {/* Whois */}
                    {data.whois && (data.whois.name || data.whois.abuseEmail) && (
                        <div className="text-xs text-gray-600 dark:text-gray-300 flex flex-wrap gap-x-4 gap-y-0.5">
                            {data.whois.name && <span><span className="text-gray-400">{t('components.ipInvestigation.network')}:</span> {data.whois.name}</span>}
                            {data.whois.abuseEmail && (
                                <span>
                                    <span className="text-gray-400">{t('components.ipInvestigation.abuse')}:</span>{' '}
                                    <a href={`mailto:${data.whois.abuseEmail}`} className="text-primary-600 dark:text-primary-400 hover:underline">{data.whois.abuseEmail}</a>
                                </span>
                            )}
                        </div>
                    )}

                    {/* Stats */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 text-xs">
                        {[
                            { label: t('components.ipInvestigation.firstSeen'), value: formatWhen(data.firstSeen) },
                            { label: t('components.ipInvestigation.lastSeen'), value: formatWhen(data.lastSeen) },
                            { label: t('components.ipInvestigation.alerts'), value: String(data.alertCount) },
                            { label: t('components.ipInvestigation.timesBanned'), value: String(data.timesBanned) },
                            { label: t('components.ipInvestigation.activeDecisions'), value: String(data.activeDecisions) },
                        ].map((stat) => (
                            <div key={stat.label} className="bg-white dark:bg-gray-950 rounded border border-gray-200 dark:border-gray-800 px-3 py-1.5">
                                <div className="text-gray-400 dark:text-gray-500">{stat.label}</div>
                                <div className="font-medium text-gray-800 dark:text-gray-200">{stat.value}</div>
                            </div>
                        ))}
                    </div>

                    {/* Aggregates */}
                    {(data.subnetAggregate || data.asnAggregate) && (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                            {data.subnetAggregate && (
                                <div className="bg-white dark:bg-gray-950 rounded border border-gray-200 dark:border-gray-800 px-3 py-1.5">
                                    <span className="font-mono text-gray-400">{data.subnetAggregate.key}</span>{' — '}
                                    {t('components.ipInvestigation.aggregate', { ips: data.subnetAggregate.ipCount, alerts: data.subnetAggregate.alertCount })}
                                </div>
                            )}
                            {data.asnAggregate && (
                                <div className="bg-white dark:bg-gray-950 rounded border border-gray-200 dark:border-gray-800 px-3 py-1.5">
                                    <span className="font-mono text-gray-400">{data.asnAggregate.key}</span>{' — '}
                                    {t('components.ipInvestigation.aggregate', { ips: data.asnAggregate.ipCount, alerts: data.asnAggregate.alertCount })}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Activity */}
                    {data.activity.length > 0 && (
                        <div>
                            <div className="text-xs font-semibold text-gray-500 dark:text-gray-400 mb-1">{t('components.ipInvestigation.activity')}</div>
                            <div className="flex items-end gap-0.5 h-12 bg-white dark:bg-gray-950 rounded border border-gray-200 dark:border-gray-800 px-2 py-1">
                                {data.activity.slice(-60).map((point) => (
                                    <div
                                        key={point.day}
                                        className="flex-1 min-w-[2px] bg-primary-400 dark:bg-primary-500 rounded-sm"
                                        style={{ height: `${Math.max(8, (point.count / maxActivity) * 100)}%` }}
                                        title={`${point.day}: ${point.count}`}
                                    />
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Detail sections tile two-up on wide screens */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 items-start">
                    {/* Scenarios */}
                    {data.scenarios.length > 0 && (
                        <div>
                            <div className="text-xs font-semibold text-gray-500 dark:text-gray-400 mb-1">{t('components.ipInvestigation.scenarios')}</div>
                            <div className="bg-white dark:bg-gray-950 rounded border border-gray-200 dark:border-gray-800 divide-y divide-gray-100 dark:divide-gray-800">
                                {data.scenarios.map((s) => (
                                    <div key={s.scenario} className="grid grid-cols-[1fr_auto] gap-2 px-3 py-1.5 text-xs">
                                        <span className="font-mono truncate text-gray-700 dark:text-gray-300" title={s.scenario}>{s.scenario}</span>
                                        <span className="text-gray-400 flex-shrink-0">{t('components.ipInvestigation.alertsCount', { count: s.count })}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Decisions */}
                    {data.decisions.length > 0 && (
                        <div>
                            <div className="text-xs font-semibold text-gray-500 dark:text-gray-400 mb-1">{t('components.ipInvestigation.decisions')}</div>
                            <div className="bg-white dark:bg-gray-950 rounded border border-gray-200 dark:border-gray-800 divide-y divide-gray-100 dark:divide-gray-800">
                                {data.decisions.slice(0, 50).map((d) => (
                                    <div key={d.id} className="flex flex-wrap items-center gap-x-3 gap-y-0.5 px-3 py-1.5 text-xs">
                                        <Badge variant={d.expired ? 'secondary' : (d.type === 'ban' ? 'danger' : 'warning')}>{d.type}</Badge>
                                        <span className="font-mono truncate text-gray-700 dark:text-gray-300 max-w-[200px]" title={d.scenario ?? ''}>{d.scenario || d.origin}</span>
                                        {d.duration && <span className="text-gray-400">{d.duration}</span>}
                                        <span className="text-gray-400 ml-auto">
                                            {d.expired ? t('components.ipInvestigation.expired') : t('components.ipInvestigation.expiresIn', { time: formatRemaining(d.stop_at) })}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Related */}
                    {data.relatedSameSubnet.length > 0 && (
                        <div>
                            <div className="text-xs font-semibold text-gray-500 dark:text-gray-400 mb-1 flex items-center gap-1.5">
                                <ShieldAlert size={12} />{t('components.ipInvestigation.relatedSubnet', { cidr: data.cidr24 ?? '' })}
                            </div>
                            {renderRelated(data.relatedSameSubnet)}
                        </div>
                    )}
                    {data.relatedSameAsn.length > 0 && (
                        <div>
                            <div className="text-xs font-semibold text-gray-500 dark:text-gray-400 mb-1 flex items-center gap-1.5">
                                <ShieldAlert size={12} />{t('components.ipInvestigation.relatedAsn', { asn: data.asNumber ?? '' })}
                            </div>
                            {renderRelated(data.relatedSameAsn)}
                        </div>
                    )}

                    {/* Blocklists */}
                    {data.blocklists.length > 0 && (
                        <div>
                            <div className="text-xs font-semibold text-gray-500 dark:text-gray-400 mb-1">{t('components.ipInvestigation.blocklists')}</div>
                            <div className="flex flex-wrap gap-1.5">
                                {data.blocklists.map((b, i) => (
                                    <Badge key={`${b.origin}-${i}`} variant="warning" title={b.scenario ?? ''}>{b.origin}</Badge>
                                ))}
                            </div>
                        </div>
                    )}
                    </div>

                    {data.alertCount === 0 && data.timesBanned === 0 && (
                        <div className="text-xs text-gray-400 dark:text-gray-500">{t('components.ipInvestigation.noData')}</div>
                    )}

                    {/* External quick-links */}
                    <div className="flex flex-wrap gap-x-3 gap-y-1 pt-1 text-xs">
                        {QUICK_LINKS.map((link) => (
                            <a key={link.label} href={link.href(data.ip)} target="_blank" rel="noopener noreferrer"
                                className="inline-flex items-center gap-0.5 text-gray-500 dark:text-gray-400 hover:text-primary-600 dark:hover:text-primary-400 transition-colors">
                                {link.label}<ArrowUpRight size={11} />
                            </a>
                        ))}
                    </div>
                </div>
            ) : null}
        </div>
    );
}
