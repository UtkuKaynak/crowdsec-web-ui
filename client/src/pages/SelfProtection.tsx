import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertCircle, Ban, Check, Copy, Download, Search, ShieldCheck, TriangleAlert } from 'lucide-react';
import {
    checkAllowlist,
    deleteDecision,
    fetchAllowlists,
    fetchSelfProtection,
} from '../lib/api';
import { useRefresh } from '../contexts/useRefresh';
import { Badge } from '../components/ui/Badge';
import { exportCsv } from '../lib/csv';
import { useI18n } from '../lib/i18n';
import type { AllowlistCheckResponse, AllowlistsResponse, SelfProtectionResponse } from '../types';

function CopyButton({ text, label }: { text: string; label: string }) {
    const [copied, setCopied] = useState(false);
    const onCopy = async () => {
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
        } catch {
            // clipboard may be unavailable (insecure context); ignore
        }
    };
    return (
        <button type="button" onClick={onCopy} className="inline-flex items-center gap-1 text-xs text-primary-600 dark:text-primary-400 hover:underline">
            {copied ? <Check size={12} /> : <Copy size={12} />}{label}
        </button>
    );
}

export function SelfProtection() {
    const { t } = useI18n();
    const { refreshSignal } = useRefresh();
    const [data, setData] = useState<SelfProtectionResponse | null>(null);
    const [allowlists, setAllowlists] = useState<AllowlistsResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const [testIp, setTestIp] = useState('');
    const [testResult, setTestResult] = useState<AllowlistCheckResponse | null>(null);
    const [helperIp, setHelperIp] = useState('');
    const [helperName, setHelperName] = useState('crowdsec-web-ui');

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const [sp, al] = await Promise.all([fetchSelfProtection(), fetchAllowlists()]);
            setData(sp);
            setAllowlists(al);
            setHelperName(al.suggestedName || 'crowdsec-web-ui');
        } catch (err) {
            setError(err instanceof Error ? err.message : t('pages.selfProtection.loadError'));
        } finally {
            setLoading(false);
        }
    }, [t]);

    useEffect(() => {
        const id = window.setTimeout(() => { void load(); }, 0);
        return () => window.clearTimeout(id);
    }, [load, refreshSignal]);

    const conflicts = data?.conflicts ?? [];

    const unban = async (decisionId: string) => {
        try {
            await deleteDecision(decisionId);
            await load();
        } catch (err) {
            setError(err instanceof Error ? err.message : t('pages.selfProtection.unbanError'));
        }
    };

    const runTest = async () => {
        const ip = testIp.trim();
        if (!ip) return;
        try {
            setTestResult(await checkAllowlist(ip));
        } catch {
            setTestResult({ ip, allowlisted: false, detail: null });
        }
    };

    const cscliCmd = (name: string, value: string) => `cscli allowlists add ${name || 'crowdsec-web-ui'} ${value}`;

    const exportConflicts = () => {
        exportCsv('allowlist-conflicts', conflicts, [
            { key: 'value', label: 'IP' },
            { key: 'matchedAllowlist', label: 'Allowlist' },
            { key: 'matchedValue', label: 'Allowlist entry' },
            { key: 'scenario', label: 'Scenario' },
            { key: 'origin', label: 'Origin' },
            { key: 'stop_at', label: 'Expires' },
        ]);
    };

    return (
        <div className="space-y-6">
            <p className="text-sm text-gray-500 dark:text-gray-400">{t('pages.selfProtection.description')}</p>

            {error && (
                <div role="alert" className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 flex items-center gap-2 text-red-700 dark:text-red-300">
                    <AlertCircle size={16} />{error}
                </div>
            )}

            {loading ? (
                <div className="text-center text-gray-500 dark:text-gray-400 py-12">{t('common.loading')}</div>
            ) : (
                <>
                    {/* Allowlist conflicts: active bans on allowlisted IPs */}
                    <section>
                        <div className="flex items-center justify-between gap-3 mb-3">
                            <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                                {conflicts.length > 0 ? <TriangleAlert size={18} className="text-amber-500" /> : <ShieldCheck size={18} className="text-green-500" />}
                                {t('pages.selfProtection.conflictsTitle')}
                            </h3>
                            {conflicts.length > 0 && (
                                <button type="button" onClick={exportConflicts} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium border border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                                    <Download size={16} />{t('common.exportCsv')}
                                </button>
                            )}
                        </div>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">{t('pages.selfProtection.conflictsHelp')}</p>
                        {data?.allowlistAvailable === false ? (
                            <div className="bg-gray-50 dark:bg-gray-900/40 border border-gray-200 dark:border-gray-700 rounded-lg p-4 text-sm text-gray-500 dark:text-gray-400">
                                {t('pages.selfProtection.allowlistUnavailable')}
                            </div>
                        ) : conflicts.length === 0 ? (
                            <div className="bg-green-50 dark:bg-green-900/10 border border-green-200 dark:border-green-900/30 rounded-lg p-4 text-sm text-green-700 dark:text-green-300">
                                {t('pages.selfProtection.conflictsNone')}
                            </div>
                        ) : (
                            <div className="space-y-2">
                                {conflicts.map((c) => (
                                    <div key={c.decisionId} className="bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-900/30 rounded-lg p-3 flex flex-wrap items-center gap-x-4 gap-y-2">
                                        <TriangleAlert size={16} className="text-amber-500 flex-shrink-0" />
                                        <Link to={`/ip/${encodeURIComponent(c.value)}`} className="font-mono text-sm text-primary-600 dark:text-primary-400 hover:underline">{c.value}</Link>
                                        <span className="text-sm text-gray-600 dark:text-gray-300">
                                            {t('pages.selfProtection.inAllowlist', { name: c.matchedAllowlist, value: c.matchedValue })}
                                        </span>
                                        {c.scenario && <span className="text-xs font-mono text-gray-400">{c.scenario}</span>}
                                        <button type="button" onClick={() => unban(c.decisionId)} className="ml-auto inline-flex items-center gap-1 text-xs text-red-600 dark:text-red-400 hover:underline">
                                            <Ban size={12} />{t('pages.selfProtection.unban')}
                                        </button>
                                    </div>
                                ))}
                            </div>
                        )}
                    </section>

                    {/* Allowlists viewer + tester */}
                    <section>
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">{t('pages.selfProtection.allowlistTitle')}</h3>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">{t('pages.selfProtection.allowlistHelp')}</p>

                        {allowlists?.available === false ? (
                            <div className="bg-gray-50 dark:bg-gray-900/40 border border-gray-200 dark:border-gray-700 rounded-lg p-4 text-sm text-gray-500 dark:text-gray-400">
                                {t('pages.selfProtection.allowlistUnavailable')}
                            </div>
                        ) : (
                            <div className="space-y-3">
                                {(allowlists?.allowlists.length ?? 0) === 0 ? (
                                    <div className="bg-gray-50 dark:bg-gray-900/40 border border-gray-200 dark:border-gray-700 rounded-lg p-4 text-sm text-gray-500 dark:text-gray-400">
                                        {t('pages.selfProtection.allowlistEmpty')}
                                    </div>
                                ) : (
                                    allowlists?.allowlists.map((al) => (
                                        <div key={al.name} className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-3">
                                            <div className="flex items-center gap-2 mb-1">
                                                <span className="font-medium text-gray-900 dark:text-gray-100">{al.name}</span>
                                                <Badge variant="secondary">{al.items.length}</Badge>
                                                {al.description && <span className="text-xs text-gray-400">{al.description}</span>}
                                            </div>
                                            <div className="flex flex-wrap gap-1.5">
                                                {al.items.map((it) => (
                                                    <span key={it.value} className="font-mono text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-700/50 text-gray-700 dark:text-gray-300" title={it.description ?? ''}>{it.value}</span>
                                                ))}
                                            </div>
                                        </div>
                                    ))
                                )}

                                <div className="flex flex-wrap items-center gap-2">
                                    <input value={testIp} onChange={(e) => setTestIp(e.target.value)} placeholder={t('pages.selfProtection.testPlaceholder')}
                                        className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 text-sm rounded-md px-2 py-1.5 font-mono w-48" />
                                    <button type="button" onClick={runTest} disabled={!testIp.trim()} className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md text-sm font-medium bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-40">
                                        <Search size={14} />{t('pages.selfProtection.test')}
                                    </button>
                                    {testResult && (
                                        <Badge variant={testResult.allowlisted ? 'success' : 'secondary'}>
                                            {testResult.allowlisted ? t('pages.selfProtection.allowlisted') : t('pages.selfProtection.notAllowlisted')}
                                        </Badge>
                                    )}
                                </div>
                            </div>
                        )}
                    </section>

                    {/* Add-to-allowlist helper (cscli) */}
                    <section>
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">{t('pages.selfProtection.addHelperTitle')}</h3>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">{t('pages.selfProtection.addHelperHelp')}</p>
                        <div className="flex flex-wrap items-center gap-2 mb-2">
                            <input value={helperName} onChange={(e) => setHelperName(e.target.value)} placeholder="crowdsec-web-ui"
                                className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 text-sm rounded-md px-2 py-1.5 w-44" />
                            <input value={helperIp} onChange={(e) => setHelperIp(e.target.value)} placeholder={t('pages.selfProtection.testPlaceholder')}
                                className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 text-sm rounded-md px-2 py-1.5 font-mono w-48" />
                        </div>
                        {helperIp.trim() && (
                            <div className="flex items-center gap-3 bg-gray-900 dark:bg-gray-950 text-gray-100 rounded-md px-3 py-2 font-mono text-xs">
                                <span className="flex-1 break-all">{cscliCmd(helperName, helperIp.trim())}</span>
                                <CopyButton text={cscliCmd(helperName, helperIp.trim())} label={t('common.copy')} />
                            </div>
                        )}
                    </section>
                </>
            )}
        </div>
    );
}

export default SelfProtection;
