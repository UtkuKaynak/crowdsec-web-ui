import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Flame, Repeat, ShieldAlert } from 'lucide-react';
import { fetchInsightsSummary } from '../lib/api';
import { useRefresh } from '../contexts/useRefresh';
import { useI18n } from '../lib/i18n';
import type { InsightsSummary } from '../types';

/**
 * Compact "at a glance" strip for the dashboard, linking to the analytics pages.
 * Self-contained: fetches its own summary and stays hidden until it loads.
 */
export function InsightsStrip() {
    const { t } = useI18n();
    const { refreshSignal } = useRefresh();
    const [summary, setSummary] = useState<InsightsSummary | null>(null);

    const load = useCallback(async () => {
        try {
            setSummary(await fetchInsightsSummary());
        } catch {
            // best-effort; the strip simply stays hidden on failure
        }
    }, []);

    useEffect(() => {
        const id = window.setTimeout(() => { void load(); }, 0);
        return () => window.clearTimeout(id);
    }, [load, refreshSignal]);

    if (!summary) {
        return null;
    }

    const cards = [
        {
            to: '/incidents',
            icon: Flame,
            label: t('components.insightsStrip.incidents'),
            value: summary.incidents24h,
            tone: summary.incidents24h > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-gray-400',
        },
        {
            to: '/self-protection',
            icon: ShieldAlert,
            label: t('components.insightsStrip.conflicts'),
            value: summary.allowlistConflicts,
            tone: summary.allowlistConflicts > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-400',
        },
        {
            to: '/insights',
            icon: Repeat,
            label: t('components.insightsStrip.repeatOffenders'),
            value: summary.repeatOffenders,
            tone: summary.repeatOffenders > 0 ? 'text-primary-600 dark:text-primary-400' : 'text-gray-400',
        },
    ];

    return (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {cards.map((c) => (
                <Link key={c.to} to={c.to} className="block transition-transform hover:scale-[1.02]">
                    <div className="flex items-center gap-3 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-4 py-3 hover:shadow-md transition-shadow">
                        <c.icon className={`h-5 w-5 ${c.tone}`} />
                        <div className="min-w-0">
                            <div className={`text-xl font-bold ${c.tone}`}>{c.value}</div>
                            <div className="text-xs text-gray-500 dark:text-gray-400 truncate">{c.label}</div>
                        </div>
                    </div>
                </Link>
            ))}
        </div>
    );
}
