import { useCallback, useEffect, useState } from 'react';
import { AlertCircle, ChevronLeft, ChevronRight, ScrollText } from 'lucide-react';
import { fetchAuditLogPaginated } from '../lib/api';
import { useRefresh } from '../contexts/useRefresh';
import { Badge } from '../components/ui/Badge';
import { Card, CardContent } from '../components/ui/Card';
import { TimeDisplay } from '../components/TimeDisplay';
import { useI18n } from '../lib/i18n';
import type { AuditLogItem } from '../types';

const PAGE_SIZE = 50;

const ACTION_BADGE_VARIANT: Record<string, 'danger' | 'warning' | 'secondary'> = {
  'decision.add': 'warning',
  'decision.delete': 'danger',
  'decision.bulk_delete': 'danger',
  'alert.delete': 'danger',
  'alert.bulk_delete': 'danger',
  'cleanup.by_ip': 'danger',
};

function formatDetail(detail: Record<string, unknown>): string {
  const entries = Object.entries(detail).filter(([, value]) => value !== undefined && value !== null && value !== '');
  if (entries.length === 0) {
    return '';
  }
  return entries
    .map(([key, value]) => `${key}=${Array.isArray(value) ? `[${value.length}]` : String(value)}`)
    .join('  ');
}

export function AuditLog() {
  const { t } = useI18n();
  const { refreshSignal } = useRefresh();
  const [items, setItems] = useState<AuditLogItem[]>([]);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (targetPage: number) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetchAuditLogPaginated(targetPage, PAGE_SIZE);
      setItems(response.data);
      setTotalPages(Math.max(1, response.pagination.total_pages));
      setTotal(response.pagination.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('pages.auditLog.loadError'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      void load(page);
    }, 0);
    return () => window.clearTimeout(timeoutId);
  }, [load, page, refreshSignal]);

  return (
    <div className="space-y-6">
      <p className="text-sm text-gray-500 dark:text-gray-400">
        {t('pages.auditLog.description')}
      </p>

      {error && (
        <div role="alert" className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 flex items-center gap-2 text-red-700 dark:text-red-300">
          <AlertCircle size={16} className="flex-shrink-0" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      <Card>
        {loading ? (
          <CardContent className="text-center text-gray-500 dark:text-gray-400">
            {t('common.loading')}
          </CardContent>
        ) : items.length === 0 ? (
          <CardContent className="flex flex-col items-center gap-3 py-12 text-gray-500 dark:text-gray-400">
            <ScrollText size={32} className="opacity-60" />
            <span className="text-sm">{t('pages.auditLog.empty')}</span>
          </CardContent>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-gray-50 dark:bg-gray-900/50 text-xs uppercase tracking-wider text-gray-500 dark:text-gray-400">
                <tr>
                  <th className="px-6 py-3 font-semibold">{t('pages.auditLog.columns.time')}</th>
                  <th className="px-6 py-3 font-semibold">{t('pages.auditLog.columns.actor')}</th>
                  <th className="px-6 py-3 font-semibold">{t('pages.auditLog.columns.action')}</th>
                  <th className="px-6 py-3 font-semibold">{t('pages.auditLog.columns.target')}</th>
                  <th className="px-6 py-3 font-semibold">{t('pages.auditLog.columns.detail')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700/50">
                {items.map((item) => (
                  <tr key={item.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/30">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <TimeDisplay timestamp={item.created_at} />
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900 dark:text-gray-100 max-w-[200px] truncate" title={item.actor}>
                      {item.actor}
                    </td>
                    <td className="px-6 py-4">
                      <Badge variant={ACTION_BADGE_VARIANT[item.action] ?? 'secondary'}>
                        {t(`pages.auditLog.actions.${item.action}`, { defaultValue: item.action })}
                      </Badge>
                    </td>
                    <td className="px-6 py-4 text-sm font-mono text-gray-900 dark:text-gray-100 max-w-[220px] truncate" title={item.target ?? ''}>
                      {item.target || '-'}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400 font-mono max-w-[360px] truncate" title={formatDetail(item.detail)}>
                      {formatDetail(item.detail) || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-500 dark:text-gray-400">
            {t('pages.auditLog.pageStatus', { page, totalPages, total })}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setPage((current) => Math.max(1, current - 1))}
              disabled={page <= 1}
              className="flex items-center gap-1 px-3 py-1.5 rounded-md border border-gray-200 dark:border-gray-700 text-sm text-gray-600 dark:text-gray-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700/50"
            >
              <ChevronLeft size={16} />
              {t('common.previous')}
            </button>
            <button
              type="button"
              onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
              disabled={page >= totalPages}
              className="flex items-center gap-1 px-3 py-1.5 rounded-md border border-gray-200 dark:border-gray-700 text-sm text-gray-600 dark:text-gray-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700/50"
            >
              {t('common.next')}
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default AuditLog;
