import { Badge } from "./ui/Badge";
import { Collapsible } from "./ui/Collapsible";
import { getHubUrl } from "../lib/utils";
import { ExternalLink, Shield, EyeOff } from "lucide-react";
import type { AlertEvent, AlertMetaValue } from '../types';
import { useI18n } from "../lib/i18n";
import { formatMetaValue, humanizeMetaKey, metaValueToPairs } from "../lib/meta";

interface EventCardProps {
    event: AlertEvent;
    index: number;
}

// Meta keys that get special styled rendering in the summary section
const STYLED_META_KEYS = new Set([
    'target_fqdn', 'target_host', 'target_uri', 'uri',
    'traefik_router_name', 'http_verb', 'http_path',
    'http_status', 'http_user_agent', 'service',
    'matched_zones', 'rule_name', 'appsec_action',
    'rule_ids', 'msg', 'message',
]);

// Potentially sensitive captured context — shown only behind an explicit,
// collapsed opt-in with a warning (may contain usernames, paths, payloads).
const SENSITIVE_META_KEYS = new Set(['context']);

// High-signal operational fields surfaced in a prominent "Context" grid for any
// scenario (SSH, port scans, etc.) instead of being buried in "Additional
// Metadata". Order here is the display order; only keys actually present render.
const CONTEXT_META_KEYS = [
    'log_type', 'program', 'method', 'auth_type', 'status',
    'username', 'user', 'target_user', 'source_ip', 'ip',
    'port', 'dst_port', 'src_port', 'machine',
    'datasource_type', 'datasource_path',
];

export function EventCard({ event, index }: EventCardProps) {
    const { t } = useI18n();
    const getMeta = (key: string): AlertMetaValue | undefined => event.meta?.find((meta) => meta.key === key)?.value;

    const isAppSecEvent = event.meta?.some((meta) =>
        meta.key === 'matched_zones' || meta.key === 'rule_name' || meta.key === 'appsec_action'
    );

    // Known fields
    const ruleName = formatMetaValue(getMeta('rule_name'));
    const matchedZones = formatMetaValue(getMeta('matched_zones'));
    const ruleIds = formatMetaValue(getMeta('rule_ids'));
    const message = formatMetaValue(getMeta('msg')) || formatMetaValue(getMeta('message'));
    const targetFqdn = formatMetaValue(getMeta('target_fqdn'));
    const targetHost = formatMetaValue(getMeta('target_host'));
    const targetUri = formatMetaValue(getMeta('target_uri')) || formatMetaValue(getMeta('uri'));
    const traefikRouter = formatMetaValue(getMeta('traefik_router_name'));
    const httpVerb = formatMetaValue(getMeta('http_verb'));
    const httpPath = formatMetaValue(getMeta('http_path'));
    const httpStatus = formatMetaValue(getMeta('http_status'));
    const httpUserAgent = formatMetaValue(getMeta('http_user_agent'));
    const service = formatMetaValue(getMeta('service'));

    const hasValue = (value: AlertMetaValue | undefined): boolean => value != null && value !== '';

    // Prominent "Context" grid: curated operational fields, in CONTEXT_META_KEYS order.
    const contextMeta = CONTEXT_META_KEYS
        .map((key) => ({ key, value: getMeta(key) }))
        .filter((entry) => hasValue(entry.value));

    // Everything else not already styled or surfaced above goes to the collapsible.
    const additionalMeta = event.meta?.filter((meta) =>
        !STYLED_META_KEYS.has(meta.key)
        && !SENSITIVE_META_KEYS.has(meta.key)
        && !CONTEXT_META_KEYS.includes(meta.key)
        && hasValue(meta.value)
    ) || [];

    // Potentially sensitive captured context, flattened to key/value rows.
    const sensitiveContext = (event.meta ?? [])
        .filter((meta) => SENSITIVE_META_KEYS.has(meta.key) && hasValue(meta.value))
        .flatMap((meta) => metaValueToPairs(meta.value));

    return (
        <div className={`flex gap-3 items-start p-3 rounded border text-sm ${isAppSecEvent
            ? 'bg-red-50 dark:bg-red-900/10 border-red-100 dark:border-red-900/30'
            : 'bg-gray-50 dark:bg-gray-900/30 border-gray-100 dark:border-gray-800'
        }`}>
            <span className="text-xs font-semibold text-gray-400 dark:text-gray-500 pt-0.5 shrink-0">#{index + 1}</span>
            <div className="flex-1 min-w-0">
                {/* AppSec Badge */}
                {isAppSecEvent && (
                    <div className="mb-2 flex items-center gap-2">
                        <Badge variant="danger" className="flex items-center gap-1">
                            <Shield size={12} />
                            AppSec / WAF
                        </Badge>
                    </div>
                )}

                <div className="space-y-2">
                {/* Timestamp and Service */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <div>
                        <span className="text-gray-500">{t('components.eventCard.timestamp')}:</span>{' '}
                        <span className="font-mono text-xs">{event.timestamp || '-'}</span>
                    </div>
                    {service && (
                        <div>
                            <span className="text-gray-500">{t('components.eventCard.service')}:</span> {service}
                        </div>
                    )}
                </div>

                {/* Target FQDN/Host */}
                {(targetFqdn || targetHost) && (
                    <div>
                        <span className="text-gray-500">{t('components.eventCard.target')}:</span>{' '}
                        <span className="font-mono text-xs">{targetFqdn || targetHost}</span>
                    </div>
                )}

                {/* Traefik Router */}
                {traefikRouter && (
                    <div>
                        <span className="text-gray-500">{t('components.eventCard.router')}:</span>{' '}
                        <span className="font-mono text-xs">{traefikRouter}</span>
                    </div>
                )}

                {/* AppSec Rule Info */}
                {isAppSecEvent && ruleName && (
                    <div>
                        <span className="text-gray-500">{t('components.eventCard.rule')}:</span>{' '}
                        {(() => {
                            const hubUrl = getHubUrl(ruleName);
                            return hubUrl ? (
                                <a
                                    href={hubUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="font-mono text-xs hover:text-primary-600 dark:hover:text-primary-400 transition-colors inline-flex items-center gap-1"
                                >
                                    {ruleName}
                                    <ExternalLink size={10} />
                                </a>
                            ) : (
                                <span className="font-mono text-xs">{ruleName}</span>
                            );
                        })()}
                    </div>
                )}

                {/* AppSec Details */}
                {isAppSecEvent && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {matchedZones && (
                            <div>
                                <span className="text-gray-500">{t('components.eventCard.matchedZone')}:</span>{' '}
                                <Badge variant="outline" className="ml-1">{matchedZones}</Badge>
                            </div>
                        )}
                        {ruleIds && (
                            <div>
                                <span className="text-gray-500">{t('components.eventCard.ruleId')}:</span>{' '}
                                <span className="font-mono text-xs">{ruleIds}</span>
                            </div>
                        )}
                    </div>
                )}

                {/* Message/Description */}
                {isAppSecEvent && message && (
                    <div className="text-xs text-gray-600 dark:text-gray-300 italic">
                        {message}
                    </div>
                )}

                {/* HTTP Request Details */}
                {(httpVerb || httpPath || targetUri) && (
                    <div className="font-mono text-xs break-all bg-white dark:bg-gray-950 p-2 rounded border border-gray-200 dark:border-gray-800">
                        <span className="text-blue-600 dark:text-blue-400 font-bold">{httpVerb || 'GET'}</span>{' '}
                        {httpPath || targetUri || '/'}
                        {(httpStatus || httpUserAgent) && (
                            <div className="text-gray-400 mt-1">
                                {httpStatus && `${t('components.eventCard.status')}: ${httpStatus}`}
                                {httpStatus && httpUserAgent && ' | '}
                                {httpUserAgent && `UA: ${httpUserAgent}`}
                            </div>
                        )}
                    </div>
                )}

                {/* Context — prominent labelled grid of operational fields */}
                {contextMeta.length > 0 && (
                    <div>
                        <div className="text-xs font-semibold text-gray-500 dark:text-gray-400 mb-1">
                            {t('components.eventCard.context')}
                        </div>
                        <div className="bg-white dark:bg-gray-950 rounded border border-gray-200 dark:border-gray-800 divide-y divide-gray-100 dark:divide-gray-800">
                            {contextMeta.map((meta) => (
                                <div key={meta.key} className="grid grid-cols-[minmax(110px,auto)_1fr] gap-3 px-3 py-1.5 text-xs">
                                    <span className="text-gray-500 dark:text-gray-400 font-medium">{humanizeMetaKey(meta.key)}</span>
                                    <span className="font-mono break-all text-gray-700 dark:text-gray-300">
                                        {formatMetaValue(meta.value)}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Additional Metadata — collapsible generic key-value display */}
                {additionalMeta.length > 0 && (
                    <Collapsible
                        trigger={
                            <span className="text-xs font-medium text-gray-500 dark:text-gray-400">
                                {t('components.eventCard.additionalMetadata', { count: additionalMeta.length })}
                            </span>
                        }
                        defaultOpen={false}
                    >
                        <div className="mt-1 bg-white dark:bg-gray-950 rounded border border-gray-200 dark:border-gray-800 divide-y divide-gray-100 dark:divide-gray-800">
                            {additionalMeta.map((meta, i) => (
                                <div key={i} className="grid grid-cols-[minmax(100px,auto)_1fr] gap-3 px-3 py-1.5 text-xs">
                                    <span className="text-gray-500 font-medium" title={meta.key}>{humanizeMetaKey(meta.key)}</span>
                                    <span className="font-mono break-all text-gray-700 dark:text-gray-300">
                                        {formatMetaValue(meta.value)}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </Collapsible>
                )}

                {/* Captured context — potentially sensitive, opt-in + collapsed */}
                {sensitiveContext.length > 0 && (
                    <Collapsible
                        trigger={
                            <span className="text-xs font-medium text-amber-600 dark:text-amber-400 inline-flex items-center gap-1.5">
                                <EyeOff size={12} />
                                {t('components.eventCard.capturedContext')}
                            </span>
                        }
                        defaultOpen={false}
                    >
                        <p className="mt-1 mb-1 text-[11px] text-amber-600/80 dark:text-amber-400/80">
                            {t('components.eventCard.capturedContextNote')}
                        </p>
                        <div className="bg-white dark:bg-gray-950 rounded border border-amber-200 dark:border-amber-900/40 divide-y divide-gray-100 dark:divide-gray-800">
                            {sensitiveContext.map((pair, i) => (
                                <div key={`${pair.key}-${i}`} className="grid grid-cols-[minmax(110px,auto)_1fr] gap-3 px-3 py-1.5 text-xs">
                                    <span className="text-gray-500 dark:text-gray-400 font-medium" title={pair.key}>{pair.key ? humanizeMetaKey(pair.key) : '-'}</span>
                                    <span className="font-mono break-all text-gray-700 dark:text-gray-300">{pair.value}</span>
                                </div>
                            ))}
                        </div>
                    </Collapsible>
                )}
            </div>
            </div>
        </div>
    );
}
