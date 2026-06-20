import type { AlertMetaValue } from '../types';

// Acronyms that should stay uppercase when a raw meta key is humanized.
const META_ACRONYMS: Record<string, string> = {
    ip: 'IP', ua: 'UA', asn: 'ASN', url: 'URL', uri: 'URI',
    http: 'HTTP', id: 'ID', fqdn: 'FQDN', os: 'OS', dst: 'Dst', src: 'Src',
};

/** Turns a raw CrowdSec meta key (e.g. "source_ip") into a readable label ("Source IP"). */
export function humanizeMetaKey(key: string): string {
    const parts = key.split('_').filter(Boolean);
    if (parts.length === 0) {
        return key;
    }
    return parts
        .map((part, index) => {
            const acronym = META_ACRONYMS[part];
            if (acronym) return acronym;
            const lower = part.toLowerCase();
            return index === 0
                ? lower.charAt(0).toUpperCase() + lower.slice(1)
                : lower;
        })
        .join(' ');
}

/** Renders a meta value as a display string, or undefined when empty. */
export function formatMetaValue(value: AlertMetaValue | undefined): string | undefined {
    if (value == null || value === '') {
        return undefined;
    }

    if (typeof value === 'object') {
        return JSON.stringify(value);
    }

    return String(value);
}

/**
 * Normalises a free-form meta value (string, object, or array) into key/value
 * rows for grid display. Falls back to a single row when it isn't an object.
 */
export function metaValueToPairs(value: AlertMetaValue | undefined): Array<{ key: string; value: string }> {
    if (value == null || value === '') {
        return [];
    }

    if (Array.isArray(value)) {
        return value.flatMap((entry, index) => {
            if (entry && typeof entry === 'object' && 'key' in entry && 'value' in entry) {
                const pair = entry as { key: unknown; value: unknown };
                return [{ key: String(pair.key), value: String(pair.value) }];
            }
            const formatted = formatMetaValue(entry as AlertMetaValue);
            return formatted ? [{ key: String(index), value: formatted }] : [];
        });
    }

    if (typeof value === 'object') {
        return Object.entries(value as Record<string, unknown>).flatMap(([key, entry]) => {
            const formatted = formatMetaValue(entry as AlertMetaValue);
            return formatted ? [{ key, value: formatted }] : [];
        });
    }

    return [{ key: '', value: String(value) }];
}
