export interface CsvColumn<T> {
    key: keyof T | string;
    label: string;
    /** Optional custom cell renderer; defaults to String(row[key]). */
    value?: (row: T) => string | number | null | undefined;
}

function escapeCsvCell(value: unknown): string {
    if (value == null) return '';
    const str = String(value);
    // Quote if the cell contains a comma, quote, or newline.
    if (/[",\n\r]/.test(str)) {
        return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
}

/**
 * Builds a CSV string from rows + column definitions and triggers a browser
 * download. Pure client-side; no dependency.
 */
export function exportCsv<T>(filename: string, rows: T[], columns: CsvColumn<T>[]): void {
    const header = columns.map((c) => escapeCsvCell(c.label)).join(',');
    const body = rows
        .map((row) =>
            columns
                .map((c) => escapeCsvCell(c.value ? c.value(row) : (row as Record<string, unknown>)[c.key as string]))
                .join(','),
        )
        .join('\n');
    const csv = `${header}\n${body}\n`;

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename.endsWith('.csv') ? filename : `${filename}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}
