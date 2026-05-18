/**
 * 将 API 时间值格式化为本地时钟精度：YYYY-MM-DD HH:mm:ss（24 小时制）
 */
export function formatDateTime(
  value: string | Date | null | undefined,
  fallback = '-',
): string {
  if (value == null || value === '') {
    return fallback;
  }

  const date = value instanceof Date ? value : parseApiDateTime(String(value));
  if (Number.isNaN(date.getTime())) {
    return fallback;
  }

  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  );
}

function parseApiDateTime(raw: string): Date {
  const value = raw.trim();
  if (!value) {
    return new Date(Number.NaN);
  }

  // ISO 8601 without timezone (e.g. 2025-05-18T10:30:45.123) — must run before display regex
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(value) && !/(?:Z|[+-]\d{2}:?\d{2})$/i.test(value)) {
    const [datePart, timePart] = value.split('T');
    const [y, mo, d] = datePart.split('-').map(Number);
    const timeBits = timePart.split(':');
    const h = Number(timeBits[0]);
    const mi = Number(timeBits[1]);
    const sec = Number.parseFloat(timeBits[2] ?? '0');
    return new Date(y, mo - 1, d, h, mi, Math.floor(sec), Math.round((sec % 1) * 1000));
  }

  // Backend display format: YYYY-MM-DD HH:mm:ss (space-separated, no fractional seconds)
  const displayMatch = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/.exec(value);
  if (displayMatch) {
    const y = Number(displayMatch[1]);
    const mo = Number(displayMatch[2]);
    const d = Number(displayMatch[3]);
    const h = Number(displayMatch[4]);
    const mi = Number(displayMatch[5]);
    const s = Number(displayMatch[6]);
    return new Date(y, mo - 1, d, h, mi, s);
  }

  return new Date(value);
}
