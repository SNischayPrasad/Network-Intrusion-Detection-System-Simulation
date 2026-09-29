export function fmtTime(iso, withDate = false) {
  if (!iso) return "—";
  const d = new Date(iso);
  const opts = { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false };
  return withDate ? d.toLocaleString([], { month: "short", day: "2-digit", ...opts }) : d.toLocaleTimeString([], opts);
}

export function fmtAxisTime(iso, bucketSeconds = 60) {
  const d = new Date(iso);
  if (bucketSeconds >= 10800) return d.toLocaleDateString([], { month: "short", day: "2-digit" });
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

export function fmtNumber(n, digits = 0) {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  return Number(n).toLocaleString(undefined, { maximumFractionDigits: digits });
}

export function fmtCompact(n) {
  if (n === null || n === undefined) return "—";
  return Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function fmtBytes(n) {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function titleCase(s) {
  return String(s || "").replaceAll("_", " ").toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
}
