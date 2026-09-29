// Chart colours (validated dark-surface palette; see README "Dashboard design").
// Categorical slots are assigned in FIXED order — a series keeps its colour.
export const SERIES = [
  "#3987e5", // 1 blue
  "#d95926", // 2 orange
  "#199e70", // 3 aqua
  "#c98500", // 4 yellow
  "#d55181", // 5 magenta
  "#008300", // 6 green
  "#9085e9", // 7 violet
  "#e66767", // 8 red
];

// Severity = status meaning: reserved colours, ALWAYS shown with a text label.
export const SEVERITY_COLORS = {
  INFO: "#8a8983",
  LOW: "#5598e7",
  MEDIUM: "#fab219",
  HIGH: "#ec835a",
  CRITICAL: "#d03b3b",
};

export const CLASS_COLORS = {
  NORMAL: "#0ca30c",
  SUSPICIOUS: "#fab219",
  POTENTIAL_INTRUSION: "#d03b3b",
};

export const CHART = {
  grid: "#2e2e2b",
  axis: "#8a8983",
  text: "#c3c2b7",
  surface: "#1a1a19",
};

export const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const STATUSES = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"];
export const RANGES = [
  ["15m", "Last 15 min"],
  ["1h", "Last hour"],
  ["6h", "Last 6 hours"],
  ["24h", "Last 24 hours"],
  ["7d", "Last 7 days"],
  ["all", "All time"],
];
