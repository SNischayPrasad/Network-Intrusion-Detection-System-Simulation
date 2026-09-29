// Reusable chart building blocks (Recharts) with consistent SOC styling:
// thin marks, 2px lines, rounded bar ends, recessive grid, hover tooltips,
// and a legend whenever there are 2+ series.
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { CHART } from "../theme";
import { fmtAxisTime, fmtCompact, fmtTime } from "../services/format";

const axisProps = {
  stroke: CHART.axis,
  tick: { fill: CHART.axis, fontSize: 11 },
  tickLine: false,
  axisLine: { stroke: CHART.grid },
};

function TooltipBox({ active, payload, label, labelFormatter, valueFormatter }) {
  if (!active || !payload || !payload.length) return null;
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-label">{labelFormatter ? labelFormatter(label) : label}</div>
      {payload.map((p) => (
        <div key={p.dataKey} className="chart-tooltip-row">
          <span className="swatch" style={{ background: p.color || p.payload?.fill }} />
          <span>{p.name}</span>
          <strong>{valueFormatter ? valueFormatter(p.value) : fmtCompact(p.value)}</strong>
        </div>
      ))}
    </div>
  );
}

/** Time-series chart. type: "line" | "area" | "bar" (stacked when `stacked`). */
export function TimeSeriesChart({ data, series, type = "line", stacked = false, bucketSeconds = 60,
  height = 240, valueFormatter, yFormatter = fmtCompact }) {
  if (!data || data.length === 0) return <Empty height={height} />;
  const Chart = type === "area" ? AreaChart : type === "bar" ? BarChart : LineChart;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <Chart data={data} margin={{ top: 8, right: 12, left: 0, bottom: 0 }} barCategoryGap={1}>
        <CartesianGrid stroke={CHART.grid} vertical={false} />
        <XAxis dataKey="time" {...axisProps} minTickGap={40}
          tickFormatter={(t) => fmtAxisTime(t, bucketSeconds)} />
        <YAxis {...axisProps} width={48} tickFormatter={yFormatter} allowDecimals={false} />
        <Tooltip cursor={{ stroke: CHART.axis, strokeDasharray: "3 3", fill: "rgba(255,255,255,0.04)" }}
          content={<TooltipBox labelFormatter={(t) => fmtTime(t, true)} valueFormatter={valueFormatter} />} />
        {series.length > 1 && <Legend iconType="circle" iconSize={8}
          wrapperStyle={{ fontSize: 12, color: CHART.text, paddingTop: 4 }} />}
        {series.map((s) => {
          if (type === "area") {
            return <Area key={s.key} dataKey={s.key} name={s.name} stackId={stacked ? "a" : undefined}
              type="monotone" stroke={s.color} strokeWidth={2} fill={s.color} fillOpacity={0.35}
              isAnimationActive={false} />;
          }
          if (type === "bar") {
            return <Bar key={s.key} dataKey={s.key} name={s.name} stackId={stacked ? "a" : undefined}
              fill={s.color} isAnimationActive={false} />;
          }
          return <Line key={s.key} dataKey={s.key} name={s.name} type="monotone" stroke={s.color}
            strokeWidth={2} dot={false} activeDot={{ r: 4, strokeWidth: 2, stroke: CHART.surface }}
            strokeDasharray={s.dashed ? "5 4" : undefined} isAnimationActive={false} />;
        })}
      </Chart>
    </ResponsiveContainer>
  );
}

/** Horizontal bar chart for ranked categories. colorFor(row) optional. */
export function HBarChart({ data, labelKey, valueKey, color, colorFor, height, valueName = "Count",
  labelWidth = 120, onBarClick }) {
  if (!data || data.length === 0) return <Empty height={height || 200} />;
  const h = height || Math.max(120, data.length * 30 + 20);
  return (
    <ResponsiveContainer width="100%" height={h}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 36, left: 4, bottom: 4 }}
        barCategoryGap={6}>
        <CartesianGrid stroke={CHART.grid} horizontal={false} />
        <XAxis type="number" {...axisProps} tickFormatter={fmtCompact} allowDecimals={false} />
        <YAxis type="category" dataKey={labelKey} {...axisProps} width={labelWidth}
          tick={{ fill: CHART.text, fontSize: 12 }} />
        <Tooltip cursor={{ fill: "rgba(255,255,255,0.05)" }} content={<TooltipBox />} />
        <Bar dataKey={valueKey} name={valueName} fill={color} radius={[0, 4, 4, 0]} maxBarSize={18}
          isAnimationActive={false} label={{ position: "right", fill: CHART.text, fontSize: 11,
            formatter: fmtCompact }}
          onClick={onBarClick ? (d) => onBarClick(d) : undefined}
          style={onBarClick ? { cursor: "pointer" } : undefined}>
          {colorFor && data.map((row) => <Cell key={row[labelKey]} fill={colorFor(row)} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Vertical column chart (e.g. histogram / severity counts). */
export function ColumnChart({ data, labelKey, valueKey, color, colorFor, height = 220, valueName = "Count" }) {
  if (!data || data.every((d) => !d[valueKey])) return <Empty height={height} />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 18, right: 8, left: 0, bottom: 0 }} barCategoryGap={4}>
        <CartesianGrid stroke={CHART.grid} vertical={false} />
        <XAxis dataKey={labelKey} {...axisProps} interval={0} tick={{ fill: CHART.text, fontSize: 11 }} />
        <YAxis {...axisProps} width={44} tickFormatter={fmtCompact} allowDecimals={false} />
        <Tooltip cursor={{ fill: "rgba(255,255,255,0.05)" }} content={<TooltipBox />} />
        <Bar dataKey={valueKey} name={valueName} fill={color} radius={[4, 4, 0, 0]} maxBarSize={48}
          isAnimationActive={false} label={{ position: "top", fill: CHART.text, fontSize: 11,
            formatter: (v) => (v ? fmtCompact(v) : "") }}>
          {colorFor && data.map((row) => <Cell key={row[labelKey]} fill={colorFor(row)} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function Empty({ height = 200, text = "No data in this time range" }) {
  return <div className="chart-empty" style={{ height }}>{text}</div>;
}
