import React, { useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  Area,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { EmailThreatReport } from '../types';
import {
  Activity,
  AlertTriangle,
  Calendar,
  Flame,
  ShieldAlert,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
} from 'lucide-react';

interface ThirtyDayThreatTrendChartProps {
  scans: EmailThreatReport[];
  className?: string;
}

interface DayThreatData {
  dateKey: string;
  displayDate: string;
  fullDate: string;
  dayOfWeek: string;
  threats: number;
  criticalThreats: number;
  phishing: number;
  malware: number;
  bec: number;
  suspicious: number;
  safe: number;
  totalVolume: number;
}

export const ThirtyDayThreatTrendChart: React.FC<ThirtyDayThreatTrendChartProps> = ({
  scans = [],
  className = '',
}) => {
  const [metricView, setMetricView] = useState<'all' | 'critical' | 'combined'>('all');

  // Compute 30-day chronological dataset (day -29 to day 0)
  const thirtyDayTrend = useMemo(() => {
    const days: DayThreatData[] = [];

    // Reference date is latest scan date or current date
    let referenceTime = Date.now();
    scans.forEach((s) => {
      const raw = s.scannedAt || s.date || s.headers?.date;
      if (raw) {
        const t = new Date(raw).getTime();
        if (!isNaN(t) && t > referenceTime) {
          referenceTime = t;
        }
      }
    });

    const refDate = new Date(referenceTime);
    refDate.setHours(23, 59, 59, 999);

    // Build 30 calendar days
    for (let i = 29; i >= 0; i--) {
      const d = new Date(refDate);
      d.setDate(d.getDate() - i);
      const year = d.getFullYear();
      const month = String(d.getMonth() + 1).padStart(2, '0');
      const day = String(d.getDate()).padStart(2, '0');
      const dateKey = `${year}-${month}-${day}`;

      const displayDate = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      const fullDate = d.toLocaleDateString('en-US', {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      });
      const dayOfWeek = d.toLocaleDateString('en-US', { weekday: 'short' });

      days.push({
        dateKey,
        displayDate,
        fullDate,
        dayOfWeek,
        threats: 0,
        criticalThreats: 0,
        phishing: 0,
        malware: 0,
        bec: 0,
        suspicious: 0,
        safe: 0,
        totalVolume: 0,
      });
    }

    const dayMap = new Map<string, DayThreatData>();
    days.forEach((day) => dayMap.set(day.dateKey, day));

    // Aggregate scans into day buckets
    scans.forEach((scan) => {
      const rawDate = scan.scannedAt || scan.date || scan.headers?.date;
      if (!rawDate) return;

      const scanDate = new Date(rawDate);
      if (isNaN(scanDate.getTime())) return;

      const sYear = scanDate.getFullYear();
      const sMonth = String(scanDate.getMonth() + 1).padStart(2, '0');
      const sDay = String(scanDate.getDate()).padStart(2, '0');
      const scanKey = `${sYear}-${sMonth}-${sDay}`;

      const targetDay = dayMap.get(scanKey);
      if (targetDay) {
        targetDay.totalVolume += 1;

        const classification = scan.classification || 'Safe';
        const isClean = classification === 'Safe' || (classification as string) === 'Clean';
        const isThreat = !isClean || (scan.riskScore ?? 0) >= 35;
        const isCritical =
          (scan.riskScore ?? 0) >= 70 ||
          scan.status === 'quarantined' ||
          scan.status === 'blocked';

        if (isThreat) {
          targetDay.threats += 1;
          if (isCritical) {
            targetDay.criticalThreats += 1;
          }

          const norm = classification.toLowerCase();
          if (norm.includes('phish') || norm.includes('credential')) {
            targetDay.phishing += 1;
          } else if (
            norm.includes('malware') ||
            norm.includes('trojan') ||
            norm.includes('virus')
          ) {
            targetDay.malware += 1;
          } else if (
            norm.includes('bec') ||
            norm.includes('compromise') ||
            norm.includes('impersonat')
          ) {
            targetDay.bec += 1;
          } else {
            targetDay.suspicious += 1;
          }
        } else {
          targetDay.safe += 1;
        }
      }
    });

    return days;
  }, [scans]);

  // Aggregate summary telemetry for header KPI chips
  const metrics = useMemo(() => {
    const totalThreats = thirtyDayTrend.reduce((acc, d) => acc + d.threats, 0);
    const totalCritical = thirtyDayTrend.reduce((acc, d) => acc + d.criticalThreats, 0);
    const totalVolume = thirtyDayTrend.reduce((acc, d) => acc + d.totalVolume, 0);
    const dailyAvg = (totalThreats / 30).toFixed(1);

    let peakDay: DayThreatData = thirtyDayTrend[0];
    thirtyDayTrend.forEach((d) => {
      if (d.threats > peakDay.threats) {
        peakDay = d;
      }
    });

    // Recent 7 days vs Previous 7 days velocity trend
    const recent7 = thirtyDayTrend.slice(23, 30).reduce((acc, d) => acc + d.threats, 0);
    const prev7 = thirtyDayTrend.slice(16, 23).reduce((acc, d) => acc + d.threats, 0);
    const delta = recent7 - prev7;

    return {
      totalThreats,
      totalCritical,
      totalVolume,
      dailyAvg,
      peakDay,
      recent7,
      prev7,
      delta,
    };
  }, [thirtyDayTrend]);

  const startDateLabel = thirtyDayTrend[0]?.displayDate || '';
  const endDateLabel = thirtyDayTrend[thirtyDayTrend.length - 1]?.displayDate || '';

  return (
    <div
      id="chart-card-30-day-threats"
      className={`bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between transition-all ${className}`}
    >
      {/* Chart Header with SOC Meta and View Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-100">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-rose-50 border border-rose-100 flex items-center justify-center text-rose-600 shrink-0">
              <Activity className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-slate-900">
                  30-Day Incoming Threat Velocity
                </h3>
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                  <span className="relative flex h-1.5 w-1.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
                  </span>
                  Live Telemetry
                </span>
              </div>
              <p className="text-xs text-slate-500">
                Daily frequency of phishing, malware, BEC, and malicious inbound attacks ({startDateLabel} – {endDateLabel})
              </p>
            </div>
          </div>
        </div>

        {/* View Toggle Buttons & KPI Quick Badges */}
        <div className="flex flex-wrap items-center gap-2 sm:self-auto self-start">
          <div
            id="trend-chart-filter-group"
            className="inline-flex items-center bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-xs font-medium text-slate-600"
          >
            <button
              id="chart-filter-all-threats"
              type="button"
              onClick={() => setMetricView('all')}
              className={`px-2.5 py-1 rounded-md transition-all ${
                metricView === 'all'
                  ? 'bg-white text-slate-900 shadow-xs font-semibold'
                  : 'hover:text-slate-900'
              }`}
            >
              All Threats
            </button>
            <button
              id="chart-filter-critical-threats"
              type="button"
              onClick={() => setMetricView('critical')}
              className={`px-2.5 py-1 rounded-md transition-all ${
                metricView === 'critical'
                  ? 'bg-white text-rose-700 shadow-xs font-semibold'
                  : 'hover:text-slate-900'
              }`}
            >
              Critical Only
            </button>
            <button
              id="chart-filter-combined-threats"
              type="button"
              onClick={() => setMetricView('combined')}
              className={`px-2.5 py-1 rounded-md transition-all ${
                metricView === 'combined'
                  ? 'bg-white text-blue-700 shadow-xs font-semibold'
                  : 'hover:text-slate-900'
              }`}
            >
              Dual Trend
            </button>
          </div>
        </div>
      </div>

      {/* KPI Highlight Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 my-3.5 py-2.5 px-3 bg-slate-50/70 border border-slate-100 rounded-lg">
        <div id="stat-30d-total-threats" className="space-y-0.5">
          <span className="text-[11px] font-medium text-slate-500 block">30-Day Threat Total</span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-base font-bold text-slate-900">{metrics.totalThreats}</span>
            <span className="text-[10px] font-semibold text-rose-600">
              {metrics.totalThreats > 0 ? `${metrics.totalCritical} Critical` : '0 Active'}
            </span>
          </div>
        </div>

        <div id="stat-30d-daily-avg" className="space-y-0.5">
          <span className="text-[11px] font-medium text-slate-500 block">Daily Average</span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-base font-bold text-slate-900">{metrics.dailyAvg}</span>
            <span className="text-[10px] text-slate-500 font-medium">threats/day</span>
          </div>
        </div>

        <div id="stat-30d-peak-day" className="space-y-0.5">
          <span className="text-[11px] font-medium text-slate-500 block">Peak Inbound Spike</span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-base font-bold text-slate-900">
              {metrics.peakDay.threats}
            </span>
            <span className="text-[10px] text-slate-600 font-medium">
              {metrics.peakDay.threats > 0 ? `on ${metrics.peakDay.displayDate}` : 'None logged'}
            </span>
          </div>
        </div>

        <div id="stat-30d-weekly-trend" className="space-y-0.5">
          <span className="text-[11px] font-medium text-slate-500 block">7-Day Velocity</span>
          <div className="flex items-center gap-1.5">
            <span className="text-base font-bold text-slate-900">{metrics.recent7}</span>
            {metrics.delta > 0 ? (
              <span className="inline-flex items-center text-[10px] font-semibold text-rose-600 gap-0.5">
                <TrendingUp className="w-3 h-3" />
                +{metrics.delta} vs prev
              </span>
            ) : metrics.delta < 0 ? (
              <span className="inline-flex items-center text-[10px] font-semibold text-emerald-600 gap-0.5">
                <TrendingDown className="w-3 h-3" />
                {metrics.delta} vs prev
              </span>
            ) : (
              <span className="text-[10px] font-semibold text-slate-500">Steady</span>
            )}
          </div>
        </div>
      </div>

      {/* Main 30-Day Line Chart Area */}
      <div className="h-60 sm:h-64 w-full mt-1">
        {thirtyDayTrend.length === 0 ? (
          <div className="h-full w-full flex flex-col items-center justify-center text-center p-4">
            <div className="w-9 h-9 rounded-full bg-slate-100 flex items-center justify-center text-slate-400 mb-2">
              <Calendar className="w-4 h-4" />
            </div>
            <p className="text-xs font-semibold text-slate-700">Awaiting 30-Day Inbound Data</p>
            <p className="text-[11px] text-slate-400 mt-1 max-w-xs">
              Scan inbound Gmail messages to plot continuous 30-day threat velocity.
            </p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart
              data={thirtyDayTrend}
              margin={{ top: 12, right: 12, left: -20, bottom: 0 }}
            >
              <defs>
                {/* Gradient for Total Threats Area */}
                <linearGradient id="threatAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#EF4444" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
                </linearGradient>

                {/* Gradient for Critical Threats Area */}
                <linearGradient id="criticalAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#DC2626" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#DC2626" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#F1F5F9" />

              <XAxis
                dataKey="displayDate"
                interval={3}
                tickLine={false}
                axisLine={{ stroke: '#E2E8F0' }}
                tick={{ fontSize: 10, fill: '#64748B' }}
              />

              <YAxis
                allowDecimals={false}
                tickLine={false}
                axisLine={false}
                tick={{ fontSize: 10, fill: '#64748B' }}
                domain={[0, (dataMax: number) => Math.max(3, dataMax + 1)]}
              />

              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data: DayThreatData = payload[0].payload;
                    const isElevated = data.threats >= 2;
                    const isModerate = data.threats === 1;

                    return (
                      <div className="bg-white p-3 rounded-xl border border-slate-200 shadow-lg text-xs font-sans min-w-[200px] space-y-2">
                        <div className="flex items-center justify-between pb-1.5 border-b border-slate-100">
                          <div className="flex items-center gap-1.5 text-slate-700 font-semibold">
                            <Calendar className="w-3.5 h-3.5 text-slate-400" />
                            <span>{data.fullDate}</span>
                          </div>
                          <span
                            className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                              isElevated
                                ? 'bg-red-50 text-red-700 border border-red-200'
                                : isModerate
                                ? 'bg-amber-50 text-amber-700 border border-amber-200'
                                : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            }`}
                          >
                            {isElevated ? 'High Activity' : isModerate ? 'Incident' : 'Clean'}
                          </span>
                        </div>

                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-600 flex items-center gap-1.5">
                              <span className="w-2 h-2 rounded-full bg-rose-500" />
                              Incoming Threats:
                            </span>
                            <span className="font-bold text-slate-900 text-sm">
                              {data.threats}
                            </span>
                          </div>

                          {data.criticalThreats > 0 && (
                            <div className="flex items-center justify-between text-rose-700">
                              <span className="flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full bg-rose-700" />
                                Critical (Score ≥ 70):
                              </span>
                              <span className="font-bold">{data.criticalThreats}</span>
                            </div>
                          )}

                          {data.threats > 0 && (
                            <div className="pt-1.5 border-t border-slate-100 text-[11px] text-slate-600 space-y-1">
                              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">
                                Attack Breakdown
                              </span>
                              <div className="flex flex-wrap gap-1">
                                {data.phishing > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-red-50 text-red-700 font-medium">
                                    Phishing: {data.phishing}
                                  </span>
                                )}
                                {data.malware > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-700 font-medium">
                                    Malware: {data.malware}
                                  </span>
                                )}
                                {data.bec > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 font-medium">
                                    BEC: {data.bec}
                                  </span>
                                )}
                                {data.suspicious > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 font-medium">
                                    Suspicious: {data.suspicious}
                                  </span>
                                )}
                              </div>
                            </div>
                          )}

                          {data.totalVolume > 0 && (
                            <div className="pt-1 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
                              <span>Total Inbound Emails:</span>
                              <span className="font-semibold text-slate-700">{data.totalVolume}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  }
                  return null;
                }}
              />

              {/* View: All Threats */}
              {(metricView === 'all' || metricView === 'combined') && (
                <Area
                  type="monotone"
                  dataKey="threats"
                  name="Incoming Threats"
                  stroke="#EF4444"
                  strokeWidth={2.5}
                  fill="url(#threatAreaGrad)"
                  activeDot={{ r: 6, fill: '#EF4444', stroke: '#FFFFFF', strokeWidth: 2 }}
                  dot={(props: any) => {
                    const { cx, cy, payload } = props;
                    if (payload && payload.threats > 0) {
                      return (
                        <circle
                          key={`dot-threat-${payload.dateKey}`}
                          cx={cx}
                          cy={cy}
                          r={3.5}
                          fill="#EF4444"
                          stroke="#FFFFFF"
                          strokeWidth={1.5}
                        />
                      );
                    }
                    return <React.Fragment key={`dot-empty-${payload?.dateKey || Math.random()}`} />;
                  }}
                  isAnimationActive={true}
                />
              )}

              {/* View: Critical Only */}
              {metricView === 'critical' && (
                <Area
                  type="monotone"
                  dataKey="criticalThreats"
                  name="Critical Threats"
                  stroke="#DC2626"
                  strokeWidth={2.5}
                  fill="url(#criticalAreaGrad)"
                  activeDot={{ r: 6, fill: '#DC2626', stroke: '#FFFFFF', strokeWidth: 2 }}
                  dot={(props: any) => {
                    const { cx, cy, payload } = props;
                    if (payload && payload.criticalThreats > 0) {
                      return (
                        <circle
                          key={`dot-crit-${payload.dateKey}`}
                          cx={cx}
                          cy={cy}
                          r={3.5}
                          fill="#DC2626"
                          stroke="#FFFFFF"
                          strokeWidth={1.5}
                        />
                      );
                    }
                    return <React.Fragment key={`dot-empty-crit-${payload?.dateKey || Math.random()}`} />;
                  }}
                  isAnimationActive={true}
                />
              )}

              {/* Combined View Secondary Line: Critical Incidents */}
              {metricView === 'combined' && (
                <Line
                  type="monotone"
                  dataKey="criticalThreats"
                  name="Critical (Score ≥ 70)"
                  stroke="#B91C1C"
                  strokeWidth={2}
                  strokeDasharray="4 3"
                  dot={false}
                  activeDot={{ r: 5, fill: '#B91C1C', stroke: '#FFFFFF', strokeWidth: 2 }}
                  isAnimationActive={true}
                />
              )}
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Chart Footer: Legend and Coverage Info */}
      <div className="pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between text-xs text-slate-500 mt-2 gap-2">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
            <span className="font-medium text-slate-700">Incoming Attacks</span>
          </div>
          {metricView === 'combined' && (
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-0.5 border-b-2 border-dashed border-rose-800" />
              <span className="font-medium text-rose-800">Critical Threat Floor</span>
            </div>
          )}
          <span className="hidden sm:inline text-slate-400">|</span>
          <span className="hidden sm:inline text-slate-500">
            Window: <strong>30 Consecutive Days</strong>
          </span>
        </div>

        <div className="flex items-center gap-1.5 text-slate-600 font-medium">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
          <span>Automated Inbound Quarantine & Mitigation Active</span>
        </div>
      </div>
    </div>
  );
};
