import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from 'recharts';
import { EmailThreatReport, InsforgeStats } from '../types';
import { ShieldCheck, TrendingUp } from 'lucide-react';
import { ThreatClassificationDonutChart } from './ThreatClassificationDonutChart';
import { ThirtyDayThreatTrendChart } from './ThirtyDayThreatTrendChart';

interface SecurityChartsProps {
  scans: EmailThreatReport[];
  stats: InsforgeStats;
}

export const SecurityCharts: React.FC<SecurityChartsProps> = ({ scans, stats }) => {
  // Risk Range Distribution
  const riskRanges = [
    { range: '0 - 20 (Clean)', count: 0, color: '#10B981' },
    { range: '21 - 40 (Low)', count: 0, color: '#3B82F6' },
    { range: '41 - 60 (Med)', count: 0, color: '#F59E0B' },
    { range: '61 - 80 (High)', count: 0, color: '#F97316' },
    { range: '81 - 100 (Crit)', count: 0, color: '#EF4444' },
  ];

  scans.forEach((s) => {
    const score = s.riskScore;
    if (score <= 20) riskRanges[0].count += 1;
    else if (score <= 40) riskRanges[1].count += 1;
    else if (score <= 60) riskRanges[2].count += 1;
    else if (score <= 80) riskRanges[3].count += 1;
    else riskRanges[4].count += 1;
  });

  // Authentication Compliance (SPF / DKIM / DMARC)
  let spfPass = 0,
    dkimPass = 0,
    dmarcPass = 0;
  scans.forEach((s) => {
    if (s.headers.spfStatus === 'pass') spfPass++;
    if (s.headers.dkimStatus === 'pass') dkimPass++;
    if (s.headers.dmarcStatus === 'pass') dmarcPass++;
  });
  const total = Math.max(1, scans.length);

  return (
    <div className="space-y-5 mb-6">
      {/* 30-Day Incoming Threats Velocity Line Chart */}
      <ThirtyDayThreatTrendChart scans={scans} />

      {/* Auxiliary Security Breakdown Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Chart 1: Threat Classification Donut Chart */}
        <ThreatClassificationDonutChart scans={scans} stats={stats} />

        {/* Chart 2: Risk Score Distribution */}
        <div id="chart-card-risk-score" className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-slate-900">Risk Score Profile</h3>
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                  <span className="relative flex h-1.5 w-1.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
                  </span>
                  Live Real-Time
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">Real-time risk distribution across verified inbound emails</p>
            </div>
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 shrink-0">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>

          <div className="h-56 w-full mt-2">
            {scans.length === 0 ? (
              <div className="h-full w-full flex flex-col items-center justify-center text-center p-4">
                <div className="w-9 h-9 rounded-full bg-slate-100 flex items-center justify-center text-slate-400 mb-2">
                  <TrendingUp className="w-4 h-4" />
                </div>
                <p className="text-xs font-semibold text-slate-700">Awaiting Real-Time Email Telemetry</p>
                <p className="text-[11px] text-slate-400 mt-1 max-w-xs">
                  Connect your Gmail or click Scan Gmail Inbox to stream live risk scores.
                </p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={riskRanges} margin={{ top: 15, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="range" tick={{ fontSize: 10, fill: '#64748B' }} interval={0} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: '#64748B' }} />
                  <Tooltip
                    cursor={{ fill: 'rgba(241, 245, 249, 0.6)' }}
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0].payload;
                        const pct = scans.length > 0 ? Math.round((data.count / scans.length) * 100) : 0;
                        return (
                          <div className="bg-white p-2.5 rounded-lg border border-slate-200 shadow-md text-xs font-sans">
                            <div className="flex items-center gap-1.5 font-semibold text-slate-900">
                              <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: data.color }} />
                              <span>{data.range}</span>
                            </div>
                            <div className="mt-1 text-slate-600">
                              Scanned Count: <span className="font-bold text-slate-900">{data.count}</span>
                            </div>
                            <div className="text-slate-600">
                              Distribution: <span className="font-bold text-slate-900">{pct}%</span>
                            </div>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]} isAnimationActive={true}>
                    {riskRanges.map((entry, index) => (
                      <Cell key={`bar-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 mt-2">
            <span>Total Real-Time Sample: <strong className="text-slate-800">{scans.length}</strong></span>
            <span className="text-emerald-600 font-semibold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              Live Stream
            </span>
          </div>
        </div>

        {/* Chart 3: Email Header Authentication Compliance */}
        <div id="chart-card-header-compliance" className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Header Compliance</h3>
              <p className="text-xs text-slate-500">SPF, DKIM, and DMARC pass rates</p>
            </div>
            <div className="w-8 h-8 rounded-lg bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>

          <div className="space-y-4 my-auto py-2">
            {/* SPF */}
            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span className="text-slate-700">SPF Validation</span>
                <span className="text-slate-900">{Math.round((spfPass / total) * 100)}% Pass</span>
              </div>
              <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-600 rounded-full transition-all duration-500"
                  style={{ width: `${Math.round((spfPass / total) * 100)}%` }}
                />
              </div>
            </div>

            {/* DKIM */}
            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span className="text-slate-700">DKIM Cryptographic Signature</span>
                <span className="text-slate-900">{Math.round((dkimPass / total) * 100)}% Pass</span>
              </div>
              <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-emerald-500 rounded-full transition-all duration-500"
                  style={{ width: `${Math.round((dkimPass / total) * 100)}%` }}
                />
              </div>
            </div>

            {/* DMARC */}
            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span className="text-slate-700">DMARC Policy Alignment</span>
                <span className="text-slate-900">{Math.round((dmarcPass / total) * 100)}% Pass</span>
              </div>
              <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-amber-500 rounded-full transition-all duration-500"
                  style={{ width: `${Math.round((dmarcPass / total) * 100)}%` }}
                />
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
            <span>Standard: RFC 7208 / 6376 / 7489</span>
            <span className="text-blue-600 font-semibold">{total} Scanned</span>
          </div>
        </div>
      </div>
    </div>
  );
};
