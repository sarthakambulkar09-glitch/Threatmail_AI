import React from 'react';
import { InsforgeStats } from '../types';
import { ShieldCheck, ShieldAlert, AlertOctagon, Mail, Activity, ArrowUpRight, Zap } from 'lucide-react';

interface StatsBarProps {
  stats: InsforgeStats;
  onViewFilter?: (filter: 'all' | 'critical' | 'suspicious' | 'safe') => void;
}

export const StatsBar: React.FC<StatsBarProps> = ({ stats, onViewFilter }) => {
  const avgScore = stats.averageRiskScore || 0;
  const criticalCount = stats.highRiskCount || 0;

  const scoreColor =
    avgScore >= 70 ? 'text-red-600' : avgScore >= 40 ? 'text-amber-600' : 'text-emerald-600';
  const scoreBg =
    avgScore >= 70 ? 'bg-red-50 text-red-700 border-red-200' : avgScore >= 40 ? 'bg-amber-50 text-amber-700 border-amber-200' : 'bg-emerald-50 text-emerald-700 border-emerald-200';
  const scoreLabel =
    avgScore >= 70 ? 'High Risk' : avgScore >= 40 ? 'Moderate' : 'Optimal / Safe';

  return (
    <div id="soc-stats-bar" className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4 mb-6">
      {/* KPI 1: Emails Scanned */}
      <div
        id="kpi-card-emails-scanned"
        onClick={() => onViewFilter && onViewFilter('all')}
        className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs hover:shadow-md hover:border-blue-300 transition-all cursor-pointer flex flex-col justify-between group"
      >
        <div id="kpi-header-emails-scanned" className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Emails Scanned
            </span>
          </div>
          <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 group-hover:scale-105 transition-transform">
            <Mail className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-3">
          <div id="kpi-value-emails-scanned" className="text-3xl font-bold tracking-tight text-slate-900 tabular-nums">
            {stats.totalScanned}
          </div>
          <div className="mt-2 flex items-center justify-between text-xs text-slate-500 pt-2 border-t border-slate-100">
            <span className="inline-flex items-center gap-1.5 text-emerald-600 font-semibold">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
              </span>
              Real-Time
            </span>
            <span className="text-[11px] font-medium text-slate-400">Gmail OAuth API</span>
          </div>
        </div>
      </div>

      {/* KPI 2: Threats Detected */}
      <div
        id="kpi-card-threats-detected"
        onClick={() => onViewFilter && onViewFilter('suspicious')}
        className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs hover:shadow-md hover:border-amber-300 transition-all cursor-pointer flex flex-col justify-between group"
      >
        <div id="kpi-header-threats-detected" className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Threats Detected
            </span>
          </div>
          <div className="w-8 h-8 rounded-lg bg-amber-50 border border-amber-100 flex items-center justify-center text-amber-600 group-hover:scale-105 transition-transform">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-3">
          <div id="kpi-value-threats-detected" className="text-3xl font-bold tracking-tight text-slate-900 tabular-nums">
            {stats.threatsBlocked}
          </div>
          <div className="mt-2 flex items-center justify-between text-xs text-slate-500 pt-2 border-t border-slate-100">
            <span className="text-slate-500">Quarantined / Risk</span>
            <span className="font-semibold text-amber-600 text-[11px]">
              {stats.phishingCount + stats.becCount + stats.malwareCount} Active
            </span>
          </div>
        </div>
      </div>

      {/* KPI 3: Safe Emails */}
      <div
        id="kpi-card-safe-emails"
        onClick={() => onViewFilter && onViewFilter('safe')}
        className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs hover:shadow-md hover:border-emerald-300 transition-all cursor-pointer flex flex-col justify-between group"
      >
        <div id="kpi-header-safe-emails" className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Safe Emails
            </span>
          </div>
          <div className="w-8 h-8 rounded-lg bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600 group-hover:scale-105 transition-transform">
            <ShieldCheck className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-3">
          <div id="kpi-value-safe-emails" className="text-3xl font-bold tracking-tight text-emerald-600 tabular-nums">
            {stats.safeEmails}
          </div>
          <div className="mt-2 flex items-center justify-between text-xs text-slate-500 pt-2 border-t border-slate-100">
            <span className="text-emerald-600 font-semibold text-[11px] flex items-center gap-1">
              <span>SPF/DKIM Valid</span>
            </span>
            <span className="text-slate-400 text-[11px]">Clean Inbox</span>
          </div>
        </div>
      </div>

      {/* KPI 4: Critical Alerts */}
      <div
        id="kpi-card-critical-alerts"
        onClick={() => onViewFilter && onViewFilter('critical')}
        className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs hover:shadow-md hover:border-red-300 transition-all cursor-pointer flex flex-col justify-between group"
      >
        <div id="kpi-header-critical-alerts" className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Critical Alerts
            </span>
          </div>
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center transition-transform group-hover:scale-105 ${
            criticalCount > 0 ? 'bg-red-100 border border-red-200 text-red-600' : 'bg-slate-50 border border-slate-200 text-slate-400'
          }`}>
            <AlertOctagon className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-3">
          <div id="kpi-value-critical-alerts" className={`text-3xl font-bold tracking-tight tabular-nums ${
            criticalCount > 0 ? 'text-red-600' : 'text-slate-800'
          }`}>
            {criticalCount}
          </div>
          <div className="mt-2 flex items-center justify-between text-xs text-slate-500 pt-2 border-t border-slate-100">
            <span className="text-[11px] text-slate-500">Risk &gt; 70/100</span>
            <span className={`text-[11px] font-semibold ${criticalCount > 0 ? 'text-red-600' : 'text-emerald-600'}`}>
              {criticalCount > 0 ? 'Action Required' : '0 Immediate Risk'}
            </span>
          </div>
        </div>
      </div>

      {/* KPI 5: Average Risk Score */}
      <div
        id="kpi-card-avg-risk-score"
        className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs hover:shadow-md hover:border-blue-300 transition-all flex flex-col justify-between group"
      >
        <div id="kpi-header-avg-risk-score" className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Avg Risk Score
            </span>
          </div>
          <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 group-hover:scale-105 transition-transform">
            <Activity className="w-4 h-4" />
          </div>
        </div>
        <div id="kpi-container-avg-risk-score" className="mt-3">
          <div className="flex items-baseline justify-between">
            <div className="flex items-baseline gap-1">
              <span id="kpi-value-avg-risk-score" className={`text-3xl font-bold tracking-tight tabular-nums ${scoreColor}`}>
                {avgScore}
              </span>
              <span className="text-xs text-slate-400 font-medium">/ 100</span>
            </div>
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${scoreBg}`}>
              {scoreLabel}
            </span>
          </div>

          {/* Minimalist Progress Meter */}
          <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden mt-3">
            <div
              className={`h-full transition-all duration-700 rounded-full ${
                avgScore >= 70 ? 'bg-red-500' : avgScore >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(100, Math.max(stats.totalScanned > 0 ? 5 : 0, avgScore))}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
