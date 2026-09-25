import React, { useEffect, useState, useMemo, useCallback } from 'react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  Label,
} from 'recharts';
import { getSupabaseClient } from '../lib/supabase';
import { EmailThreatReport, InsforgeStats } from '../types';
import { ShieldCheck, RefreshCw, Database } from 'lucide-react';

interface ThreatClassificationDonutChartProps {
  scans?: EmailThreatReport[];
  stats?: InsforgeStats;
  className?: string;
}

interface ThreatTypeSlice {
  name: string;
  value: number;
  percentage: number;
  color: string;
}

const THREAT_COLORS: Record<string, string> = {
  Clean: '#00c853',
  Phishing: '#ef4444',
  Malware: '#f59e0b',
  BEC: '#0f2d5e',
  Spam: '#64748b',
};

/**
 * Standardizes arbitrary classification labels into the 5 core threat types
 */
function normalizeThreatType(rawType?: string | null): 'Clean' | 'Phishing' | 'Malware' | 'BEC' | 'Spam' {
  if (!rawType) return 'Clean';
  const lower = rawType.toLowerCase().trim();

  if (lower.includes('clean') || lower.includes('safe') || lower.includes('informational') || lower.includes('legit')) {
    return 'Clean';
  }
  if (lower.includes('phish') || lower.includes('credential')) {
    return 'Phishing';
  }
  if (lower.includes('malware') || lower.includes('trojan') || lower.includes('virus') || lower.includes('payload')) {
    return 'Malware';
  }
  if (lower.includes('bec') || lower.includes('compromise') || lower.includes('impersonat')) {
    return 'BEC';
  }
  if (lower.includes('spam') || lower.includes('suspicious') || lower.includes('spoof') || lower.includes('junk')) {
    return 'Spam';
  }

  return 'Spam';
}

export const ThreatClassificationDonutChart: React.FC<ThreatClassificationDonutChartProps> = ({
  scans = [],
  stats,
  className = '',
}) => {
  const [supabaseThreatTypes, setSupabaseThreatTypes] = useState<string[] | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isLiveFromSupabase, setIsLiveFromSupabase] = useState<boolean>(false);

  // Fetch live from Supabase table 'results' column 'threat_type'
  const fetchSupabaseData = useCallback(async () => {
    const client = getSupabaseClient();
    if (!client) {
      setIsLiveFromSupabase(false);
      return;
    }

    try {
      setIsLoading(true);
      const { data, error } = await client
        .from('results')
        .select('threat_type');

      if (error) {
        console.warn("Supabase 'results' query error:", error.message);
        setIsLiveFromSupabase(false);
        return;
      }

      if (data && Array.isArray(data) && data.length > 0) {
        const types = data
          .map((row: any) => row.threat_type)
          .filter((t: any): t is string => typeof t === 'string' && t.trim().length > 0);
        setSupabaseThreatTypes(types);
        setIsLiveFromSupabase(true);
      } else {
        // Table exists but is currently empty
        setSupabaseThreatTypes([]);
        setIsLiveFromSupabase(true);
      }
    } catch (err) {
      console.warn('Failed to fetch live Supabase threat types:', err);
      setIsLiveFromSupabase(false);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSupabaseData();

    // Set up real-time listener if Supabase is connected
    const client = getSupabaseClient();
    if (client) {
      try {
        const channel = client
          .channel('results_threat_type_live')
          .on('postgres_changes', { event: '*', schema: 'public', table: 'results' }, () => {
            fetchSupabaseData();
          })
          .subscribe();

        return () => {
          client.removeChannel(channel);
        };
      } catch (err) {
        console.warn('Supabase realtime subscription failed:', err);
      }
    }
  }, [fetchSupabaseData]);

  // Aggregate and group threat types dynamically without hardcoded values
  const { chartData, totalItems, cleanPercentage, safePercentage } = useMemo(() => {
    const rawList: string[] = [];

    // Use Supabase data if live rows were retrieved
    if (supabaseThreatTypes && supabaseThreatTypes.length > 0) {
      rawList.push(...supabaseThreatTypes);
    } else if (scans && scans.length > 0) {
      // Dynamic fallback to the app's live scan stream
      scans.forEach((scan) => {
        rawList.push(scan.classification || 'Clean');
      });
    } else if (stats && stats.totalScanned > 0) {
      // Dynamic fallback to dashboard statistics
      for (let i = 0; i < (stats.safeEmails || 0); i++) rawList.push('Clean');
      for (let i = 0; i < (stats.phishingCount || 0); i++) rawList.push('Phishing');
      for (let i = 0; i < (stats.malwareCount || 0); i++) rawList.push('Malware');
      for (let i = 0; i < (stats.becCount || 0); i++) rawList.push('BEC');
      for (let i = 0; i < (stats.suspiciousCount || 0); i++) rawList.push('Spam');
    }

    // Dynamic grouping
    const counts: Record<'Clean' | 'Phishing' | 'Malware' | 'BEC' | 'Spam', number> = {
      Clean: 0,
      Phishing: 0,
      Malware: 0,
      BEC: 0,
      Spam: 0,
    };

    rawList.forEach((item) => {
      const normalized = normalizeThreatType(item);
      counts[normalized] = (counts[normalized] || 0) + 1;
    });

    const total = rawList.length;

    // Ordered sequence
    const categories: Array<'Clean' | 'Phishing' | 'Malware' | 'BEC' | 'Spam'> = [
      'Clean',
      'Phishing',
      'Malware',
      'BEC',
      'Spam',
    ];

    // Filter to categories that have occurrences
    const slices: ThreatTypeSlice[] = categories
      .map((cat) => {
        const val = counts[cat];
        const pct = total > 0 ? (val / total) * 100 : 0;
        return {
          name: cat,
          value: val,
          percentage: Number(pct.toFixed(1)),
          color: THREAT_COLORS[cat],
        };
      })
      .filter((s) => s.value > 0);

    const cleanCount = counts.Clean;
    const computedCleanPct = total > 0 ? Math.round((cleanCount / total) * 100) : 0;

    return {
      chartData: total > 0 ? slices : [{ name: 'Awaiting Scans', value: 1, percentage: 100, color: '#E2E8F0' }],
      totalItems: total,
      cleanPercentage: computedCleanPct,
      safePercentage: computedCleanPct,
    };
  }, [supabaseThreatTypes, scans, stats]);

  return (
    <div
      id="chart-card-threat-classification"
      className={`rounded-xl p-5 border border-slate-200 shadow-xs flex flex-col justify-between ${className}`}
      style={{ backgroundColor: '#ffffff' }}
    >
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-100">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-slate-900">Threat Classification</h3>
            {isLiveFromSupabase ? (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                <Database className="w-2.5 h-2.5" />
                Live Supabase
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping" />
                Real-Time
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 mt-0.5">Live distribution of analyzed threat vectors</p>
        </div>
        <button
          type="button"
          onClick={() => fetchSupabaseData()}
          title="Refresh Supabase records"
          className="w-8 h-8 rounded-lg bg-blue-50 hover:bg-blue-100 border border-blue-100 flex items-center justify-center text-blue-600 transition-colors shrink-0"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Donut Chart Container */}
      <div className="h-64 w-full mt-2 relative" style={{ backgroundColor: '#ffffff' }}>
        {/* Center Overlay */}
        <div
          className="absolute pointer-events-none flex flex-col items-center justify-center text-center z-10 select-none"
          style={{
            top: '45%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
          }}
        >
          {totalItems > 0 ? (
            <>
              <span className="text-3xl font-extrabold tracking-tight text-slate-900 leading-none">
                {cleanPercentage}%
              </span>
              <span className="text-xs font-bold uppercase tracking-wider text-emerald-600 mt-1 flex items-center gap-1 justify-center">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" />
                Clean
              </span>
            </>
          ) : (
            <>
              <span className="text-2xl font-bold tracking-tight text-slate-400 leading-none">
                0
              </span>
              <span className="text-[10px] font-medium uppercase tracking-wider text-slate-400 mt-1">
                Awaiting Telemetry
              </span>
            </>
          )}
        </div>

        <ResponsiveContainer width="100%" height="100%">
          <PieChart style={{ backgroundColor: '#ffffff' }}>
            <Pie
              data={chartData}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="45%"
              innerRadius={65}
              outerRadius={90}
              paddingAngle={chartData.length > 1 ? 3 : 0}
              isAnimationActive={true}
            >
              {chartData.map((entry) => (
                <Cell key={`cell-${entry.name}`} fill={entry.color} stroke="#ffffff" strokeWidth={2} />
              ))}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload as ThreatTypeSlice;
                  return (
                    <div
                      className="p-2.5 rounded-lg border border-slate-200 shadow-md text-xs font-sans"
                      style={{ backgroundColor: '#ffffff' }}
                    >
                      <div className="flex items-center gap-2 font-semibold text-slate-800">
                        <span
                          className="w-2.5 h-2.5 rounded-full"
                          style={{ backgroundColor: data.color }}
                        />
                        <span>{data.name}</span>
                      </div>
                      <div className="mt-1 text-slate-600">
                        Count: <span className="font-semibold text-slate-900">{data.value}</span>
                      </div>
                      <div className="text-slate-600">
                        Share: <span className="font-semibold text-slate-900">{data.percentage}%</span>
                      </div>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Legend
              verticalAlign="bottom"
              height={36}
              iconType="circle"
              iconSize={8}
              formatter={(value, entry: any) => {
                const item = chartData.find((d) => d.name === value);
                const pct = item ? ` (${item.percentage}%)` : '';
                const isClean = value === 'Clean';
                return (
                  <span className={`text-[11px] ${isClean ? 'font-semibold text-emerald-700' : 'font-medium text-slate-700'}`}>
                    {value}
                    <span className={isClean ? 'text-emerald-600 font-medium text-[10px] ml-1' : 'text-slate-400 text-[10px] ml-1'}>
                      {pct}
                    </span>
                  </span>
                );
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
