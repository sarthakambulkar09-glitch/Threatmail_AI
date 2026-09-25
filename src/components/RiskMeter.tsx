import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';

interface RiskMeterProps {
  score: number;
  confidence?: number;
  size?: number;
  strokeWidth?: number;
  showDetails?: boolean;
  classification?: string;
}

export const RiskMeter: React.FC<RiskMeterProps> = ({
  score,
  confidence = 94,
  size = 140,
  strokeWidth = 10,
  showDetails = true,
  classification,
}) => {
  const normalizedScore = Math.min(100, Math.max(0, Math.round(score)));

  // Color selection according to prompt specifications:
  // 0-30 Green (#10B981)
  // 31-60 Orange (#F59E0B)
  // 61-100 Red (#EF4444)
  let strokeColor = '#10B981'; // Green
  let threatLevel = 'Safe / Verified';
  let badgeBg = 'bg-emerald-50 text-emerald-700 border-emerald-200';
  let textColor = 'text-emerald-600';
  let IconComponent = ShieldCheck;

  if (normalizedScore > 60) {
    strokeColor = '#EF4444'; // Red
    threatLevel = 'Critical Alert';
    badgeBg = 'bg-red-50 text-red-700 border-red-200';
    textColor = 'text-red-600';
    IconComponent = ShieldAlert;
  } else if (normalizedScore > 30) {
    strokeColor = '#F59E0B'; // Orange
    threatLevel = 'Suspicious';
    badgeBg = 'bg-amber-50 text-amber-700 border-amber-200';
    textColor = 'text-amber-600';
    IconComponent = AlertTriangle;
  }

  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        {/* Background Track Circle */}
        <svg className="transform -rotate-90" width={size} height={size}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#E2E8F0"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Active Progress Circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-700 ease-out"
          />
        </svg>

        {/* Center Score Display */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-3xl font-bold tracking-tight text-slate-900 leading-none">
            {normalizedScore}
          </span>
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider mt-0.5">
            / 100
          </span>
        </div>
      </div>

      {showDetails && (
        <div className="mt-3 flex flex-col items-center text-center">
          <div className="flex items-center gap-1.5">
            <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${badgeBg}`}>
              <IconComponent className="w-3.5 h-3.5" />
              {classification || threatLevel}
            </span>
          </div>
          <div className="mt-1.5 flex items-center gap-2 text-xs text-slate-500">
            <span>Threat Level: <strong className={textColor}>{threatLevel}</strong></span>
            <span>•</span>
            <span>Confidence: <strong className="text-slate-800">{confidence}%</strong></span>
          </div>
        </div>
      )}
    </div>
  );
};
