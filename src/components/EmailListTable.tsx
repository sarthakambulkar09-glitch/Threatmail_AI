import React, { useState, useRef, useEffect } from 'react';
import { EmailThreatReport } from '../types';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  Filter,
  FileDown,
  ArrowRight,
  Shield,
  Globe,
  MapPin,
  CheckCircle2,
  XCircle,
  AlertCircle,
  ExternalLink,
  Inbox,
  FileText,
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface EmailListTableProps {
  scans: EmailThreatReport[];
  selectedScanId: string | null;
  onSelectScan: (id: string) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  filterSeverity: 'all' | 'critical' | 'suspicious' | 'safe';
  onFilterChange: (f: 'all' | 'critical' | 'suspicious' | 'safe') => void;
  onExportPdf?: (report: EmailThreatReport) => void;
  onScanLiveGmail?: () => void;
  onOpenRealEmailScan?: () => void;
}

interface HoveredSenderData {
  scan: EmailThreatReport;
  x: number;
  y: number;
  placement: 'top' | 'bottom';
}

export const EmailListTable: React.FC<EmailListTableProps> = ({
  scans,
  selectedScanId,
  onSelectScan,
  searchQuery,
  onSearchChange,
  filterSeverity,
  onFilterChange,
  onExportPdf,
  onScanLiveGmail,
  onOpenRealEmailScan,
}) => {
  const criticalCount = scans.filter((s) => s.riskScore >= 70).length;
  const suspiciousCount = scans.filter((s) => s.riskScore >= 35 && s.riskScore < 70).length;
  const safeCount = scans.filter((s) => s.riskScore < 35).length;

  const [hoveredSender, setHoveredSender] = useState<HoveredSenderData | null>(null);
  const hideTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Close popup on window or table scroll
  useEffect(() => {
    const handleScroll = () => {
      setHoveredSender(null);
    };
    window.addEventListener('scroll', handleScroll, true);
    return () => {
      window.removeEventListener('scroll', handleScroll, true);
      if (hideTimeoutRef.current) clearTimeout(hideTimeoutRef.current);
    };
  }, []);

  const handleSenderMouseEnter = (scan: EmailThreatReport, e: React.MouseEvent<HTMLElement>) => {
    if (hideTimeoutRef.current) {
      clearTimeout(hideTimeoutRef.current);
      hideTimeoutRef.current = null;
    }
    const rect = e.currentTarget.getBoundingClientRect();
    const spaceBelow = window.innerHeight - rect.bottom;
    const placement = spaceBelow < 280 ? 'top' : 'bottom';
    const cardWidth = 320;
    
    // Clamp horizontal position within viewport
    let x = rect.left;
    if (x + cardWidth > window.innerWidth - 16) {
      x = window.innerWidth - cardWidth - 16;
    }
    if (x < 16) x = 16;

    setHoveredSender({
      scan,
      x,
      y: placement === 'bottom' ? rect.bottom + 8 : rect.top - 8,
      placement,
    });
  };

  const handleSenderMouseLeave = () => {
    hideTimeoutRef.current = setTimeout(() => {
      setHoveredSender(null);
    }, 150);
  };

  const handlePopupMouseEnter = () => {
    if (hideTimeoutRef.current) {
      clearTimeout(hideTimeoutRef.current);
      hideTimeoutRef.current = null;
    }
  };

  const handlePopupMouseLeave = () => {
    setHoveredSender(null);
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden flex flex-col">
      {/* Controls Bar: Search & Severity Filters */}
      <div className="p-4 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-3 bg-white">
        <div className="flex items-center gap-3">
          <div className="relative w-full md:w-80">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search sender, subject, IP, or threat..."
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              className="w-full pl-9 pr-3.5 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 placeholder-slate-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
            />
          </div>
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex items-center gap-1.5 p-1 bg-slate-100 rounded-lg text-xs font-medium self-start md:self-auto">
          <button
            onClick={() => onFilterChange('all')}
            className={`px-3 py-1 rounded-md transition-all ${
              filterSeverity === 'all'
                ? 'bg-white text-slate-900 font-semibold shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            All ({scans.length})
          </button>
          <button
            onClick={() => onFilterChange('critical')}
            className={`px-3 py-1 rounded-md transition-all flex items-center gap-1.5 ${
              filterSeverity === 'critical'
                ? 'bg-red-50 text-red-700 font-semibold shadow-xs border border-red-200'
                : 'text-red-600 hover:text-red-700'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-red-500" />
            Critical ({criticalCount})
          </button>
          <button
            onClick={() => onFilterChange('suspicious')}
            className={`px-3 py-1 rounded-md transition-all flex items-center gap-1.5 ${
              filterSeverity === 'suspicious'
                ? 'bg-amber-50 text-amber-700 font-semibold shadow-xs border border-amber-200'
                : 'text-amber-600 hover:text-amber-700'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-amber-500" />
            Suspicious ({suspiciousCount})
          </button>
          <button
            onClick={() => onFilterChange('safe')}
            className={`px-3 py-1 rounded-md transition-all flex items-center gap-1.5 ${
              filterSeverity === 'safe'
                ? 'bg-emerald-50 text-emerald-700 font-semibold shadow-xs border border-emerald-200'
                : 'text-emerald-600 hover:text-emerald-700'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            Safe ({safeCount})
          </button>
        </div>
      </div>

      {/* Modern Table Layout */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-200 bg-slate-50/80 text-slate-600 font-semibold uppercase tracking-wider text-[11px]">
              <th className="py-3 px-4">Threat Level</th>
              <th className="py-3 px-4">Sender</th>
              <th className="py-3 px-4">Subject</th>
              <th className="py-3 px-4 hidden md:table-cell">Date</th>
              <th className="py-3 px-4 text-right">Risk Score</th>
              <th className="py-3 px-3 text-center">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {scans.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-400">
                  <div className="flex flex-col items-center justify-center max-w-md mx-auto px-4">
                    <div className="w-12 h-12 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center mb-3 border border-blue-100 shadow-2xs">
                      <Shield className="w-6 h-6" />
                    </div>
                    <p className="font-bold text-slate-800 text-sm">No Scanned Emails in Private History</p>
                    <p className="text-xs text-slate-500 mt-1 text-center leading-relaxed">
                      ThreatMail AI scans actual emails directly from your logged-in Google mailbox with RFC 822 forensic inspection. No hardcoded or fake sample data is loaded.
                    </p>
                    <div className="flex flex-wrap items-center justify-center gap-2.5 mt-4">
                      {onScanLiveGmail && (
                        <button
                          type="button"
                          onClick={onScanLiveGmail}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-xs transition-colors"
                        >
                          <Inbox className="w-3.5 h-3.5" />
                          <span>Scan Live Gmail Inbox</span>
                        </button>
                      )}
                      {onOpenRealEmailScan && (
                        <button
                          type="button"
                          onClick={onOpenRealEmailScan}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-800 font-semibold text-xs border border-slate-200 transition-colors"
                        >
                          <FileText className="w-3.5 h-3.5 text-slate-600" />
                          <span>Analyze Real Email</span>
                        </button>
                      )}
                    </div>
                  </div>
                </td>
              </tr>
            ) : (
              scans.map((scan) => {
                const isSelected = selectedScanId === scan.id;
                const isCritical = scan.riskScore >= 70;
                const isSuspicious = scan.riskScore >= 35 && scan.riskScore < 70;

                // User prompt badges:
                // Safe = Green Badge
                // Suspicious = Amber Badge
                // Critical = Red Badge
                let badgeClass = 'bg-emerald-50 text-emerald-700 border-emerald-200';
                let levelLabel = 'Safe';
                let IconComponent = ShieldCheck;

                if (isCritical) {
                  badgeClass = 'bg-red-50 text-red-700 border-red-200';
                  levelLabel = 'Critical';
                  IconComponent = ShieldAlert;
                } else if (isSuspicious) {
                  badgeClass = 'bg-amber-50 text-amber-700 border-amber-200';
                  levelLabel = 'Suspicious';
                  IconComponent = AlertTriangle;
                }

                const dateStr = new Date(scan.date || scan.scannedAt).toLocaleDateString(undefined, {
                  month: 'short',
                  day: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit',
                });

                return (
                  <tr
                    key={scan.id}
                    onClick={() => onSelectScan(scan.id)}
                    className={`cursor-pointer transition-colors duration-100 group ${
                      isSelected
                        ? 'bg-blue-50/60 font-medium'
                        : 'hover:bg-slate-50'
                    }`}
                  >
                    {/* Column 1: Threat Level */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${badgeClass}`}
                      >
                        <IconComponent className="w-3.5 h-3.5" />
                        {levelLabel}
                      </span>
                    </td>

                    {/* Column 2: Sender */}
                    <td className="py-3 px-4">
                      <div
                        id={`sender-cell-${scan.id}`}
                        className="inline-block max-w-[190px] cursor-pointer group/sender"
                        onMouseEnter={(e) => handleSenderMouseEnter(scan, e)}
                        onMouseLeave={handleSenderMouseLeave}
                      >
                        <div className="font-semibold text-slate-900 truncate">
                          {scan.sender?.name || (scan.sender?.email ? scan.sender.email.split('@')[0] : 'Unknown Sender')}
                        </div>
                        <div className="text-[11px] text-slate-500 group-hover/sender:text-blue-600 truncate underline decoration-dotted decoration-slate-300 group-hover/sender:decoration-blue-500 transition-colors flex items-center gap-1">
                          <span className="truncate">{scan.sender?.email || 'unknown@domain.com'}</span>
                        </div>
                      </div>
                    </td>

                    {/* Column 3: Subject */}
                    <td className="py-3 px-4 max-w-xs sm:max-w-md">
                      <div className="font-medium text-slate-800 truncate group-hover:text-blue-600 transition-colors">
                        {scan.subject || '(No Subject)'}
                      </div>
                      <div className="text-[11px] text-slate-500 truncate">
                        {scan.classification} • {scan.attackVector}
                      </div>
                    </td>

                    {/* Column 4: Date */}
                    <td className="py-3 px-4 whitespace-nowrap text-slate-500 text-[11px] hidden md:table-cell">
                      {dateStr}
                    </td>

                    {/* Column 5: Risk Score */}
                    <td className="py-3 px-4 whitespace-nowrap text-right">
                      <div className="inline-flex items-center gap-2">
                        <span
                          className={`font-bold text-sm ${
                            isCritical
                              ? 'text-red-600'
                              : isSuspicious
                              ? 'text-amber-600'
                              : 'text-emerald-600'
                          }`}
                        >
                          {scan.riskScore}
                        </span>
                        <div className="w-12 bg-slate-100 h-1.5 rounded-full overflow-hidden hidden sm:block">
                          <div
                            className={`h-full ${
                              isCritical
                                ? 'bg-red-500'
                                : isSuspicious
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${Math.min(100, Math.max(5, scan.riskScore))}%` }}
                          />
                        </div>
                      </div>
                    </td>

                    {/* Column 6: Action */}
                    <td className="py-3 px-3 text-center whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectScan(scan.id);
                        }}
                        className={`p-1.5 rounded-md transition-colors ${
                          isSelected
                            ? 'bg-blue-600 text-white'
                            : 'text-slate-400 hover:text-slate-700 hover:bg-slate-200/60'
                        }`}
                        title="View Full Analysis"
                      >
                        <ArrowRight className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Hover Preview Floating Card for Sender Reputation & Threat Category */}
      <AnimatePresence>
        {hoveredSender && (() => {
          const scan = hoveredSender.scan;
          const reputationScore = Math.max(0, 100 - (scan.riskScore || 0));
          const isHighTrust = reputationScore >= 75;
          const isModerateTrust = reputationScore >= 45 && reputationScore < 75;
          const isUntrusted = reputationScore < 45;

          const repBadgeBg = isHighTrust
            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
            : isModerateTrust
            ? 'bg-amber-50 text-amber-700 border-amber-200'
            : 'bg-red-50 text-red-700 border-red-200';

          const repMeterBg = isHighTrust
            ? 'bg-emerald-500'
            : isModerateTrust
            ? 'bg-amber-500'
            : 'bg-red-500';

          const repStatusLabel = isHighTrust
            ? 'High Trust (Verified)'
            : isModerateTrust
            ? 'Moderate Risk'
            : 'Untrusted / Threat';

          const threatCat = scan.classification || 'Safe';
          const threatBadgeBg =
            threatCat === 'Safe'
              ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
              : threatCat === 'Phishing'
              ? 'bg-red-50 text-red-700 border-red-200'
              : threatCat === 'Malware Risk'
              ? 'bg-purple-50 text-purple-700 border-purple-200'
              : 'bg-amber-50 text-amber-700 border-amber-200';

          const spfPass = scan.headers?.spfStatus === 'pass';
          const dkimPass = scan.headers?.dkimStatus === 'pass';
          const dmarcPass = scan.headers?.dmarcStatus === 'pass';

          return (
            <motion.div
              id="sender-hover-preview-card"
              key={`sender-preview-${scan.id}`}
              initial={{ opacity: 0, scale: 0.96, y: hoveredSender.placement === 'bottom' ? -6 : 6 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96 }}
              transition={{ duration: 0.15, ease: 'easeOut' }}
              onMouseEnter={handlePopupMouseEnter}
              onMouseLeave={handlePopupMouseLeave}
              style={{
                position: 'fixed',
                left: `${hoveredSender.x}px`,
                ...(hoveredSender.placement === 'bottom'
                  ? { top: `${hoveredSender.y}px` }
                  : { bottom: `${window.innerHeight - hoveredSender.y}px` }),
              }}
              className="z-50 w-80 bg-white border border-slate-200/95 rounded-xl shadow-xl p-4 text-xs font-sans pointer-events-auto text-left"
            >
              {/* Header: Sender Identity */}
              <div id="sender-preview-header" className="pb-3 border-b border-slate-100">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                    Sender Reputation Intel
                  </span>
                  <span className="inline-flex items-center gap-1 text-[11px] text-slate-500 font-mono">
                    <Globe className="w-3 h-3 text-slate-400 shrink-0" />
                    <span className="truncate max-w-[120px]">{scan.sender?.domain || scan.sender?.email?.split('@')[1] || 'domain.com'}</span>
                  </span>
                </div>

                <div className="mt-1.5 font-semibold text-slate-900 text-sm truncate">
                  {scan.sender?.name || (scan.sender?.email ? scan.sender.email.split('@')[0] : 'Unknown Sender')}
                </div>
                <div className="text-[11px] text-blue-600 font-mono truncate select-all mt-0.5">
                  {scan.sender?.email}
                </div>
              </div>

              {/* Metric 1: Reputation Score */}
              <div id="sender-preview-reputation-section" className="py-3 border-b border-slate-100">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[11px] font-semibold text-slate-600">
                    Reputation Score
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${repBadgeBg}`}>
                    {repStatusLabel}
                  </span>
                </div>

                <div className="flex items-baseline gap-1.5">
                  <span className="text-2xl font-bold tracking-tight text-slate-900 tabular-nums">
                    {reputationScore}
                  </span>
                  <span className="text-[11px] text-slate-400 font-medium">/ 100</span>
                  <span className="ml-auto text-[10px] text-slate-500">
                    Risk: <strong className="text-slate-800">{scan.riskScore}/100</strong>
                  </span>
                </div>

                {/* Score Progress Bar */}
                <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden mt-1.5">
                  <div
                    className={`h-full transition-all duration-300 rounded-full ${repMeterBg}`}
                    style={{ width: `${Math.min(100, Math.max(4, reputationScore))}%` }}
                  />
                </div>
              </div>

              {/* Metric 2: Primary Threat Category & Attack Vector */}
              <div id="sender-preview-threat-category-section" className="py-3 border-b border-slate-100">
                <div className="text-[11px] font-semibold text-slate-600 mb-1.5">
                  Primary Threat Category
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border ${threatBadgeBg}`}>
                    {threatCat === 'Safe' ? (
                      <ShieldCheck className="w-3.5 h-3.5" />
                    ) : (
                      <ShieldAlert className="w-3.5 h-3.5" />
                    )}
                    {threatCat}
                  </span>
                  <span className="text-[11px] text-slate-500 text-right truncate max-w-[130px]" title={scan.attackVector}>
                    {scan.attackVector}
                  </span>
                </div>
              </div>

              {/* Metric 3: Authentication & Origin Security Footprint */}
              <div id="sender-preview-auth-section" className="pt-3">
                <div className="flex items-center justify-between text-[11px] text-slate-600 mb-1.5">
                  <span>Auth Verification</span>
                  <div className="flex items-center gap-1.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                      spfPass ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-700'
                    }`}>
                      SPF:{spfPass ? 'PASS' : 'FAIL'}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                      dkimPass ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-700'
                    }`}>
                      DKIM:{dkimPass ? 'PASS' : 'FAIL'}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                      dmarcPass ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-600'
                    }`}>
                      DMARC:{dmarcPass ? 'PASS' : (scan.headers?.dmarcStatus?.toUpperCase() || 'NONE')}
                    </span>
                  </div>
                </div>

                {/* Sender Origin IP / Geolocation */}
                <div className="flex items-center justify-between text-[10px] text-slate-500 mt-1">
                  <span className="flex items-center gap-1 truncate max-w-[150px]">
                    <MapPin className="w-3 h-3 text-slate-400 shrink-0" />
                    <span className="truncate">
                      {scan.senderLocation ? `${scan.senderLocation.city}, ${scan.senderLocation.country}` : 'Unknown Geolocation'}
                    </span>
                  </span>
                  <span className="font-mono text-slate-400 text-[10px]">
                    {scan.senderIp || scan.headers?.senderIp || 'N/A'}
                  </span>
                </div>

                <div className="mt-2.5 pt-2 border-t border-slate-100 flex items-center justify-between text-[10px] text-slate-400">
                  <span>Click email row for deep forensics</span>
                  <ArrowRight className="w-3 h-3 text-slate-400" />
                </div>
              </div>
            </motion.div>
          );
        })()}
      </AnimatePresence>
    </div>
  );
};
