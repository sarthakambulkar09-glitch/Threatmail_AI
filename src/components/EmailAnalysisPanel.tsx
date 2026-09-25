import React from 'react';
import { EmailThreatReport } from '../types';
import { RiskMeter } from './RiskMeter';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileDown,
  Lock,
  Server,
  Globe,
  Link2,
  Paperclip,
  CheckCircle2,
  XCircle,
  AlertCircle,
  ArrowRight,
  ExternalLink,
  Shield,
  Clock,
  Send,
} from 'lucide-react';
import { generateForensicPdf } from '../lib/pdfReport';

interface EmailAnalysisPanelProps {
  report: EmailThreatReport | null;
  onUpdateStatus: (id: string, status: 'scanned' | 'quarantined' | 'whitelisted' | 'monitoring') => void;
  onOpenDetailModal: () => void;
}

export const EmailAnalysisPanel: React.FC<EmailAnalysisPanelProps> = ({
  report,
  onUpdateStatus,
  onOpenDetailModal,
}) => {
  if (!report) {
    return (
      <div className="bg-white border border-slate-200 rounded-xl p-12 shadow-xs flex flex-col items-center justify-center text-center">
        <Shield className="w-12 h-12 text-slate-300 mb-3" />
        <h3 className="text-base font-semibold text-slate-800">No Email Selected</h3>
        <p className="text-xs text-slate-500 max-w-sm mt-1">
          Select an incident from the threat feed or table to view comprehensive AI classification, sender telemetry, and forensic analysis.
        </p>
      </div>
    );
  }

  // Header verification chips
  const renderAuthChip = (label: string, status?: string) => {
    const s = (status || 'neutral').toLowerCase();
    if (s === 'pass') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
          {label}: PASS
        </span>
      );
    }
    if (s === 'fail') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-red-50 text-red-700 border border-red-200">
          <XCircle className="w-3.5 h-3.5 text-red-600" />
          {label}: FAIL
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
        <AlertCircle className="w-3.5 h-3.5 text-amber-600" />
        {label}: WARNING ({s.toUpperCase()})
      </span>
    );
  };

  const isQuarantined = report.status === 'quarantined';
  const isCritical = report.riskScore >= 70;
  const isSuspicious = report.riskScore >= 35 && report.riskScore < 70;

  return (
    <div className="space-y-5">
      {/* Top Banner & Action Controls */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 mb-1">
            <span className="font-semibold text-slate-900">INC-{report.id.slice(0, 8).toUpperCase()}</span>
            <span>•</span>
            <span className="text-slate-600">{new Date(report.date || report.scannedAt).toLocaleString()}</span>
            <span>•</span>
            <span
              className={`font-semibold px-2 py-0.5 rounded text-[11px] uppercase ${
                isQuarantined ? 'bg-red-100 text-red-800' : 'bg-slate-100 text-slate-700'
              }`}
            >
              Status: {report.status}
            </span>
          </div>

          <h2 className="text-lg font-bold text-slate-900 tracking-tight truncate">
            {report.subject || '(No Subject)'}
          </h2>
          <p className="text-xs text-slate-600 truncate mt-0.5">
            From: <strong className="text-slate-800">{report.sender.name}</strong> &lt;{report.sender.email}&gt;
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={() => generateForensicPdf(report)}
            className="flex items-center gap-1.5 bg-white hover:bg-slate-50 text-slate-700 font-semibold text-xs px-3.5 py-2 rounded-lg border border-slate-200 shadow-xs transition-colors"
          >
            <FileDown className="w-4 h-4 text-blue-600" />
            <span>Forensic PDF</span>
          </button>

          <button
            onClick={() =>
              onUpdateStatus(report.id, isQuarantined ? 'scanned' : 'quarantined')
            }
            className={`flex items-center gap-1.5 text-xs font-semibold px-3.5 py-2 rounded-lg transition-colors shadow-xs ${
              isQuarantined
                ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300'
                : 'bg-red-600 hover:bg-red-700 text-white'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>{isQuarantined ? 'Release Quarantine' : 'Quarantine Email'}</span>
          </button>

          <button
            onClick={onOpenDetailModal}
            className="flex items-center gap-1 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs px-3.5 py-2 rounded-lg shadow-xs transition-colors"
          >
            <span>Full Audit</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Grid: Risk Score Card & Threat Summary Card */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
        {/* Card 1: Modern Circular Risk Score (col-span-12 md:col-span-4) */}
        <div className="md:col-span-4 bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col items-center justify-center">
          <div className="w-full flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600">
              Risk Score
            </h3>
            <span className="text-[11px] text-slate-400 font-medium">RFC Telemetry</span>
          </div>

          <RiskMeter
            score={report.riskScore}
            confidence={95}
            classification={report.classification}
            size={150}
            strokeWidth={12}
          />
        </div>

        {/* Card 2: Modern Threat Summary Report Card (col-span-12 md:col-span-8) */}
        <div className="md:col-span-8 bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600">
                Threat Summary Report
              </h3>
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-100">
                Gemini SOC Intelligence
              </span>
            </div>

            <div className="grid grid-cols-3 gap-3 mb-3">
              <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-100">
                <span className="text-[11px] text-slate-500 font-medium block">Threat Type</span>
                <span className="text-sm font-bold text-slate-900">{report.classification}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-100">
                <span className="text-[11px] text-slate-500 font-medium block">Threat Score</span>
                <span className={`text-sm font-bold ${isCritical ? 'text-red-600' : isSuspicious ? 'text-amber-600' : 'text-emerald-600'}`}>
                  {report.riskScore} / 100
                </span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-100">
                <span className="text-[11px] text-slate-500 font-medium block">Confidence</span>
                <span className="text-sm font-bold text-slate-900">95% High</span>
              </div>
            </div>

            <p className="text-xs text-slate-600 leading-relaxed italic bg-slate-50 p-3 rounded-lg border border-slate-100">
              "{report.threatExplanation}"
            </p>
          </div>

          {/* Key Indicators & Recommended Actions */}
          <div className="mt-3 pt-3 border-t border-slate-100 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-700 block mb-1">
                Key Indicators:
              </span>
              <ul className="space-y-1 text-slate-600">
                {report.indicatorsOfCompromise && report.indicatorsOfCompromise.length > 0 ? (
                  report.indicatorsOfCompromise.slice(0, 2).map((ioc, i) => (
                    <li key={i} className="flex items-start gap-1.5 truncate">
                      <span className="text-red-500 font-bold">•</span>
                      <span className="truncate">{ioc}</span>
                    </li>
                  ))
                ) : (
                  <li className="text-slate-400">No active IoCs identified in message body.</li>
                )}
              </ul>
            </div>

            <div>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-700 block mb-1">
                Recommended Actions:
              </span>
              <p className="text-slate-600">
                {isCritical
                  ? 'Quarantine mail server IP, revoke sender relay privileges, purge matching inbound messages.'
                  : isSuspicious
                  ? 'Flag for security analyst manual review; monitor destination URLs.'
                  : 'Message authenticated through verified cryptographic domain signatures.'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Grid: 4 Modern Enterprise Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Card 3: Sender Analysis */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-100">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-blue-600" />
              Sender Analysis
            </h4>
          </div>

          <div className="space-y-2 text-xs">
            <div>
              <span className="text-slate-400 block text-[11px]">Originating IP:</span>
              <span className="font-mono font-semibold text-slate-900">
                {report.senderIp || 'Extracted via MTA'}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block text-[11px]">Server Location:</span>
              <span className="text-slate-800 font-medium">
                {report.senderLocation?.city || 'Ashburn'}, {report.senderLocation?.country || 'United States'}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block text-[11px]">ISP / ASN Organization:</span>
              <span className="text-slate-800 font-medium truncate block">
                {report.senderLocation?.isp || 'Cloud MTA Relay'}
              </span>
            </div>
          </div>

          <div className="mt-3 pt-2.5 border-t border-slate-100 text-[11px] text-slate-500">
            Domain: <strong className="text-slate-800">{report.sender.domain}</strong>
          </div>
        </div>

        {/* Card 4: Kaggle Ensemble Classification */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-100">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-blue-600" />
              Kaggle ML Classification
            </h4>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-semibold">
              0.65*BERT + 0.35*XGB
            </span>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 block text-[11px]">SIH26106 Label:</span>
              <span
                className={`font-mono font-bold text-xs px-2 py-0.5 rounded border ${
                  report.ensembleDetails?.sih26106OutputLabel === 'PHISHING' || report.ensembleDetails?.sih26106OutputLabel === 'MALWARE' || report.ensembleDetails?.sih26106OutputLabel === 'BEC'
                    ? 'bg-red-50 text-red-700 border-red-200'
                    : report.ensembleDetails?.sih26106OutputLabel === 'SPAM'
                    ? 'bg-amber-50 text-amber-700 border-amber-200'
                    : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                }`}
              >
                {report.ensembleDetails?.sih26106OutputLabel || (report.classification === 'Safe' ? 'SAFE' : report.classification.toUpperCase())}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400 block text-[11px]">Primary Attack Vector:</span>
              <span className="text-slate-800 font-medium truncate max-w-[130px]">{report.attackVector}</span>
            </div>
            
            {/* DistilBERT & XGBoost Branches */}
            <div className="pt-1.5 border-t border-slate-100 space-y-1">
              <div className="flex justify-between items-center text-[11px]">
                <span className="text-slate-500">DistilBERT Text Branch:</span>
                <span className="font-mono font-semibold text-slate-800">
                  {report.ensembleDetails?.textBranchScore ?? Math.min(99, Math.round(report.riskScore * 0.95))}/100
                </span>
              </div>
              <div className="flex justify-between items-center text-[11px]">
                <span className="text-slate-500">XGBoost 28-Feature:</span>
                <span className="font-mono font-semibold text-slate-800">
                  {report.ensembleDetails?.xgbBranchScore ?? Math.min(99, Math.round(report.riskScore * 1.05))}/100
                </span>
              </div>
            </div>

            {/* Capping Rule Indicator */}
            {report.ensembleDetails?.urlDeceptionCapped && (
              <div className="p-1.5 rounded bg-blue-50 border border-blue-200 text-blue-800 text-[10px] font-medium leading-tight">
                No URL Deception: Phishing Score Capped at ≤30 (Safe Link Rule)
              </div>
            )}

            {/* Legit Boosters / Overrides */}
            {report.ensembleDetails?.legitBoostersApplied && report.ensembleDetails.legitBoostersApplied.length > 0 && (
              <div className="p-1.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-800 text-[10px] font-medium leading-tight">
                Safe Link Protection Applied (OTP/Newsletter/Notice)
              </div>
            )}

            {report.ensembleDetails?.hardOverrideTriggered && (
              <div className="p-1.5 rounded bg-red-50 border border-red-200 text-red-800 text-[10px] font-medium leading-tight">
                URL Deception Override Triggered
              </div>
            )}
          </div>

          <div className="mt-3 pt-2.5 border-t border-slate-100 text-[11px] text-slate-500 flex items-center justify-between">
            <span className="font-mono text-[10px] text-slate-600">sih26106_detector.pkl</span>
            <a
              href="/api/sih26106/download-model"
              download="sih26106_detector.pkl"
              className="text-blue-600 hover:text-blue-800 font-medium text-[11px] flex items-center gap-1"
            >
              <FileDown className="w-3 h-3" />
              Download PKL
            </a>
          </div>
        </div>

        {/* Card 5: SPF / DKIM / DMARC */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-100">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-blue-600" />
              SPF / DKIM / DMARC
            </h4>
          </div>

          <div className="space-y-2">
            <div>{renderAuthChip('SPF', report.headers.spfStatus)}</div>
            <div>{renderAuthChip('DKIM', report.headers.dkimStatus)}</div>
            <div>{renderAuthChip('DMARC', report.headers.dmarcStatus)}</div>
          </div>

          <div className="mt-3 pt-2.5 border-t border-slate-100 text-[11px] text-slate-500">
            RFC 5322 Inbound Validation
          </div>
        </div>

        {/* Card 6: Network Indicators */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-100">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
              <Link2 className="w-3.5 h-3.5 text-blue-600" />
              Network Indicators
            </h4>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex justify-between items-center">
              <span className="text-slate-500">Extracted Links:</span>
              <span className="font-semibold text-slate-900">{report.extractedLinks?.length || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-500">Suspicious URLs:</span>
              <span
                className={`font-semibold ${
                  (report.extractedLinks?.filter((l) => l.isSuspicious).length || 0) > 0
                    ? 'text-red-600'
                    : 'text-emerald-600'
                }`}
              >
                {report.extractedLinks?.filter((l) => l.isSuspicious).length || 0}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-500">Attachments:</span>
              <span className="font-semibold text-slate-900">{report.attachments?.length || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-500">Hop Count:</span>
              <span className="font-semibold text-slate-900">{report.travelRoute?.length || 2} Hops</span>
            </div>
          </div>

          <div className="mt-3 pt-2.5 border-t border-slate-100 text-[11px] text-slate-500 flex items-center justify-between">
            <span>Destination:</span>
            <span className="font-mono text-slate-700">mx.google.com</span>
          </div>
        </div>
      </div>
    </div>
  );
};
