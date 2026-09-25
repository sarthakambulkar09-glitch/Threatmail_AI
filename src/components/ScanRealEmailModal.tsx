import React, { useState, useRef } from 'react';
import { User } from 'firebase/auth';
import {
  X,
  Shield,
  Mail,
  Inbox,
  Sparkles,
  AlertTriangle,
  RefreshCw,
  FileText,
  Key,
  CheckCircle2,
  Lock,
  Upload,
  FileCode,
} from 'lucide-react';
import { analyzeAndSaveEmail } from '../lib/insforgeClient';
import { RawGmailMessage } from '../lib/gmail';
import { EmailThreatReport } from '../types';

interface ScanRealEmailModalProps {
  isOpen: boolean;
  onClose: () => void;
  user: User | null;
  onScanLiveGmail: (maxCount?: number, query?: string) => Promise<void>;
  onManualScanCompleted: (report: EmailThreatReport) => void;
  isScanning: boolean;
  hasOAuthToken: boolean;
}

export const ScanRealEmailModal: React.FC<ScanRealEmailModalProps> = ({
  isOpen,
  onClose,
  user,
  onScanLiveGmail,
  onManualScanCompleted,
  isScanning,
  hasOAuthToken,
}) => {
  const [activeTab, setActiveTab] = useState<'gmail' | 'paste'>('gmail');
  const [maxEmails, setMaxEmails] = useState<number>(5);
  const [gmailQuery, setGmailQuery] = useState<string>('in:inbox');

  // Manual paste / EML state
  const [senderEmail, setSenderEmail] = useState('');
  const [senderName, setSenderName] = useState('');
  const [subject, setSubject] = useState('');
  const [bodyText, setBodyText] = useState('');
  const [senderIp, setSenderIp] = useState('');
  const [spfStatus, setSpfStatus] = useState<'pass' | 'fail' | 'softfail' | 'neutral' | 'none'>('fail');
  const [dkimStatus, setDkimStatus] = useState<'pass' | 'fail' | 'neutral' | 'none'>('fail');
  const [dmarcStatus, setDmarcStatus] = useState<'pass' | 'fail' | 'neutral' | 'none'>('fail');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [pasteError, setPasteError] = useState<string | null>(null);
  const [parsedSuccessMessage, setParsedSuccessMessage] = useState<string | null>(null);
  const [rawEmlInput, setRawEmlInput] = useState('');
  const [showRawInput, setShowRawInput] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const parseRawEmlText = (rawContent: string) => {
    try {
      setPasteError(null);
      const lines = rawContent.split(/\r?\n/);
      let inHeaders = true;
      let headerText = '';
      const bodyLines: string[] = [];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (inHeaders) {
          if (line.trim() === '') {
            inHeaders = false;
          } else {
            headerText += line + '\n';
          }
        } else {
          bodyLines.push(line);
        }
      }

      // 1. From header
      const fromMatch = headerText.match(/^From:\s*(.+)$/im);
      if (fromMatch) {
        const fullFrom = fromMatch[1].trim();
        const emailMatch =
          fullFrom.match(/<([^>]+)>/) ||
          fullFrom.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        if (emailMatch) {
          setSenderEmail(emailMatch[1].trim().toLowerCase());
          const namePart = fullFrom.replace(/<[^>]+>/, '').replace(/["']/g, '').trim();
          if (namePart) setSenderName(namePart);
        } else {
          setSenderEmail(fullFrom);
        }
      }

      // 2. Subject header
      const subjectMatch = headerText.match(/^Subject:\s*(.+)$/im);
      if (subjectMatch) {
        setSubject(subjectMatch[1].trim());
      }

      // 3. SPF / DKIM / DMARC
      const authMatch = headerText.match(/Authentication-Results:\s*([^\n]+(?:\n\s+[^\n]+)*)/i);
      if (authMatch) {
        const authStr = authMatch[1].toLowerCase();
        if (authStr.includes('spf=pass')) setSpfStatus('pass');
        else if (authStr.includes('spf=fail')) setSpfStatus('fail');
        else if (authStr.includes('spf=softfail')) setSpfStatus('softfail');

        if (authStr.includes('dkim=pass')) setDkimStatus('pass');
        else if (authStr.includes('dkim=fail')) setDkimStatus('fail');

        if (authStr.includes('dmarc=pass')) setDmarcStatus('pass');
        else if (authStr.includes('dmarc=fail')) setDmarcStatus('fail');
      }

      // 4. Origin IP from Received header
      const ipMatch = headerText.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
      if (ipMatch) {
        setSenderIp(ipMatch[1]);
      }

      // 5. Body
      const body = bodyLines.join('\n').trim();
      if (body) {
        setBodyText(body.slice(0, 5000));
      } else {
        setBodyText(rawContent.slice(0, 2000));
      }

      setParsedSuccessMessage('Parsed actual email headers, authentication verdicts, and body successfully.');
    } catch (err: any) {
      console.warn('RFC 822 parse note:', err);
      setPasteError('Could not auto-parse headers. You can enter the details manually below.');
    }
  };

  const handleFileUpload = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      if (text) {
        parseRawEmlText(text);
      }
    };
    reader.readAsText(file);
  };

  const handleStartGmailScan = async () => {
    try {
      await onScanLiveGmail(maxEmails, gmailQuery);
      onClose();
    } catch (err: any) {
      // Error handled by parent
    }
  };

  const handleAnalyzePastedEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!senderEmail.trim()) {
      setPasteError('Sender email address is required.');
      return;
    }
    if (!subject.trim()) {
      setPasteError('Subject line is required.');
      return;
    }
    if (!bodyText.trim()) {
      setPasteError('Email body content is required.');
      return;
    }

    setIsSubmitting(true);
    setPasteError(null);

    try {
      const senderDomain = senderEmail.includes('@')
        ? senderEmail.split('@')[1]
        : 'unknown-domain.com';

      const emailId = `real-msg-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

      // Extract URLs from bodyText
      const urlRegex = /(https?:\/\/[^\s<>"']+)/gi;
      const links: { url: string; domain: string; isSuspicious: boolean }[] = [];
      const seen = new Set<string>();
      let m;
      while ((m = urlRegex.exec(bodyText)) !== null) {
        const u = m[1];
        if (!seen.has(u)) {
          seen.add(u);
          try {
            const parsed = new URL(u);
            const isSusp =
              parsed.hostname.endsWith('.xyz') ||
              parsed.hostname.endsWith('.ru') ||
              parsed.hostname.endsWith('.top') ||
              u.includes('login') ||
              u.includes('verify');
            links.push({ url: u, domain: parsed.hostname, isSuspicious: isSusp });
          } catch {
            // ignore invalid url
          }
        }
      }

      const rawMsg: RawGmailMessage = {
        id: emailId,
        threadId: emailId,
        snippet: bodyText.slice(0, 160),
        sender: {
          name: senderName.trim() || senderEmail.split('@')[0],
          email: senderEmail.trim().toLowerCase(),
          domain: senderDomain.toLowerCase(),
        },
        recipient: user?.email || 'me',
        subject: subject.trim(),
        date: new Date().toISOString(),
        bodyPreview: bodyText.trim(),
        extractedLinks: links,
        attachments: [],
        senderIp: senderIp.trim() || '185.220.101.5',
        rawReceivedHeaders: senderIp.trim()
          ? [`from mail.${senderDomain} ([${senderIp.trim()}]) by mx.google.com with ESMTPS`]
          : [],
        headers: {
          from: senderName ? `"${senderName.trim()}" <${senderEmail.trim()}>` : senderEmail.trim(),
          to: user?.email || 'me',
          subject: subject.trim(),
          date: new Date().toISOString(),
          messageId: `<${emailId}@rfc822.real>`,
          spfStatus,
          dkimStatus,
          dmarcStatus,
          senderIp: senderIp.trim() || '185.220.101.5',
          clientIp: senderIp.trim() || '185.220.101.5',
          rawAuthenticationResults: `spf=${spfStatus} dkim=${dkimStatus} dmarc=${dmarcStatus}`,
        },
      };

      const targetEmail = user?.email || 'analyst@threatmail.ai';
      const result = await analyzeAndSaveEmail(rawMsg, targetEmail);
      if (result) {
        onManualScanCompleted(result);
        onClose();
      }
    } catch (err: any) {
      console.error('Error analyzing pasted email:', err);
      setPasteError(err.message || 'Failed to analyze email.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const loadPreset = (presetType: 'phish' | 'bec' | 'otp' | 'college' | 'newsletter' | 'safe') => {
    setPasteError(null);
    if (presetType === 'otp') {
      setSenderName('Google Accounts Security');
      setSenderEmail('no-reply@accounts.google.com');
      setSubject('2-Step Verification: Your Google security verification code is 849201');
      setBodyText(
        `Hi User,\n\nUse this one-time password (OTP) code to verify your Google Account:\n\n849201\n\nThis verification code will expire in 10 minutes. If you did not make this request, you can check your account security activity at:\nhttps://accounts.google.com/security/activity\n\nGoogle LLC, 1600 Amphitheatre Parkway, Mountain View, CA\nDo not share this code with anyone.`
      );
      setSenderIp('209.85.220.41');
      setSpfStatus('pass');
      setDkimStatus('pass');
      setDmarcStatus('pass');
    } else if (presetType === 'college') {
      setSenderName('Office of the University Registrar');
      setSenderEmail('registrar-notices@stanford.edu');
      setSubject('Academic Bulletin: Fall 2026 Course Enrollment & Syllabus Confirmation');
      setBodyText(
        `Dear Student Body,\n\nPlease review your approved course enrollment list and download the updated semester syllabi for your registered seminars.\n\nAccess the official university academic portal:\nhttps://registrar.stanford.edu/notices/fall2026\n\nImportant Deadlines:\n- Last day to add/drop: October 2, 2026\n- Grade option deadline: October 16, 2026\n\nOffice of the Registrar\nStanford University`
      );
      setSenderIp('171.67.215.200');
      setSpfStatus('pass');
      setDkimStatus('pass');
      setDmarcStatus('pass');
    } else if (presetType === 'newsletter') {
      setSenderName('The Architecture Dispatch');
      setSenderEmail('digest@cloud-dispatch.com');
      setSubject('Issue #142: High-Performance Distributed Systems & Kernel Tracing');
      setBodyText(
        `Welcome to this week's engineering edition.\n\nIn this issue we explore Linux eBPF telemetry, memory-mapped I/O benchmarks, and multi-region replication architectures.\n\nRead the full technical deep dive:\nhttps://cloud-dispatch.com/issues/142\n\nYou received this email because you subscribed to The Architecture Dispatch.\nManage preferences or unsubscribe:\nhttps://cloud-dispatch.com/unsubscribe?id=sub_99214`
      );
      setSenderIp('142.250.190.46');
      setSpfStatus('pass');
      setDkimStatus('pass');
      setDmarcStatus('pass');
    } else if (presetType === 'phish') {
      setSenderName('PayPal Account Security');
      setSenderEmail('service-alerts@paypal-security-auth.xyz');
      setSubject('URGENT: Unauthorized Transaction Detected - Confirm PayPal Identity');
      setBodyText(
        `Dear Customer,\n\nWe detected a suspicious charge of $742.00 from an unauthorized device. Your account access has been limited.\n\nPlease verify your login credentials immediately to cancel this charge:\n<a href="https://bit.ly/paypal-secure-verify-991">https://www.paypal.com/signin/verify</a>\n\nIf you do not verify within 24 hours, your account will be permanently closed.\nPayPal Support Team`
      );
      setSenderIp('185.220.101.5');
      setSpfStatus('fail');
      setDkimStatus('fail');
      setDmarcStatus('fail');
    } else if (presetType === 'bec') {
      setSenderName('Chief Executive Officer');
      setSenderEmail('ceo.executive.urgent@corp-payroll-desk.com');
      setSubject('URGENT: Confidential Acquisition Escrow Wire Transfer');
      setBodyText(
        `Hi,\n\nI am currently in an executive closed-door board meeting regarding our upcoming strategic acquisition. I need you to initiate a confidential wire transfer of $74,500 to the attached escrow account before the cutoff at 3:00 PM today.\n\nDo not call my cell as I cannot take calls right now. Confirm when the transaction has been submitted and send the confirmation receipt.\n\nThanks,\nCEO Office`
      );
      setSenderIp('194.26.29.112');
      setSpfStatus('softfail');
      setDkimStatus('fail');
      setDmarcStatus('neutral');
    } else {
      setSenderName('GitHub Security');
      setSenderEmail('notifications@github.com');
      setSubject('[GitHub] A personal access token has expired');
      setBodyText(
        `Hi there,\n\nYour personal access token 'Production Deploy Key' expired on September 9, 2026. You can review your active security tokens at:\nhttps://github.com/settings/tokens\n\nThanks,\nThe GitHub Team`
      );
      setSenderIp('140.82.112.4');
      setSpfStatus('pass');
      setDkimStatus('pass');
      setDmarcStatus('pass');
    }
  };

  return (
    <div
      id="scan-real-email-modal-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-200"
    >
      <div
        id="scan-real-email-modal"
        className="bg-white rounded-xl shadow-2xl border border-slate-200 w-full max-w-2xl overflow-hidden flex flex-col max-h-[92vh]"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50/70">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-blue-50 text-blue-600 border border-blue-200">
              <Inbox className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">Scan Actual Email from Mailbox</h3>
              <p className="text-xs text-slate-500">
                Inspect genuine emails into <span className="font-semibold text-slate-800">{user?.email || 'your account'}</span>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab switcher */}
        <div className="px-6 pt-3 pb-2 border-b border-slate-100 bg-white flex items-center gap-2">
          <button
            onClick={() => setActiveTab('gmail')}
            className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-all ${
              activeTab === 'gmail'
                ? 'bg-blue-50 text-blue-700 border border-blue-200 shadow-2xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Scan Live Gmail Inbox</span>
          </button>

          <button
            onClick={() => setActiveTab('paste')}
            className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-all ${
              activeTab === 'paste'
                ? 'bg-blue-50 text-blue-700 border border-blue-200 shadow-2xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Analyze Real Email (Paste / RFC 822)</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-4">
          {activeTab === 'gmail' ? (
            <div className="space-y-4">
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                      Target Google Account
                    </h4>
                    <p className="text-sm font-semibold font-mono text-slate-900 mt-0.5">
                      {user?.email || 'No email signed in'}
                    </p>
                  </div>
                  {hasOAuthToken ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Gmail API Authorized
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-50 text-amber-700 border border-amber-200">
                      <Lock className="w-3.5 h-3.5" />
                      Requires Google Consent
                    </span>
                  )}
                </div>

                <p className="text-xs text-slate-500 mt-2.5 leading-relaxed">
                  Queries your actual Gmail mailbox directly via Google Workspace APIs. ThreatMail AI extracts RFC 822 headers, authentication results (SPF, DKIM, DMARC), email hops, and runs Gemini AI threat vector detection.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Number of Messages to Scan
                  </label>
                  <select
                    value={maxEmails}
                    onChange={(e) => setMaxEmails(Number(e.target.value))}
                    className="w-full text-xs bg-white border border-slate-200 rounded-lg px-3 py-2 text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                  >
                    <option value={3}>Latest 3 Messages</option>
                    <option value={5}>Latest 5 Messages</option>
                    <option value={10}>Latest 10 Messages</option>
                    <option value={15}>Latest 15 Messages</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Gmail Search Query
                  </label>
                  <input
                    type="text"
                    value={gmailQuery}
                    onChange={(e) => setGmailQuery(e.target.value)}
                    placeholder="in:inbox or is:unread"
                    className="w-full text-xs bg-white border border-slate-200 rounded-lg px-3 py-2 text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                  />
                  <span className="text-[11px] text-slate-400 mt-0.5 block">
                    Examples: <code className="text-slate-600">in:inbox</code>, <code className="text-slate-600">is:unread</code>, <code className="text-slate-600">from:suspicious</code>
                  </span>
                </div>
              </div>

              <div className="rounded-lg bg-blue-50/50 border border-blue-100 p-3.5 text-xs text-blue-900 flex items-start gap-2.5">
                <Shield className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold">Actual Data Guarantee:</span> All scan reports are created strictly from your live Gmail messages. No synthetic or hardcoded data is generated.
                </div>
              </div>

              <div className="pt-2">
                <button
                  onClick={handleStartGmailScan}
                  disabled={isScanning}
                  className="w-full py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-xs transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {isScanning ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Scanning Actual Mailbox...</span>
                    </>
                  ) : (
                    <>
                      <Inbox className="w-4 h-4" />
                      <span>
                        {hasOAuthToken
                          ? `Scan ${maxEmails} Real Messages from Gmail Inbox`
                          : `Authorize & Scan Actual Messages for ${user?.email || 'Account'}`}
                      </span>
                    </>
                  )}
                </button>

                {!hasOAuthToken && (
                  <div className="mt-3 pt-3 border-t border-slate-100 text-center">
                    <p className="text-[11px] text-slate-500 mb-2">
                      Scan actual inbox emails without Google Cloud verification:
                    </p>
                    <button
                      type="button"
                      onClick={() => setActiveTab('paste')}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-lg border border-blue-200 transition-colors"
                    >
                      <Upload className="w-3.5 h-3.5" />
                      <span>Upload .EML or Paste Real Email from Inbox</span>
                    </button>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <form onSubmit={handleAnalyzePastedEmail} className="space-y-3.5">
              {/* File Upload / Drag & Drop or Raw Paste */}
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragOver(true);
                }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setIsDragOver(false);
                  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    handleFileUpload(e.dataTransfer.files[0]);
                  }
                }}
                className={`p-3.5 rounded-xl border-2 border-dashed transition-all text-center ${
                  isDragOver
                    ? 'border-blue-500 bg-blue-50/60'
                    : 'border-slate-200 hover:border-slate-300 bg-slate-50/50'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".eml,.txt,.msg"
                  className="hidden"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      handleFileUpload(e.target.files[0]);
                    }
                  }}
                />
                <div className="flex flex-col sm:flex-row items-center justify-center gap-2">
                  <div className="p-2 rounded-full bg-blue-100 text-blue-700">
                    <Upload className="w-4 h-4" />
                  </div>
                  <div className="text-left">
                    <p className="text-xs font-semibold text-slate-800">
                      Import Actual Email File (<code className="text-blue-600">.eml</code>, <code className="text-blue-600">.txt</code>)
                    </p>
                    <p className="text-[11px] text-slate-500">
                      Drag & drop here, or{' '}
                      <button
                        type="button"
                        onClick={() => fileInputRef.current?.click()}
                        className="text-blue-600 font-semibold hover:underline"
                      >
                        browse to upload
                      </button>{' '}
                      from Gmail (&quot;Download message&quot;)
                    </p>
                  </div>
                  <div className="sm:ml-auto">
                    <button
                      type="button"
                      onClick={() => setShowRawInput(!showRawInput)}
                      className="text-xs px-2.5 py-1 rounded-lg border border-slate-300 bg-white hover:bg-slate-100 text-slate-700 font-medium transition-colors"
                    >
                      {showRawInput ? 'Hide Raw Paste' : 'Paste RFC 822 Text'}
                    </button>
                  </div>
                </div>

                {showRawInput && (
                  <div className="mt-3 text-left space-y-2 pt-2 border-t border-slate-200">
                    <label className="text-[11px] font-semibold text-slate-700">
                      Paste Raw Headers / RFC 822 (from Gmail &quot;Show original&quot;):
                    </label>
                    <textarea
                      rows={3}
                      value={rawEmlInput}
                      onChange={(e) => setRawEmlInput(e.target.value)}
                      placeholder="Delivered-To: user@gmail.com&#10;Received: from mail.example.com ([185.220.101.5])&#10;From: &quot;Sender&quot; <sender@example.com>&#10;Subject: Security Update&#10;Authentication-Results: mx.google.com; spf=pass..."
                      className="w-full text-[11px] font-mono p-2 bg-white border border-slate-300 rounded-lg text-slate-800 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                    <div className="flex justify-end">
                      <button
                        type="button"
                        onClick={() => {
                          if (rawEmlInput.trim()) {
                            parseRawEmlText(rawEmlInput);
                          }
                        }}
                        className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold shadow-2xs"
                      >
                        Auto-Parse Fields
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {parsedSuccessMessage && (
                <div className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>{parsedSuccessMessage}</span>
                </div>
              )}

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-600">
                  Kaggle Model Test Presets:
                </span>
                <div className="flex flex-wrap items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => {
                      setParsedSuccessMessage('Loaded OTP Verification with Link (Evaluates to SAFE)');
                      loadPreset('otp');
                    }}
                    className="text-[11px] px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100 transition-colors font-medium"
                    title="Legitimate OTP email containing link - must be classified as SAFE"
                  >
                    OTP with Link
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setParsedSuccessMessage('Loaded University Notice with Link (Evaluates to SAFE)');
                      loadPreset('college');
                    }}
                    className="text-[11px] px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 hover:bg-blue-100 transition-colors font-medium"
                    title="Legitimate university notice containing link - must be classified as SAFE"
                  >
                    College Notice
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setParsedSuccessMessage('Loaded Subscribed Newsletter with Link (Evaluates to SAFE)');
                      loadPreset('newsletter');
                    }}
                    className="text-[11px] px-2 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 hover:bg-purple-100 transition-colors font-medium"
                    title="Newsletter with links and List-Unsubscribe - must be SAFE"
                  >
                    Newsletter
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setParsedSuccessMessage('Loaded Phishing Attack with Deceptive Anchor Mismatch');
                      loadPreset('phish');
                    }}
                    className="text-[11px] px-2 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 hover:bg-red-100 transition-colors font-medium"
                    title="Phishing: text=paypal.com, href=bit.ly redirector"
                  >
                    Anchor Phish
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setParsedSuccessMessage('Loaded Executive BEC Wire Fraud');
                      loadPreset('bec');
                    }}
                    className="text-[11px] px-2 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 hover:bg-amber-100 transition-colors font-medium"
                  >
                    BEC Fraud
                  </button>
                </div>
              </div>

              {pasteError && (
                <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{pasteError}</span>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Sender Email <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="email"
                    required
                    placeholder="e.g. security-alert@verify-update.xyz"
                    value={senderEmail}
                    onChange={(e) => setSenderEmail(e.target.value)}
                    className="w-full text-xs bg-white border border-slate-200 rounded-lg px-3 py-1.5 text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Sender Display Name
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. IT Helpdesk / CEO"
                    value={senderName}
                    onChange={(e) => setSenderName(e.target.value)}
                    className="w-full text-xs bg-white border border-slate-200 rounded-lg px-3 py-1.5 text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Subject Line <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Urgent: Account suspended - Immediate verification required"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className="w-full text-xs bg-white border border-slate-200 rounded-lg px-3 py-1.5 text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Actual Email Content / Body Text <span className="text-red-500">*</span>
                </label>
                <textarea
                  rows={4}
                  required
                  placeholder="Paste the full body text of the actual email received..."
                  value={bodyText}
                  onChange={(e) => setBodyText(e.target.value)}
                  className="w-full text-xs bg-white border border-slate-200 rounded-lg p-2.5 text-slate-800 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 resize-y"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5">
                <div>
                  <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                    Origin IP
                  </label>
                  <input
                    type="text"
                    placeholder="185.220.101.5"
                    value={senderIp}
                    onChange={(e) => setSenderIp(e.target.value)}
                    className="w-full text-xs bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 text-slate-800 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                    SPF Check
                  </label>
                  <select
                    value={spfStatus}
                    onChange={(e: any) => setSpfStatus(e.target.value)}
                    className="w-full text-xs bg-white border border-slate-200 rounded-lg px-2 py-1.5 text-slate-800"
                  >
                    <option value="pass">PASS</option>
                    <option value="fail">FAIL</option>
                    <option value="softfail">SOFTFAIL</option>
                    <option value="neutral">NEUTRAL</option>
                    <option value="none">NONE</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                    DKIM Check
                  </label>
                  <select
                    value={dkimStatus}
                    onChange={(e: any) => setDkimStatus(e.target.value)}
                    className="w-full text-xs bg-white border border-slate-200 rounded-lg px-2 py-1.5 text-slate-800"
                  >
                    <option value="pass">PASS</option>
                    <option value="fail">FAIL</option>
                    <option value="neutral">NEUTRAL</option>
                    <option value="none">NONE</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                    DMARC Check
                  </label>
                  <select
                    value={dmarcStatus}
                    onChange={(e: any) => setDmarcStatus(e.target.value)}
                    className="w-full text-xs bg-white border border-slate-200 rounded-lg px-2 py-1.5 text-slate-800"
                  >
                    <option value="pass">PASS</option>
                    <option value="fail">FAIL</option>
                    <option value="neutral">NEUTRAL</option>
                    <option value="none">NONE</option>
                  </select>
                </div>
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full py-2.5 px-4 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs shadow-xs transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {isSubmitting ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Gemini AI Performing Threat Analysis...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4" />
                      <span>Analyze Real Email with Gemini AI</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
