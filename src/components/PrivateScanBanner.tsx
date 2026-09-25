import React from 'react';
import { User } from 'firebase/auth';
import {
  Shield,
  Lock,
  UserCheck,
  LogOut,
  ArrowRightLeft,
  Inbox,
  FileText,
  RefreshCw,
  CheckCircle2,
} from 'lucide-react';

interface PrivateScanBannerProps {
  user: User | null;
  scansCount: number;
  isScanning: boolean;
  hasOAuthToken: boolean;
  onOpenLoginModal: () => void;
  onLogout: () => void;
  onScanLiveGmail: () => void;
  onOpenRealEmailScan: () => void;
}

export const PrivateScanBanner: React.FC<PrivateScanBannerProps> = ({
  user,
  scansCount,
  isScanning,
  hasOAuthToken,
  onOpenLoginModal,
  onLogout,
  onScanLiveGmail,
  onOpenRealEmailScan,
}) => {
  return (
    <div
      id="private-scan-isolation-banner"
      className="bg-white text-slate-900 border-b border-slate-200 px-4 sm:px-6 py-2.5 shadow-xs"
    >
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 bg-white">
        {/* Left Side: Identity Banner */}
        <div className="flex items-center flex-wrap gap-2.5">
          <div className="flex h-6 w-6 items-center justify-center rounded-md bg-blue-50 text-blue-600 border border-blue-200 shrink-0">
            <Lock className="w-3.5 h-3.5" />
          </div>

          <div className="flex items-center gap-2">
            {user ? (
              <h2 id="logged-in-email-display" className="text-xs sm:text-sm font-semibold tracking-tight text-slate-800 flex items-center gap-1.5">
                <span>My Scans - Logged in as:</span>
                <span className="font-mono text-emerald-700 font-bold bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                  {user.email}
                </span>
              </h2>
            ) : (
              <h2 id="logged-in-email-display" className="text-xs sm:text-sm font-semibold tracking-tight text-slate-800 flex items-center gap-1.5">
                <span>Threat Mailbox Scanner:</span>
                <span className="text-slate-500 font-normal">
                  Sign in with Google to view and scan your inbox
                </span>
              </h2>
            )}

            {user ? (
              <span className="hidden md:inline-flex items-center gap-1 text-[11px] font-medium bg-blue-50 text-blue-700 border border-blue-200 px-2 py-0.5 rounded-full">
                <Shield className="w-3 h-3 text-blue-600" />
                Actual Mailbox Scans
              </span>
            ) : (
              <span className="inline-flex items-center text-[11px] font-medium bg-amber-50 text-amber-800 border border-amber-200 px-2 py-0.5 rounded-full">
                Please sign in with Google to scan live emails
              </span>
            )}
          </div>

          {user && (
            <span className="text-xs text-slate-500 pl-1 font-medium">
              ({scansCount} {scansCount === 1 ? 'email' : 'emails'} in your account)
            </span>
          )}
        </div>

        {/* Right Side: Real Email Scanning Controls */}
        <div className="flex items-center flex-wrap gap-2 text-xs">
          {user ? (
            <>
              {/* Scan Live Gmail Inbox */}
              <button
                id="btn-scan-live-gmail"
                onClick={onScanLiveGmail}
                disabled={isScanning}
                className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-medium border border-blue-600 shadow-2xs transition-colors disabled:opacity-50"
                title={`Fetch and scan actual emails from ${user.email}'s Gmail inbox`}
              >
                {isScanning ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Inbox className="w-3.5 h-3.5" />
                )}
                <span>Scan Live Gmail Inbox</span>
              </button>

              {/* Scan / Paste Real Email */}
              <button
                id="btn-scan-real-email"
                onClick={onOpenRealEmailScan}
                disabled={isScanning}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-800 font-medium border border-slate-300 shadow-2xs transition-colors disabled:opacity-50"
                title="Inspect any actual email with RFC 822 headers and body"
              >
                <FileText className="w-3.5 h-3.5 text-slate-600" />
                <span>Analyze Real Email</span>
              </button>

              {/* Switch User */}
              <button
                id="btn-switch-account"
                onClick={onOpenLoginModal}
                disabled={isScanning}
                className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-white hover:bg-slate-50 text-slate-700 hover:text-slate-900 border border-slate-200 font-medium transition-colors"
                title="Switch logged-in email"
              >
                <ArrowRightLeft className="w-3 h-3 text-slate-600" />
                <span className="hidden sm:inline">Switch User</span>
              </button>

              {/* Logout */}
              <button
                id="btn-logout-banner"
                onClick={onLogout}
                className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-rose-50 hover:bg-rose-100 text-rose-700 hover:text-rose-800 border border-rose-200 font-medium transition-colors"
                title="Log out and secure session"
              >
                <LogOut className="w-3 h-3" />
                <span>Logout</span>
              </button>
            </>
          ) : (
            <button
              id="btn-login-banner"
              onClick={onOpenLoginModal}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-medium shadow-xs transition-colors"
            >
              <UserCheck className="w-3.5 h-3.5" />
              <span>Sign In with Google Email</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
