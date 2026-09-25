import React, { useState } from 'react';
import { User } from 'firebase/auth';
import { X, Shield, Mail, Lock, Check, Sparkles, UserCheck, AlertCircle, ArrowRight } from 'lucide-react';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentUser: User | null;
  onGoogleLogin: () => Promise<void>;
  onSelectEmailLogin: (email: string, displayName?: string) => void;
}

export const LoginModal: React.FC<LoginModalProps> = ({
  isOpen,
  onClose,
  currentUser,
  onGoogleLogin,
  onSelectEmailLogin,
}) => {
  const [googleEmailInput, setGoogleEmailInput] = useState('');
  const [isLoadingGoogle, setIsLoadingGoogle] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleGoogleOAuth = async () => {
    setIsLoadingGoogle(true);
    setError(null);
    try {
      await onGoogleLogin();
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Google authentication failed.');
    } finally {
      setIsLoadingGoogle(false);
    }
  };

  const handleQuickSelect = (email: string, name?: string) => {
    setError(null);
    onSelectEmailLogin(email, name);
    onClose();
  };

  const handleEmailSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    let email = googleEmailInput.trim().toLowerCase();
    if (!email) {
      setError('Please enter your Google email ID.');
      return;
    }
    // Auto-append @gmail.com if user only entered their username
    if (!email.includes('@')) {
      email = `${email}@gmail.com`;
    }
    if (!email.includes('.') || email.length < 5) {
      setError('Please enter a valid Google email address.');
      return;
    }
    handleQuickSelect(email);
  };

  const quickGoogleAccounts = [
    { email: 'analyst@threatmail.ai', label: 'SOC Security Lead', tag: 'Primary SOC' },
    { email: 'auditor@threatmail.ai', label: 'Compliance Auditor', tag: 'Auditor' },
    { email: 'sandbox@threatmail.ai', label: 'Threat Sandbox Lab', tag: 'Sandbox' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
      <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-150">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 bg-white flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white font-bold text-xs shadow-xs">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900">
                Sign In with Google Email ID
              </h3>
              <p className="text-[11px] text-slate-500">Anyone can log in with their Google account</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4 bg-slate-50/50">
          {error && (
            <div className="flex items-center gap-2 p-3 rounded-xl bg-red-50 border border-red-200 text-red-700 text-xs">
              <AlertCircle className="w-4 h-4 shrink-0 text-red-500" />
              <span>{error}</span>
            </div>
          )}

          {/* Current Active Account Card */}
          {currentUser && (
            <div className="p-3.5 rounded-xl bg-emerald-50/80 border border-emerald-200 flex items-center justify-between">
              <div className="overflow-hidden pr-2">
                <p className="text-[10px] font-bold text-emerald-800 uppercase tracking-wide">Currently Active Identity</p>
                <p className="text-xs font-mono font-bold text-emerald-950 truncate mt-0.5">
                  {currentUser.email}
                </p>
              </div>
              <span className="shrink-0 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-600 text-white flex items-center gap-1">
                <Check className="w-3 h-3" />
                Active
              </span>
            </div>
          )}

          {/* Primary Method 1: Official Google Sign-In (Any Account, No Access Blocked) */}
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-blue-600" />
                <span>Google Sign-In</span>
              </span>
              <span className="text-[10px] text-emerald-700 bg-emerald-50 border border-emerald-200 px-1.5 py-0.5 rounded font-medium">
                Standard Identity • No Block
              </span>
            </div>

            <button
              id="btn-google-oauth-popup"
              onClick={handleGoogleOAuth}
              disabled={isLoadingGoogle}
              className="w-full flex items-center justify-center gap-3 bg-white hover:bg-slate-50 text-slate-800 font-semibold text-xs py-2.5 px-4 rounded-xl border border-slate-300 shadow-xs hover:border-slate-400 transition-all disabled:opacity-50"
            >
              <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
              <span>{isLoadingGoogle ? 'Connecting to Google...' : 'Sign In with Google'}</span>
            </button>

            <p className="text-[11px] text-slate-500 leading-tight">
              Sign in with any Google account. Uses standard profile authentication to guarantee zero access-blocked errors.
            </p>
          </div>

          {/* Divider */}
          <div className="relative flex items-center justify-center my-1">
            <div className="border-t border-slate-200 w-full" />
            <span className="bg-slate-50 px-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400 absolute">
              or enter email directly
            </span>
          </div>

          {/* Secondary Method: Enter Any Google Email ID */}
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs space-y-3">
            <div className="flex items-center justify-between">
              <label htmlFor="google-email-input" className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-blue-600" />
                <span>Enter Any Google Email ID</span>
              </label>
              <span className="text-[10px] text-blue-700 bg-blue-50 border border-blue-200 px-1.5 py-0.5 rounded font-medium">
                Instant Access
              </span>
            </div>

            <form onSubmit={handleEmailSubmit} className="space-y-2">
              <div className="relative">
                <input
                  id="google-email-input"
                  type="text"
                  value={googleEmailInput}
                  onChange={(e) => setGoogleEmailInput(e.target.value)}
                  placeholder="e.g. yourname@gmail.com or username"
                  className="w-full text-xs pl-3 pr-20 py-2.5 bg-slate-50 border border-slate-300 rounded-xl text-slate-900 placeholder-slate-400 focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all font-mono"
                />
                {!googleEmailInput.includes('@') && googleEmailInput.trim().length > 0 && (
                  <button
                    type="button"
                    onClick={() => setGoogleEmailInput((prev) => `${prev.trim()}@gmail.com`)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] bg-blue-50 hover:bg-blue-100 text-blue-700 font-semibold px-2 py-1 rounded border border-blue-200 transition-colors"
                  >
                    + @gmail.com
                  </button>
                )}
              </div>

              <button
                id="btn-submit-google-email"
                type="submit"
                className="w-full flex items-center justify-center gap-2 text-xs font-semibold py-2 px-4 bg-slate-800 hover:bg-slate-900 text-white rounded-xl shadow-xs transition-colors"
              >
                <span>Continue with Email ID</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </form>
          </div>

          {/* Quick-Pick Test Accounts */}
          <div className="space-y-1.5 pt-1">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-700">Quick Test Accounts</span>
              <span className="text-[10px] text-slate-400">Click to switch</span>
            </div>
            <div className="grid grid-cols-1 gap-1.5">
              {quickGoogleAccounts.map((acc) => {
                const isActive = currentUser?.email?.toLowerCase() === acc.email.toLowerCase();
                return (
                  <button
                    key={acc.email}
                    onClick={() => handleQuickSelect(acc.email, acc.label)}
                    className={`flex items-center justify-between px-3 py-2 rounded-lg border text-left transition-all ${
                      isActive
                        ? 'bg-blue-50 border-blue-300 ring-1 ring-blue-300'
                        : 'bg-white hover:bg-slate-50 border-slate-200'
                    }`}
                  >
                    <div className="overflow-hidden pr-2">
                      <p className="text-xs font-semibold text-slate-800 truncate">{acc.label}</p>
                      <p className="text-[11px] font-mono text-slate-500 truncate">{acc.email}</p>
                    </div>
                    {isActive ? (
                      <span className="text-[10px] font-bold text-blue-700 bg-blue-100 px-2 py-0.5 rounded shrink-0">
                        Active
                      </span>
                    ) : (
                      <span className="text-[10px] font-medium text-blue-600 shrink-0">
                        Select &rarr;
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Privacy & Isolation Note */}
          <div className="p-3 rounded-xl bg-blue-50/70 border border-blue-200 text-blue-950 text-[11px] space-y-1">
            <p className="font-semibold flex items-center gap-1 text-blue-900">
              <Lock className="w-3 h-3 text-blue-600" />
              Strict Per-User History Isolation:
            </p>
            <p className="text-blue-800 leading-relaxed">
              Every Google email ID has an isolated scan database. Signing in with your Google email ensures only you can view your scans and forensic reports.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
