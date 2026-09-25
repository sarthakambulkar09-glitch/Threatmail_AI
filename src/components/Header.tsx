import React from 'react';
import { User } from 'firebase/auth';
import { InsforgeStatus } from '../lib/insforgeClient';
import { RefreshCw, Bell, LogIn, Shield, CheckCircle2, ChevronDown, Menu, Radio, Mic } from 'lucide-react';

interface HeaderProps {
  user: User | null;
  insforgeStatus: InsforgeStatus | null;
  unreadCount: number;
  criticalCount: number;
  suspiciousCount: number;
  isScanning: boolean;
  isSyncing: boolean;
  onSyncGmail: () => void;
  onOpenNotifications: () => void;
  onOpenProfile: () => void;
  onLogin: () => void;
  onLogout: () => void;
  onToggleSidebar?: () => void;
  onOpenVoice?: () => void;
  onOpenLocationMonitor?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  user,
  insforgeStatus,
  unreadCount,
  criticalCount,
  suspiciousCount,
  isScanning,
  isSyncing,
  onSyncGmail,
  onOpenNotifications,
  onOpenProfile,
  onLogin,
  onToggleSidebar,
  onOpenVoice,
  onOpenLocationMonitor,
}) => {
  return (
    <header className="flex h-16 items-center justify-between border-b border-slate-200 bg-white px-4 sm:px-6 shrink-0 z-30 shadow-xs">
      {/* Brand Identity & Live Status */}
      <div className="flex items-center gap-3 sm:gap-4">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="md:hidden p-1.5 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 transition-colors"
            title="Toggle Navigation Menu"
          >
            <Menu className="w-5 h-5" />
          </button>
        )}

        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 text-white shadow-xs">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base sm:text-lg font-bold tracking-tight text-slate-900">
                ThreatMail <span className="text-blue-600">AI</span>
              </h1>
              <span className="hidden sm:inline-flex items-center gap-1 rounded-full bg-blue-50 px-2 py-0.5 text-[11px] font-semibold text-blue-700 border border-blue-200">
                Enterprise SOC
              </span>
            </div>
          </div>
        </div>

        {/* Live Protection & InsForge DB Status Indicators */}
        <div className="hidden lg:flex items-center gap-2 ml-4 pl-4 border-l border-slate-200">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-medium">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
            </span>
            <span>Live Protection Active</span>
          </div>

          <div
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-50 border border-amber-200 text-amber-800 text-xs font-medium"
            title="Connected to Cloud Firestore (ai-studio-threatmailai-795c09a4-f277-4c5a-93a0-c0150d293e7d)"
          >
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
            <span>Firestore DB</span>
          </div>
        </div>
      </div>

      {/* Center & Right Status & Actions */}
      <div className="flex items-center gap-3 sm:gap-4">
        {/* Severity Metrics Chips */}
        <div className="hidden xl:flex items-center gap-2.5 text-xs">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-50 border border-slate-200 text-slate-700">
            <span className="h-2 w-2 rounded-full bg-red-500" />
            <span className="font-semibold text-slate-900">{criticalCount}</span>
            <span className="text-slate-500">Critical</span>
          </div>
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-50 border border-slate-200 text-slate-700">
            <span className="h-2 w-2 rounded-full bg-amber-500" />
            <span className="font-semibold text-slate-900">{suspiciousCount}</span>
            <span className="text-slate-500">Suspicious</span>
          </div>
        </div>

        <div className="hidden sm:block h-6 w-px bg-slate-200" />

        {/* Sync Button */}
        {user && (
          <button
            onClick={onSyncGmail}
            disabled={isSyncing || isScanning}
            className="flex items-center gap-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 hover:text-slate-900 text-xs font-medium px-3 py-2 rounded-lg border border-slate-200 transition-colors disabled:opacity-50"
            title="Scan latest Gmail inbox messages"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-slate-600 ${isSyncing ? 'animate-spin text-blue-600' : ''}`} />
            <span className="hidden md:inline">{isSyncing ? 'Syncing...' : 'Sync Gmail'}</span>
          </button>
        )}

        {/* Real-time Location Monitoring Google Maps Trigger Button */}
        {onOpenLocationMonitor && (
          <button
            onClick={onOpenLocationMonitor}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border border-emerald-200 text-xs font-semibold shadow-2xs transition-colors"
            title="Real-Time Location Monitoring using Google Maps"
          >
            <Radio className="w-3.5 h-3.5 text-emerald-600 animate-pulse" />
            <span className="hidden sm:inline">GPS Monitor</span>
          </button>
        )}

        {/* Live Voice Assistant Trigger Button */}
        {onOpenVoice && (
          <button
            onClick={onOpenVoice}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs font-semibold shadow-2xs transition-colors"
            title="Launch Gemini 3.1 Flash Live Voice SOC Assistant"
          >
            <Radio className="w-3.5 h-3.5 text-rose-600 animate-pulse" />
            <span className="hidden sm:inline">Voice SOC</span>
          </button>
        )}

        {/* Notification Bell */}
        <button
          onClick={onOpenNotifications}
          className="relative p-2 rounded-lg bg-slate-50 hover:bg-slate-100 text-slate-600 hover:text-slate-900 border border-slate-200 transition-colors"
          title="Security Notifications"
        >
          <Bell className="w-4 h-4" />
          {unreadCount > 0 && (
            <span className="absolute -top-1 -right-1 h-4 min-w-4 px-1 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center shadow-xs">
              {unreadCount > 9 ? '9+' : unreadCount}
            </span>
          )}
        </button>

        {/* User Profile / Connect Gmail Button (Selected Element) */}
        <div id="header-auth-account-chip" className="flex items-center">
          {user ? (
            <div
              id="header-user-active-card"
              onClick={onOpenProfile}
              className="flex items-center gap-2.5 cursor-pointer pl-2 pr-3 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-all shadow-2xs group"
              title="Click to manage Gmail account & SOC credentials"
            >
              <div className="relative">
                {user.photoURL ? (
                  <img
                    src={user.photoURL}
                    alt="Profile"
                    className="h-7 w-7 rounded-full border border-slate-200 object-cover ring-2 ring-emerald-500/20 shadow-2xs"
                    referrerPolicy="no-referrer"
                  />
                ) : (
                  <div className="h-7 w-7 rounded-full bg-blue-600 border border-blue-700 flex items-center justify-center text-white text-xs font-bold ring-2 ring-emerald-500/20 shadow-2xs">
                    {user.email?.charAt(0).toUpperCase() || 'G'}
                  </div>
                )}
                <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-emerald-500 border-2 border-white" title="Gmail Live Link Active" />
              </div>
              <div className="text-left hidden sm:block">
                <div className="flex items-center gap-1.5">
                  <p className="text-xs font-semibold text-slate-900 leading-tight truncate max-w-[140px]">
                    {user.displayName || user.email?.split('@')[0]}
                  </p>
                  <span className="inline-flex items-center px-1.5 py-0.2 rounded text-[10px] font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">
                    Live
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 truncate max-w-[140px]">
                  {user.email}
                </p>
              </div>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-600 transition-colors hidden sm:block" />
            </div>
          ) : (
            <button
              id="header-connect-gmail-btn"
              onClick={onLogin}
              className="flex items-center gap-2 bg-white hover:bg-slate-50 text-slate-800 hover:text-slate-900 text-xs font-semibold px-3 py-2 rounded-lg border border-slate-300 shadow-2xs hover:border-slate-400 transition-all"
              title="Sign in with any Google email ID to access your private threat history"
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
              <span>Sign In with Google</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
