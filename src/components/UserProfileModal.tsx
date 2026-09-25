import React from 'react';
import { User } from 'firebase/auth';
import { X, LogOut, CheckCircle2, Shield, Key, Mail, Database } from 'lucide-react';
import { InsforgeStatus } from '../lib/insforgeClient';

interface UserProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  user: User | null;
  onLogout: () => void;
  onSwitchAccount?: () => void;
  insforgeStatus: InsforgeStatus | null;
}

export const UserProfileModal: React.FC<UserProfileModalProps> = ({
  isOpen,
  onClose,
  user,
  onLogout,
  onSwitchAccount,
  insforgeStatus,
}) => {
  if (!isOpen || !user) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs">
      <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 bg-white flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 font-bold text-white text-xs shadow-xs">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900">
                SOC Analyst Profile
              </h3>
              <p className="text-[11px] text-slate-500">Security Credentials &amp; Engine</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4 bg-slate-50/50">
          {/* User Info Card */}
          <div className="flex items-center gap-3.5 p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs">
            {user.photoURL ? (
              <img
                src={user.photoURL}
                alt={user.displayName || 'User'}
                className="w-12 h-12 rounded-full border border-slate-200 object-cover"
                referrerPolicy="no-referrer"
              />
            ) : (
              <div className="w-12 h-12 rounded-full bg-blue-100 border border-blue-200 flex items-center justify-center text-blue-700 font-bold text-lg">
                {user.email?.charAt(0).toUpperCase() || 'A'}
              </div>
            )}
            <div className="overflow-hidden">
              <h4 className="text-sm font-bold text-slate-900 truncate">
                {user.displayName || 'SOC Security Analyst'}
              </h4>
              <p className="text-xs text-slate-500 truncate flex items-center gap-1 mt-0.5">
                <Mail className="w-3 h-3 text-slate-400" />
                {user.email}
              </p>
              <div className="flex items-center gap-1.5 mt-1.5">
                <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                  <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                  Authenticated Analyst
                </span>
              </div>
            </div>
          </div>

          {/* Connected Firebase & Cloud Infrastructure Details */}
          <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2.5">
            <h5 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5 pb-2 border-b border-slate-100">
              <Database className="w-3.5 h-3.5 text-blue-600" />
              Connected Threat Infrastructure
            </h5>

            <div className="flex justify-between text-xs py-1">
              <span className="text-slate-500">Authentication:</span>
              <span className="font-semibold text-emerald-700 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                Firebase Auth (Google Sign-In)
              </span>
            </div>

            <div className="flex justify-between text-xs py-1">
              <span className="text-slate-500">Security Database:</span>
              <span className="font-semibold text-amber-700 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                Cloud Firestore (Persistent)
              </span>
            </div>

            <div className="flex justify-between text-xs py-1">
              <span className="text-slate-500">Firestore DB ID:</span>
              <span className="font-mono text-[10px] text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded truncate max-w-[200px]" title="ai-studio-threatmailai-795c09a4-f277-4c5a-93a0-c0150d293e7d">
                ai-studio-threatmailai-795c...
              </span>
            </div>

            <div className="flex justify-between text-xs py-1">
              <span className="text-slate-500">User UID:</span>
              <span className="font-mono text-[10px] text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded truncate max-w-[200px]">
                {user.uid}
              </span>
            </div>

            <div className="flex justify-between text-xs py-1">
              <span className="text-slate-500">AI Threat Intelligence:</span>
              <span className="font-semibold text-blue-600">
                gemini-3.5-flash
              </span>
            </div>

            <div className="flex justify-between text-xs py-1">
              <span className="text-slate-500">Maps Grounding Tool:</span>
              <span className="text-emerald-700 font-semibold text-[11px] flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                Active (googleMaps tool)
              </span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-white border-t border-slate-200 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                onLogout();
                onClose();
              }}
              className="flex items-center gap-1.5 text-xs font-semibold text-red-600 hover:bg-red-50 px-3 py-2 rounded-lg border border-red-200 transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign Out</span>
            </button>

            {onSwitchAccount && (
              <button
                onClick={() => {
                  onClose();
                  onSwitchAccount();
                }}
                className="flex items-center gap-1.5 text-xs font-semibold text-blue-600 hover:bg-blue-50 px-3 py-2 rounded-lg border border-blue-200 transition-colors"
              >
                <span>Switch User</span>
              </button>
            )}
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-lg transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
