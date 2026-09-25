import React from 'react';
import { InsforgeNotification } from '../types';
import { X, ShieldAlert, CheckCheck, Bell, AlertTriangle, ArrowRight } from 'lucide-react';

interface NotificationCenterProps {
  isOpen: boolean;
  onClose: () => void;
  notifications: InsforgeNotification[];
  onMarkRead: (id: string) => void;
  onMarkAllRead: () => void;
  onSelectReport: (reportId: string) => void;
}

export const NotificationCenter: React.FC<NotificationCenterProps> = ({
  isOpen,
  onClose,
  notifications,
  onMarkRead,
  onMarkAllRead,
  onSelectReport,
}) => {
  if (!isOpen) return null;

  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-900/40 backdrop-blur-xs">
      <div className="w-full max-w-md bg-white border-l border-slate-200 h-full shadow-2xl flex flex-col animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="p-4 bg-white border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
              <Bell className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900">
                Security Threat Alerts
              </h3>
              <p className="text-[11px] text-slate-500">Live SOC telemetry events</p>
            </div>
            {unreadCount > 0 && (
              <span className="text-xs font-bold bg-blue-600 text-white px-2 py-0.5 rounded-full ml-1">
                {unreadCount} new
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {unreadCount > 0 && (
              <button
                onClick={onMarkAllRead}
                className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1 transition-colors px-2 py-1 rounded hover:bg-blue-50"
                title="Mark all as read"
              >
                <CheckCheck className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Mark read</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-slate-100 text-slate-400 hover:text-slate-700 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Notifications List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-slate-50/50">
          {notifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-8 text-center text-slate-400">
              <ShieldAlert className="w-10 h-10 text-slate-300 mb-2" />
              <p className="text-sm font-semibold text-slate-700">No Threat Alerts</p>
              <p className="text-xs text-slate-500 mt-1">High-risk email incidents and phishing triggers will appear here.</p>
            </div>
          ) : (
            notifications.map((notif) => {
              const isHigh = notif.severity === 'high' || notif.severity === 'critical';

              return (
                <div
                  key={notif.id}
                  onClick={() => {
                    if (!notif.read) onMarkRead(notif.id);
                    if (notif.reportId) {
                      onSelectReport(notif.reportId);
                      onClose();
                    }
                  }}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer relative group ${
                    !notif.read
                      ? 'bg-white border-blue-200 shadow-xs ring-1 ring-blue-500/10'
                      : 'bg-white/80 border-slate-200 hover:bg-white hover:border-slate-300'
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <div
                      className={`p-2 rounded-lg shrink-0 mt-0.5 ${
                        isHigh
                          ? 'bg-red-50 text-red-600 border border-red-200'
                          : 'bg-amber-50 text-amber-600 border border-amber-200'
                      }`}
                    >
                      {isHigh ? (
                        <ShieldAlert className="w-4 h-4" />
                      ) : (
                        <AlertTriangle className="w-4 h-4" />
                      )}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <span
                          className={`text-[11px] font-bold uppercase tracking-wider ${
                            isHigh ? 'text-red-600' : 'text-amber-600'
                          }`}
                        >
                          {((notif as any).type || notif.classification || 'THREAT ALERT').toString().replace(/_/g, ' ')}
                        </span>
                        <span className="text-[11px] text-slate-400">
                          {new Date(notif.timestamp || (notif as any).createdAt || Date.now()).toLocaleTimeString([], {
                            hour: '2-digit',
                            minute: '2-digit',
                          })}
                        </span>
                      </div>

                      <h4 className="text-xs font-bold text-slate-900 mt-0.5 truncate">
                        {notif.title}
                      </h4>

                      <p className="text-xs text-slate-600 mt-1 line-clamp-2 leading-relaxed">
                        {notif.message}
                      </p>

                      <div className="mt-2.5 flex items-center justify-between pt-2 border-t border-slate-100">
                        <span className="text-[11px] font-medium text-blue-600 group-hover:text-blue-700 flex items-center gap-1">
                          Investigate Incident <ArrowRight className="w-3 h-3" />
                        </span>
                        {!notif.read && (
                          <span className="w-2 h-2 rounded-full bg-blue-600" />
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="p-3 bg-white border-t border-slate-200 text-center text-xs text-slate-500">
          Real-time Event Stream • RFC 5322 Inbound Filter
        </div>
      </div>
    </div>
  );
};
