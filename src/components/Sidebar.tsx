import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  MailCheck,
  Binary,
  FileText,
  MapPin,
  Bell,
  Settings,
  Shield,
  Activity,
  Layers,
  Bot,
  Mic,
  Radio,
} from 'lucide-react';

export type SidebarTab =
  | 'dashboard'
  | 'threat-feed'
  | 'email-analysis'
  | 'realtime-location'
  | 'gemini-chat'
  | 'geo-intel'
  | 'threat-intelligence'
  | 'forensic-reports'
  | 'maps'
  | 'notifications'
  | 'settings';

interface SidebarProps {
  activeTab: SidebarTab;
  onTabChange: (tab: SidebarTab) => void;
  unreadCount: number;
  criticalCount: number;
  onOpenVoice?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  unreadCount,
  criticalCount,
  onOpenVoice,
}) => {
  const navItems = [
    {
      id: 'dashboard' as SidebarTab,
      label: 'Dashboard',
      icon: LayoutDashboard,
      description: 'Overview & KPIs',
    },
    {
      id: 'realtime-location' as SidebarTab,
      label: 'Live Location Monitor',
      icon: Radio,
      badge: 'Google Maps',
      badgeColor: 'bg-emerald-50 text-emerald-700 border border-emerald-200',
      description: 'Real-time GPS Tracking',
    },
    {
      id: 'threat-feed' as SidebarTab,
      label: 'Threat Feed',
      icon: ShieldAlert,
      badge: criticalCount > 0 ? criticalCount : undefined,
      badgeColor: 'bg-red-50 text-red-600 border border-red-200',
    },
    {
      id: 'email-analysis' as SidebarTab,
      label: 'Email Analysis',
      icon: MailCheck,
    },
    {
      id: 'gemini-chat' as SidebarTab,
      label: 'Gemini SOC Assistant',
      icon: Bot,
      badge: 'AI Multi-Turn',
      badgeColor: 'bg-blue-50 text-blue-700 border border-blue-200',
    },
    {
      id: 'geo-intel' as SidebarTab,
      label: 'Maps Grounding',
      icon: MapPin,
      badge: 'Google Maps',
      badgeColor: 'bg-blue-50 text-blue-700 border border-blue-200',
    },
    {
      id: 'threat-intelligence' as SidebarTab,
      label: 'Threat Intelligence',
      icon: Binary,
    },
    {
      id: 'forensic-reports' as SidebarTab,
      label: 'Forensic Reports',
      icon: FileText,
    },
    {
      id: 'maps' as SidebarTab,
      label: 'Threat Origins Map',
      icon: Layers,
    },
    {
      id: 'notifications' as SidebarTab,
      label: 'Notifications',
      icon: Bell,
      badge: unreadCount > 0 ? unreadCount : undefined,
      badgeColor: 'bg-blue-50 text-blue-600 border border-blue-200',
    },
    {
      id: 'settings' as SidebarTab,
      label: 'Settings',
      icon: Settings,
    },
  ];

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col shrink-0 select-none">
      {/* Platform Sub-label */}
      <div className="px-5 pt-4 pb-2">
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            SOC Operations Center
          </span>
        </div>
      </div>

      {/* Navigation List */}
      <div className="flex-1 px-3 py-2 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const isSelected = activeTab === item.id;
          const Icon = item.icon;

          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group text-left ${
                isSelected
                  ? 'bg-blue-50 text-blue-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon
                  className={`w-4 h-4 transition-colors ${
                    isSelected ? 'text-blue-600' : 'text-slate-400 group-hover:text-slate-600'
                  }`}
                />
                <span className={isSelected ? 'font-semibold text-blue-700' : 'text-slate-700'}>
                  {item.label}
                </span>
              </div>

              {item.badge !== undefined && (
                <span
                  className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${
                    item.badgeColor || 'bg-slate-100 text-slate-700'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Live Voice Assistant Quick Launcher */}
      {onOpenVoice && (
        <div className="mx-3 my-2 p-3 rounded-xl bg-gradient-to-br from-slate-900 to-slate-800 text-white shadow-xs">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-rose-400 animate-pulse" />
              <span className="text-xs font-bold text-white">Live Voice SOC</span>
            </div>
            <span className="text-[10px] bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded border border-rose-500/30">
              Live API
            </span>
          </div>
          <p className="text-[11px] text-slate-300 leading-snug mb-3">
            Real-time spoken dialogue with Gemini 3.1 Flash Live.
          </p>
          <button
            onClick={onOpenVoice}
            className="w-full flex items-center justify-center gap-1.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold py-2 px-3 rounded-lg transition-colors shadow-2xs"
          >
            <Mic className="w-3.5 h-3.5" />
            <span>Launch Voice SOC</span>
          </button>
        </div>
      )}

      {/* Compliance / Engine Tag */}
      <div className="p-4 m-3 rounded-xl bg-slate-50 border border-slate-200/80">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-blue-600 shrink-0" />
          <div className="min-w-0">
            <p className="text-xs font-semibold text-slate-800 truncate">Insforge Threat Engine</p>
            <p className="text-[11px] text-slate-500 truncate">Zero-Trust RFC 5322 Audit</p>
          </div>
        </div>
        <div className="mt-2.5 pt-2 border-t border-slate-200 flex items-center justify-between text-[10px] text-slate-500 font-medium">
          <span>Engine Status</span>
          <span className="text-emerald-600 font-semibold flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            Active Protection
          </span>
        </div>
      </div>
    </aside>
  );
};
