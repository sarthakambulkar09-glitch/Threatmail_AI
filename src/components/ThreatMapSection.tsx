import React from 'react';
import { ThreatMap } from './ThreatMap';
import { RouteHop } from '../types';
import { Globe, MapPin, ExternalLink, ShieldCheck, ShieldAlert, Server, Navigation } from 'lucide-react';

interface ThreatMapSectionProps {
  senderIp?: string;
  senderLocation?: {
    city: string;
    country: string;
    countryCode?: string;
    lat: number;
    lng: number;
    isp?: string;
    org?: string;
  };
  travelRoute?: RouteHop[];
  riskScore?: number;
}

export const ThreatMapSection: React.FC<ThreatMapSectionProps> = ({
  senderIp,
  senderLocation,
  travelRoute = [],
  riskScore = 0,
}) => {
  const isHighRisk = riskScore >= 70;

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden flex flex-col">
      {/* Container Header */}
      <div className="p-5 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
              <Globe className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 leading-tight">
                Email Origin Infrastructure Mapping
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Mail Server Location &amp; Route Analysis
              </p>
            </div>
          </div>
        </div>

        {/* Location & Hop Summary Badges */}
        <div className="flex items-center gap-2 self-start sm:self-auto text-xs">
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-50 border border-slate-200 text-slate-700">
            <MapPin className="w-3.5 h-3.5 text-blue-600" />
            <span>
              {senderLocation?.city || 'Ashburn'}, {senderLocation?.countryCode || 'US'}
            </span>
          </div>

          <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-50 border border-slate-200 text-slate-700">
            <Server className="w-3.5 h-3.5 text-slate-500" />
            <span>{travelRoute.length || 2} Hops</span>
          </div>

          {senderIp && (
            <div className="hidden md:flex items-center gap-1 px-3 py-1 rounded-lg bg-slate-50 border border-slate-200 text-slate-600 font-mono text-[11px]">
              <span>IP:</span>
              <strong className="text-slate-800">{senderIp}</strong>
            </div>
          )}
        </div>
      </div>

      {/* Interactive Map Canvas Container */}
      <div className="h-[320px] sm:h-[380px] w-full relative bg-slate-50">
        <ThreatMap
          senderIp={senderIp}
          senderLocation={senderLocation}
          travelRoute={travelRoute}
          riskScore={riskScore}
          className="w-full h-full"
        />
      </div>

      {/* Footer Info / Route Telemetry */}
      <div className="p-3.5 bg-slate-50/70 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-600">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-700">Origin Provider:</span>
          <span>{senderLocation?.isp || 'Cloud Mail Transfer Agent'}</span>
          <span className="text-slate-300">•</span>
          <span className="font-semibold text-slate-700">AS Organization:</span>
          <span>{senderLocation?.org || 'Tier-1 Backbone Transit'}</span>
        </div>

        <div className="flex items-center gap-3 text-[11px]">
          <a
            href="https://www.openstreetmap.org/#map=14/22.04674/78.83368"
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-600 hover:text-blue-700 font-medium flex items-center gap-1 hover:underline"
          >
            <span>OpenStreetMap</span>
            <ExternalLink className="w-3 h-3" />
          </a>
          <span className="text-slate-300">|</span>
          <a
            href="https://maps.google.com/?q=20.5937,78.9629"
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-600 hover:text-blue-700 font-semibold flex items-center gap-1 hover:underline"
          >
            <span>Google Maps</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </div>
    </div>
  );
};
