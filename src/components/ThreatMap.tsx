// Source: Google Maps Platform Code Assist
import React, { useState } from 'react';
import { RouteHop } from '../types';
import { GoogleThreatMap } from './GoogleThreatMap';
import { OpenStreetMapClone, OSM_TARGET_COORDS } from './OpenStreetMapClone';
import { Globe, Map as MapIcon, ExternalLink } from 'lucide-react';

interface ThreatMapProps {
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
  mapLink?: string;
  osmUrl?: string;
  defaultProvider?: 'google' | 'osm';
  className?: string;
}

export const ThreatMap: React.FC<ThreatMapProps> = ({
  senderIp,
  senderLocation,
  travelRoute = [],
  riskScore = 0,
  mapLink = 'https://maps.app.goo.gl/D185NwCpHo8tS6i89',
  osmUrl = OSM_TARGET_COORDS.url,
  defaultProvider = 'google',
  className = '',
}) => {
  const [activeProvider, setActiveProvider] = useState<'google' | 'osm'>(defaultProvider);

  return (
    <div className={`relative w-full h-full flex flex-col bg-slate-900 overflow-hidden ${className}`}>
      {/* Map Provider Selector Floating Control */}
      <div className="absolute top-2.5 left-2.5 z-20 flex items-center bg-white/95 backdrop-blur-xs p-1 rounded-lg border border-slate-200 text-xs shadow-md">
        <button
          type="button"
          onClick={() => setActiveProvider('google')}
          className={`px-2.5 py-1 rounded-md font-medium text-[11px] transition-all flex items-center gap-1.5 ${
            activeProvider === 'google'
              ? 'bg-blue-600 text-white shadow-xs font-semibold'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <MapIcon className="w-3.5 h-3.5" />
          <span>Google Maps</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveProvider('osm')}
          className={`px-2.5 py-1 rounded-md font-medium text-[11px] transition-all flex items-center gap-1.5 ${
            activeProvider === 'osm'
              ? 'bg-blue-600 text-white shadow-xs font-semibold'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Globe className="w-3.5 h-3.5" />
          <span>OpenStreetMap</span>
        </button>
      </div>

      {/* Render Selected Map Provider */}
      {activeProvider === 'google' ? (
        <GoogleThreatMap
          senderIp={senderIp}
          senderLocation={senderLocation}
          travelRoute={travelRoute}
          riskScore={riskScore}
          className="w-full h-full"
        />
      ) : (
        <OpenStreetMapClone
          senderIp={senderIp}
          senderLocation={senderLocation}
          travelRoute={travelRoute}
          riskScore={riskScore}
          osmUrl={osmUrl}
          className="w-full h-full"
        />
      )}
    </div>
  );
};
