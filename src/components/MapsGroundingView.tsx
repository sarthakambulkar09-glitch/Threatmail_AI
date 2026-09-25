import React, { useState } from 'react';
import {
  MapPin,
  Search,
  ExternalLink,
  Shield,
  Server,
  Building2,
  Navigation,
  Sparkles,
  AlertCircle,
  RefreshCw,
  CheckCircle2,
} from 'lucide-react';

interface GroundingLink {
  title: string;
  uri: string;
  sourceType: 'maps' | 'web';
  snippet?: string;
}

interface MapsGroundingResult {
  text: string;
  groundingLinks: GroundingLink[];
  fallback?: boolean;
  quotaExceeded?: boolean;
  message?: string;
}

export const MapsGroundingView: React.FC = () => {
  const [query, setQuery] = useState<string>('Find cybersecurity emergency response teams (CERT) and incident centers in my region');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [result, setResult] = useState<MapsGroundingResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [userLocation, setUserLocation] = useState<{ latitude: number; longitude: number } | null>(null);
  const [locatingStatus, setLocatingStatus] = useState<string>('');

  const detectLocation = async (): Promise<{ latitude: number; longitude: number } | null> => {
    if (!navigator.geolocation) return null;
    setLocatingStatus('Locating device...');
    try {
      const pos = await new Promise<GeolocationPosition>((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 5000 });
      });
      const coords = { latitude: pos.coords.latitude, longitude: pos.coords.longitude };
      setUserLocation(coords);
      setLocatingStatus('Location acquired');
      return coords;
    } catch (e) {
      console.warn('Geolocation unavailable or denied:', e);
      setLocatingStatus('Using global search');
      return null;
    }
  };

  const handleSearch = async (searchQuery?: string) => {
    const q = searchQuery || query.trim();
    if (!q || isLoading) return;

    setError(null);
    setIsLoading(true);

    try {
      let coords = userLocation;
      if (!coords) {
        coords = await detectLocation();
      }

      const res = await fetch('/api/gemini/maps-grounding', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: q,
          userLocation: coords || undefined,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `Error status ${res.status}`);
      }

      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      console.error('Maps Grounding Error:', err);
      setError(err?.message || 'Failed to retrieve Maps Grounding data');
    } finally {
      setIsLoading(false);
    }
  };

  const presetQueries = [
    {
      title: 'Local CERT / CSIRT Centers',
      icon: Shield,
      query: 'Where are certified cybersecurity emergency response teams (CERT) and SOC incident hubs located near me?',
    },
    {
      title: 'Tier 3/4 Data Centers & IXPs',
      icon: Server,
      query: 'Find major enterprise data centers and Internet Exchange Points (IXPs) in this region.',
    },
    {
      title: 'Cloud Infrastructure Hubs',
      icon: Building2,
      query: 'Locate Google Cloud regional data centers and cloud interconnection facilities.',
    },
    {
      title: 'DNS & Internet Backbone Facilities',
      icon: Navigation,
      query: 'Find core tier 1 carrier colocation and internet exchange facilities.',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-12 w-12 rounded-xl bg-emerald-600 text-white flex items-center justify-center shadow-xs">
              <MapPin className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-slate-900">Cyber Geo-Intelligence & Maps Grounding</h2>
                <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                  gemini-3.5-flash with Google Maps
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Physical security intelligence grounded with real-world Google Maps location data
              </p>
            </div>
          </div>

          {/* User Location Status */}
          <div className="flex items-center gap-2 text-xs">
            <button
              onClick={() => detectLocation()}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 font-medium transition-colors"
            >
              <Navigation className="w-3.5 h-3.5 text-blue-600" />
              <span>{userLocation ? 'Location Detected' : 'Detect My Location'}</span>
            </button>
            {locatingStatus && (
              <span className="text-slate-400 font-medium">{locatingStatus}</span>
            )}
          </div>
        </div>

        {/* Search Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSearch();
          }}
          className="mt-6 flex flex-col sm:flex-row items-stretch gap-2"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search for emergency response centers, data center colocation, or security hubs..."
              disabled={isLoading}
              className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-300 focus:border-emerald-500 focus:bg-white focus:outline-none rounded-xl text-xs sm:text-sm text-slate-900 shadow-2xs transition-colors"
            />
          </div>
          <button
            type="submit"
            disabled={isLoading || !query.trim()}
            className="flex items-center justify-center gap-2 px-6 py-2.5 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-xs sm:text-sm font-semibold rounded-xl shadow-xs transition-colors"
          >
            {isLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
            <span>{isLoading ? 'Querying Maps...' : 'Ground with Google Maps'}</span>
          </button>
        </form>

        {/* Preset Cards */}
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {presetQueries.map((preset, idx) => {
            const Icon = preset.icon;
            return (
              <button
                key={idx}
                onClick={() => {
                  setQuery(preset.query);
                  handleSearch(preset.query);
                }}
                className="flex items-center gap-2.5 p-3 rounded-xl border border-slate-200 bg-slate-50/70 hover:bg-emerald-50/60 hover:border-emerald-200 text-left transition-all group"
              >
                <div className="h-7 w-7 rounded-lg bg-white border border-slate-200 flex items-center justify-center text-slate-600 group-hover:text-emerald-700 group-hover:border-emerald-200 shrink-0">
                  <Icon className="w-3.5 h-3.5" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-semibold text-slate-800 group-hover:text-emerald-900 truncate">
                    {preset.title}
                  </p>
                  <p className="text-[11px] text-slate-400 truncate">Click to search</p>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Results Section */}
      {result && (
        <div className="space-y-6">
          {/* Extracted Google Maps Links (Mandatory Requirement) */}
          {result.groundingLinks && result.groundingLinks.length > 0 && (
            <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <MapPin className="w-5 h-5 text-emerald-600" />
                  <h3 className="text-sm font-bold text-slate-900">
                    Google Maps Grounded Locations ({result.groundingLinks.length})
                  </h3>
                </div>
                <span className="text-xs text-emerald-700 font-medium bg-emerald-50 px-2.5 py-0.5 rounded-full border border-emerald-200 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" />
                  Verified Real-World Place Sources
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {result.groundingLinks.map((link, idx) => (
                  <a
                    key={idx}
                    href={link.uri}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-4 rounded-xl border border-emerald-200 bg-emerald-50/40 hover:bg-emerald-50/80 transition-all group flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-start justify-between gap-2 mb-1.5">
                        <h4 className="text-xs font-bold text-slate-900 group-hover:text-emerald-700 group-hover:underline">
                          {link.title || 'View Facility on Google Maps'}
                        </h4>
                        <ExternalLink className="w-3.5 h-3.5 text-emerald-600 shrink-0 mt-0.5" />
                      </div>
                      {link.snippet && (
                        <p className="text-xs text-slate-600 line-clamp-3">
                          {link.snippet}
                        </p>
                      )}
                    </div>
                    <div className="mt-3 pt-2 border-t border-emerald-200/60 flex items-center justify-between text-[11px] text-emerald-700 font-semibold">
                      <span>Open in Google Maps</span>
                      <span>&rarr;</span>
                    </div>
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Textual Analysis from Gemini */}
          <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs">
            <h3 className="text-sm font-bold text-slate-900 mb-3 flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-600" />
              <span>Geo-Intelligence Synthesis</span>
            </h3>
            <div className="text-xs sm:text-sm text-slate-700 leading-relaxed whitespace-pre-wrap">
              {result.text}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
