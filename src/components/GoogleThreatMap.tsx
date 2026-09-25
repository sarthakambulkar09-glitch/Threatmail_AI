// Source: Google Maps Platform Code Assist
import React, { useEffect, useState, useMemo, useCallback } from 'react';
import {
  APIProvider,
  Map,
  AdvancedMarker,
  Pin,
  InfoWindow,
  Polyline,
  useMap,
  ControlPosition,
  MapControl,
} from '@vis.gl/react-google-maps';
import { RouteHop } from '../types';
import { ShieldAlert, Radio, RefreshCw, ExternalLink, MapPin, KeyRound, Layers } from 'lucide-react';

interface GoogleThreatMapProps {
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
  className?: string;
}

const INDIA_CENTER = { lat: 20.5937, lng: 78.9629 };

/**
 * Validates whether an API key has the structure of a valid Google Maps Platform key
 * (both standard keys and Maps Demo Keys start with "AIza" and are 39 characters long).
 */
export const isValidGoogleMapsKey = (key?: string | null): boolean => {
  if (!key) return false;
  const trimmed = key.trim();
  return trimmed.startsWith('AIza') && trimmed.length >= 30;
};

// Inner controller to manipulate camera and fit bounds
const MapCameraController: React.FC<{
  senderLocation?: { lat: number; lng: number };
  coordinates: { lat: number; lng: number }[];
}> = ({ senderLocation, coordinates }) => {
  const map = useMap();

  useEffect(() => {
    if (!map) return;

    if (coordinates.length > 1) {
      const bounds = new google.maps.LatLngBounds();
      coordinates.forEach((coord) => bounds.extend(coord));
      map.fitBounds(bounds, { top: 40, right: 40, bottom: 40, left: 40 });
    } else if (coordinates.length === 1) {
      map.panTo(coordinates[0]);
      map.setZoom(5);
    } else if (senderLocation?.lat && senderLocation?.lng) {
      map.panTo({ lat: senderLocation.lat, lng: senderLocation.lng });
      map.setZoom(5);
    }
  }, [map, coordinates, senderLocation]);

  return null;
};

export const GoogleThreatMap: React.FC<GoogleThreatMapProps> = ({
  senderIp,
  senderLocation,
  travelRoute = [],
  riskScore = 0,
  className = '',
}) => {
  const [selectedHop, setSelectedHop] = useState<{
    type: 'origin' | 'hop';
    title: string;
    ip?: string;
    city?: string;
    country?: string;
    isp?: string;
    org?: string;
    hopNumber?: number;
    fromServer?: string;
    byServer?: string;
    position: { lat: number; lng: number };
  } | null>(null);

  const [mapType, setMapType] = useState<'roadmap' | 'satellite' | 'hybrid'>('roadmap');
  const [authFailed, setAuthFailed] = useState(false);

  // Monitor for runtime authentication failure from Google Maps API
  useEffect(() => {
    const prevAuthFailure = (window as any).gm_authFailure;
    (window as any).gm_authFailure = () => {
      console.warn('Google Maps JS API reported authentication failure. Falling back to live embed view.');
      setAuthFailed(true);
      if (typeof prevAuthFailure === 'function') {
        try {
          prevAuthFailure();
        } catch {
          // ignore
        }
      }
    };
    return () => {
      (window as any).gm_authFailure = prevAuthFailure;
    };
  }, []);

  // Catch script-level errors from Google Maps CDN
  useEffect(() => {
    const handleScriptError = (event: ErrorEvent) => {
      if (
        event.message?.includes('InvalidKeyMapError') ||
        event.message?.includes('Google Maps') ||
        (event.filename && event.filename.includes('maps.googleapis.com'))
      ) {
        console.warn('Caught Google Maps script error, switching to fallback view.');
        setAuthFailed(true);
      }
    };
    window.addEventListener('error', handleScriptError);
    return () => {
      window.removeEventListener('error', handleScriptError);
    };
  }, []);

  const rawApiKey = (import.meta.env.VITE_GOOGLE_MAPS_API_KEY || '').trim();
  const hasValidKey = isValidGoogleMapsKey(rawApiKey) && !authFailed;

  const isHighRisk = riskScore >= 70;

  // Origin point
  const originCoord = useMemo(() => {
    if (senderLocation?.lat && senderLocation?.lng) {
      return { lat: senderLocation.lat, lng: senderLocation.lng };
    }
    return null;
  }, [senderLocation]);

  // Combined route coordinates for polyline
  const coordinates = useMemo(() => {
    const list: { lat: number; lng: number }[] = [];
    if (originCoord) {
      list.push(originCoord);
    }
    travelRoute.forEach((h) => {
      if (h.location?.lat && h.location?.lng) {
        list.push({ lat: h.location.lat, lng: h.location.lng });
      }
    });
    return list;
  }, [originCoord, travelRoute]);

  const initialCenter = originCoord || INDIA_CENTER;
  const initialZoom = originCoord ? 4 : 5;

  const externalMapLink = originCoord
    ? `https://maps.google.com/?q=${originCoord.lat},${originCoord.lng}`
    : 'https://maps.app.goo.gl/D185NwCpHo8tS6i89';

  // If no valid Google Maps API key is configured or auth failed, show the clean live embed view
  if (!hasValidKey) {
    return (
      <div className={`relative w-full h-full min-h-[300px] flex flex-col bg-slate-900 overflow-hidden ${className}`}>
        {/* Google Maps Embed as live preview fallback */}
        <iframe
          src={`https://maps.google.com/maps?q=${originCoord ? `${originCoord.lat},${originCoord.lng}` : 'India'}&t=m&z=${originCoord ? 6 : 4}&output=embed`}
          className="w-full h-full border-0 opacity-85"
          loading="lazy"
          title="Google Maps Platform Live Telemetry"
        />

        {/* Floating Quickstart Notice & Demo Key Badge */}
        <div className="absolute inset-x-3 bottom-3 z-10 p-3 bg-slate-900/95 backdrop-blur-md rounded-xl border border-slate-800 text-white shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start sm:items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400 shrink-0">
              <KeyRound className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-slate-100">Google Maps Platform</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 font-semibold border border-blue-500/30">
                  Live Telemetry
                </span>
                {originCoord && (
                  <span className="text-[10px] text-slate-400 font-mono">
                    {originCoord.lat.toFixed(4)}, {originCoord.lng.toFixed(4)}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Displaying Google Maps telemetry. To activate custom client-side vector layers &amp; Advanced Markers, configure a key (<code className="text-blue-300">AIza...</code>) in <code className="text-blue-300">VITE_GOOGLE_MAPS_API_KEY</code>.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <a
              href="https://mapsplatform.google.com/maps-demo-key?utm_campaign=gmp_mcp_codeassist_v1_aistudio"
              target="_blank"
              rel="noopener noreferrer"
              className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-xs flex items-center gap-1.5 transition-colors"
            >
              <span>Get Demo Key</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
            <a
              href={externalMapLink}
              target="_blank"
              rel="noopener noreferrer"
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 flex items-center gap-1 transition-colors"
            >
              <span>Open in Maps</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`relative w-full h-full min-h-[300px] flex flex-col bg-slate-900 ${className}`}>
      <APIProvider apiKey={rawApiKey} libraries={['marker', 'geometry']}>
        <Map
          mapId="DEMO_MAP_ID"
          defaultCenter={initialCenter}
          defaultZoom={initialZoom}
          mapTypeId={mapType}
          style={{ width: '100%', height: '100%' }}
          gestureHandling="greedy"
          disableDefaultUI={false}
          zoomControl={true}
          mapTypeControl={false}
          streetViewControl={false}
          fullscreenControl={false}
          internalUsageAttributionIds={['gmp_mcp_codeassist_v1_aistudio']}
        >
          {/* Automatic camera viewport controller */}
          <MapCameraController senderLocation={originCoord || undefined} coordinates={coordinates} />

          {/* Source Origin Advanced Marker */}
          {originCoord && (
            <AdvancedMarker
              position={originCoord}
              title={`Source Origin Server: ${senderIp || 'Extracted Node'}`}
              onClick={() =>
                setSelectedHop({
                  type: 'origin',
                  title: 'Source Origin Node',
                  ip: senderIp,
                  city: senderLocation?.city,
                  country: senderLocation?.country,
                  isp: senderLocation?.isp,
                  org: senderLocation?.org,
                  position: originCoord,
                })
              }
            >
              <Pin
                background={isHighRisk ? '#ef4444' : riskScore >= 35 ? '#f59e0b' : '#10b981'}
                borderColor="#ffffff"
                glyphColor="#ffffff"
                scale={1.2}
              />
            </AdvancedMarker>
          )}

          {/* Relay Hop Advanced Markers */}
          {travelRoute.map((hop, idx) => {
            if (!hop.location?.lat || !hop.location?.lng) return null;
            const pos = { lat: hop.location.lat, lng: hop.location.lng };
            const isLastHop = idx === travelRoute.length - 1;

            return (
              <AdvancedMarker
                key={`hop-${hop.hopNumber}-${idx}`}
                position={pos}
                title={`Relay Hop #${hop.hopNumber}: ${hop.byServer}`}
                onClick={() =>
                  setSelectedHop({
                    type: 'hop',
                    title: isLastHop ? 'Target Destination MX' : `Relay Hop #${hop.hopNumber}`,
                    ip: hop.ip,
                    city: hop.location?.city,
                    country: hop.location?.country,
                    hopNumber: hop.hopNumber,
                    fromServer: hop.fromServer,
                    byServer: hop.byServer,
                    position: pos,
                  })
                }
              >
                <Pin
                  background={isLastHop ? '#10b981' : '#3b82f6'}
                  borderColor="#ffffff"
                  glyphColor="#ffffff"
                  scale={1.0}
                />
              </AdvancedMarker>
            );
          })}

          {/* Active Flight Path Polylines */}
          {coordinates.length > 1 && (
            <>
              {/* Outer glow line */}
              <Polyline
                path={coordinates}
                geodesic={true}
                strokeColor={isHighRisk ? '#dc2626' : '#60a5fa'}
                strokeOpacity={0.25}
                strokeWeight={8}
              />
              {/* Core geodesic line */}
              <Polyline
                path={coordinates}
                geodesic={true}
                strokeColor={isHighRisk ? '#ef4444' : '#2563eb'}
                strokeOpacity={0.9}
                strokeWeight={3}
              />
            </>
          )}

          {/* Interactive InfoWindow on Marker Click */}
          {selectedHop && (
            <InfoWindow
              position={selectedHop.position}
              onCloseClick={() => setSelectedHop(null)}
            >
              <div className="p-2 min-w-[220px] max-w-[280px] font-sans text-slate-800 text-xs">
                <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-slate-200">
                  <span
                    className={`font-bold uppercase tracking-wider text-[10px] px-1.5 py-0.5 rounded ${
                      selectedHop.type === 'origin'
                        ? isHighRisk
                          ? 'bg-red-100 text-red-700'
                          : 'bg-amber-100 text-amber-700'
                        : 'bg-blue-100 text-blue-700'
                    }`}
                  >
                    {selectedHop.title}
                  </span>
                  {selectedHop.type === 'origin' && (
                    <span className="text-[10px] font-bold text-slate-500">
                      Risk: {riskScore}/100
                    </span>
                  )}
                </div>

                {selectedHop.ip && (
                  <div className="font-mono text-[11px] mb-1 font-semibold text-slate-900">
                    IP: {selectedHop.ip}
                  </div>
                )}

                {selectedHop.city && (
                  <div className="text-[11px] text-slate-600 mb-0.5">
                    Location: {selectedHop.city}, {selectedHop.country}
                  </div>
                )}

                {selectedHop.isp && (
                  <div className="text-[11px] text-slate-600 mb-0.5">
                    ISP: {selectedHop.isp}
                  </div>
                )}

                {selectedHop.org && (
                  <div className="text-[11px] text-slate-600 mb-0.5">
                    ASN: {selectedHop.org}
                  </div>
                )}

                {selectedHop.fromServer && (
                  <div className="text-[10px] text-slate-500 mt-1 truncate">
                    From: {selectedHop.fromServer}
                  </div>
                )}

                {selectedHop.byServer && (
                  <div className="text-[10px] text-slate-500 truncate">
                    By: {selectedHop.byServer}
                  </div>
                )}
              </div>
            </InfoWindow>
          )}

          {/* Custom Map Floating Controls */}
          <MapControl position={ControlPosition.TOP_RIGHT}>
            <div className="m-2.5 flex items-center gap-1.5 bg-white/95 p-1 rounded-lg border border-slate-200 shadow-md text-xs">
              <button
                type="button"
                onClick={() => setMapType(mapType === 'roadmap' ? 'hybrid' : 'roadmap')}
                className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-[11px] flex items-center gap-1 transition-colors"
                title="Toggle Satellite / Roadmap view"
              >
                <Layers className="w-3.5 h-3.5 text-blue-600" />
                <span>{mapType === 'roadmap' ? 'Satellite' : 'Roadmap'}</span>
              </button>

              <a
                href={externalMapLink}
                target="_blank"
                rel="noopener noreferrer"
                className="px-2.5 py-1 rounded bg-blue-50 hover:bg-blue-100 text-blue-700 font-semibold text-[11px] flex items-center gap-1 transition-colors"
                title="View in Google Maps"
              >
                <span>Google Maps</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </MapControl>
        </Map>
      </APIProvider>
    </div>
  );
};
