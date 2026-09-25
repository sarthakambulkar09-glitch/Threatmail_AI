import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import { RouteHop } from '../types';
import { ExternalLink, Radio, MapPin, Layers, RefreshCw, Compass } from 'lucide-react';

interface OpenStreetMapCloneProps {
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
  osmUrl?: string;
  className?: string;
}

// User specified target coordinates from: https://www.openstreetmap.org/#map=14/22.04674/78.83368
export const OSM_TARGET_COORDS = {
  lat: 22.04674,
  lng: 78.83368,
  zoom: 14,
  url: 'https://www.openstreetmap.org/#map=14/22.04674/78.83368',
};

export const OpenStreetMapClone: React.FC<OpenStreetMapCloneProps> = ({
  senderIp,
  senderLocation,
  travelRoute = [],
  riskScore = 0,
  osmUrl = OSM_TARGET_COORDS.url,
  className = '',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const markersLayerRef = useRef<L.LayerGroup | null>(null);
  const tileLayerRef = useRef<L.TileLayer | null>(null);

  const [tileTheme, setTileTheme] = useState<'standard' | 'dark'>('dark');
  const [viewMode, setViewMode] = useState<'interactive' | 'embed'>('interactive');
  const [mapReady, setMapReady] = useState(false);

  // Initialize Leaflet OpenStreetMap
  useEffect(() => {
    if (!containerRef.current || mapInstanceRef.current) return;

    // Center on target coords (22.04674, 78.83368) or sender location
    const initialLat = senderLocation?.lat ?? OSM_TARGET_COORDS.lat;
    const initialLng = senderLocation?.lng ?? OSM_TARGET_COORDS.lng;
    const initialZoom = senderLocation ? 4 : OSM_TARGET_COORDS.zoom;

    const map = L.map(containerRef.current, {
      center: [initialLat, initialLng],
      zoom: initialZoom,
      zoomControl: false,
      attributionControl: false,
    });

    // Custom Zoom control placed at bottom right
    L.control.zoom({ position: 'bottomright' }).addTo(map);

    // Attribution control
    L.control
      .attribution({
        position: 'bottomleft',
        prefix: '<a href="https://www.openstreetmap.org" target="_blank" rel="noopener">OpenStreetMap</a>',
      })
      .addTo(map);

    // Initial Tile Layer
    const tileUrl =
      tileTheme === 'dark'
        ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
        : 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';

    const tiles = L.tileLayer(tileUrl, {
      maxZoom: 19,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    }).addTo(map);

    tileLayerRef.current = tiles;

    const markersGroup = L.layerGroup().addTo(map);
    markersLayerRef.current = markersGroup;

    mapInstanceRef.current = map;
    setMapReady(true);

    return () => {
      map.remove();
      mapInstanceRef.current = null;
    };
  }, []);

  // Update Tile Layer when tileTheme changes
  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map) return;

    if (tileLayerRef.current) {
      map.removeLayer(tileLayerRef.current);
    }

    const tileUrl =
      tileTheme === 'dark'
        ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
        : 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';

    const tiles = L.tileLayer(tileUrl, {
      maxZoom: 19,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
    }).addTo(map);

    tileLayerRef.current = tiles;
  }, [tileTheme]);

  // Update Markers and Transmission Lines
  useEffect(() => {
    const map = mapInstanceRef.current;
    const group = markersLayerRef.current;
    if (!map || !group || !mapReady) return;

    group.clearLayers();

    // 1. Primary Target Pin from user link (22.04674, 78.83368)
    const targetIcon = L.divIcon({
      className: 'custom-osm-target-pin',
      html: `
        <div style="position:relative; display:flex; align-items:center; justify-content:center;">
          <div style="position:absolute; width:22px; height:22px; border-radius:50%; background:rgba(59,130,246,0.3); animation:ping 2s cubic-bezier(0,0,0.2,1) infinite;"></div>
          <div style="width:12px; height:12px; border-radius:50%; background:#3b82f6; border:2px solid #ffffff; box-shadow:0 0 10px #3b82f6;"></div>
        </div>
      `,
      iconSize: [22, 22],
      iconAnchor: [11, 11],
    });

    const targetMarker = L.marker([OSM_TARGET_COORDS.lat, OSM_TARGET_COORDS.lng], {
      icon: targetIcon,
      title: 'OSM Coords: 22.04674, 78.83368',
    }).addTo(group);

    targetMarker.bindPopup(`
      <div style="background:#090d16; color:#e2e8f0; font-family:monospace; padding:8px 10px; border-radius:6px; border:1px solid #1e293b; max-width:240px; font-size:11px;">
        <div style="color:#60a5fa; font-weight:bold; margin-bottom:4px; text-transform:uppercase;">
          [OpenStreetMap Target Node]
        </div>
        <div><strong>Coords:</strong> 22.04674° N, 78.83368° E</div>
        <div><strong>Zoom:</strong> Level 14</div>
        <div style="margin-top:6px;">
          <a href="${OSM_TARGET_COORDS.url}" target="_blank" rel="noopener noreferrer" style="color:#38bdf8; text-decoration:underline;">
            Open on OpenStreetMap.org &rarr;
          </a>
        </div>
      </div>
    `);

    const polyPoints: [number, number][] = [];

    // 2. Sender Threat Origin Pin (if exists)
    if (senderLocation && senderLocation.lat && senderLocation.lng) {
      polyPoints.push([senderLocation.lat, senderLocation.lng]);

      const isHighRisk = riskScore >= 70;
      const markerColor = isHighRisk ? '#ef4444' : riskScore >= 35 ? '#f59e0b' : '#10b981';

      const originIcon = L.divIcon({
        className: 'custom-osm-origin-pin',
        html: `
          <div style="position:relative; display:flex; align-items:center; justify-content:center;">
            <div style="position:absolute; width:26px; height:26px; border-radius:50%; background:${markerColor}44; animation:ping 1.5s cubic-bezier(0,0,0.2,1) infinite;"></div>
            <div style="width:14px; height:14px; border-radius:50%; background:${markerColor}; border:2px solid #ffffff; box-shadow:0 0 12px ${markerColor};"></div>
          </div>
        `,
        iconSize: [26, 26],
        iconAnchor: [13, 13],
      });

      const originMarker = L.marker([senderLocation.lat, senderLocation.lng], {
        icon: originIcon,
        title: `Origin: ${senderIp || 'Sender IP'}`,
      }).addTo(group);

      originMarker.bindPopup(`
        <div style="background:#090d16; color:#e2e8f0; font-family:monospace; padding:8px 10px; border-radius:6px; border:1px solid #1e293b; max-width:240px; font-size:11px;">
          <div style="color:${markerColor}; font-weight:bold; margin-bottom:4px; text-transform:uppercase;">
            [Threat Origin Node]
          </div>
          <div><strong>IP:</strong> ${senderIp || 'Unknown'}</div>
          <div><strong>City:</strong> ${senderLocation.city}, ${senderLocation.country}</div>
          <div><strong>Risk Score:</strong> ${riskScore}/100</div>
        </div>
      `);
    }

    // 3. MTA Relay Hops
    travelRoute.forEach((hop, idx) => {
      if (hop.location && hop.location.lat && hop.location.lng) {
        polyPoints.push([hop.location.lat, hop.location.lng]);
        const isDest = idx === travelRoute.length - 1;
        const hopColor = isDest ? '#10b981' : '#f59e0b';

        const hopIcon = L.divIcon({
          className: 'custom-osm-hop-pin',
          html: `
            <div style="width:10px; height:10px; border-radius:50%; background:${hopColor}; border:1.5px solid #000; box-shadow:0 0 6px ${hopColor};"></div>
          `,
          iconSize: [10, 10],
          iconAnchor: [5, 5],
        });

        const hopMarker = L.marker([hop.location.lat, hop.location.lng], {
          icon: hopIcon,
          title: `Hop ${hop.hopNumber}: ${hop.byServer}`,
        }).addTo(group);

        hopMarker.bindPopup(`
          <div style="background:#090d16; color:#e2e8f0; font-family:monospace; padding:8px 10px; border-radius:6px; border:1px solid #1e293b; max-width:240px; font-size:11px;">
            <div style="color:${hopColor}; font-weight:bold; margin-bottom:4px; text-transform:uppercase;">
              [Relay Hop #${hop.hopNumber}]
            </div>
            <div><strong>By:</strong> ${hop.byServer}</div>
            <div><strong>From:</strong> ${hop.fromServer}</div>
            <div><strong>Location:</strong> ${hop.location.city}, ${hop.location.country}</div>
          </div>
        `);
      }
    });

    // 4. Connect with route line
    if (polyPoints.length > 1) {
      L.polyline(polyPoints, {
        color: '#ef4444',
        weight: 2.5,
        opacity: 0.8,
        dashArray: '6, 6',
      }).addTo(group);
    }
  }, [senderLocation, travelRoute, riskScore, mapReady, senderIp]);

  // Jump to OSM specified coordinates (22.04674, 78.83368) at zoom 14
  const handlePanTargetCoords = () => {
    if (mapInstanceRef.current) {
      mapInstanceRef.current.flyTo([OSM_TARGET_COORDS.lat, OSM_TARGET_COORDS.lng], OSM_TARGET_COORDS.zoom, {
        duration: 1.5,
      });
    }
  };

  // Recenter to sender origin
  const handleRecenterOrigin = () => {
    if (mapInstanceRef.current && senderLocation?.lat && senderLocation?.lng) {
      mapInstanceRef.current.flyTo([senderLocation.lat, senderLocation.lng], 6, {
        duration: 1.2,
      });
    }
  };

  return (
    <div className={`relative w-full h-full flex flex-col bg-neutral-950 overflow-hidden ${className}`}>
      {/* Map or Embed View */}
      {viewMode === 'embed' ? (
        <iframe
          src={`https://www.openstreetmap.org/export/embed.html?bbox=78.81368%2C22.02674%2C78.85368%2C22.06674&layer=mapnik&marker=22.04674%2C78.83368`}
          className="w-full h-full min-h-[190px] border-0"
          title="OpenStreetMap Official Embed"
          loading="lazy"
        />
      ) : (
        <div ref={containerRef} className="w-full h-full min-h-[190px] z-0" />
      )}

      {/* Floating HUD Controls */}
      <div className="absolute top-2 right-2 flex items-center gap-1.5 z-[1000] font-mono">
        {/* Recenter Origin */}
        <button
          onClick={handleRecenterOrigin}
          className="p-1 rounded bg-black/85 hover:bg-neutral-800 text-neutral-300 border border-neutral-800 text-[9px] flex items-center gap-1 px-2 transition-colors shadow-sm"
          title="Recenter to Sender Server IP"
        >
          <Radio className="w-2.5 h-2.5 text-red-500 animate-pulse" />
          <span>Origin</span>
        </button>

        {/* Go to user-specified OSM Coords (22.04674, 78.83368) */}
        <button
          onClick={handlePanTargetCoords}
          className="p-1 rounded bg-blue-950/80 hover:bg-blue-900 text-blue-300 border border-blue-800 text-[9px] flex items-center gap-1 px-2 transition-colors shadow-sm"
          title="Fly to OpenStreetMap Coords: 22.04674, 78.83368 (Zoom 14)"
        >
          <Compass className="w-2.5 h-2.5 text-blue-400" />
          <span>OSM Pin (z14)</span>
        </button>

        {/* Theme Toggle: Dark SOC vs Standard OpenStreetMap */}
        <button
          onClick={() => setTileTheme(tileTheme === 'dark' ? 'standard' : 'dark')}
          className="p-1 rounded bg-black/85 hover:bg-neutral-800 text-neutral-300 border border-neutral-800 text-[9px] flex items-center gap-1 px-1.5 transition-colors shadow-sm"
          title={tileTheme === 'dark' ? 'Switch to Standard OpenStreetMap Tiles' : 'Switch to Dark SOC Cyber Tiles'}
        >
          <Layers className="w-2.5 h-2.5 text-amber-400" />
          <span>{tileTheme === 'dark' ? 'Dark' : 'OSM'}</span>
        </button>

        {/* View Mode Toggle: Leaflet Canvas vs Direct OSM Embed */}
        <button
          onClick={() => setViewMode(viewMode === 'interactive' ? 'embed' : 'interactive')}
          className="p-1 rounded bg-black/85 hover:bg-neutral-800 text-neutral-300 border border-neutral-800 text-[9px] flex items-center gap-1 px-1.5 transition-colors shadow-sm"
          title="Toggle between Leaflet Canvas and Official OSM Iframe Embed"
        >
          <span>{viewMode === 'interactive' ? 'Embed' : 'Canvas'}</span>
        </button>

        {/* External Link to OpenStreetMap.org with target location */}
        <a
          href={osmUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="p-1 rounded bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 text-[9px] flex items-center gap-1 px-2 transition-colors shadow-sm"
          title="Open in OpenStreetMap Web"
        >
          <span>OSM</span>
          <ExternalLink className="w-2.5 h-2.5" />
        </a>
      </div>

      {/* Target coordinates badge */}
      <div className="absolute bottom-1 left-2 z-[1000] text-[8px] font-mono text-neutral-400 bg-black/85 px-2 py-0.5 rounded border border-neutral-800 pointer-events-none flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
        <span>OSM Node: 22.04674°N, 78.83368°E (Zoom 14)</span>
      </div>
    </div>
  );
};
