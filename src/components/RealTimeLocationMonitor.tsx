// Source: Google Maps Platform Code Assist
// Attribution: gmp_mcp_codeassist_v1_aistudio
import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
  APIProvider,
  Map,
  AdvancedMarker,
  Pin,
  InfoWindow,
  ControlPosition,
  MapControl,
  useMap,
} from '@vis.gl/react-google-maps';
import {
  Radio,
  Navigation,
  Compass,
  Gauge,
  MapPin,
  Shield,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Play,
  Pause,
  Layers,
  Crosshair,
  Download,
  Trash2,
  ExternalLink,
  Activity,
  AlertTriangle,
  Globe,
  Sliders,
  ChevronRight,
  Server,
  Zap,
} from 'lucide-react';
import { MapCircle, MapPolyline, MapCameraLock } from './MapLayers';
import {
  getGoogleMapsApiKey,
  isValidGoogleMapsKey,
  calculateDistanceKm,
  calculateBearing,
  formatCoordinates,
  isWithinGeofence,
} from '../lib/mapsConfig';
import { EmailThreatReport } from '../types';

interface Breadcrumb {
  lat: number;
  lng: number;
  accuracy: number;
  speed: number | null;
  heading: number | null;
  timestamp: Date;
}

interface TelemetryEvent {
  id: string;
  time: string;
  type: 'fix' | 'geofence' | 'threat_correlation' | 'system';
  message: string;
}

interface RealTimeLocationMonitorProps {
  scans?: EmailThreatReport[];
  selectedScan?: EmailThreatReport | null;
  className?: string;
  userEmail?: string | null;
}

// Center of India as initial default fallback
const FALLBACK_CENTER = { lat: 20.5937, lng: 78.9629 };

export const RealTimeLocationMonitor: React.FC<RealTimeLocationMonitorProps> = ({
  scans = [],
  selectedScan = null,
  className = '',
  userEmail,
}) => {
  const [apiKey] = useState<string>(getGoogleMapsApiKey());
  const [isMonitoring, setIsMonitoring] = useState<boolean>(true);
  const [followMode, setFollowMode] = useState<boolean>(true);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [mapType, setMapType] = useState<'roadmap' | 'satellite' | 'hybrid'>('roadmap');

  // Real-time location state
  const [currentPosition, setCurrentPosition] = useState<google.maps.LatLngLiteral | null>(null);
  const [accuracy, setAccuracy] = useState<number>(15); // meters
  const [altitude, setAltitude] = useState<number | null>(null);
  const [heading, setHeading] = useState<number | null>(null);
  const [speed, setSpeed] = useState<number | null>(null); // m/s
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [updateCount, setUpdateCount] = useState<number>(0);
  const [locationStatus, setLocationStatus] = useState<string>('Acquiring real-time satellite fix...');
  const [permissionError, setPermissionError] = useState<string | null>(null);

  // Breadcrumbs history trail
  const [breadcrumbs, setBreadcrumbs] = useState<Breadcrumb[]>([]);

  // Geofence settings
  const [geofenceRadius, setGeofenceRadius] = useState<number>(2000); // 2km default
  const [geofenceCenter, setGeofenceCenter] = useState<google.maps.LatLngLiteral | null>(null);
  const [geofenceAlert, setGeofenceAlert] = useState<boolean>(false);

  // Interactive Markers / InfoWindows
  const [isDeviceInfoOpen, setIsDeviceInfoOpen] = useState<boolean>(false);
  const [selectedThreatMarker, setSelectedThreatMarker] = useState<{
    id: string;
    title: string;
    ip: string;
    city: string;
    country: string;
    riskScore: number;
    lat: number;
    lng: number;
    isp?: string;
  } | null>(null);

  // Live telemetry event log
  const [telemetryEvents, setTelemetryEvents] = useState<TelemetryEvent[]>([]);

  // Watch position reference
  const watchIdRef = useRef<number | null>(null);
  const simTimerRef = useRef<any>(null);

  const addTelemetryEvent = useCallback(
    (type: TelemetryEvent['type'], message: string) => {
      const newEvent: TelemetryEvent = {
        id: `${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
        time: new Date().toLocaleTimeString(),
        type,
        message,
      };
      setTelemetryEvents((prev) => [newEvent, ...prev.slice(0, 49)]);
    },
    []
  );

  // 1. Setup HTML5 Geolocation watchPosition
  useEffect(() => {
    if (!isMonitoring || isSimulating) {
      if (watchIdRef.current !== null) {
        navigator.geolocation.clearWatch(watchIdRef.current);
        watchIdRef.current = null;
      }
      return;
    }

    if (!navigator.geolocation) {
      setPermissionError('Geolocation API not supported by this browser.');
      setLocationStatus('Geolocation unsupported');
      return;
    }

    setLocationStatus('Watching live GPS telemetry...');
    setPermissionError(null);

    const handleSuccess = (position: GeolocationPosition) => {
      const { latitude, longitude, accuracy, altitude, heading, speed } = position.coords;
      const pos = { lat: latitude, lng: longitude };

      setCurrentPosition(pos);
      setAccuracy(accuracy || 10);
      setAltitude(altitude);
      setHeading(heading);
      setSpeed(speed);
      const now = new Date();
      setLastUpdated(now);
      setUpdateCount((c) => c + 1);
      setLocationStatus('Live Real-Time Lock Active');

      // Set initial geofence center if not yet set
      setGeofenceCenter((prev) => prev || pos);

      // Record breadcrumb
      setBreadcrumbs((prev) => {
        const next = [
          ...prev,
          {
            lat: pos.lat,
            lng: pos.lng,
            accuracy: accuracy || 10,
            speed,
            heading,
            timestamp: now,
          },
        ];
        return next.slice(-200); // keep recent 200 points
      });

      addTelemetryEvent('fix', `GPS Fix: ${latitude.toFixed(5)}, ${longitude.toFixed(5)} (±${Math.round(accuracy)}m)`);
    };

    const handleError = (error: GeolocationPositionError) => {
      console.warn('Geolocation watch error:', error);
      let msg = 'Unable to retrieve location';
      if (error.code === error.PERMISSION_DENIED) {
        msg = 'Location permission denied. Click "Simulate Live Movement" to test tracking.';
      } else if (error.code === error.POSITION_UNAVAILABLE) {
        msg = 'Location position unavailable. Waiting for GPS signal...';
      } else if (error.code === error.TIMEOUT) {
        msg = 'Location request timed out. Retrying...';
      }
      setPermissionError(msg);
      setLocationStatus(msg);

      // If user hasn't gotten any position yet, set a realistic starting position so the map is immediately useful
      setCurrentPosition((prev) => {
        if (!prev) {
          const defaultPos = { lat: 28.6139, lng: 77.2090 }; // New Delhi / SOC HQ
          setGeofenceCenter(defaultPos);
          return defaultPos;
        }
        return prev;
      });
    };

    watchIdRef.current = navigator.geolocation.watchPosition(handleSuccess, handleError, {
      enableHighAccuracy: true,
      maximumAge: 0,
      timeout: 10000,
    });

    return () => {
      if (watchIdRef.current !== null) {
        navigator.geolocation.clearWatch(watchIdRef.current);
        watchIdRef.current = null;
      }
    };
  }, [isMonitoring, isSimulating, addTelemetryEvent]);

  // 2. Simulated Real-time Movement Mode (Field Agent Patrol)
  useEffect(() => {
    if (!isSimulating) {
      if (simTimerRef.current) {
        clearInterval(simTimerRef.current);
        simTimerRef.current = null;
      }
      return;
    }

    setLocationStatus('Field Agent Patrol Simulation Active (Streaming telemetry)');
    addTelemetryEvent('system', 'Initiated real-time field patrol simulation');

    // Starting baseline location (e.g. current or New Delhi SOC)
    let lat = currentPosition?.lat || 28.6139;
    let lng = currentPosition?.lng || 77.2090;
    let currentAngle = 45;
    let stepCount = 0;

    simTimerRef.current = setInterval(() => {
      stepCount++;
      // Calculate realistic smooth motion with slight heading changes
      const speedKmH = 25 + Math.sin(stepCount * 0.2) * 12; // 15 - 37 km/h patrol drive
      const speedMs = (speedKmH * 1000) / 3600;
      currentAngle = (currentAngle + (Math.sin(stepCount * 0.5) * 8)) % 360;

      const deltaLat = (Math.cos((currentAngle * Math.PI) / 180) * 0.00035);
      const deltaLng = (Math.sin((currentAngle * Math.PI) / 180) * 0.00035);

      lat += deltaLat;
      lng += deltaLng;

      const pos = { lat, lng };
      const simulatedAccuracy = Math.max(4, Math.round(8 + Math.sin(stepCount) * 4));
      const now = new Date();

      setCurrentPosition(pos);
      setAccuracy(simulatedAccuracy);
      setAltitude(216 + Math.round(Math.sin(stepCount * 0.3) * 15));
      setHeading(Math.round(currentAngle));
      setSpeed(speedMs);
      setLastUpdated(now);
      setUpdateCount((c) => c + 1);

      setBreadcrumbs((prev) => [
        ...prev.slice(-199),
        {
          lat,
          lng,
          accuracy: simulatedAccuracy,
          speed: speedMs,
          heading: Math.round(currentAngle),
          timestamp: now,
        },
      ]);

      if (stepCount % 5 === 0) {
        addTelemetryEvent(
          'fix',
          `Field Telemetry: ${lat.toFixed(5)}, ${lng.toFixed(5)} • ${speedKmH.toFixed(1)} km/h • HDG ${Math.round(currentAngle)}°`
        );
      }
    }, 1800);

    return () => {
      if (simTimerRef.current) {
        clearInterval(simTimerRef.current);
        simTimerRef.current = null;
      }
    };
  }, [isSimulating, addTelemetryEvent]);

  // 3. Geofence evaluation
  useEffect(() => {
    if (!currentPosition || !geofenceCenter || geofenceRadius <= 0) {
      setGeofenceAlert(false);
      return;
    }

    const inside = isWithinGeofence(
      geofenceCenter.lat,
      geofenceCenter.lng,
      currentPosition.lat,
      currentPosition.lng,
      geofenceRadius
    );

    if (!inside && !geofenceAlert) {
      setGeofenceAlert(true);
      addTelemetryEvent(
        'geofence',
        `⚠️ GEOFENCE BREACH: Monitored position moved outside ${geofenceRadius}m security perimeter!`
      );
    } else if (inside && geofenceAlert) {
      setGeofenceAlert(false);
      addTelemetryEvent('geofence', `✓ Safe Perimeter: Position re-entered ${geofenceRadius}m security zone.`);
    }
  }, [currentPosition, geofenceCenter, geofenceRadius, geofenceAlert, addTelemetryEvent]);

  // 4. Correlate with active threat nodes from scans
  const threatNodes = useMemo(() => {
    const list: Array<{
      id: string;
      title: string;
      ip: string;
      city: string;
      country: string;
      riskScore: number;
      lat: number;
      lng: number;
      isp?: string;
    }> = [];

    scans.forEach((scan) => {
      if (scan.senderLocation?.lat && scan.senderLocation?.lng) {
        list.push({
          id: scan.id,
          title: scan.subject,
          ip: scan.senderIp || 'Unknown IP',
          city: scan.senderLocation.city || 'Unknown City',
          country: scan.senderLocation.country || 'Unknown Country',
          riskScore: scan.riskScore,
          lat: scan.senderLocation.lat,
          lng: scan.senderLocation.lng,
          isp: scan.senderLocation.isp,
        });
      }
    });

    // Also include selectedScan if not already in list
    if (
      selectedScan?.senderLocation?.lat &&
      selectedScan?.senderLocation?.lng &&
      !list.some((item) => item.id === selectedScan.id)
    ) {
      list.unshift({
        id: selectedScan.id,
        title: selectedScan.subject,
        ip: selectedScan.senderIp || 'Threat Node',
        city: selectedScan.senderLocation.city || 'Origin',
        country: selectedScan.senderLocation.country || 'Transit',
        riskScore: selectedScan.riskScore,
        lat: selectedScan.senderLocation.lat,
        lng: selectedScan.senderLocation.lng,
        isp: selectedScan.senderLocation.isp,
      });
    }

    return list;
  }, [scans, selectedScan]);

  // Active correlated threat node (defaults to selectedScan or closest threat)
  const activeThreatNode = useMemo(() => {
    if (selectedThreatMarker) return selectedThreatMarker;
    if (selectedScan?.senderLocation?.lat && selectedScan?.senderLocation?.lng) {
      return {
        id: selectedScan.id,
        title: selectedScan.subject,
        ip: selectedScan.senderIp || 'Selected Incident',
        city: selectedScan.senderLocation.city || 'Origin',
        country: selectedScan.senderLocation.country || 'Transit',
        riskScore: selectedScan.riskScore,
        lat: selectedScan.senderLocation.lat,
        lng: selectedScan.senderLocation.lng,
        isp: selectedScan.senderLocation.isp,
      };
    }
    return threatNodes[0] || null;
  }, [selectedThreatMarker, selectedScan, threatNodes]);

  // Geodesic distance and bearing from current monitored position to active threat
  const threatCorrelation = useMemo(() => {
    if (!currentPosition || !activeThreatNode) return null;
    const distanceKm = calculateDistanceKm(
      currentPosition.lat,
      currentPosition.lng,
      activeThreatNode.lat,
      activeThreatNode.lng
    );
    const bearing = calculateBearing(
      currentPosition.lat,
      currentPosition.lng,
      activeThreatNode.lat,
      activeThreatNode.lng
    );
    const distanceMiles = distanceKm * 0.621371;

    return {
      distanceKm: Math.round(distanceKm),
      distanceMiles: Math.round(distanceMiles),
      bearing,
      threatNode: activeThreatNode,
    };
  }, [currentPosition, activeThreatNode]);

  // Path coordinates for breadcrumb trail
  const breadcrumbPath = useMemo(() => {
    return breadcrumbs.map((b) => ({ lat: b.lat, lng: b.lng }));
  }, [breadcrumbs]);

  // Arc path between current monitored position and active threat node
  const threatFlightArc = useMemo(() => {
    if (!currentPosition || !activeThreatNode) return [];
    return [currentPosition, { lat: activeThreatNode.lat, lng: activeThreatNode.lng }];
  }, [currentPosition, activeThreatNode]);

  // Export Telemetry Log
  const handleExportLog = () => {
    const data = {
      deviceOwner: userEmail || 'ThreatMail SOC Analyst',
      exportTimestamp: new Date().toISOString(),
      currentLocation: currentPosition,
      telemetryStats: {
        totalPings: updateCount,
        accuracyMeters: accuracy,
        altitudeMeters: altitude,
        speedKmh: speed ? speed * 3.6 : 0,
        headingDegrees: heading,
      },
      geofence: {
        radiusMeters: geofenceRadius,
        center: geofenceCenter,
        status: geofenceAlert ? 'BREACHED' : 'SECURE',
      },
      breadcrumbsCount: breadcrumbs.length,
      breadcrumbs,
      eventsLog: telemetryEvents,
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threatmail-telemetry-${new Date().toISOString().slice(0, 19)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const clearTrail = () => {
    setBreadcrumbs([]);
    addTelemetryEvent('system', 'Breadcrumb trail cleared');
  };

  const initialCenter = currentPosition || FALLBACK_CENTER;

  return (
    <div className={`flex flex-col space-y-5 ${className}`}>
      {/* SECTION 1: HEADER & LIVE TELEMETRY BAR */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600 shadow-xs relative">
              <Radio className="w-5 h-5 animate-pulse" />
              {isMonitoring && (
                <span className="absolute -top-1 -right-1 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500" />
                </span>
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-slate-900 leading-tight">
                  Real-Time Location Monitoring
                </h2>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-100 text-blue-800 border border-blue-200 flex items-center gap-1">
                  <Globe className="w-3 h-3" />
                  Google Maps Platform
                </span>
                {isSimulating && (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-100 text-purple-800 border border-purple-200 animate-pulse">
                    Field Patrol Simulation
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Continuous high-accuracy GPS telemetry, geodesic threat correlation, and active geofencing
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Toggle Live Monitoring */}
          <button
            type="button"
            onClick={() => {
              setIsMonitoring(!isMonitoring);
              addTelemetryEvent('system', isMonitoring ? 'Paused GPS monitoring' : 'Resumed GPS monitoring');
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              isMonitoring
                ? 'bg-emerald-50 text-emerald-700 hover:bg-emerald-100 border border-emerald-300'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200 border border-slate-300'
            }`}
          >
            {isMonitoring ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isMonitoring ? 'Monitoring Active' : 'Resume Monitoring'}</span>
          </button>

          {/* Toggle Simulation Mode */}
          <button
            type="button"
            onClick={() => setIsSimulating(!isSimulating)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              isSimulating
                ? 'bg-purple-600 text-white shadow-xs hover:bg-purple-700'
                : 'bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-300'
            }`}
          >
            <Zap className={`w-3.5 h-3.5 ${isSimulating ? 'text-amber-300' : 'text-purple-600'}`} />
            <span>{isSimulating ? 'Stop Simulation' : 'Simulate Movement'}</span>
          </button>

          {/* Camera Follow Mode Toggle */}
          <button
            type="button"
            onClick={() => setFollowMode(!followMode)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 border transition-colors ${
              followMode
                ? 'bg-blue-50 text-blue-700 border-blue-300'
                : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
            }`}
            title="Auto-center camera on device updates"
          >
            <Crosshair className={`w-3.5 h-3.5 ${followMode ? 'text-blue-600' : 'text-slate-400'}`} />
            <span>{followMode ? 'Follow Locked' : 'Free Explore'}</span>
          </button>

          {/* Export Telemetry */}
          <button
            type="button"
            onClick={handleExportLog}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 shadow-2xs flex items-center gap-1.5 transition-colors"
            title="Download telemetry logs"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            <span className="hidden sm:inline">Export</span>
          </button>
        </div>
      </div>

      {/* Geofence Breach Banner Alert */}
      {geofenceAlert && (
        <div className="bg-red-50 border border-red-300 rounded-xl p-4 flex items-center justify-between gap-3 text-red-900 animate-pulse">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="w-5 h-5 text-red-600 shrink-0" />
            <div>
              <span className="font-bold text-xs uppercase tracking-wider text-red-700">
                Security Perimeter Breach Warning
              </span>
              <p className="text-xs text-red-800">
                Current monitored location has traversed outside the designated {geofenceRadius}m security radius. SOC audit logged.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setGeofenceCenter(currentPosition)}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white font-semibold text-xs rounded-lg shadow-xs shrink-0"
          >
            Reset Perimeter Here
          </button>
        </div>
      )}

      {/* SECTION 2: TELEMETRY METRICS HUD */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Coordinates */}
        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-[11px] font-semibold mb-1">
            <span>Coordinates</span>
            <MapPin className="w-3.5 h-3.5 text-blue-500" />
          </div>
          <div className="font-mono font-bold text-xs text-slate-900 truncate">
            {currentPosition ? `${currentPosition.lat.toFixed(4)}°N` : 'Acquiring...'}
          </div>
          <div className="font-mono text-[11px] text-slate-500 truncate">
            {currentPosition ? `${currentPosition.lng.toFixed(4)}°E` : '--'}
          </div>
        </div>

        {/* GPS Accuracy */}
        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-[11px] font-semibold mb-1">
            <span>Precision</span>
            <Crosshair className="w-3.5 h-3.5 text-emerald-500" />
          </div>
          <div className="font-bold text-sm text-slate-900 flex items-center gap-1">
            <span>±{Math.round(accuracy)}</span>
            <span className="text-xs font-normal text-slate-500">meters</span>
          </div>
          <div className="text-[10px] text-emerald-600 font-semibold mt-0.5">
            {accuracy <= 10 ? 'High Precision' : accuracy <= 30 ? 'Normal GPS' : 'Cellular / Wi-Fi'}
          </div>
        </div>

        {/* Velocity / Speed */}
        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-[11px] font-semibold mb-1">
            <span>Velocity</span>
            <Gauge className="w-3.5 h-3.5 text-purple-500" />
          </div>
          <div className="font-bold text-sm text-slate-900 flex items-center gap-1">
            <span>{speed !== null ? (speed * 3.6).toFixed(1) : '0.0'}</span>
            <span className="text-xs font-normal text-slate-500">km/h</span>
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            {speed && speed > 1 ? 'Moving in Transit' : 'Stationary Node'}
          </div>
        </div>

        {/* Heading & Compass */}
        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-[11px] font-semibold mb-1">
            <span>Bearing</span>
            <Compass className="w-3.5 h-3.5 text-amber-500" />
          </div>
          <div className="font-bold text-sm text-slate-900 flex items-center gap-1">
            <span>{heading !== null ? `${Math.round(heading)}°` : '0°'}</span>
            <span className="text-xs font-semibold text-amber-600">
              {heading !== null ? (heading < 90 ? 'NE' : heading < 180 ? 'SE' : heading < 270 ? 'SW' : 'NW') : 'N'}
            </span>
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            Compass Orientation
          </div>
        </div>

        {/* Threat Distance */}
        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-[11px] font-semibold mb-1">
            <span>Threat Range</span>
            <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
          </div>
          <div className="font-bold text-sm text-red-600 flex items-center gap-1">
            <span>{threatCorrelation ? threatCorrelation.distanceKm.toLocaleString() : '--'}</span>
            <span className="text-xs font-normal text-slate-500">km</span>
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5 truncate">
            {activeThreatNode ? `${activeThreatNode.city}` : 'No active incident'}
          </div>
        </div>

        {/* Telemetry Pings */}
        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-[11px] font-semibold mb-1">
            <span>Pings Recorded</span>
            <Activity className="w-3.5 h-3.5 text-blue-500" />
          </div>
          <div className="font-bold text-sm text-slate-900">
            {updateCount.toLocaleString()}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            {lastUpdated ? lastUpdated.toLocaleTimeString() : 'Awaiting lock'}
          </div>
        </div>
      </div>

      {/* SECTION 3: INTERACTIVE GOOGLE MAP CONTAINER */}
      <div className="relative w-full h-[460px] sm:h-[520px] rounded-xl overflow-hidden border border-slate-200 shadow-sm bg-slate-900">
        <APIProvider apiKey={apiKey} libraries={['marker', 'geometry']}>
          <Map
            mapId="DEMO_MAP_ID"
            defaultCenter={initialCenter}
            defaultZoom={14}
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
            {/* Camera auto-follow controller */}
            <MapCameraLock target={currentPosition} enabled={followMode} />

            {/* 1. Accuracy Circle around monitored device */}
            {currentPosition && (
              <MapCircle
                center={currentPosition}
                radius={accuracy}
                fillColor="#3b82f6"
                fillOpacity={0.18}
                strokeColor="#2563eb"
                strokeOpacity={0.7}
                strokeWeight={1.5}
                zIndex={1}
              />
            )}

            {/* 2. Geofence Boundary Circle */}
            {geofenceCenter && geofenceRadius > 0 && (
              <MapCircle
                center={geofenceCenter}
                radius={geofenceRadius}
                fillColor={geofenceAlert ? '#ef4444' : '#10b981'}
                fillOpacity={0.08}
                strokeColor={geofenceAlert ? '#dc2626' : '#059669'}
                strokeOpacity={0.6}
                strokeWeight={2}
                zIndex={0}
              />
            )}

            {/* 3. Breadcrumb History Trail */}
            {breadcrumbPath.length > 1 && (
              <>
                <MapPolyline
                  path={breadcrumbPath}
                  geodesic={true}
                  strokeColor="#60a5fa"
                  strokeOpacity={0.35}
                  strokeWeight={6}
                  zIndex={2}
                />
                <MapPolyline
                  path={breadcrumbPath}
                  geodesic={true}
                  strokeColor="#2563eb"
                  strokeOpacity={0.9}
                  strokeWeight={3}
                  zIndex={3}
                />
              </>
            )}

            {/* 4. Threat Geodesic Correlation Arc */}
            {threatFlightArc.length === 2 && (
              <>
                <MapPolyline
                  path={threatFlightArc}
                  geodesic={true}
                  strokeColor="#ef4444"
                  strokeOpacity={0.7}
                  strokeWeight={2}
                  zIndex={4}
                />
              </>
            )}

            {/* 5. Monitored User / Device Advanced Marker (Pulsing Radar Beacon) */}
            {currentPosition && (
              <AdvancedMarker
                position={currentPosition}
                title="Your Monitored Device Location"
                onClick={() => setIsDeviceInfoOpen(true)}
                zIndex={10}
              >
                <div className="relative flex items-center justify-center cursor-pointer">
                  {/* Outer animated radar wave */}
                  <span className="absolute w-12 h-12 rounded-full bg-blue-500/25 animate-ping pointer-events-none" />
                  {/* Secondary glow ring */}
                  <span className="absolute w-8 h-8 rounded-full bg-blue-500/30 border border-blue-400" />
                  {/* Inner Solid Badge with orientation pointer */}
                  <div className="relative w-6 h-6 rounded-full bg-blue-600 border-2 border-white shadow-lg flex items-center justify-center text-white">
                    <Navigation
                      className="w-3.5 h-3.5 transition-transform duration-300"
                      style={{
                        transform: heading !== null ? `rotate(${heading}deg)` : 'rotate(0deg)',
                      }}
                    />
                  </div>
                </div>
              </AdvancedMarker>
            )}

            {/* 6. Device InfoWindow */}
            {currentPosition && isDeviceInfoOpen && (
              <InfoWindow
                position={currentPosition}
                onCloseClick={() => setIsDeviceInfoOpen(false)}
              >
                <div className="p-2 min-w-[220px] max-w-[260px] text-xs font-sans text-slate-800">
                  <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-slate-200">
                    <span className="font-bold text-blue-700 uppercase tracking-wider text-[10px] flex items-center gap-1">
                      <Radio className="w-3 h-3 text-blue-600" />
                      Live Monitored Device
                    </span>
                    <span className="text-[10px] font-mono text-emerald-600 font-semibold">
                      GPS Active
                    </span>
                  </div>
                  <div className="space-y-1 text-[11px]">
                    <div className="font-mono text-slate-900 font-semibold">
                      {formatCoordinates(currentPosition.lat, currentPosition.lng)}
                    </div>
                    <div className="text-slate-600">
                      Accuracy: <strong className="text-slate-800">±{Math.round(accuracy)}m</strong>
                    </div>
                    {speed !== null && (
                      <div className="text-slate-600">
                        Speed: <strong className="text-slate-800">{(speed * 3.6).toFixed(1)} km/h</strong>
                      </div>
                    )}
                    {heading !== null && (
                      <div className="text-slate-600">
                        Heading: <strong className="text-slate-800">{Math.round(heading)}°</strong>
                      </div>
                    )}
                    {altitude !== null && (
                      <div className="text-slate-600">
                        Altitude: <strong className="text-slate-800">{Math.round(altitude)}m</strong>
                      </div>
                    )}
                    <div className="text-[10px] text-slate-400 pt-1">
                      Pings: {updateCount} • {lastUpdated?.toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              </InfoWindow>
            )}

            {/* 7. Incident Threat Node Markers on Map */}
            {threatNodes.map((threat) => {
              const isSelected = activeThreatNode?.id === threat.id;
              return (
                <AdvancedMarker
                  key={`threat-${threat.id}`}
                  position={{ lat: threat.lat, lng: threat.lng }}
                  title={`Threat Origin Node: ${threat.city}, ${threat.country}`}
                  onClick={() => setSelectedThreatMarker(threat)}
                  zIndex={isSelected ? 9 : 5}
                >
                  <Pin
                    background={threat.riskScore >= 70 ? '#ef4444' : '#f59e0b'}
                    borderColor="#ffffff"
                    glyphColor="#ffffff"
                    scale={isSelected ? 1.25 : 1.0}
                  />
                </AdvancedMarker>
              );
            })}

            {/* 8. Threat Node InfoWindow */}
            {selectedThreatMarker && (
              <InfoWindow
                position={{ lat: selectedThreatMarker.lat, lng: selectedThreatMarker.lng }}
                onCloseClick={() => setSelectedThreatMarker(null)}
              >
                <div className="p-2 min-w-[220px] max-w-[270px] text-xs font-sans text-slate-800">
                  <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-slate-200">
                    <span
                      className={`font-bold uppercase tracking-wider text-[10px] px-1.5 py-0.5 rounded ${
                        selectedThreatMarker.riskScore >= 70
                          ? 'bg-red-100 text-red-700'
                          : 'bg-amber-100 text-amber-700'
                      }`}
                    >
                      {selectedThreatMarker.riskScore >= 70 ? 'Malicious Node' : 'Suspicious Origin'}
                    </span>
                    <span className="text-[10px] font-bold text-slate-500">
                      Score: {selectedThreatMarker.riskScore}/100
                    </span>
                  </div>
                  <div className="space-y-1 text-[11px]">
                    <div className="font-semibold text-slate-900 truncate">
                      {selectedThreatMarker.title}
                    </div>
                    <div className="font-mono text-slate-600">
                      IP: {selectedThreatMarker.ip}
                    </div>
                    <div className="text-slate-600">
                      Location: {selectedThreatMarker.city}, {selectedThreatMarker.country}
                    </div>
                    {selectedThreatMarker.isp && (
                      <div className="text-slate-500 text-[10px] truncate">
                        ISP: {selectedThreatMarker.isp}
                      </div>
                    )}
                    {threatCorrelation && (
                      <div className="pt-1 mt-1 border-t border-slate-100 text-blue-700 font-semibold text-[10px]">
                        Distance from you: {threatCorrelation.distanceKm.toLocaleString()} km ({threatCorrelation.bearing.cardinal})
                      </div>
                    )}
                  </div>
                </div>
              </InfoWindow>
            )}

            {/* Custom Map Control: Map Layer Switcher & Re-center */}
            <MapControl position={ControlPosition.TOP_RIGHT}>
              <div className="m-3 flex items-center gap-1.5 bg-white/95 backdrop-blur-xs p-1 rounded-lg border border-slate-200 shadow-md text-xs">
                <button
                  type="button"
                  onClick={() => setMapType(mapType === 'roadmap' ? 'hybrid' : 'roadmap')}
                  className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-[11px] flex items-center gap-1 transition-colors"
                  title="Toggle Satellite / Roadmap"
                >
                  <Layers className="w-3.5 h-3.5 text-blue-600" />
                  <span>{mapType === 'roadmap' ? 'Satellite' : 'Roadmap'}</span>
                </button>

                {currentPosition && (
                  <button
                    type="button"
                    onClick={() => {
                      setFollowMode(true);
                      addTelemetryEvent('system', 'Re-centered camera on device');
                    }}
                    className="px-2.5 py-1 rounded bg-blue-50 hover:bg-blue-100 text-blue-700 font-semibold text-[11px] flex items-center gap-1 transition-colors"
                    title="Center on Monitored Device"
                  >
                    <Crosshair className="w-3.5 h-3.5" />
                    <span>Center Me</span>
                  </button>
                )}

                {breadcrumbs.length > 0 && (
                  <button
                    type="button"
                    onClick={clearTrail}
                    className="px-2 py-1 rounded text-slate-500 hover:text-red-600 hover:bg-red-50 text-[11px] transition-colors"
                    title="Clear breadcrumb trail"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </MapControl>

            {/* Custom Map Control: Geofence Slider */}
            <MapControl position={ControlPosition.BOTTOM_LEFT}>
              <div className="m-3 bg-white/95 backdrop-blur-xs p-2 rounded-xl border border-slate-200 shadow-md text-xs flex items-center gap-2.5">
                <div className="flex items-center gap-1.5 text-slate-700 font-semibold text-[11px]">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Geofence:</span>
                </div>
                <select
                  value={geofenceRadius}
                  onChange={(e) => {
                    const r = Number(e.target.value);
                    setGeofenceRadius(r);
                    addTelemetryEvent('system', `Updated geofence radius to ${r}m`);
                  }}
                  className="bg-slate-50 border border-slate-200 text-slate-800 text-[11px] rounded-md px-2 py-0.5 font-medium focus:outline-none"
                >
                  <option value={500}>500 meters (Local)</option>
                  <option value={2000}>2,000 meters (2 km)</option>
                  <option value={10000}>10 km (Metropolitan)</option>
                  <option value={50000}>50 km (Regional)</option>
                  <option value={0}>Disabled</option>
                </select>
                {currentPosition && (
                  <button
                    type="button"
                    onClick={() => {
                      setGeofenceCenter(currentPosition);
                      addTelemetryEvent('system', 'Set geofence center to current position');
                    }}
                    className="text-[10px] text-blue-600 hover:underline font-semibold"
                  >
                    Anchor Here
                  </button>
                )}
              </div>
            </MapControl>
          </Map>
        </APIProvider>

        {/* Live Status HUD Overlay */}
        <div className="absolute top-3 left-3 z-10 bg-slate-900/90 backdrop-blur-md px-3 py-1.5 rounded-lg border border-slate-700/80 text-white shadow-lg flex items-center gap-2 text-xs">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          <span className="font-semibold">{locationStatus}</span>
          {permissionError && (
            <span className="text-[10px] text-amber-300 ml-1">({permissionError})</span>
          )}
        </div>
      </div>

      {/* SECTION 4: SPLIT TELEMETRY FEED & THREAT CORRELATION AUDIT */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left: Active Threat Distance Correlation (5 cols) */}
        <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-600" />
                <span>Geodesic Threat Correlation</span>
              </h3>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-50 text-red-700 border border-red-200">
                Live Vector
              </span>
            </div>

            {threatCorrelation ? (
              <div className="space-y-3">
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-slate-800 truncate">
                      {threatCorrelation.threatNode.title}
                    </span>
                    <span className="text-red-600 font-bold font-mono">
                      Risk {threatCorrelation.threatNode.riskScore}/100
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono">
                    IP: {threatCorrelation.threatNode.ip} • {threatCorrelation.threatNode.city}, {threatCorrelation.threatNode.country}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="p-2.5 rounded-lg bg-blue-50/60 border border-blue-100">
                    <span className="text-[10px] text-blue-600 font-semibold uppercase tracking-wider block">
                      Geodesic Distance
                    </span>
                    <span className="text-base font-bold text-slate-900">
                      {threatCorrelation.distanceKm.toLocaleString()} km
                    </span>
                    <span className="text-[10px] text-slate-500 block">
                      ({threatCorrelation.distanceMiles.toLocaleString()} miles)
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-blue-50/60 border border-blue-100">
                    <span className="text-[10px] text-blue-600 font-semibold uppercase tracking-wider block">
                      Azimuth Bearing
                    </span>
                    <span className="text-base font-bold text-slate-900">
                      {threatCorrelation.bearing.degrees}° {threatCorrelation.bearing.cardinal}
                    </span>
                    <span className="text-[10px] text-slate-500 block">
                      Flight Vector
                    </span>
                  </div>
                </div>

                <p className="text-[11px] text-slate-500 leading-relaxed">
                  Real-time spherical geodesic distance mapped directly from your device location to the suspicious mail transfer agent server node.
                </p>
              </div>
            ) : (
              <div className="p-8 text-center text-slate-400 text-xs">
                Scan an inbound email or select an incident from your feed to view geodesic threat correlation.
              </div>
            )}
          </div>

          <div className="pt-3 mt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
            <span>Correlation engine: <strong>Haversine Geodesic</strong></span>
            <span>Attribution: <strong>GMP v1 AI Studio</strong></span>
          </div>
        </div>

        {/* Right: Streaming Telemetry Log (7 cols) */}
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden flex flex-col">
          <div className="p-4 border-b border-slate-200 bg-slate-50/70 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-600" />
              <h3 className="text-sm font-bold text-slate-900">
                Real-Time Telemetry Audit Trail
              </h3>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-100 text-blue-800 font-semibold">
                {breadcrumbs.length} Trail Points
              </span>
              <button
                type="button"
                onClick={clearTrail}
                className="text-[11px] text-slate-500 hover:text-red-600 font-medium"
              >
                Clear
              </button>
            </div>
          </div>

          <div className="p-3 divide-y divide-slate-100 max-h-[220px] overflow-y-auto font-mono text-xs">
            {telemetryEvents.length === 0 ? (
              <div className="p-6 text-center text-slate-400 text-xs">
                Awaiting initial telemetry fix...
              </div>
            ) : (
              telemetryEvents.map((ev) => (
                <div key={ev.id} className="py-1.5 flex items-start gap-2.5 text-[11px]">
                  <span className="text-slate-400 shrink-0">{ev.time}</span>
                  <span
                    className={`font-semibold shrink-0 ${
                      ev.type === 'geofence'
                        ? 'text-red-600'
                        : ev.type === 'fix'
                        ? 'text-blue-600'
                        : 'text-slate-700'
                    }`}
                  >
                    [{ev.type.toUpperCase()}]
                  </span>
                  <span className="text-slate-800 truncate">{ev.message}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
