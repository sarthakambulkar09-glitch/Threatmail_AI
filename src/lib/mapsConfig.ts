// Google Maps Platform Configuration & Geolocation Telemetry Utilities
// Attribution: gmp_mcp_codeassist_v1_aistudio

export const DEFAULT_MAPS_API_KEY = 'AIzaSyBu50aetRFwb8hBlgq26bVrdcbf_8GgHDM';

/**
 * Retrieves the active Google Maps Platform API key from Vite environment
 * with provisioned fallback.
 */
export const getGoogleMapsApiKey = (): string => {
  const envKey = (import.meta.env.VITE_GOOGLE_MAPS_API_KEY || '').trim();
  if (envKey && envKey.startsWith('AIza') && envKey.length >= 30) {
    return envKey;
  }
  return DEFAULT_MAPS_API_KEY;
};

/**
 * Validates Google Maps API key structure.
 */
export const isValidGoogleMapsKey = (key?: string | null): boolean => {
  if (!key) return false;
  const trimmed = key.trim();
  return trimmed.startsWith('AIza') && trimmed.length >= 30;
};

/**
 * Calculates geodesic distance between two latitude/longitude points in kilometers.
 * Uses the Haversine formula.
 */
export const calculateDistanceKm = (
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number
): number => {
  const R = 6371; // Earth's radius in kilometers
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
};

/**
 * Calculates compass bearing from start coordinates to end coordinates.
 * Returns degree (0-360) and cardinal direction string (e.g. 'N', 'NE', 'ESE').
 */
export const calculateBearing = (
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number
): { degrees: number; cardinal: string } => {
  const y = Math.sin(((lon2 - lon1) * Math.PI) / 180) * Math.cos((lat2 * Math.PI) / 180);
  const x =
    Math.cos((lat1 * Math.PI) / 180) * Math.sin((lat2 * Math.PI) / 180) -
    Math.sin((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.cos(((lon2 - lon1) * Math.PI) / 180);
  let brng = (Math.atan2(y, x) * 180) / Math.PI;
  brng = (brng + 360) % 360;

  const cardinals = [
    'N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE',
    'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW',
  ];
  const index = Math.round(brng / 22.5) % 16;
  return {
    degrees: Math.round(brng),
    cardinal: cardinals[index],
  };
};

/**
 * Formats coordinates for telemetry HUD.
 */
export const formatCoordinates = (lat: number, lng: number): string => {
  const latDir = lat >= 0 ? 'N' : 'S';
  const lngDir = lng >= 0 ? 'E' : 'W';
  return `${Math.abs(lat).toFixed(4)}° ${latDir}, ${Math.abs(lng).toFixed(4)}° ${lngDir}`;
};

/**
 * Checks if target position is within a geofence radius (in meters) of center.
 */
export const isWithinGeofence = (
  centerLat: number,
  centerLng: number,
  targetLat: number,
  targetLng: number,
  radiusMeters: number
): boolean => {
  const distKm = calculateDistanceKm(centerLat, centerLng, targetLat, targetLng);
  return distKm * 1000 <= radiusMeters;
};
