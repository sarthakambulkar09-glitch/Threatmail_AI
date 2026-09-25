// Source: Google Maps Platform Code Assist
// Attribution: gmp_mcp_codeassist_v1_aistudio
import React, { useEffect, useRef } from 'react';
import { useMap } from '@vis.gl/react-google-maps';

interface MapCircleProps {
  center: google.maps.LatLngLiteral;
  radius: number; // in meters
  fillColor?: string;
  fillOpacity?: number;
  strokeColor?: string;
  strokeOpacity?: number;
  strokeWeight?: number;
  zIndex?: number;
}

export const MapCircle: React.FC<MapCircleProps> = ({
  center,
  radius,
  fillColor = '#3b82f6',
  fillOpacity = 0.15,
  strokeColor = '#2563eb',
  strokeOpacity = 0.7,
  strokeWeight = 2,
  zIndex = 1,
}) => {
  const map = useMap();
  const circleRef = useRef<google.maps.Circle | null>(null);

  useEffect(() => {
    if (!map) return;

    if (!circleRef.current) {
      circleRef.current = new google.maps.Circle({
        map,
        center,
        radius,
        fillColor,
        fillOpacity,
        strokeColor,
        strokeOpacity,
        strokeWeight,
        zIndex,
      });
    } else {
      circleRef.current.setMap(map);
      circleRef.current.setCenter(center);
      circleRef.current.setRadius(radius);
      circleRef.current.setOptions({
        fillColor,
        fillOpacity,
        strokeColor,
        strokeOpacity,
        strokeWeight,
        zIndex,
      });
    }

    return () => {
      if (circleRef.current) {
        circleRef.current.setMap(null);
        circleRef.current = null;
      }
    };
  }, [
    map,
    center.lat,
    center.lng,
    radius,
    fillColor,
    fillOpacity,
    strokeColor,
    strokeOpacity,
    strokeWeight,
    zIndex,
  ]);

  return null;
};

interface MapPolylineProps {
  path: google.maps.LatLngLiteral[];
  geodesic?: boolean;
  strokeColor?: string;
  strokeOpacity?: number;
  strokeWeight?: number;
  zIndex?: number;
}

export const MapPolyline: React.FC<MapPolylineProps> = ({
  path,
  geodesic = true,
  strokeColor = '#3b82f6',
  strokeOpacity = 0.8,
  strokeWeight = 3,
  zIndex = 2,
}) => {
  const map = useMap();
  const polylineRef = useRef<google.maps.Polyline | null>(null);

  useEffect(() => {
    if (!map) return;

    if (path.length < 2) {
      if (polylineRef.current) {
        polylineRef.current.setMap(null);
        polylineRef.current = null;
      }
      return;
    }

    if (!polylineRef.current) {
      polylineRef.current = new google.maps.Polyline({
        map,
        path,
        geodesic,
        strokeColor,
        strokeOpacity,
        strokeWeight,
        zIndex,
      });
    } else {
      polylineRef.current.setMap(map);
      polylineRef.current.setPath(path);
      polylineRef.current.setOptions({
        geodesic,
        strokeColor,
        strokeOpacity,
        strokeWeight,
        zIndex,
      });
    }

    return () => {
      if (polylineRef.current) {
        polylineRef.current.setMap(null);
        polylineRef.current = null;
      }
    };
  }, [map, path, geodesic, strokeColor, strokeOpacity, strokeWeight, zIndex]);

  return null;
};

interface MapCameraLockProps {
  target: google.maps.LatLngLiteral | null;
  enabled: boolean;
  zoom?: number;
}

export const MapCameraLock: React.FC<MapCameraLockProps> = ({ target, enabled, zoom }) => {
  const map = useMap();

  useEffect(() => {
    if (!map || !target || !enabled) return;
    map.panTo(target);
    if (typeof zoom === 'number') {
      map.setZoom(zoom);
    }
  }, [map, target?.lat, target?.lng, enabled, zoom]);

  return null;
};
