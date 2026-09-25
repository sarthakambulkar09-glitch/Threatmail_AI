import { EmailThreatReport, InsforgeNotification, InsforgeStats } from '../types';
import { RawGmailMessage } from './gmail';

export interface InsforgeStatus {
  status: string;
  connected: boolean;
  backend: string;
  version: string;
  database: string;
  storageMode: string;
  recordsStored: number;
  activeThreats: number;
  uptimeSeconds: number;
  aiProvider?: string;
  modelName?: string;
  googleMapsActive?: boolean;
  currentUserEmail?: string | null;
}

export async function fetchInsforgeStatus(userEmail?: string): Promise<InsforgeStatus> {
  const url = userEmail
    ? `/api/insforge/status?userEmail=${encodeURIComponent(userEmail)}`
    : '/api/insforge/status';
  const defaultStatus: InsforgeStatus = {
    status: 'online',
    connected: true,
    backend: 'InsForge BaaS Database',
    version: 'v2.4.0-insforge-soc',
    database: 'InsForge PostgreSQL (Agent-Native)',
    storageMode: 'persistent',
    recordsStored: 0,
    activeThreats: 0,
    uptimeSeconds: 0,
    currentUserEmail: userEmail || null,
  };

  try {
    const res = await fetch(url, {
      headers: userEmail ? { 'x-user-email': userEmail } : {},
    });
    if (!res.ok) return defaultStatus;
    return await res.json();
  } catch (err) {
    return defaultStatus;
  }
}

export async function fetchInsforgeScans(userEmail?: string): Promise<EmailThreatReport[]> {
  if (!userEmail) return [];
  const url = `/api/insforge/scans?userEmail=${encodeURIComponent(userEmail)}`;
  try {
    const res = await fetch(url, {
      headers: { 'x-user-email': userEmail },
    });
    if (!res.ok) return [];
    return await res.json();
  } catch (err) {
    return [];
  }
}

export async function analyzeAndSaveEmail(
  rawMessage: RawGmailMessage,
  userEmail?: string
): Promise<EmailThreatReport> {
  const payload = {
    ...rawMessage,
    userEmail: userEmail || rawMessage.recipient || 'analyst@threatmail.ai',
  };
  const res = await fetch('/api/insforge/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(userEmail ? { 'x-user-email': userEmail } : {}),
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Insforge analysis failed (${res.status}): ${errText}`);
  }

  return res.json();
}

export async function scanSampleEmails(
  userEmail: string,
  count: number = 1
): Promise<EmailThreatReport[]> {
  const res = await fetch('/api/insforge/scan-sample', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-user-email': userEmail,
    },
    body: JSON.stringify({ userEmail, count }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to scan sample emails: ${err}`);
  }

  const data = await res.json();
  return data.scans || [];
}

export async function updateScanStatusInInsforge(
  id: string,
  status: 'scanned' | 'quarantined' | 'whitelisted' | 'monitoring',
  userEmail?: string
): Promise<EmailThreatReport> {
  const res = await fetch(`/api/insforge/scans/${id}/status`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      ...(userEmail ? { 'x-user-email': userEmail } : {}),
    },
    body: JSON.stringify({ status, userEmail }),
  });
  if (!res.ok) throw new Error('Failed to update scan status');
  return res.json();
}

export async function deleteScanFromInsforge(id: string, userEmail?: string): Promise<boolean> {
  const url = userEmail
    ? `/api/insforge/scans/${id}?userEmail=${encodeURIComponent(userEmail)}`
    : `/api/insforge/scans/${id}`;
  const res = await fetch(url, {
    method: 'DELETE',
    headers: userEmail ? { 'x-user-email': userEmail } : {},
  });
  return res.ok;
}

export async function fetchInsforgeNotifications(userEmail?: string): Promise<InsforgeNotification[]> {
  const url = userEmail
    ? `/api/insforge/notifications?userEmail=${encodeURIComponent(userEmail)}`
    : '/api/insforge/notifications';
  try {
    const res = await fetch(url, {
      headers: userEmail ? { 'x-user-email': userEmail } : {},
    });
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function markNotificationAsRead(id: string): Promise<void> {
  try {
    await fetch(`/api/insforge/notifications/${id}/read`, { method: 'PATCH' });
  } catch {
    // Ignore network blip
  }
}

export async function markAllNotificationsAsRead(userEmail?: string): Promise<void> {
  try {
    await fetch('/api/insforge/notifications/read-all', {
      method: 'POST',
      headers: userEmail ? { 'x-user-email': userEmail } : {},
      body: JSON.stringify({ userEmail }),
    });
  } catch {
    // Ignore network blip
  }
}

export async function fetchInsforgeStats(userEmail?: string): Promise<InsforgeStats> {
  const defaultStats: InsforgeStats = {
    totalScanned: 0,
    threatsBlocked: 0,
    safeEmails: 0,
    averageRiskScore: 0,
    highRiskCount: 0,
    phishingCount: 0,
    malwareCount: 0,
    becCount: 0,
    suspiciousCount: 0,
    lastScannedAt: null,
  };

  const url = userEmail
    ? `/api/insforge/stats?userEmail=${encodeURIComponent(userEmail)}`
    : '/api/insforge/stats';
  try {
    const res = await fetch(url, {
      headers: userEmail ? { 'x-user-email': userEmail } : {},
    });
    if (!res.ok) return defaultStats;
    return await res.json();
  } catch {
    return defaultStats;
  }
}
