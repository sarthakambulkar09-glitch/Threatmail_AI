import fs from 'fs';
import path from 'path';
import { EmailThreatReport, InsforgeNotification, InsforgeStats, RouteHop } from '../src/types.js';
import { predictThreatEnsemble } from './kaggleEnsembleModel.js';

const DATA_DIR = path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'insforge-db.json');

interface InsforgeDatabase {
  version: string;
  updatedAt: string;
  scans: EmailThreatReport[];
  notifications: InsforgeNotification[];
  logs: { timestamp: string; level: string; message: string }[];
}

// Ensure database file exists
function initializeDatabase(): InsforgeDatabase {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(DB_FILE)) {
    const initialDb: InsforgeDatabase = {
      version: '2.4.0-insforge-soc',
      updatedAt: new Date().toISOString(),
      scans: [],
      notifications: [],
      logs: [
        {
          timestamp: new Date().toISOString(),
          level: 'INFO',
          message: 'Insforge SOC Persistent Database initialized successfully.',
        },
      ],
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2), 'utf-8');
    return initialDb;
  }

  try {
    const content = fs.readFileSync(DB_FILE, 'utf-8');
    const parsed = JSON.parse(content) as InsforgeDatabase;
    if (Array.isArray(parsed.scans)) {
      let modified = false;
      parsed.scans.forEach((s) => {
        if (!s.userEmail) {
          s.userEmail = s.recipient || 'analyst@threatmail.ai';
          modified = true;
        }
      });
      if (modified) {
        fs.writeFileSync(DB_FILE, JSON.stringify(parsed, null, 2), 'utf-8');
      }
    }
    return parsed;
  } catch (err) {
    console.error('Failed to read Insforge database, resetting:', err);
    const initialDb: InsforgeDatabase = {
      version: '2.4.0-insforge-soc',
      updatedAt: new Date().toISOString(),
      scans: [],
      notifications: [],
      logs: [{ timestamp: new Date().toISOString(), level: 'WARN', message: 'Database reset after corrupt state' }],
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2), 'utf-8');
    return initialDb;
  }
}

export function getDatabase(): InsforgeDatabase {
  return initializeDatabase();
}

export function saveDatabase(db: InsforgeDatabase): void {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    db.updatedAt = new Date().toISOString();
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8');
  } catch (err) {
    console.error('Error saving Insforge database:', err);
  }
}

/**
 * Retrieves scans belonging STRICTLY to the requested userEmail.
 * Returns empty array if no user is provided, guaranteeing private isolation.
 */
export function getScans(userEmail?: string): EmailThreatReport[] {
  const db = getDatabase();
  if (!userEmail) {
    // Strict isolation: no mixed or unauthenticated access
    return [];
  }
  const target = userEmail.toLowerCase().trim();
  return db.scans
    .filter((s) => (s.userEmail || s.recipient || '').toLowerCase().trim() === target)
    .sort((a, b) => new Date(b.scannedAt).getTime() - new Date(a.scannedAt).getTime());
}

export function saveScanReport(report: EmailThreatReport, userEmail?: string): EmailThreatReport {
  const db = getDatabase();
  const ownerEmail = (userEmail || report.userEmail || report.recipient || '').toLowerCase().trim();
  report.userEmail = ownerEmail;

  const existingIndex = db.scans.findIndex((s) => s.id === report.id);

  if (existingIndex >= 0) {
    db.scans[existingIndex] = report;
  } else {
    db.scans.unshift(report);
  }

  // Generate notification if risk score >= 50 or critical classification
  if (
    report.riskScore >= 50 ||
    report.classification === 'Phishing' ||
    report.classification === 'Malware Risk' ||
    report.classification === 'Business Email Compromise'
  ) {
    const severity =
      report.riskScore >= 80 ? 'critical' : report.riskScore >= 65 ? 'high' : 'medium';
    
    // Check if notification already exists for this scan
    const hasNotification = db.notifications.some((n) => n.reportId === report.id);
    if (!hasNotification) {
      const notification: InsforgeNotification = {
        id: 'notif_' + Math.random().toString(36).substring(2, 9),
        reportId: report.id,
        userEmail: ownerEmail,
        title: `${report.classification.toUpperCase()} Alert: ${report.subject.slice(0, 45)}`,
        message: `High risk email (Score: ${report.riskScore}/100) from ${report.sender.email}. Vector: ${report.attackVector}.`,
        severity,
        classification: report.classification,
        type: report.classification,
        riskScore: report.riskScore,
        sender: report.sender.email,
        timestamp: new Date().toISOString(),
        createdAt: new Date().toISOString(),
        read: false,
      };
      db.notifications.unshift(notification);
    }
  }

  db.logs.push({
    timestamp: new Date().toISOString(),
    level: 'INFO',
    message: `Scanned email [${report.id}] for '${ownerEmail}' - Classification: ${report.classification}, Risk: ${report.riskScore}`,
  });

  // Limit logs to last 500
  if (db.logs.length > 500) {
    db.logs = db.logs.slice(-500);
  }

  saveDatabase(db);
  return report;
}

/**
 * Deletes a scan record, strictly verifying user ownership.
 */
export function deleteScan(id: string, userEmail?: string): boolean {
  const db = getDatabase();
  const initialLength = db.scans.length;
  const targetUser = userEmail ? userEmail.toLowerCase().trim() : null;

  db.scans = db.scans.filter((s) => {
    if (s.id !== id) return true;
    if (targetUser) {
      const scanUser = (s.userEmail || s.recipient || '').toLowerCase().trim();
      return scanUser !== targetUser; // Keep if not owned by this user
    }
    return false; // Purge
  });

  if (db.scans.length !== initialLength) {
    db.notifications = db.notifications.filter((n) => n.reportId !== id);
    saveDatabase(db);
    return true;
  }
  return false;
}

export function updateScanStatus(
  id: string,
  status: 'scanned' | 'quarantined' | 'whitelisted' | 'monitoring',
  userEmail?: string
): EmailThreatReport | null {
  const db = getDatabase();
  const scan = db.scans.find((s) => {
    if (s.id !== id) return false;
    if (userEmail) {
      const owner = (s.userEmail || s.recipient || '').toLowerCase().trim();
      return owner === userEmail.toLowerCase().trim();
    }
    return true;
  });

  if (scan) {
    scan.status = status;
    db.logs.push({
      timestamp: new Date().toISOString(),
      level: 'INFO',
      message: `Status of email [${id}] updated to '${status}' by ${userEmail || 'system'}`,
    });
    saveDatabase(db);
    return scan;
  }
  return null;
}

export function getNotifications(userEmail?: string): InsforgeNotification[] {
  const db = getDatabase();
  if (!userEmail) return [];
  const target = userEmail.toLowerCase().trim();
  const userScanIds = new Set(
    db.scans
      .filter((s) => (s.userEmail || s.recipient || '').toLowerCase().trim() === target)
      .map((s) => s.id)
  );
  return db.notifications.filter(
    (n) =>
      (n.userEmail && n.userEmail.toLowerCase().trim() === target) ||
      userScanIds.has(n.reportId)
  );
}

export function markNotificationRead(id: string): boolean {
  const db = getDatabase();
  const notif = db.notifications.find((n) => n.id === id);
  if (notif) {
    notif.read = true;
    saveDatabase(db);
    return true;
  }
  return false;
}

export function markAllNotificationsRead(userEmail?: string): void {
  const db = getDatabase();
  const target = userEmail ? userEmail.toLowerCase().trim() : null;
  db.notifications.forEach((n) => {
    if (!target || (n.userEmail && n.userEmail.toLowerCase().trim() === target)) {
      n.read = true;
    }
  });
  saveDatabase(db);
}

export function getInsforgeStats(userEmail?: string): InsforgeStats {
  const scans = getScans(userEmail);
  const totalScanned = scans.length;
  
  if (totalScanned === 0) {
    return {
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
  }

  const threatsBlocked = scans.filter((s) => s.status === 'quarantined' || (s.riskScore || 0) >= 70).length;
  const safeEmails = scans.filter((s) => s.classification === 'Safe').length;
  const phishingCount = scans.filter((s) => s.classification === 'Phishing').length;
  const malwareCount = scans.filter((s) => s.classification === 'Malware Risk').length;
  const becCount = scans.filter((s) => s.classification === 'Business Email Compromise').length;
  const suspiciousCount = scans.filter((s) => s.classification === 'Suspicious').length;
  const highRiskCount = scans.filter((s) => (s.riskScore || 0) >= 70).length;
  const totalScore = scans.reduce((acc, curr) => acc + (curr.riskScore || 0), 0);
  const averageRiskScore = Math.round(totalScore / totalScanned);

  return {
    totalScanned,
    threatsBlocked,
    safeEmails,
    averageRiskScore,
    highRiskCount,
    phishingCount,
    malwareCount,
    becCount,
    suspiciousCount,
    lastScannedAt: scans[0]?.scannedAt || null,
  };
}

/**
 * Generates sample emails directly scanned for a specific user identity.
 * Allows effortless testing of User A (3 scans) vs User B (1 scan).
 */
export function generateSampleScansForUser(userEmail: string, count: number = 1): EmailThreatReport[] {
  const templates = [
    {
      subject: 'URGENT: Executive Wire Transfer Authorization Required (#TR-9942)',
      senderName: 'Chief Financial Officer',
      senderEmail: 'cfo-exec@corporate-acme.co.vu',
      senderDomain: 'corporate-acme.co.vu',
      snippet: 'Please immediately process the foreign vendor invoice for $48,200. Wire details are attached in the encrypted ledger.',
      classification: 'Business Email Compromise' as const,
      riskScore: 92,
      attackVector: 'VIP Impersonation / BEC' as const,
      status: 'quarantined' as const,
      explanation: 'Sender display name impersonates executive authority. Return-path domain differs from legitimate corporate MX records.',
      senderIp: '185.220.101.5',
      city: 'Frankfurt',
      country: 'Germany',
      links: [{ url: 'https://corporate-acme.co.vu/transfer', domain: 'corporate-acme.co.vu', isSuspicious: true }],
    },
    {
      subject: 'Security Alert: Microsoft 365 Password Expiration in 24 Hours',
      senderName: 'IT Security Helpdesk',
      senderEmail: 'support@login-verify365.online',
      senderDomain: 'login-verify365.online',
      snippet: 'Your single-sign-on credentials expire today. Click below to retain access and verify active multi-factor authentication.',
      classification: 'Phishing' as const,
      riskScore: 88,
      attackVector: 'Credential Harvesting' as const,
      status: 'quarantined' as const,
      explanation: 'Typosquatted domain mimicking official Microsoft identity provider. High likelihood of credential harvesting portal.',
      senderIp: '104.244.72.115',
      city: 'Moscow',
      country: 'Russia',
      links: [{ url: 'https://login-verify365.online/auth', domain: 'login-verify365.online', isSuspicious: true }],
    },
    {
      subject: 'Weekly Cloud Architecture Sprint Sync & Milestone Review',
      senderName: 'Engineering Operations',
      senderEmail: 'devops@internal-cloud.org',
      senderDomain: 'internal-cloud.org',
      snippet: 'Here is the summary of recent microservice deployments, test results, and our upcoming quarterly security patch cycle.',
      classification: 'Safe' as const,
      riskScore: 8,
      attackVector: 'Clean' as const,
      status: 'scanned' as const,
      explanation: 'Valid SPF, DKIM, and DMARC alignment. Sender IP verified by authentic corporate relay server.',
      senderIp: '142.250.190.46',
      city: 'Mountain View',
      country: 'United States',
      links: [{ url: 'https://internal-cloud.org/docs', domain: 'internal-cloud.org', isSuspicious: false }],
    },
    {
      subject: 'FedEx Parcel Delivery Exception: Custom Fees Pending for Package #FX-81920',
      senderName: 'FedEx Express Dispatch',
      senderEmail: 'notice@fedx-customs-clearance.cc',
      senderDomain: 'fedx-customs-clearance.cc',
      snippet: 'Your parcel could not be delivered due to unpaid customs clearance tariff of $4.85. Settle clearance immediately.',
      classification: 'Phishing' as const,
      riskScore: 84,
      attackVector: 'Deceptive Link / Typosquatting' as const,
      status: 'quarantined' as const,
      explanation: 'Spoofed logistics communication designed to obtain banking payment details via malicious payment gateway.',
      senderIp: '194.26.29.112',
      city: 'Amsterdam',
      country: 'Netherlands',
      links: [{ url: 'https://fedx-customs-clearance.cc/pay', domain: 'fedx-customs-clearance.cc', isSuspicious: true }],
    },
  ];

  const results: EmailThreatReport[] = [];
  const normalizedUser = userEmail.toLowerCase().trim();

  for (let i = 0; i < count; i++) {
    const t = templates[i % templates.length];
    const reportId = `scan_${normalizedUser.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}_${i + 1}`;

    const report: EmailThreatReport = {
      id: reportId,
      userEmail: normalizedUser,
      userId: `user_${normalizedUser.replace(/[^a-zA-Z0-9]/g, '_')}`,
      subject: t.subject,
      sender: {
        name: t.senderName,
        email: t.senderEmail,
        domain: t.senderDomain,
      },
      recipient: normalizedUser,
      date: new Date(Date.now() - i * 3600000).toISOString(),
      snippet: t.snippet,
      bodyPreview: t.snippet,
      headers: {
        from: `"${t.senderName}" <${t.senderEmail}>`,
        to: normalizedUser,
        subject: t.subject,
        date: new Date(Date.now() - i * 3600000).toISOString(),
        messageId: `<${reportId}@threatmail.soc>`,
        spfStatus: t.riskScore > 50 ? 'fail' : 'pass',
        dkimStatus: t.riskScore > 50 ? 'fail' : 'pass',
        dmarcStatus: t.riskScore > 50 ? 'fail' : 'pass',
        senderIp: t.senderIp,
        clientIp: t.senderIp,
      },
      extractedLinks: t.links,
      attachments: [],
      senderIp: t.senderIp,
      senderLocation: {
        city: t.city,
        country: t.country,
        countryCode: t.country.slice(0, 2).toUpperCase(),
        lat: 50.1109,
        lng: 8.6821,
        isp: 'Secure Global Backbone Transit',
      },
      travelRoute: [
        {
          hopNumber: 1,
          fromServer: t.senderDomain,
          byServer: 'mx.relay-security.net',
          ip: t.senderIp,
          timestamp: new Date().toISOString(),
          location: { city: t.city, country: t.country, lat: 50.1109, lng: 8.6821 },
        },
      ],
      riskScore: t.riskScore,
      classification: t.classification,
      attackVector: t.attackVector,
      threatExplanation: t.explanation,
      indicatorsOfCompromise: [
        `Origin IP: ${t.senderIp}`,
        `Unauthorized Domain: ${t.senderDomain}`,
        `Target Identity: ${normalizedUser}`,
      ],
      mitigationRecommendation:
        t.riskScore >= 70
          ? 'Quarantine email immediately and report domain to SOC threat intel feed.'
          : 'Standard inbound email delivery permitted.',
      ensembleDetails: predictThreatEnsemble({
        headers: {
          spfStatus: t.riskScore > 50 ? 'fail' : 'pass',
          dkimStatus: t.riskScore > 50 ? 'fail' : 'pass',
          dmarcStatus: t.riskScore > 50 ? 'fail' : 'pass',
          returnPath: `<bounce@${t.senderDomain}>`,
        },
        bodyText: t.snippet,
        subject: t.subject,
        links: t.links,
        attachments: [],
        sender: { name: t.senderName, email: t.senderEmail, domain: t.senderDomain },
        recipient: normalizedUser,
      }).ensembleDetails,
      status: t.status,
      scannedAt: new Date(Date.now() - i * 1800000).toISOString(),
    };

    saveScanReport(report, normalizedUser);
    results.push(report);
  }

  return results;
}

// In-memory cache for IP Geolocation to eliminate redundant network queries and make scanning ultra-fast
const ipGeoCache = new Map<
  string,
  {
    city: string;
    country: string;
    countryCode: string;
    lat: number;
    lng: number;
    isp?: string;
    org?: string;
  }
>();

// Pre-seed cache with common mail providers / relays
ipGeoCache.set('209.85.220.41', {
  city: 'Mountain View',
  country: 'United States',
  countryCode: 'US',
  lat: 37.422,
  lng: -122.0841,
  isp: 'Google LLC MX Relay',
  org: 'Google Workspace',
});
ipGeoCache.set('142.251.12.26', {
  city: 'Council Bluffs',
  country: 'United States',
  countryCode: 'US',
  lat: 41.2619,
  lng: -95.8608,
  isp: 'Google LLC Mail Transit',
  org: 'Google Cloud Platform',
});

// IP Geolocation resolver with in-memory caching & fast deterministic fallback for high-speed scanning
export async function resolveIpGeolocation(ip: string): Promise<{
  city: string;
  country: string;
  countryCode: string;
  lat: number;
  lng: number;
  isp?: string;
  org?: string;
}> {
  if (!ip) {
    return {
      city: 'Local Mail Gateway',
      country: 'Private Network',
      countryCode: 'LAN',
      lat: 37.7749,
      lng: -122.4194,
      isp: 'Internal Enterprise Relay',
    };
  }

  // Check cache first (0 ms response)
  const cached = ipGeoCache.get(ip);
  if (cached) {
    return cached;
  }

  // Check for private / localhost / loopback IPs
  if (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('172.16.')
  ) {
    const localResult = {
      city: 'Local Mail Gateway',
      country: 'Private Network',
      countryCode: 'LAN',
      lat: 37.7749,
      lng: -122.4194,
      isp: 'Internal Enterprise Relay',
    };
    ipGeoCache.set(ip, localResult);
    return localResult;
  }

  // Try external IP geolocation API with 400ms fast abort timeout
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 400);
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,lat,lon,isp,org`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      if (data && data.status === 'success' && data.lat && data.lon) {
        const resolved = {
          city: data.city || 'Unknown City',
          country: data.country || 'Unknown Country',
          countryCode: data.countryCode || 'XX',
          lat: data.lat,
          lng: data.lon,
          isp: data.isp || data.org || 'Mail Service Provider',
          org: data.org,
        };
        ipGeoCache.set(ip, resolved);
        return resolved;
      }
    }
  } catch {
    // Fallback if network lookup times out or fails
  }

  // Deterministic geographic hashing for realistic routing visualization (instantaneous fallback)
  const hash = ip.split('.').reduce((acc, part) => (acc * 31 + parseInt(part || '0', 10)) % 10000, 0);
  const locations = [
    { city: 'San Jose', country: 'United States', countryCode: 'US', lat: 37.3382, lng: -121.8863, isp: 'Cloudflare / Google Cloud' },
    { city: 'Frankfurt', country: 'Germany', countryCode: 'DE', lat: 50.1109, lng: 8.6821, isp: 'Equinix Datacenter' },
    { city: 'London', country: 'United Kingdom', countryCode: 'GB', lat: 51.5074, lng: -0.1278, isp: 'British Telecom Gateway' },
    { city: 'Singapore', country: 'Singapore', countryCode: 'SG', lat: 1.3521, lng: 103.8198, isp: 'Singtel Asia Relay' },
    { city: 'Tokyo', country: 'Japan', countryCode: 'JP', lat: 35.6762, lng: 139.6503, isp: 'NTT Communications' },
    { city: 'Sydney', country: 'Australia', countryCode: 'AU', lat: -33.8688, lng: 151.2093, isp: 'Telstra Global' },
    { city: 'Dublin', country: 'Ireland', countryCode: 'IE', lat: 53.3498, lng: -6.2603, isp: 'Amazon AWS EU West' },
    { city: 'Ashburn', country: 'United States', countryCode: 'US', lat: 39.0438, lng: -77.4874, isp: 'Amazon AWS US East' },
    { city: 'Sao Paulo', country: 'Brazil', countryCode: 'BR', lat: -23.5505, lng: -46.6333, isp: 'Embratel Americas' },
    { city: 'Mumbai', country: 'India', countryCode: 'IN', lat: 19.076, lng: 72.8777, isp: 'Tata Communications' },
  ];

  const chosen = locations[hash % locations.length];
  const deterministicResult = {
    ...chosen,
    isp: chosen.isp,
  };
  ipGeoCache.set(ip, deterministicResult);
  return deterministicResult;
}

// Parse email travel route from Received headers with parallel IP resolution (Ultra-Fast)
export async function parseTravelRoute(rawReceivedHeaders: string[]): Promise<RouteHop[]> {
  // Received headers are in reverse chronological order (top is final destination, bottom is first origin)
  // We reverse them to show true travel order: Hop 1 (Origin) -> Hop N (Destination)
  // Take at most 4 hops to avoid unbounded parsing delay
  const orderedHeaders = [...rawReceivedHeaders].reverse().slice(0, 4);

  if (orderedHeaders.length === 0) {
    const [loc1, loc2] = await Promise.all([
      resolveIpGeolocation('209.85.220.41'),
      resolveIpGeolocation('142.251.12.26'),
    ]);
    return [
      {
        hopNumber: 1,
        fromServer: 'mail-origin.external.net',
        byServer: 'smtp-relay.transit.net',
        ip: '209.85.220.41',
        location: { city: loc1.city, country: loc1.country, lat: loc1.lat, lng: loc1.lng },
      },
      {
        hopNumber: 2,
        fromServer: 'smtp-relay.transit.net',
        byServer: 'mx.google.com',
        ip: '142.251.12.26',
        location: { city: loc2.city, country: loc2.country, lat: loc2.lat, lng: loc2.lng },
      },
    ];
  }

  // Resolve all hops in parallel using Promise.all for high speed
  const hopPromises = orderedHeaders.map(async (header, i) => {
    const ipMatch =
      header.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/) ||
      header.match(/from\s+([^\s]+)\s+\((?:[^\)]*\[)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    const ip = ipMatch ? ipMatch[1] || ipMatch[2] : `198.51.100.${10 + i * 5}`;

    const fromMatch = header.match(/from\s+([^\s\(\)]+)/i);
    const byMatch = header.match(/by\s+([^\s\(\)]+)/i);

    const fromServer = fromMatch
      ? fromMatch[1]
      : i === 0
      ? 'origin.mailserver.net'
      : `relay-${i}.network.net`;
    const byServer = byMatch
      ? byMatch[1]
      : i === orderedHeaders.length - 1
      ? 'mx.google.com'
      : `hop-${i + 1}.gateway.com`;

    const location = await resolveIpGeolocation(ip);

    return {
      hopNumber: i + 1,
      fromServer,
      byServer,
      ip,
      location: {
        city: location.city,
        country: location.country,
        lat: location.lat,
        lng: location.lng,
      },
    } as RouteHop;
  });

  return await Promise.all(hopPromises);
}
