export type ThreatClassification =
  | 'Safe'
  | 'Suspicious'
  | 'Phishing'
  | 'Malware Risk'
  | 'Business Email Compromise';

export type AttackVector =
  | 'Clean'
  | 'Credential Harvesting'
  | 'VIP Impersonation / BEC'
  | 'Malicious Attachment / Payload'
  | 'Deceptive Link / Typosquatting'
  | 'Extortion / Blackmail'
  | 'Suspicious Relay / Spoofing';

export interface EmailAttachment {
  filename: string;
  mimeType: string;
  size: number;
  attachmentId?: string;
  isSuspicious?: boolean;
}

export interface EmailLink {
  url: string;
  domain: string;
  isSuspicious: boolean;
  reason?: string;
}

export interface RouteHop {
  hopNumber: number;
  fromServer: string;
  byServer: string;
  ip: string;
  timestamp?: string;
  location?: {
    city?: string;
    country?: string;
    lat: number;
    lng: number;
  };
}

export interface SecurityHeaders {
  from: string;
  to: string;
  subject: string;
  date: string;
  messageId: string;
  returnPath?: string;
  replyTo?: string;
  spfStatus?: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none';
  dkimStatus?: 'pass' | 'fail' | 'neutral' | 'none';
  dmarcStatus?: 'pass' | 'fail' | 'neutral' | 'none';
  senderIp?: string;
  clientIp?: string;
  rawAuthenticationResults?: string;
}

export interface EmailThreatReport {
  id: string; // Message ID
  threadId?: string;
  userEmail?: string; // Dedicated owner email identity for private scan history
  userId?: string;
  subject: string;
  sender: {
    name: string;
    email: string;
    domain: string;
  };
  recipient: string;
  date: string;
  snippet: string;
  bodyPreview: string;
  headers: SecurityHeaders;
  extractedLinks: EmailLink[];
  attachments: EmailAttachment[];
  
  // Geolocation & Route
  senderIp?: string;
  senderLocation?: {
    city: string;
    country: string;
    countryCode: string;
    lat: number;
    lng: number;
    isp?: string;
    org?: string;
  };
  travelRoute: RouteHop[];
  
  // AI & Insforge Classification
  riskScore: number; // 0 - 100
  classification: ThreatClassification;
  attackVector: AttackVector;
  threatExplanation: string;
  indicatorsOfCompromise: string[];
  mitigationRecommendation: string;
  
  // Forensic Status
  status: 'scanned' | 'quarantined' | 'whitelisted' | 'monitoring';
  scannedAt: string;

  // Kaggle Ensemble Model Forensic Evaluation
  ensembleDetails?: {
    modelType: string;
    textBranchScore: number;
    xgbBranchScore: number;
    rawEnsembleScore: number;
    hardOverrideTriggered: boolean;
    hardOverrideReason?: string;
    legitBoostersApplied: string[];
    features28?: Record<string, boolean | number | string>;
    sih26106OutputLabel?: 'SAFE' | 'PHISHING' | 'MALWARE' | 'BEC' | 'SPAM';
    sih26106ModelFile?: string;
    urlDeceptionCapped?: boolean;
  };
}

export interface InsforgeNotification {
  id: string;
  reportId: string;
  userEmail?: string; // Logged-in user who owns this notification
  title: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  classification: ThreatClassification;
  type?: string;
  riskScore: number;
  sender: string;
  timestamp: string;
  createdAt?: string;
  read: boolean;
}

export interface InsforgeStats {
  totalScanned: number;
  threatsBlocked: number;
  safeEmails: number;
  averageRiskScore: number;
  highRiskCount: number;
  phishingCount: number;
  malwareCount: number;
  becCount: number;
  suspiciousCount: number;
  lastScannedAt: string | null;
}
