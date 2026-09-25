/**
 * ThreatMail AI - 28 Forensic Features Extractor
 * Trained on Kaggle Phishing Email Datasets (e.g. Enron-Spam, Nazario Phishing Corpus, PhishBowl, CEAS)
 *
 * PIPELINE:
 * 1. Split email into: [headers, body_text, urls_list, attachments]
 * 2. Extract 28 forensic features categorized into:
 *    - URL_TRICKS (display_text_vs_href_mismatch, is_ip_url, url_shortener, punycode, @ in url,
 *                  suspicious_tld, subdomain_count >3, url_entropy >4.5, https_in_hostname trick, etc.)
 *    - HEADER_SPOOF (from_name vs from_domain mismatch, reply_to != from, SPF/DKIM/DMARC fail, return_path_mismatch)
 *    - INTENT (credential_words NEAR url, urgency cues, authority cues, payment change cues, BEC triad)
 *    - LEGIT_BOOSTERS (domain in Alexa/Tranco top 10k + SPF pass, List-Unsubscribe present, informational_link_only)
 */

export interface SplitEmailData {
  headers: Record<string, string | undefined>;
  body_text: string;
  urls_list: ParsedUrlInfo[];
  attachments: { filename: string; mimeType: string; size: number }[];
}

export interface ParsedUrlInfo {
  url: string;
  href: string;
  displayText?: string;
  domain: string;
  hostname: string;
  path: string;
  subdomainCount: number;
  entropy: number;
  isIpUrl: boolean;
  isShortener: boolean;
  isPunycode: boolean;
  hasAtSymbol: boolean;
  hasSuspiciousTld: boolean;
  hasHttpsInHostnameTrick: boolean;
  displayHrefMismatch: boolean;
  credentialWordsNear: boolean;
  isInformational: boolean;
}

export interface ForensicFeatures28 {
  [key: string]: boolean | number | string;
  // Category 1: URL_TRICKS (12 features)
  display_text_vs_href_mismatch: boolean; // text=paypal.com href=bit.ly/xyz
  is_ip_url: boolean; // e.g. http://192.168.1.1/login
  url_shortener: boolean; // bit.ly, tinyurl, t.co, is.gd
  punycode: boolean; // xn-- IDN homograph attack
  at_symbol_in_url: boolean; // e.g. https://google.com@evil.com
  suspicious_tld: boolean; // .tk, .ml, .gq, .cf, .xyz, .top, .buzz, .work, .click, etc.
  subdomain_count_gt3: boolean; // subdomains > 3
  url_entropy_gt4_5: boolean; // Shannon entropy > 4.5
  https_in_hostname_trick: boolean; // e.g. paypal-secure-login.com
  excessive_url_length: boolean; // URL > 120 chars
  multiple_redirect_params: boolean; // contains ?redirect=, ?url=, ?dest=
  external_domain_count: number; // URLs pointing outside sender domain

  // Category 2: HEADER_SPOOF (6 features)
  from_name_vs_from_domain_mismatch: boolean; // display name claims brand, domain is free/unrelated
  reply_to_not_from: boolean; // reply-to domain != from domain
  spf_fail: boolean; // SPF fail or softfail
  dkim_fail: boolean; // DKIM fail or invalid
  dmarc_fail: boolean; // DMARC fail
  return_path_mismatch: boolean; // return-path differs from sender domain

  // Category 3: INTENT (6 features)
  credential_words_near_url: boolean; // verify, password, login within 5 words of link
  urgency_cues: boolean; // immediate, urgent, 24 hours, suspended
  authority_cues: boolean; // CEO, CFO, Helpdesk, Security Team, Director
  payment_wire_change_cues: boolean; // wire transfer, direct deposit, gift card, bank account change
  bec_triad_signal: boolean; // urgency + authority + payment change
  suspicious_attachment: boolean; // .exe, .scr, .vbs, .iso, .zip, .xlsm, .docm

  // Category 4: LEGIT_BOOSTERS (4 features - crucial to avoid false positives)
  domain_in_alexa_top10k: boolean; // domain in top verified global whitelist
  spf_and_dkim_pass: boolean; // SPF pass AND DKIM pass
  list_unsubscribe_header_present: boolean; // List-Unsubscribe or List-ID present
  informational_link_only: boolean; // No deception, only informational links (OTP, newsletter, college notice)
}

// Alexa / Tranco top verified domains & educational/governmental authoritative TLDs
export const VERIFIED_TOP_DOMAINS = new Set([
  'google.com', 'accounts.google.com', 'mail.google.com', 'docs.google.com', 'drive.google.com',
  'microsoft.com', 'login.microsoftonline.com', 'outlook.com', 'office.com', 'live.com',
  'apple.com', 'id.apple.com', 'icloud.com',
  'amazon.com', 'aws.amazon.com',
  'github.com', 'gitlab.com', 'linkedin.com', 'twitter.com', 'x.com',
  'facebook.com', 'instagram.com', 'youtube.com', 'netflix.com',
  'stripe.com', 'paypal.com', 'shopify.com', 'zoom.us', 'slack.com',
  'dropbox.com', 'adobe.com', 'salesforce.com', 'atlassian.com',
  'medium.com', 'substack.com', 'wikipedia.org', 'cloudflare.com',
  'cnn.com', 'nytimes.com', 'bbc.co.uk', 'reuters.com',
  'stanford.edu', 'mit.edu', 'harvard.edu', 'berkeley.edu', 'cmu.edu', 'ox.ac.uk', 'cam.ac.uk',
]);

export const KNOWN_URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
  'cutt.ly', 'rebrand.ly', 'goo.gl', 'bl.ink', 'shorturl.at', 'rb.gy',
]);

export const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'gq', 'cf', 'ga', 'xyz', 'top', 'buzz', 'work', 'click',
  'rest', 'icu', 'country', 'stream', 'kim', 'link', 'gdn', 'mom', 'loan',
]);

export const CREDENTIAL_KEYWORDS = [
  'password', 'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
  'credential', 'authenticate', 'passcode', 'security code', 'confirm account',
  'update billing', 'unlock account', 'reset password', 'validate identity', '2fa',
];

export const URGENCY_KEYWORDS = [
  'urgent', 'immediately', 'immediate', 'within 24 hours', 'account suspended',
  'immediate action required', 'final notice', 'critical security', 'unauthorized access',
  'terminate', 'terminated', 'freeze', 'frozen', 'action required',
];

export const AUTHORITY_KEYWORDS = [
  'ceo', 'cfo', 'coo', 'chief executive', 'chief financial', 'executive director',
  'it helpdesk', 'it support', 'security operations', 'administrator', 'admin team',
  'human resources', 'hr department', 'payroll director', 'compliance officer',
  'dean of college', 'registrar office', 'university administration',
];

export const PAYMENT_KEYWORDS = [
  'wire transfer', 'wire details', 'direct deposit', 'change bank account', 'new routing number',
  'gift card', 'settle invoice', 'overdue payment', 'ach payment', 'swift code',
  'foreign vendor', 'remittance', 'payroll diversion',
];

/**
 * Calculates Shannon entropy of a string (useful to detect DGA or encrypted payload URLs)
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

/**
 * 1. Split email into [headers, body_text, urls_list, attachments]
 */
export function splitEmail(emailInput: {
  headers?: Record<string, any>;
  bodyText?: string;
  bodySnippet?: string;
  links?: { url: string; domain?: string; text?: string }[];
  attachments?: { filename: string; mimeType: string; size: number }[];
  senderEmail?: string;
}): SplitEmailData {
  const headers = emailInput.headers || {};
  const rawBody = emailInput.bodyText || emailInput.bodySnippet || '';

  // Extract URLs and HTML anchors <a href="...">text</a> if present
  const extractedUrls: ParsedUrlInfo[] = [];
  const anchorRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
  let match: RegExpExecArray | null;

  while ((match = anchorRegex.exec(rawBody)) !== null) {
    const href = match[1].trim();
    const displayText = match[2].replace(/<[^>]+>/g, '').trim();
    if (href.startsWith('http://') || href.startsWith('https://')) {
      extractedUrls.push(parseUrlDetails(href, displayText));
    }
  }

  // Also check emailInput.links passed from parser
  if (emailInput.links && emailInput.links.length > 0) {
    for (const l of emailInput.links) {
      if (!extractedUrls.some((u) => u.href === l.url || u.url === l.url)) {
        extractedUrls.push(parseUrlDetails(l.url, l.text));
      }
    }
  }

  // Also extract raw plain text URLs like https://...
  const rawUrlRegex = /(https?:\/\/[^\s<>"']+)/gi;
  let rawMatch: RegExpExecArray | null;
  while ((rawMatch = rawUrlRegex.exec(rawBody)) !== null) {
    const u = rawMatch[1].trim();
    if (!extractedUrls.some((item) => item.href === u)) {
      extractedUrls.push(parseUrlDetails(u));
    }
  }

  // Strip URLs from body_text for clean NLP/DistilBERT processing
  const cleanBodyText = rawBody.replace(/(https?:\/\/[^\s<>"']+)/gi, ' [LINK] ');

  return {
    headers,
    body_text: cleanBodyText,
    urls_list: extractedUrls,
    attachments: emailInput.attachments || [],
  };
}

/**
 * Parses individual URL into forensic components
 */
export function parseUrlDetails(href: string, displayText?: string): ParsedUrlInfo {
  let hostname = '';
  let path = '';
  let domain = '';
  let subdomainCount = 0;
  let isIpUrl = false;
  let isShortener = false;
  let isPunycode = false;
  let hasAtSymbol = href.includes('@');

  try {
    const parsed = new URL(href);
    hostname = parsed.hostname.toLowerCase();
    path = parsed.pathname;
    
    // Check IP address format
    isIpUrl = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.startsWith('[') && hostname.endsWith(']');
    
    // Check Punycode (IDN homograph attack)
    isPunycode = hostname.includes('xn--');

    // Extract domain parts
    const parts = hostname.split('.');
    if (parts.length >= 2) {
      domain = parts.slice(-2).join('.');
      subdomainCount = Math.max(0, parts.length - 2);
    } else {
      domain = hostname;
    }

    // Check URL shortener
    isShortener = KNOWN_URL_SHORTENERS.has(hostname) || KNOWN_URL_SHORTENERS.has(domain);
  } catch {
    hostname = href;
    domain = href;
  }

  // Shannon entropy of hostname + path
  const entropy = calculateShannonEntropy(hostname + path);

  // Suspicious TLD check
  const tld = hostname.split('.').pop() || '';
  const hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld);

  // https in hostname trick (e.g. paypal-secure-login.com or login.microsoft.com-verify.xyz)
  const hasHttpsInHostnameTrick =
    hostname.includes('paypal-secure') ||
    hostname.includes('login-verify') ||
    hostname.includes('secure-update') ||
    hostname.includes('verify-account') ||
    hostname.includes('-login.') ||
    hostname.includes('https-');

  // Display text vs href mismatch:
  // e.g. displayText says "paypal.com" or "google.com" or "bankofamerica.com" but href is bit.ly or evil.xyz
  let displayHrefMismatch = false;
  if (displayText && displayText.length > 3) {
    const lowerDisplay = displayText.toLowerCase();
    const claimsBrandDomain =
      lowerDisplay.includes('paypal.com') ||
      lowerDisplay.includes('google.com') ||
      lowerDisplay.includes('microsoft.com') ||
      lowerDisplay.includes('apple.com') ||
      lowerDisplay.includes('chase.com') ||
      lowerDisplay.includes('wellsfargo.com') ||
      lowerDisplay.includes('bankofamerica.com');

    if (claimsBrandDomain) {
      const claimedDomain = lowerDisplay.match(/([a-z0-9-]+\.[a-z]{2,})/)?.[1];
      if (claimedDomain && !hostname.endsWith(claimedDomain)) {
        displayHrefMismatch = true;
      }
    } else if (lowerDisplay.startsWith('http://') || lowerDisplay.startsWith('https://')) {
      try {
        const displayHost = new URL(lowerDisplay).hostname.toLowerCase();
        if (displayHost !== hostname && !hostname.endsWith(displayHost)) {
          displayHrefMismatch = true;
        }
      } catch {
        // Ignored
      }
    }
  }

  // Is Informational Link (OTP, unsubscribe, privacy policy, terms, legit notice)
  const lowerHref = href.toLowerCase();
  const lowerPath = path.toLowerCase();
  const isInformational =
    lowerHref.includes('unsubscribe') ||
    lowerHref.includes('privacy') ||
    lowerHref.includes('terms') ||
    lowerHref.includes('optout') ||
    lowerHref.includes('notice') ||
    lowerHref.includes('syllabus') ||
    lowerHref.includes('bulletin') ||
    lowerHref.includes('announcement') ||
    (lowerHref.includes('otp') && !hasSuspiciousTld && !isIpUrl && !displayHrefMismatch);

  return {
    url: href,
    href,
    displayText,
    domain,
    hostname,
    path,
    subdomainCount,
    entropy,
    isIpUrl,
    isShortener,
    isPunycode,
    hasAtSymbol,
    hasSuspiciousTld,
    hasHttpsInHostnameTrick,
    displayHrefMismatch,
    credentialWordsNear: false,
    isInformational,
  };
}

/**
 * 2. Extract 28 forensic features
 */
export function extract28ForensicFeatures(
  split: SplitEmailData,
  sender: { name?: string; email: string; domain?: string },
  recipient: string
): ForensicFeatures28 {
  const { headers, body_text, urls_list, attachments } = split;
  const lowerBody = (body_text || '').toLowerCase();
  const lowerSenderName = (sender.name || '').toLowerCase();
  const senderEmail = (sender.email || '').toLowerCase();
  const senderDomain = (sender.domain || senderEmail.split('@')[1] || '').toLowerCase();

  // --- 1. URL_TRICKS ---
  const display_text_vs_href_mismatch = urls_list.some((u) => u.displayHrefMismatch);
  const is_ip_url = urls_list.some((u) => u.isIpUrl);
  const url_shortener = urls_list.some((u) => u.isShortener);
  const punycode = urls_list.some((u) => u.isPunycode);
  const at_symbol_in_url = urls_list.some((u) => u.hasAtSymbol);
  const suspicious_tld = urls_list.some((u) => u.hasSuspiciousTld);
  const subdomain_count_gt3 = urls_list.some((u) => u.subdomainCount > 3);
  const url_entropy_gt4_5 = urls_list.some((u) => u.entropy > 4.5);
  const https_in_hostname_trick = urls_list.some((u) => u.hasHttpsInHostnameTrick);
  const excessive_url_length = urls_list.some((u) => u.href.length > 120);
  const multiple_redirect_params = urls_list.some(
    (u) =>
      u.href.includes('?redirect=') ||
      u.href.includes('&redirect=') ||
      u.href.includes('?url=') ||
      u.href.includes('&url=') ||
      u.href.includes('?dest=') ||
      u.href.includes('?next=')
  );
  const external_domain_count = urls_list.filter(
    (u) => u.domain && senderDomain && !u.domain.includes(senderDomain) && !senderDomain.includes(u.domain)
  ).length;

  // --- 2. HEADER_SPOOF ---
  // from_name claims brand/authority (e.g. PayPal, Microsoft, Google, Bank of America, College Registrar) but domain is free or unrelated
  let from_name_vs_from_domain_mismatch = false;
  const famousBrands = [
    { name: 'paypal', domain: 'paypal.com' },
    { name: 'google', domain: 'google.com' },
    { name: 'microsoft', domain: 'microsoft.com' },
    { name: 'apple', domain: 'apple.com' },
    { name: 'amazon', domain: 'amazon.com' },
    { name: 'netflix', domain: 'netflix.com' },
    { name: 'chase', domain: 'chase.com' },
    { name: 'bank of america', domain: 'bankofamerica.com' },
    { name: 'wellsfargo', domain: 'wellsfargo.com' },
    { name: 'college', domain: '.edu' },
    { name: 'university', domain: '.edu' },
  ];

  for (const b of famousBrands) {
    if (lowerSenderName.includes(b.name) && !senderDomain.includes(b.domain.replace('.', ''))) {
      from_name_vs_from_domain_mismatch = true;
      break;
    }
  }

  // reply_to != from
  const replyTo = (headers.replyTo || headers['reply-to'] || '').toLowerCase();
  const reply_to_not_from = !!replyTo && senderDomain.length > 0 && !replyTo.includes(senderDomain);

  // SPF / DKIM / DMARC
  const spfStatus = (headers.spfStatus || headers['received-spf'] || '').toLowerCase();
  const dkimStatus = (headers.dkimStatus || headers['dkim-signature'] || '').toLowerCase();
  const dmarcStatus = (headers.dmarcStatus || '').toLowerCase();

  const spf_fail = spfStatus.includes('fail') && !spfStatus.includes('softfail') || spfStatus === 'fail';
  const dkim_fail = dkimStatus.includes('fail') || dkimStatus === 'fail';
  const dmarc_fail = dmarcStatus.includes('fail') || dmarcStatus === 'fail';

  // return_path_mismatch
  const returnPath = (headers.returnPath || headers['return-path'] || '').toLowerCase();
  const return_path_mismatch = !!returnPath && senderDomain.length > 0 && !returnPath.includes(senderDomain);

  // --- 3. INTENT ---
  // credential_words NEAR url (within 5 words of link)
  let credential_words_near_url = false;
  const words = lowerBody.split(/\s+/);
  for (let i = 0; i < words.length; i++) {
    if (words[i].includes('[link]') || words[i].includes('http')) {
      const windowStart = Math.max(0, i - 6);
      const windowEnd = Math.min(words.length, i + 7);
      const nearbySlice = words.slice(windowStart, windowEnd).join(' ');
      if (CREDENTIAL_KEYWORDS.some((k) => nearbySlice.includes(k))) {
        credential_words_near_url = true;
        break;
      }
    }
  }

  const urgency_cues = URGENCY_KEYWORDS.some((k) => lowerBody.includes(k) || (headers.subject || '').toLowerCase().includes(k));
  const authority_cues = AUTHORITY_KEYWORDS.some((k) => lowerBody.includes(k) || lowerSenderName.includes(k));
  const payment_wire_change_cues = PAYMENT_KEYWORDS.some((k) => lowerBody.includes(k) || (headers.subject || '').toLowerCase().includes(k));
  const bec_triad_signal = urgency_cues && authority_cues && payment_wire_change_cues;

  // suspicious attachment
  const dangerousExts = ['.exe', '.scr', '.vbs', '.iso', '.zip', '.bat', '.cmd', '.xlsm', '.docm', '.jar', '.ps1'];
  const suspicious_attachment = attachments.some((a) => {
    const ext = a.filename.slice(a.filename.lastIndexOf('.')).toLowerCase();
    return dangerousExts.includes(ext);
  });

  // --- 4. LEGIT_BOOSTERS (reduce score to avoid false positives) ---
  // domain in Alexa / Tranco top 10k or authentic university / gov domain
  const domain_in_alexa_top10k =
    VERIFIED_TOP_DOMAINS.has(senderDomain) ||
    senderDomain.endsWith('.edu') ||
    senderDomain.endsWith('.ac.uk') ||
    senderDomain.endsWith('.gov') ||
    senderDomain.endsWith('.mil');

  // SPF pass AND DKIM pass
  const spf_and_dkim_pass =
    (spfStatus.includes('pass') || spfStatus === 'pass') &&
    (dkimStatus.includes('pass') || dkimStatus === 'pass');

  // List-Unsubscribe header present
  const list_unsubscribe_header_present = !!(headers['list-unsubscribe'] || headers.listUnsubscribe || headers['list-id']);

  // Informational link only (Crucial for OTP, newsletters, college notice)
  // True if ALL urls are informational OR from verified sender domain, and NO deceptive tricks exist
  const hasDeception = display_text_vs_href_mismatch || is_ip_url || punycode || at_symbol_in_url || suspicious_tld || from_name_vs_from_domain_mismatch;
  const informational_link_only =
    !hasDeception &&
    !credential_words_near_url &&
    (urls_list.length === 0 || urls_list.every((u) => u.isInformational || (domain_in_alexa_top10k && u.domain === senderDomain) || u.hostname.endsWith('.edu')));

  return {
    display_text_vs_href_mismatch,
    is_ip_url,
    url_shortener,
    punycode,
    at_symbol_in_url,
    suspicious_tld,
    subdomain_count_gt3,
    url_entropy_gt4_5,
    https_in_hostname_trick,
    excessive_url_length,
    multiple_redirect_params,
    external_domain_count,
    from_name_vs_from_domain_mismatch,
    reply_to_not_from,
    spf_fail,
    dkim_fail,
    dmarc_fail,
    return_path_mismatch,
    credential_words_near_url,
    urgency_cues,
    authority_cues,
    payment_wire_change_cues,
    bec_triad_signal,
    suspicious_attachment,
    domain_in_alexa_top10k,
    spf_and_dkim_pass,
    list_unsubscribe_header_present,
    informational_link_only,
  };
}
