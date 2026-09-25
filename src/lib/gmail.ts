import { EmailAttachment, EmailLink, SecurityHeaders } from '../types';

export interface RawGmailMessage {
  id: string;
  threadId: string;
  snippet: string;
  headers: SecurityHeaders;
  rawReceivedHeaders: string[];
  sender: {
    name: string;
    email: string;
    domain: string;
  };
  recipient: string;
  subject: string;
  date: string;
  bodyPreview: string;
  extractedLinks: EmailLink[];
  attachments: EmailAttachment[];
  senderIp?: string;
}

// Safely decode base64url strings from Gmail API payloads
function decodeBase64Url(base64UrlStr: string): string {
  if (!base64UrlStr || typeof base64UrlStr !== 'string') return '';
  try {
    const base64 = base64UrlStr.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder('utf-8').decode(bytes);
  } catch (e) {
    try {
      return atob(base64UrlStr.replace(/-/g, '+').replace(/_/g, '/'));
    } catch {
      return '';
    }
  }
}

// Extract URLs from text and HTML
function extractLinks(text: string): EmailLink[] {
  const links: EmailLink[] = [];
  const seenUrls = new Set<string>();

  // Extract from href="..."
  const hrefRegex = /href=["'](https?:\/\/[^"'\s>]+)["']/gi;
  let match;
  while ((match = hrefRegex.exec(text)) !== null) {
    const url = match[1];
    if (!seenUrls.has(url)) {
      seenUrls.add(url);
      try {
        const domain = new URL(url).hostname;
        const isSuspicious =
          domain.endsWith('.xyz') ||
          domain.endsWith('.ru') ||
          domain.endsWith('.top') ||
          domain.endsWith('.click') ||
          /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain) ||
          url.includes('login') ||
          url.includes('verify') ||
          url.includes('banking');
        links.push({ url, domain, isSuspicious });
      } catch {
        // ignore invalid url
      }
    }
  }

  // Extract raw URLs in text
  const rawUrlRegex = /(https?:\/\/[^\s<>"']+)/gi;
  while ((match = rawUrlRegex.exec(text)) !== null) {
    const url = match[1];
    if (!seenUrls.has(url)) {
      seenUrls.add(url);
      try {
        const domain = new URL(url).hostname;
        const isSuspicious =
          domain.endsWith('.xyz') ||
          domain.endsWith('.ru') ||
          domain.endsWith('.top') ||
          domain.endsWith('.click') ||
          /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain);
        links.push({ url, domain, isSuspicious });
      } catch {
        // ignore invalid url
      }
    }
  }

  return links;
}

// Extract sender information from "Name <email@domain.com>" or "email@domain.com"
function parseSender(fromHeader: string): { name: string; email: string; domain: string } {
  if (!fromHeader) {
    return { name: 'Unknown Sender', email: 'unknown@example.com', domain: 'example.com' };
  }

  const match = fromHeader.match(/^(?:["']?([^"']*)["']?\s*)?<([^>]+)>/);
  if (match) {
    const name = (match[1] || '').trim() || match[2].split('@')[0];
    const email = match[2].trim().toLowerCase();
    const domain = email.split('@')[1] || 'unknown.com';
    return { name, email, domain };
  }

  const email = fromHeader.trim().toLowerCase();
  const domain = email.split('@')[1] || 'unknown.com';
  return { name: email.split('@')[0], email, domain };
}

// Parse authentication statuses from Authentication-Results
function parseAuthResults(authHeader: string): {
  spfStatus?: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none';
  dkimStatus?: 'pass' | 'fail' | 'neutral' | 'none';
  dmarcStatus?: 'pass' | 'fail' | 'neutral' | 'none';
  clientIp?: string;
} {
  if (!authHeader) return {};

  const lower = authHeader.toLowerCase();

  let spfStatus: any = 'neutral';
  if (lower.includes('spf=pass')) spfStatus = 'pass';
  else if (lower.includes('spf=fail')) spfStatus = 'fail';
  else if (lower.includes('spf=softfail')) spfStatus = 'softfail';
  else if (lower.includes('spf=none')) spfStatus = 'none';

  let dkimStatus: any = 'neutral';
  if (lower.includes('dkim=pass')) dkimStatus = 'pass';
  else if (lower.includes('dkim=fail')) dkimStatus = 'fail';
  else if (lower.includes('dkim=none')) dkimStatus = 'none';

  let dmarcStatus: any = 'neutral';
  if (lower.includes('dmarc=pass')) dmarcStatus = 'pass';
  else if (lower.includes('dmarc=fail')) dmarcStatus = 'fail';
  else if (lower.includes('dmarc=none')) dmarcStatus = 'none';

  // Extract client IP if present: designator client-ip=1.2.3.4
  const ipMatch = authHeader.match(/client-ip=([0-9a-fA-F.:]+)/);
  const clientIp = ipMatch ? ipMatch[1] : undefined;

  return { spfStatus, dkimStatus, dmarcStatus, clientIp };
}

// Fetch list of messages from Gmail API
export async function fetchInboxMessages(
  accessToken: string,
  maxResults = 10,
  query = 'in:inbox'
): Promise<{ id: string; threadId: string }[]> {
  if (!accessToken || accessToken === 'analyst-token-active') {
    return [];
  }

  const fetchList = async (q?: string) => {
    const qParam = q ? `&q=${encodeURIComponent(q)}` : '';
    const url = `https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=${maxResults}${qParam}`;
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      },
    });

    if (!res.ok) {
      const errBody = await res.text();
      if (res.status === 401) {
        throw new Error('AUTH_EXPIRED: Your Google session has expired. Please sign in again.');
      }
      if (
        res.status === 403 &&
        (errBody.includes('ACCESS_TOKEN_SCOPE_INSUFFICIENT') ||
          errBody.includes('insufficientPermissions') ||
          errBody.includes('insufficient authentication scopes'))
      ) {
        throw new Error('ACCESS_TOKEN_SCOPE_INSUFFICIENT: Gmail API permission scope is required.');
      }
      throw new Error(`Gmail API error (${res.status}): ${errBody}`);
    }

    const data = await res.json();
    return data.messages || [];
  };

  try {
    let messages = await fetchList(query);
    if ((!messages || messages.length === 0) && query) {
      // Fallback to general mailbox messages if inbox filter yields none
      messages = await fetchList();
    }
    return messages || [];
  } catch (err) {
    throw err;
  }
}

// Fetch full message details and parse into structured security model
export async function fetchMessageDetail(
  accessToken: string,
  messageId: string
): Promise<RawGmailMessage> {
  const url = `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`;

  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch message ${messageId}: ${res.status}`);
  }

  const msg = await res.json();
  const headersList: { name: string; value: string }[] = msg.payload?.headers || [];

  const getHeader = (name: string): string => {
    const h = headersList.find((item) => item.name.toLowerCase() === name.toLowerCase());
    return h ? h.value : '';
  };

  const getAllHeaders = (name: string): string[] => {
    return headersList
      .filter((item) => item.name.toLowerCase() === name.toLowerCase())
      .map((item) => item.value);
  };

  const fromRaw = getHeader('From');
  const toRaw = getHeader('To') || 'me';
  const subject = getHeader('Subject') || '(No Subject)';
  const date = getHeader('Date') || new Date().toISOString();
  const messageIdHeader = getHeader('Message-ID') || msg.id;
  const returnPath = getHeader('Return-Path');
  const replyTo = getHeader('Reply-To');
  const authResults = getHeader('Authentication-Results');
  const rawReceivedHeaders = getAllHeaders('Received');

  const sender = parseSender(fromRaw);
  const { spfStatus, dkimStatus, dmarcStatus, clientIp } = parseAuthResults(authResults);

  // Extract body parts & attachments
  let bodyText = '';
  let bodyHtml = '';
  const attachments: EmailAttachment[] = [];

  function processPayload(part: any) {
    if (!part) return;

    if (part.filename && part.filename.length > 0) {
      attachments.push({
        filename: part.filename,
        mimeType: part.mimeType || 'application/octet-stream',
        size: part.body?.size || 0,
        attachmentId: part.body?.attachmentId,
        isSuspicious: /\.(exe|scr|vbs|bat|iso|zip|js|xlsm|docm)$/i.test(part.filename),
      });
    }

    if (part.mimeType === 'text/plain' && part.body?.data) {
      bodyText += decodeBase64Url(part.body.data) + '\n';
    } else if (part.mimeType === 'text/html' && part.body?.data) {
      bodyHtml += decodeBase64Url(part.body.data) + '\n';
    }

    if (part.parts && Array.isArray(part.parts)) {
      part.parts.forEach(processPayload);
    }
  }

  processPayload(msg.payload);

  const fullContent = bodyHtml + '\n' + bodyText;
  const extractedLinks = extractLinks(fullContent);

  // Extract sender IP from earliest Received header or clientIp
  let senderIp = clientIp;
  if (!senderIp && rawReceivedHeaders.length > 0) {
    const originHop = rawReceivedHeaders[rawReceivedHeaders.length - 1];
    const match = originHop.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
    if (match) {
      senderIp = match[1];
    }
  }

  const headers: SecurityHeaders = {
    from: fromRaw,
    to: toRaw,
    subject,
    date,
    messageId: messageIdHeader,
    returnPath,
    replyTo,
    spfStatus,
    dkimStatus,
    dmarcStatus,
    senderIp,
    clientIp,
    rawAuthenticationResults: authResults,
  };

  return {
    id: msg.id,
    threadId: msg.threadId,
    snippet: msg.snippet || '',
    headers,
    rawReceivedHeaders,
    sender,
    recipient: toRaw,
    subject,
    date,
    bodyPreview: (bodyText || (bodyHtml ? bodyHtml.replace(/<[^>]*>?/gm, ' ') : '') || msg.snippet || '').slice(0, 3000),
    extractedLinks,
    attachments,
    senderIp,
  };
}
