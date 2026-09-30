import { GoogleGenAI, Type } from '@google/genai';
import { ThreatClassification, AttackVector } from '../src/types.js';
import { predictThreatEnsemble, EnsemblePredictionResult } from './kaggleEnsembleModel.js';

let aiClient: GoogleGenAI | null = null;

function getAi(): GoogleGenAI {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    aiClient = new GoogleGenAI({
      apiKey: apiKey || '',
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiClient;
}

export interface EmailScanInput {
  sender: {
    name: string;
    email: string;
    domain: string;
  };
  recipient: string;
  subject: string;
  bodySnippet: string;
  bodyText: string;
  headers: {
    spfStatus?: string;
    dkimStatus?: string;
    dmarcStatus?: string;
    returnPath?: string;
    replyTo?: string;
    senderIp?: string;
    [key: string]: any;
  };
  links: { url: string; domain: string; text?: string }[];
  attachments: { filename: string; mimeType: string; size: number }[];
  senderLocation?: { city: string; country: string; isp?: string };
}

export interface AiScanResult {
  classification: ThreatClassification;
  riskScore: number;
  attackVector: AttackVector;
  threatExplanation: string;
  indicatorsOfCompromise: string[];
  mitigationRecommendation: string;
  ensembleDetails?: {
    modelType: string;
    textBranchScore: number;
    xgbBranchScore: number;
    rawEnsembleScore: number;
    hardOverrideTriggered: boolean;
    hardOverrideReason?: string;
    legitBoostersApplied: string[];
    features28?: Record<string, boolean | number | string>;
  };
}

export function getActiveAiInfo(): { provider: string; model: string } {
  if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY') {
    return {
      provider: 'Kaggle Ensemble + Gemini AI',
      model: 'DistilBERT+XGBoost (0.65/0.35) & Gemini 3.5 Flash',
    };
  }
  return {
    provider: 'Kaggle Phishing Ensemble Engine',
    model: 'DistilBERT (NLP) + XGBoost (28 Forensic Features)',
  };
}

function buildThreatAnalysisPrompt(input: EmailScanInput, ensembleResult: EnsemblePredictionResult): string {
  const f = ensembleResult.ensembleDetails.features28;
  return `You are a Principal SOC Analyst & Cybersecurity Threat Hunter for ThreatMail AI.
Analyze the following incoming email using the Kaggle Email Forensic Pipeline.

OBJECTIVE: Exact threat detection. Do NOT flag every email containing links.
A legitimate email with links (OTP, newsletter, college notice, order receipt) with valid SPF/DKIM must be classified as SAFE.

28 FORENSIC FEATURES EXTRACTED BY XGBOOST BRANCH:
- Display Text vs Href Mismatch: ${f.display_text_vs_href_mismatch} (Anchor text claims trusted brand while href points elsewhere)
- Raw IP in URL: ${f.is_ip_url}
- URL Shortener: ${f.url_shortener}
- Punycode / Homograph (xn--): ${f.punycode}
- @ symbol in URL: ${f.at_symbol_in_url}
- Suspicious TLD (.tk, .xyz, .top, etc.): ${f.suspicious_tld}
- Subdomains > 3: ${f.subdomain_count_gt3}
- High URL Shannon Entropy (>4.5): ${f.url_entropy_gt4_5}
- HTTPS-in-Hostname Trick: ${f.https_in_hostname_trick}
- Display Name vs Domain Mismatch: ${f.from_name_vs_from_domain_mismatch}
- Reply-To Mismatch: ${f.reply_to_not_from}
- SPF Fail: ${f.spf_fail} | DKIM Fail: ${f.dkim_fail} | DMARC Fail: ${f.dmarc_fail}
- Credential Words Near Link: ${f.credential_words_near_url}
- BEC Triad (Urgency + Authority + Payment): ${f.bec_triad_signal}
- Dangerous Attachment Payload: ${f.suspicious_attachment}
- Domain in Alexa Top 10k / .EDU: ${f.domain_in_alexa_top10k}
- Cryptographic Pass (SPF & DKIM): ${f.spf_and_dkim_pass}
- List-Unsubscribe Header Present: ${f.list_unsubscribe_header_present}
- Informational Links Only (Benign OTP / Newsletter / Notice): ${f.informational_link_only}

ENSEMBLE PRELIMINARY VERDICT:
- DistilBERT Text Branch: ${ensembleResult.ensembleDetails.textBranchScore}/100
- XGBoost 28-Feature Branch: ${ensembleResult.ensembleDetails.xgbBranchScore}/100
- 0.65*BERT + 0.35*XGB Score: ${ensembleResult.ensembleDetails.rawEnsembleScore}/100
- Hard Override Triggered: ${ensembleResult.ensembleDetails.hardOverrideTriggered} (${ensembleResult.ensembleDetails.hardOverrideReason || 'None'})
- Legit Boosters Applied: ${ensembleResult.ensembleDetails.legitBoostersApplied.join(', ') || 'None'}
- Computed Risk Score: ${ensembleResult.finalRiskScore}/100 -> Classification: ${ensembleResult.classification}

EMAIL DETAILS:
- From: "${input.sender.name}" <${input.sender.email}> (Domain: ${input.sender.domain})
- To: ${input.recipient}
- Return-Path: ${input.headers.returnPath || 'N/A'}
- Reply-To: ${input.headers.replyTo || 'N/A'}
- Subject: "${input.subject}"
- SPF Authentication: ${input.headers.spfStatus || 'none'}
- DKIM Authentication: ${input.headers.dkimStatus || 'none'}
- DMARC Authentication: ${input.headers.dmarcStatus || 'none'}
- Sender IP: ${input.headers.senderIp || 'N/A'} (Location: ${input.senderLocation?.city || 'Unknown'}, ${input.senderLocation?.country || 'Unknown'})

EXTRACTED HYPERLINKS (${input.links.length}):
${input.links.slice(0, 10).map((l) => `- ${l.url} [Domain: ${l.domain}]`).join('\n') || 'None'}

ATTACHMENTS (${input.attachments.length}):
${input.attachments.map((a) => `- ${a.filename} (${a.mimeType}, ${Math.round(a.size / 1024)} KB)`).join('\n') || 'None'}

EMAIL BODY CONTENT (URLs stripped for NLP):
"""
${ensembleResult.ensembleDetails.features28 ? input.bodyText.slice(0, 2500) : input.bodySnippet || '(Empty body)'}
"""

INSTRUCTIONS:
1. If the email is a legitimate OTP verification, institutional college notice, or verified newsletter from an authentic domain with passing SPF/DKIM and no deceptive anchor mismatch, you MUST classify it as "Safe" with Risk Score <= 20.
2. If deceptive link tricks (e.g. anchor says paypal.com but href goes elsewhere) or credential theft are present, classify as "Phishing" with Risk Score >= 85.
3. If executive authority + wire payment diversion is requested, classify as "Business Email Compromise".

Respond ONLY with valid JSON having this exact schema:
{
  "classification": "Safe" | "Suspicious" | "Phishing" | "Malware Risk" | "Business Email Compromise",
  "riskScore": number,
  "attackVector": string,
  "threatExplanation": string,
  "indicatorsOfCompromise": string[],
  "mitigationRecommendation": string
}`;
}

function parseAndValidateResult(parsed: any): AiScanResult {
  const validClassifications: ThreatClassification[] = [
    'Safe',
    'Suspicious',
    'Phishing',
    'Malware Risk',
    'Business Email Compromise',
  ];
  const classification: ThreatClassification = validClassifications.includes(parsed.classification)
    ? parsed.classification
    : (parsed.riskScore || 0) > 60
    ? 'Phishing'
    : 'Suspicious';

  return {
    classification,
    riskScore: Math.max(0, Math.min(100, Number(parsed.riskScore) || 0)),
    attackVector: parsed.attackVector || 'Clean',
    threatExplanation: parsed.threatExplanation || 'Email evaluated through Insforge SOC AI threat hunter engine.',
    indicatorsOfCompromise: Array.isArray(parsed.indicatorsOfCompromise) ? parsed.indicatorsOfCompromise : [],
    mitigationRecommendation: parsed.mitigationRecommendation || 'Continue monitoring inbound traffic.',
  };
}

// OpenRouter Threat Analysis Implementation (Secondary Fallback)
async function analyzeWithOpenRouter(
  input: EmailScanInput,
  apiKey: string,
  ensembleResult?: EnsemblePredictionResult
): Promise<AiScanResult | null> {
  try {
    const prompt = buildThreatAnalysisPrompt(input, ensembleResult);
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': process.env.APP_URL || 'https://threatmail.ai',
        'X-Title': 'ThreatMail AI SOC Threat Hunter',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        max_tokens: 300,
        messages: [
          {
            role: 'system',
            content: 'You are a Principal SOC Analyst & Cybersecurity Threat Hunter for ThreatMail AI. Respond strictly with valid JSON without markdown wrapping.',
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        response_format: { type: 'json_object' },
        temperature: 0.1,
      }),
    });

    if (!response.ok) {
      if (response.status === 402) {
        // Insufficient credits on OpenRouter account - gracefully fall back without throwing errors
        return null;
      }
      return null;
    }

    const data: any = await response.json();
    let content = data.choices?.[0]?.message?.content;
    if (!content) return null;

    if (content.includes('```json')) {
      content = content.replace(/```json\s*/, '').replace(/\s*```/, '');
    } else if (content.includes('```')) {
      content = content.replace(/```\s*/, '').replace(/\s*```/, '');
    }

    const parsed = JSON.parse(content);
    return parseAndValidateResult(parsed);
  } catch (err: any) {
    return null;
  }
}

export async function analyzeEmailWithGemini(input: EmailScanInput): Promise<AiScanResult> {
  // 1. Run Kaggle 28-forensic-feature extractor & DistilBERT + XGBoost ensemble
  const ensembleResult = predictThreatEnsemble({
    headers: input.headers,
    bodyText: input.bodyText,
    bodySnippet: input.bodySnippet,
    subject: input.subject,
    links: input.links,
    attachments: input.attachments,
    sender: input.sender,
    recipient: input.recipient,
  });

  // 2. Primary: Use native Google Gemini API if GEMINI_API_KEY is present
  if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY') {
    const ai = getAi();
    const prompt = buildThreatAnalysisPrompt(input, ensembleResult);
    // Use valid Gemini model aliases per AI Studio guidelines
    const candidateModels = [
      'gemini-3.8-flash',
      'gemini-3.1-flash-lite',
      'gemini-flash-latest',
    ];

    for (const modelName of candidateModels) {
      try {
        // Enforce a strict 2.5-second timeout so email scanning never stalls or delays
        const generatePromise = ai.models.generateContent({
          model: modelName,
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                classification: {
                  type: Type.STRING,
                  description: 'One of: Safe, Suspicious, Phishing, Malware Risk, Business Email Compromise',
                },
                riskScore: {
                  type: Type.INTEGER,
                  description: 'Risk score from 0 to 100',
                },
                attackVector: {
                  type: Type.STRING,
                  description: 'Primary attack vector',
                },
                threatExplanation: {
                  type: Type.STRING,
                  description: 'SOC forensic threat analysis explanation',
                },
                indicatorsOfCompromise: {
                  type: Type.ARRAY,
                  items: { type: Type.STRING },
                  description: 'List of observed technical IoCs',
                },
                mitigationRecommendation: {
                  type: Type.STRING,
                  description: 'Recommended SOC action',
                },
              },
              required: [
                'classification',
                'riskScore',
                'attackVector',
                'threatExplanation',
                'indicatorsOfCompromise',
                'mitigationRecommendation',
              ],
            },
          },
        });

        const timeoutPromise = new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('TIMEOUT_FAST_SCAN')), 2500)
        );

        const response: any = await Promise.race([generatePromise, timeoutPromise]);

        if (response.text) {
          const parsed = JSON.parse(response.text);
          const validated = parseAndValidateResult(parsed);

          // Apply Kaggle Ensemble guarantees:
          // 1. Critical deception hard override
          if (ensembleResult.ensembleDetails.hardOverrideTriggered) {
            validated.classification = 'Phishing';
            validated.riskScore = Math.max(validated.riskScore, ensembleResult.finalRiskScore);
            validated.attackVector = 'Deceptive Link / Typosquatting';
          }
          // 2. Legit booster guarantee (Do NOT flag every email containing links! OTP, newsletter, college notice must be SAFE)
          if (ensembleResult.ensembleDetails.legitBoostersApplied.length > 0) {
            validated.classification = 'Safe';
            validated.riskScore = Math.min(validated.riskScore, 18);
            validated.attackVector = 'Clean';
          }

          validated.ensembleDetails = ensembleResult.ensembleDetails;
          return validated;
        }
      } catch (err: any) {
        const errMsg = String(err?.message || '');
        if (errMsg.includes('TIMEOUT_FAST_SCAN')) {
          console.log(`[ThreatMail SOC] ${modelName} took >2.5s; rapidly accelerating via Kaggle ensemble.`);
          break; // Don't delay scanning, immediately use ensemble
        }
        const isQuota =
          err?.status === 429 ||
          errMsg.includes('429') ||
          errMsg.includes('RESOURCE_EXHAUSTED') ||
          errMsg.includes('quota') ||
          errMsg.includes('Quota exceeded');

        if (isQuota) {
          console.log(`[ThreatMail SOC] ${modelName} reached rate limit, trying secondary model...`);
          continue;
        } else {
          console.log(`[ThreatMail SOC] ${modelName} evaluation fallback to Kaggle ensemble.`);
          continue;
        }
      }
    }
  }

  // 3. Secondary: Check if OpenRouter API is configured
  const openRouterKey = process.env.OPENROUTER_API_KEY;
  if (openRouterKey && openRouterKey.trim().length > 0) {
    const openRouterResult = await analyzeWithOpenRouter(input, openRouterKey.trim(), ensembleResult);
    if (openRouterResult) {
      if (ensembleResult.ensembleDetails.hardOverrideTriggered) {
        openRouterResult.classification = 'Phishing';
        openRouterResult.riskScore = Math.max(openRouterResult.riskScore, ensembleResult.finalRiskScore);
      }
      if (ensembleResult.ensembleDetails.legitBoostersApplied.length > 0) {
        openRouterResult.classification = 'Safe';
        openRouterResult.riskScore = Math.min(openRouterResult.riskScore, 18);
        openRouterResult.attackVector = 'Clean';
      }
      openRouterResult.ensembleDetails = ensembleResult.ensembleDetails;
      return openRouterResult;
    }
  }

  // 4. Return Kaggle Trained Ensemble (DistilBERT + XGBoost on 28 features)
  return {
    classification: ensembleResult.classification,
    riskScore: ensembleResult.finalRiskScore,
    attackVector: ensembleResult.attackVector,
    threatExplanation: ensembleResult.threatExplanation,
    indicatorsOfCompromise: ensembleResult.indicatorsOfCompromise,
    mitigationRecommendation: ensembleResult.mitigationRecommendation,
    ensembleDetails: ensembleResult.ensembleDetails,
  };
}

function fallbackHeuristicAnalysis(input: EmailScanInput): AiScanResult {
  let score = 10;
  const iocs: string[] = [];
  let classification: ThreatClassification = 'Safe';
  let vector: AttackVector = 'Clean';

  // Check auth failures
  if (input.headers.spfStatus === 'fail') {
    score += 35;
    iocs.push('SPF Verification Failed (Possible IP Spoofing)');
  }
  if (input.headers.dkimStatus === 'fail') {
    score += 30;
    iocs.push('DKIM Cryptographic Signature Invalid or Forged');
  }
  if (input.headers.dmarcStatus === 'fail') {
    score += 40;
    iocs.push('DMARC Alignment Policy Violated');
  }

  // Check reply-to mismatch
  if (input.headers.replyTo && !input.headers.replyTo.includes(input.sender.domain)) {
    score += 25;
    iocs.push(`Suspicious Reply-To diversion to external address: ${input.headers.replyTo}`);
  }

  // Check urgent subject keywords
  const lowerSubject = (input.subject || '').toLowerCase();
  const lowerBody = (input.bodyText || '').toLowerCase();
  const suspiciousKeywords = [
    'urgent', 'wire transfer', 'payroll', 'gift card', 'password expire',
    'account suspended', 'immediate action required', 'invoice overdue',
    'verify your identity', 'security alert', 'unauthorized sign-in'
  ];

  const matchedKeywords = suspiciousKeywords.filter(k => lowerSubject.includes(k) || lowerBody.includes(k));
  if (matchedKeywords.length > 0) {
    score += matchedKeywords.length * 15;
    iocs.push(`High-urgency social engineering triggers detected: ${matchedKeywords.join(', ')}`);
  }

  // Check dangerous attachment extensions
  const dangerousExts = ['.exe', '.scr', '.vbs', '.iso', '.zip', '.bat', '.cmd', '.xlsm', '.docm'];
  for (const att of input.attachments) {
    const ext = att.filename.slice(att.filename.lastIndexOf('.')).toLowerCase();
    if (dangerousExts.includes(ext)) {
      score += 50;
      classification = 'Malware Risk';
      vector = 'Malicious Attachment / Payload';
      iocs.push(`High-risk executable or macro attachment payload: ${att.filename}`);
    }
  }

  // Check links
  if (input.links.some(l => l.url.includes('.ru') || l.url.includes('.xyz') || l.url.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/))) {
    score += 35;
    iocs.push('Direct IP address or high-risk TLD detected in embedded hyperlink');
  }

  score = Math.min(99, Math.max(5, score));

  if (score >= 75) {
    if (classification !== 'Malware Risk') {
      if (lowerSubject.includes('wire') || lowerSubject.includes('payroll') || lowerSubject.includes('transfer')) {
        classification = 'Business Email Compromise';
        vector = 'VIP Impersonation / BEC';
      } else {
        classification = 'Phishing';
        vector = 'Credential Harvesting';
      }
    }
  } else if (score >= 40) {
    classification = 'Suspicious';
    vector = 'Suspicious Relay / Spoofing';
  } else {
    classification = 'Safe';
    vector = 'Clean';
  }

  return {
    classification,
    riskScore: score,
    attackVector: vector,
    threatExplanation: score > 50
      ? `ThreatMail Insforge heuristic SOC engine detected ${iocs.length} anomalous indicators including security header mismatches and social engineering patterns.`
      : 'Inbound message passed baseline security hygiene checks and exhibits standard communication structure.',
    indicatorsOfCompromise: iocs.length > 0 ? iocs : ['Standard communication traffic; no active exploit vectors detected'],
    mitigationRecommendation: score > 70
      ? 'Quarantine email immediately and alert recipient. Block sender IP and domain.'
      : score > 40
      ? 'Mark email with external warning banner. Advise user not to click links.'
      : 'No action required. Allow to inbox.',
  };
}
