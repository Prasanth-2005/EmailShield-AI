import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';
import { runRuleChecks } from './src/utils/ruleChecks';
import { buildOriginTrace } from './src/utils/geoTrace';
import { parseRawEml, parseAddress } from './src/utils/emlParser';
import { hashAndClassifyAttachments } from './src/utils/attachments';
import { vtLookupUrl, vtLookupFile, vtPollUrlAnalysis, buildDomainIntelReport } from './src/utils/threatIntel';
import type { DeepScanItemResult, DeepScanState } from './src/types';
import {
  SESSION_COOKIE,
  OAUTH_STATE_COOKIE,
  parseCookie,
  googleOAuthConfigured,
  buildAuthUrl,
  consumeState,
  exchangeCodeForSession,
  getSession,
  destroySession,
  listInboxMessageIds,
  getMessageMetadata,
  getMessageRaw,
  getMessageAttachments,
  AuthExpiredError,
  type Session,
} from './gmail';
import {
  IMAP_SESSION_COOKIE,
  createImapSession,
  getImapSession,
  destroyImapSession,
  listImapInbox,
  getImapMessageRaw,
  ImapAuthError,
  ImapConnError,
  type ImapSession,
} from './imap';

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '15mb' }));

/**
 * CORS for the Chrome extension (Gmail Quick Scan). The extension's background
 * worker and content script call this local API from `https://mail.google.com`
 * and from a `chrome-extension://` origin. This is a localhost-only dev server,
 * so we simply reflect those origins for the API routes.
 */
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (origin === 'https://mail.google.com' || origin.startsWith('chrome-extension://'))) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Vary', 'Origin');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    res.header('Access-Control-Max-Age', '86400');
  }
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

let aiClient: GoogleGenAI | null = null;

function getGeminiClient(): GoogleGenAI | null {
  if (!aiClient && process.env.GEMINI_API_KEY) {
    aiClient = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiClient;
}

/**
 * Fallback forensic analyzer when Gemini API key is missing or offline
 */
function heuristicForensicAnalysis(parsedEmail: any) {
  const redFlags: any[] = [];
  const suspiciousPhrases: any[] = [];
  let fraudScore = 5;
  const bodyLower = (parsedEmail.bodyText || '').toLowerCase();
  const subjectLower = (parsedEmail.subject || '').toLowerCase();
  const fromAddress = (parsedEmail.from?.address || '').toLowerCase();
  const fromName = (parsedEmail.from?.displayName || '').toLowerCase();
  const replyTo = (parsedEmail.replyTo || '').toLowerCase();
  const returnPath = (parsedEmail.returnPath || '').toLowerCase();

  let urgencyScore = 0;
  let impersonationScore = 0;
  let credentialThreat = false;
  let financialThreat = false;
  let domainSpoofing = false;
  let headerAnomaly = false;

  // 1. Check Authentication headers
  const spfStatus = parsedEmail.authResults?.spf?.status;
  const dkimStatus = parsedEmail.authResults?.dkim?.status;
  const dmarcStatus = parsedEmail.authResults?.dmarc?.status;

  if (spfStatus === 'fail') {
    fraudScore += 25;
    headerAnomaly = true;
    redFlags.push({
      id: 'flag-spf-fail',
      severity: 'critical',
      category: 'Header & Auth Anomaly',
      title: 'SPF Authentication Failed',
      description: 'The transmitting mail server IP address is not authorized by the sender domain SPF record.',
    });
  }

  if (dkimStatus === 'fail') {
    fraudScore += 20;
    headerAnomaly = true;
    redFlags.push({
      id: 'flag-dkim-fail',
      severity: 'high',
      category: 'Header & Auth Anomaly',
      title: 'DKIM Cryptographic Signature Invalid',
      description: 'The email body or headers were altered in transit or the cryptographic signature failed validation.',
    });
  }

  if (dmarcStatus === 'fail') {
    fraudScore += 20;
    headerAnomaly = true;
    redFlags.push({
      id: 'flag-dmarc-fail',
      severity: 'high',
      category: 'Header & Auth Anomaly',
      title: 'DMARC Policy Rejection',
      description: 'The sender domain published a DMARC policy rejecting unauthenticated transmissions.',
    });
  }

  // 2. Mismatched Reply-To
  if (replyTo && fromAddress && !replyTo.includes(parsedEmail.from?.domain || '___')) {
    fraudScore += 25;
    domainSpoofing = true;
    redFlags.push({
      id: 'flag-replyto-mismatch',
      severity: 'high',
      category: 'Brand Impersonation',
      title: 'Mismatched Reply-To Address',
      description: `Replies are routed to "${replyTo}" which does not match the sender domain "${parsedEmail.from?.domain}".`,
    });
  }

  // 3. Brand Impersonation (Microsoft, Google, Apple, Banking, CEO)
  const brandKeywords = ['microsoft', 'office 365', 'google', 'apple', 'paypal', 'wells fargo', 'chase', 'ceo'];
  for (const b of brandKeywords) {
    if ((fromName.includes(b) || subjectLower.includes(b)) && !fromAddress.includes(b.replace(/\s+/g, ''))) {
      impersonationScore = Math.max(impersonationScore, 75);
      domainSpoofing = true;
      fraudScore += 30;
      redFlags.push({
        id: `flag-impersonation-${b}`,
        severity: 'critical',
        category: 'Brand Impersonation',
        title: `Possible Brand Spoofing (${b.toUpperCase()})`,
        description: `Sender displays brand name "${b.toUpperCase()}" but transmits from unverified address "${fromAddress}".`,
      });
      break;
    }
  }

  // 4. Mismatched or suspicious links
  const links = parsedEmail.extractedLinks || [];
  for (const link of links) {
    if (link.isMismatched) {
      fraudScore += 35;
      redFlags.push({
        id: 'flag-mismatched-link',
        severity: 'critical',
        category: 'Suspicious Link',
        title: 'Deceptive Mismatched Hyperlink',
        description: link.mismatchReason || `Visible link text differs from the actual hyperlink destination (${link.href}).`,
      });
      suspiciousPhrases.push({
        phrase: link.text,
        explanation: 'Deceptive link where anchor text masks a malicious external destination.',
        severity: 'critical',
        category: 'Deceptive Link',
      });
    }
  }

  // 5. Urgency and fear language cues
  const urgencyPatterns = [
    { regex: /expire[s]? in \d+ hours?/i, phrase: 'will expire in 2 hours', reason: 'Artificial countdown deadline to pressure quick compliance.' },
    { regex: /immediate mailbox termination/i, phrase: 'immediate mailbox termination', reason: 'High-fear consequence threat (mailbox shutdown).' },
    { regex: /permanent loss of all/i, phrase: 'permanent loss of all archived emails', reason: 'Catastrophic loss threat designed to bypass critical thinking.' },
    { regex: /verify your identity immediately/i, phrase: 'verify your identity immediately', reason: 'Urgent demand for immediate authentication verification.' },
    { regex: /irreversible account lockout/i, phrase: 'irreversible account lockout', reason: 'Intimidation tactic threatening permanent loss of access.' },
    { regex: /before the \d+:\d+ (?:am|pm) (?:bank )?cutoff/i, phrase: 'before the 5:00 PM bank cutoff', reason: 'Urgent financial deadline engineered to induce hasty transfer.' },
    { regex: /strictly between us/i, phrase: 'strictly between us for now', reason: 'Social engineering secrecy tactic isolating the victim from verification channels.' },
  ];

  for (const p of urgencyPatterns) {
    if (bodyLower.match(p.regex) || subjectLower.match(p.regex)) {
      urgencyScore = Math.max(urgencyScore, 80);
      fraudScore += 15;
      redFlags.push({
        id: `flag-urgency-${p.phrase.slice(0, 10)}`,
        severity: 'high',
        category: 'Urgency & Fear Tactics',
        title: 'Coercive Urgency Trigger',
        description: p.reason,
      });
      suspiciousPhrases.push({
        phrase: p.phrase,
        explanation: p.reason,
        severity: 'high',
        category: 'Urgency / Coercion',
      });
    }
  }

  // 6. Credential Harvesting & Financial Fraud
  if (bodyLower.includes('password') && (bodyLower.includes('verify') || bodyLower.includes('expire') || bodyLower.includes('enter your'))) {
    credentialThreat = true;
    fraudScore += 25;
    redFlags.push({
      id: 'flag-cred-harvest',
      severity: 'critical',
      category: 'Credential Harvesting',
      title: 'Corporate Credential Solicitation',
      description: 'Email solicits user password and authentication tokens via unverified web portal.',
    });
    suspiciousPhrases.push({
      phrase: 'enter your corporate password and secondary multi-factor authentication',
      explanation: 'Direct solicitation of primary corporate credentials and 2FA secrets.',
      severity: 'critical',
      category: 'Credential Harvesting',
    });
  }

  if (bodyLower.includes('wire transfer') || bodyLower.includes('wire payment') || bodyLower.includes('gift card') || bodyLower.includes('$24,500')) {
    financialThreat = true;
    fraudScore += 30;
    redFlags.push({
      id: 'flag-financial-fraud',
      severity: 'critical',
      category: 'Financial & Wire Fraud',
      title: 'Urgent Wire / Payment Solicitation (BEC)',
      description: 'Demands an expedited confidential bank wire transfer bypassing standard accounting checks.',
    });
    suspiciousPhrases.push({
      phrase: 'urgent confidential vendor payment of $24,500 via wire transfer',
      explanation: 'High-value wire transfer solicitation leveraging executive authority.',
      severity: 'critical',
      category: 'Financial Fraud',
    });
  }

  // Cap score
  fraudScore = Math.min(Math.max(fraudScore, 0), 99);

  // If legitimate signals are strong (e.g. GitHub sample with pass SPF/DKIM and no phishing words)
  if (spfStatus === 'pass' && dkimStatus === 'pass' && redFlags.length === 0) {
    fraudScore = 4;
    redFlags.push({
      id: 'flag-auth-pass',
      severity: 'info',
      category: 'Security Verification',
      title: 'Valid Cryptographic Signatures',
      description: 'Passed SPF and DKIM authentication with no coercive language or link anomalies detected.',
    });
  }

  let classification: 'Legitimate' | 'Suspicious' | 'Phishing' | 'Fraud' = 'Legitimate';
  if (fraudScore >= 80) classification = credentialThreat ? 'Phishing' : 'Fraud';
  else if (fraudScore >= 45) classification = 'Suspicious';
  else classification = 'Legitimate';

  const explanation = classification === 'Legitimate'
    ? 'This email exhibits authentic cryptographic signatures (SPF and DKIM pass) and lacks coercive language, credential solicitation, or deceptive hyperlinks. It is deemed safe.'
    : classification === 'Phishing'
    ? 'This message demonstrates multiple critical indicators of credential phishing, including failed domain authentication, manufactured urgency, and links intended to intercept authentication credentials.'
    : classification === 'Fraud'
    ? 'High-confidence indicator of Business Email Compromise (BEC) and financial fraud, characterized by executive spoofing, secrecy demands, and urgent wire transfer requests.'
    : 'This communication displays several borderline anomalies, such as mismatched return addresses or unusual timing, requiring caution before taking action or replying.';

  return {
    classification,
    fraudScore,
    confidence: 94,
    explanation,
    redFlags,
    suspiciousPhrases,
    indicators: {
      urgencyScore,
      impersonationScore,
      credentialHarvestingRisk: credentialThreat,
      financialFraudRisk: financialThreat,
      domainSpoofingRisk: domainSpoofing,
      headerAnomalyRisk: headerAnomaly,
    },
    analyzedAt: new Date().toISOString(),
    engine: 'forensic-heuristic-fallback',
  };
}

/**
 * Renders the Received routing chain as readable lines for the Gemini prompt.
 */
function formatRelayChain(hops: any[]): string {
  if (!hops || hops.length === 0) {
    return '  (NO Received headers present — highly abnormal for legitimately delivered mail)';
  }
  return hops
    .map(
      (h: any, i: number) =>
        `  ${i + 1}. from ${h.fromServer || '?'} by ${h.byServer || '?'}` +
        `${h.ipAddress ? ` [${h.ipAddress}]` : ''}${h.timestamp ? ` (${h.timestamp})` : ''}`,
    )
    .join('\n');
}

/**
 * Ordered list of Gemini models to try. Each free-tier model has its own quota,
 * so if the first is rate-limited (HTTP 429), unavailable (404) or overloaded
 * (503) we transparently fall through to the next before giving up on the API.
 * Override with GEMINI_MODELS="a,b,c" in .env.
 */
const GEMINI_MODELS = (process.env.GEMINI_MODELS || 'gemini-flash-latest,gemini-flash-lite-latest,gemini-3.6-flash')
  .split(',')
  .map((m) => m.trim())
  .filter(Boolean);

type GeminiFallbackReason = 'no-api-key' | 'gemini-quota-exceeded' | 'gemini-model-unavailable' | 'gemini-error';
interface GeminiJudgment {
  ok: boolean;
  ai?: any;
  engine?: string;
  reason?: GeminiFallbackReason;
}

/**
 * Third detection engine — a local pretrained BERT phishing classifier served by
 * the optional Python microservice in `ml_service/` (see its README). This is a
 * best-effort call: if the service is not running, unreachable, slow or returns
 * anything unexpected, `callMlModel` returns `null` and the pipeline silently
 * drops back to the rule + Gemini blend. It never throws.
 */
const ML_SERVICE_URL = (process.env.ML_SERVICE_URL || 'http://localhost:8000').replace(/\/+$/, '');
const ML_TIMEOUT_MS = Number(process.env.ML_TIMEOUT_MS) || 8000;

interface MlModelVerdict {
  label: 'phishing' | 'legitimate';
  confidence: number; // 0 - 100, confidence in `label`
  score: number; // 0 - 100 on the fraud scale (P(phishing)), used in the blend
}

async function callMlModel(emailBody: string): Promise<MlModelVerdict | null> {
  const text = (emailBody || '').trim();
  if (!text) return null;
  try {
    const res = await fetch(`${ML_SERVICE_URL}/classify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text.slice(0, 8000) }),
      signal: AbortSignal.timeout(ML_TIMEOUT_MS),
    });
    if (!res.ok) {
      console.warn(`[EmailShield AI] ML service returned HTTP ${res.status} — ML layer skipped`);
      return null;
    }
    const data: any = await res.json();
    const label = String(data?.label || '').toLowerCase() === 'phishing' ? 'phishing' : 'legitimate';
    const confidence = Math.max(0, Math.min(100, Number(data?.confidence) || 0));
    // Prefer the service's P(phishing); otherwise derive it from label + confidence.
    const rawP = Number(data?.phishing_probability);
    const score = Number.isFinite(rawP)
      ? Math.max(0, Math.min(100, rawP))
      : label === 'phishing'
      ? confidence
      : Math.max(0, 100 - confidence);
    return { label, confidence, score: Math.round(score) };
  } catch (err: any) {
    const reason = err?.name === 'AbortError' || err?.name === 'TimeoutError' ? 'timed out' : 'unreachable';
    console.warn(`[EmailShield AI] ML service ${reason} at ${ML_SERVICE_URL} — ML layer skipped`);
    return null;
  }
}

/** HTTP statuses for which it's worth trying the next model in the chain. */
const TRY_NEXT_MODEL_STATUS = new Set([429, 404, 500, 503]);

/**
 * Runs a live Gemini judgment over the parsed email, walking the model chain on
 * transient / quota errors. Returns the parsed AI analysis plus the model id
 * that produced it, or a failure reason so the caller can fall back to the local
 * heuristic engine and surface *why* in the UI.
 *
 * The Gemini path is identical for uploaded .eml files and Chrome-extension
 * (body-only) requests — only the deterministic rule set differs upstream.
 */
async function runGeminiJudgment(parsedEmail: any): Promise<GeminiJudgment> {
  const ai = getGeminiClient();

  // No API key configured — signal the caller to use the heuristic fallback.
  if (!ai) {
    console.log('[EmailShield AI] No GEMINI_API_KEY found, using local forensic heuristic engine');
    return { ok: false, reason: 'no-api-key' };
  }

  const prompt = `
You are EmailShield AI, an elite email threat detection and forensic intelligence analyst.
Analyze the following parsed email headers, authentication records, routing hops, and body text.

Evaluate for:
1. Phishing language, coercion, and grammar anomalies
2. Urgency or fear-based social engineering cues (e.g. countdown deadlines, threats of account suspension)
3. Impersonation of a known brand, service, or executive person (e.g., Microsoft, Google, PayPal, CEO, IT Helpdesk)
4. Suspicious or mismatched links (anchor text showing trusted domain while actual link points to unrelated/malicious domain)
5. Requests for credentials (passwords, MFA codes, PINs) or financial payments (wire transfers, invoices, gift cards)
6. Header and authentication anomalies (SPF/DKIM/DMARC failures or absence, domain misalignment between Display Name, From, Return-Path and Reply-To, suspicious or excessive Received relay hops)

SCORING GUIDANCE — WEIGH HEADERS AND BODY LANGUAGE EQUALLY:
Header, authentication and routing anomalies matter as much as the wording of the message. Do NOT mark a message safe just because the prose is clean and polite:
- If SPF, DKIM or DMARC fail or are missing, raise fraudScore substantially and set headerAnomalyRisk = true.
- If the Return-Path or Reply-To organisational domain does not align with the From domain, set domainSpoofingRisk = true and raise fraudScore.
- If the From domain is a lookalike / typosquat of a well-known brand, set impersonationScore high.
- Zero or an unusually large number of Received hops is itself a routing anomaly.
- Conversely, alarming wording combined with fully aligned domains and passing SPF/DKIM/DMARC should be scored more conservatively.

PARSED EMAIL DATA:
- From Display Name: "${parsedEmail.from?.displayName}"
- From Address: <${parsedEmail.from?.address}>
- From Domain: ${parsedEmail.from?.domain || '(none)'}
- To: ${parsedEmail.to?.address || parsedEmail.to?.raw}
- Subject: ${parsedEmail.subject}
- Date: ${parsedEmail.date}
- Return-Path: ${parsedEmail.returnPath || '(none)'}
- Reply-To: ${parsedEmail.replyTo || '(none)'}
- Message-ID: ${parsedEmail.messageId || '(none)'}
- SPF Status: ${parsedEmail.authResults?.spf?.status || 'MISSING'} (${parsedEmail.authResults?.spf?.details || 'no SPF result header'})
- DKIM Status: ${parsedEmail.authResults?.dkim?.status || 'MISSING'} (${parsedEmail.authResults?.dkim?.details || 'no DKIM result header'})
- DMARC Status: ${parsedEmail.authResults?.dmarc?.status || 'MISSING'} (${parsedEmail.authResults?.dmarc?.details || 'no DMARC result header'})
- Raw Authentication-Results header: ${parsedEmail.authResults?.rawAuthHeader || '(none present)'}
- Received Relay Chain (${(parsedEmail.receivedHops || []).length} hops, origin -> destination):
${formatRelayChain(parsedEmail.receivedHops)}
- Extracted Links: ${JSON.stringify(parsedEmail.extractedLinks || [])}

EMAIL BODY TEXT:
"""
${parsedEmail.bodyText || '(No plain text body)'}
"""

CRITICAL INSTRUCTION FOR "suspiciousPhrases":
You must extract verbatim substrings from the EMAIL BODY TEXT above that represent suspicious or coercive phrases.
Each phrase MUST be an exact match to text occurring in the body text so that the frontend can highlight it inline.

CRITICAL INSTRUCTION FOR "plainSummary":
Write for someone with ZERO technical or security knowledge — imagine explaining it to a parent or grandparent.
- 2 to 4 short, everyday sentences. No bullet points.
- Use NO jargon whatsoever. Never write "SPF", "DKIM", "DMARC", "spoof", "spoofing", "phishing", "header", "authentication",
  "domain", "IP", "server", "payload", "credential". Describe the EFFECT in plain words instead.
  Example: instead of "SPF and DKIM failed" write "this email did not really come from the company it says it's from".
- Sentence 1 = the verdict in plain words: "This email is very likely a scam." / "This email is probably not safe." /
  "Be careful with this email." / "This email looks safe."
- Sentence 2 (and optionally 3) = the single biggest reason, in plain terms. For example:
  "It pretends to be from your bank and pushes you to click a link and type in your password." or
  "It was sent from a website address that was only created a few days ago."
- If it looks safe, briefly say why (e.g. "It genuinely comes from the company it claims to, and it isn't asking you
  to do anything risky.").

Respond with a valid JSON object matching this schema:
{
  "classification": "Legitimate" | "Suspicious" | "Phishing" | "Fraud",
  "fraudScore": number (0 to 100, where 0 is pristine legitimate and 100 is confirmed active attack),
  "confidence": number (0 to 100),
  "explanation": "2 to 3 concise, plain-English sentences explaining why this verdict was given",
  "plainSummary": "2 to 4 jargon-free sentences for a non-technical reader (see CRITICAL INSTRUCTION above)",
  "redFlags": [
    {
      "id": "string",
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "category": "Urgency & Fear Tactics" | "Brand Impersonation" | "Credential Harvesting" | "Financial & Wire Fraud" | "Suspicious Link" | "Header & Auth Anomaly" | "Security Verification",
      "title": "string",
      "description": "string"
    }
  ],
  "suspiciousPhrases": [
    {
      "phrase": "exact verbatim substring from the email body",
      "explanation": "why this phrase is considered suspicious or coercive",
      "severity": "critical" | "high" | "medium" | "low",
      "category": "string"
    }
  ],
  "indicators": {
    "urgencyScore": number (0 to 100),
    "impersonationScore": number (0 to 100),
    "credentialHarvestingRisk": boolean,
    "financialFraudRisk": boolean,
    "domainSpoofingRisk": boolean,
    "headerAnomalyRisk": boolean
  }
}
`;

  const config = {
        systemInstruction: 'You are an authoritative cybersecurity forensic intelligence engine specializing in email security, BEC, header analysis, and phishing detection. You provide rigorous, accurate JSON forensic reports.',
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            classification: {
              type: Type.STRING,
              description: 'Legitimate, Suspicious, Phishing, or Fraud',
            },
            fraudScore: {
              type: Type.NUMBER,
              description: 'Overall fraud threat score from 0 to 100',
            },
            confidence: {
              type: Type.NUMBER,
              description: 'Confidence score from 0 to 100',
            },
            explanation: {
              type: Type.STRING,
              description: '2-3 sentences analyst-facing verdict explanation',
            },
            plainSummary: {
              type: Type.STRING,
              description:
                '2-4 sentences for a NON-technical reader. No jargon (no SPF/DKIM/DMARC/spoof/phishing/domain/header). ' +
                'Plain verdict first, then the single biggest reason in everyday words.',
            },
            redFlags: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  id: { type: Type.STRING },
                  severity: { type: Type.STRING },
                  category: { type: Type.STRING },
                  title: { type: Type.STRING },
                  description: { type: Type.STRING },
                },
                required: ['id', 'severity', 'category', 'title', 'description'],
              },
            },
            suspiciousPhrases: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  phrase: { type: Type.STRING },
                  explanation: { type: Type.STRING },
                  severity: { type: Type.STRING },
                  category: { type: Type.STRING },
                },
                required: ['phrase', 'explanation', 'severity', 'category'],
              },
            },
            indicators: {
              type: Type.OBJECT,
              properties: {
                urgencyScore: { type: Type.NUMBER },
                impersonationScore: { type: Type.NUMBER },
                credentialHarvestingRisk: { type: Type.BOOLEAN },
                financialFraudRisk: { type: Type.BOOLEAN },
                domainSpoofingRisk: { type: Type.BOOLEAN },
                headerAnomalyRisk: { type: Type.BOOLEAN },
              },
              required: [
                'urgencyScore',
                'impersonationScore',
                'credentialHarvestingRisk',
                'financialFraudRisk',
                'domainSpoofingRisk',
                'headerAnomalyRisk',
              ],
            },
          },
          required: [
            'classification',
            'fraudScore',
            'confidence',
            'explanation',
            'plainSummary',
            'redFlags',
            'suspiciousPhrases',
            'indicators',
          ],
        },
  };

  const GEMINI_TIMEOUT_MS = Number(process.env.GEMINI_TIMEOUT_MS) || 45000;

  let lastStatus: number | undefined;
  for (const model of GEMINI_MODELS) {
    try {
      console.log(`[EmailShield AI] Calling Gemini model "${model}" for email: "${parsedEmail.subject}"`);
      const response = await ai.models.generateContent({
        model,
        contents: prompt,
        config: { ...config, abortSignal: AbortSignal.timeout(GEMINI_TIMEOUT_MS) },
      });
      const text = response.text?.trim() || '{}';

      // --- DEBUG: raw Gemini response -----------------------------------
      console.log('\n===== RAW GEMINI RESPONSE START =====');
      console.log('model:', model);
      console.log('usageMetadata:', JSON.stringify(response.usageMetadata || null));
      console.log('response.text:\n', text);
      console.log('===== RAW GEMINI RESPONSE END =====\n');
      // ----------------------------------------------------------------

      const parsed = JSON.parse(text);
      return { ok: true, ai: parsed, engine: model };
    } catch (error) {
      const status = (error as any)?.status;
      const name = (error as any)?.name;
      const timedOut = name === 'AbortError' || name === 'TimeoutError';
      if (typeof status === 'number') lastStatus = status;
      else if (timedOut) lastStatus = 504;
      console.error(
        `[EmailShield AI] Gemini model "${model}" failed — ${timedOut ? 'timed out' : `status ${status ?? '?'}`}: ` +
          String((error as any)?.message || error).replace(/\s+/g, ' ').slice(0, 300),
      );
      if (timedOut || (typeof status === 'number' && TRY_NEXT_MODEL_STATUS.has(status))) {
        continue; // timeout / quota / unavailable / overloaded — try the next model
      }
      break; // non-retryable error
    }
  }

  console.error('\n[EmailShield AI] !!! All Gemini models failed — falling back to local heuristic engine !!!');
  console.error(`[EmailShield AI] Last HTTP status: ${lastStatus ?? 'n/a'} | model chain: ${GEMINI_MODELS.join(', ')}`);
  if (lastStatus === 504) return { ok: false, reason: 'gemini-error' };
  if (lastStatus === 429) return { ok: false, reason: 'gemini-quota-exceeded' };
  if (lastStatus === 404) return { ok: false, reason: 'gemini-model-unavailable' };
  return { ok: false, reason: 'gemini-error' };
}

/** Clamp a value to an integer in [0, 100]. */
function clampScore(n: any): number {
  const v = typeof n === 'number' && isFinite(n) ? n : 0;
  return Math.min(100, Math.max(0, Math.round(v)));
}

/**
 * Jargon-free 2-4 sentence summary for a non-technical reader. Used when Gemini
 * did not supply one (heuristic fallback, or a model that ignored the field).
 */
function plainSummaryFallback(
  classification: string,
  triggeredRules: Array<{ id: string; rule: string; points: number }>,
  redFlags: Array<{ title?: string }>,
): string {
  const verdict: Record<string, string> = {
    Legitimate:
      "This email looks safe. It appears to genuinely come from who it says it does, and it isn't asking you to do anything risky.",
    Suspicious: 'Be careful with this email. Something about it does not add up.',
    Phishing: 'This email is very likely a scam designed to steal your personal information.',
    Fraud: 'This email is very likely a scam trying to trick you into sending money or sharing private details.',
  };
  if (classification === 'Legitimate') return verdict.Legitimate;

  const reasons: Array<{ test: (id: string) => boolean; text: string }> = [
    { test: (id) => id.startsWith('rule-brand-lookalike'), text: "It uses a web address that copies a well-known company's name but is not actually theirs." },
    { test: (id) => id.startsWith('rule-link-mismatch'), text: 'A link in it looks like it goes to a trusted website but actually goes somewhere else.' },
    { test: (id) => id.startsWith('rule-domain-newly-registered'), text: 'It comes from a web address that was only created in the last few weeks — something real companies rarely do.' },
    { test: (id) => id.startsWith('rule-domain-recently-registered'), text: 'It comes from a fairly new web address.' },
    { test: (id) => id.startsWith('rule-ip-abuse'), text: 'It was sent from a computer that other people have already reported for sending scam and attack messages.' },
    { test: (id) => id.startsWith('rule-origin-infra'), text: "It was sent through the kind of anonymous internet service scammers use to hide, not a normal company's mail system." },
    { test: (id) => id.startsWith('rule-origin-country-mismatch'), text: 'It claims to be from a major company but was actually sent from a different country.' },
    { test: (id) => id.startsWith('rule-att-'), text: 'It carries an attachment that could install harmful software if you open it.' },
    { test: (id) => id.startsWith('rule-returnpath-mismatch'), text: 'If you replied, your reply would go to a different address than the one it claims to be from.' },
    { test: (id) => id.startsWith('rule-auth-'), text: 'The automatic checks that confirm a sender is really who they claim to be did not pass, so it may be an impersonation.' },
    { test: (id) => id.startsWith('rule-social-engineering'), text: 'It tries to rush or scare you into acting immediately, which is a classic scam tactic.' },
    { test: (id) => id.startsWith('rule-excessive-hops') || id.startsWith('rule-no-received'), text: 'The path this email took to reach you is unusual for genuine mail.' },
  ];

  const lead = verdict[classification] || verdict.Suspicious;
  for (const r of [...triggeredRules].sort((a, b) => b.points - a.points)) {
    const m = reasons.find((x) => x.test(r.id));
    if (m) return `${lead} ${m.text}`;
  }
  const flag = redFlags.find((f) => f.title);
  if (flag?.title) return `${lead} The main concern: ${String(flag.title).toLowerCase()}.`;
  return `${lead} Several things about it look wrong — check with the sender through a phone number or website you already trust before doing anything it asks.`;
}

/** Reconcile the classification label with the final combined score. */
function reconcileClassification(
  finalScore: number,
  aiClassification: any,
): 'Legitimate' | 'Suspicious' | 'Phishing' | 'Fraud' {
  if (finalScore >= 75) {
    return aiClassification === 'Fraud' || aiClassification === 'Phishing' ? aiClassification : 'Phishing';
  }
  if (finalScore >= 45) return 'Suspicious';
  if (finalScore >= 30 && aiClassification !== 'Legitimate') return 'Suspicious';
  return 'Legitimate';
}

/**
 * Hybrid forensic verdict.
 *
 *   finalScore = ruleScore * 0.5 + geminiScore * 0.5   (capped at 100)
 *
 * The deterministic rule checks always run. The AI half is either a live Gemini
 * judgment or, if the key is missing or the call fails, the local heuristic
 * engine — the `engine` field records which one produced the AI half.
 */
export async function analyzeEmailWithGemini(parsedEmail: any, opts: { bodyOnly?: boolean } = {}) {
  // 1. Origin trace + geolocation, RDAP domain intelligence, the local ML model
  //    and the live Gemini call all run concurrently.
  const mlInputText = [parsedEmail?.subject, parsedEmail?.bodyText].filter(Boolean).join('\n\n').trim();
  const originTracePromise = buildOriginTrace(parsedEmail);
  const domainIntelPromise = buildDomainIntelReport(parsedEmail);
  const mlPromise = callMlModel(mlInputText);
  const judgmentPromise = runGeminiJudgment(parsedEmail);
  const originTrace = await originTracePromise;
  const domainIntel = await domainIntelPromise;
  const mlVerdict = await mlPromise;
  const judgment: GeminiJudgment = await judgmentPromise;

  console.log(
    `[EmailShield AI] Origin trace => ${originTrace.hops.length} hop(s), ` +
      `${originTrace.lookupCount} IP lookup(s), origin ${originTrace.originIp || 'unknown'}` +
      `${originTrace.originGeo?.status === 'success' ? ` (${originTrace.originGeo.city || '?'}, ${originTrace.originGeo.country || '?'})` : ''}` +
      `${originTrace.note ? ` — ${originTrace.note}` : ''}`,
  );

  if ((originTrace.reputationLookups ?? 0) > 0) {
    console.log(
      `[EmailShield AI] IP reputation => ${originTrace.reputationLookups} AbuseIPDB lookup(s), ` +
        `max abuse score ${originTrace.maxAbuseScore ?? 0}%${originTrace.abuseFlaggedIp ? ` (${originTrace.abuseFlaggedIp})` : ''}`,
    );
  }

  if (domainIntel.entries.length > 0) {
    console.log(
      `[EmailShield AI] Domain intel => ${domainIntel.entries.length} RDAP lookup(s): ` +
        domainIntel.entries
          .map((e) => `${e.domain} [${e.status}${typeof e.ageDays === 'number' ? `, ${e.ageDays}d` : ''}]`)
          .join(', '),
    );
  }

  // 2. Deterministic rule-based checks — always run, now with geo + reputation context.
  //    `bodyOnly` (Chrome extension / Gmail scrape) has no raw headers, so the
  //    authentication and "no Received headers" rules are skipped rather than
  //    penalising every scraped message for data it structurally cannot provide.
  const ruleResult = runRuleChecks(
    parsedEmail,
    {
      originGeo: originTrace.originGeo,
      originCountryCode: originTrace.originCountryCode,
      maxAbuseScore: originTrace.maxAbuseScore,
      abuseFlaggedIp: originTrace.abuseFlaggedIp,
      domainMinAgeDays: domainIntel.sendingMinAgeDays,
      domainAgeDomain: domainIntel.sendingYoungestDomain,
    },
    { skipHeaderRules: opts.bodyOnly },
  );

  // 3. AI judgment — live Gemini, or heuristic fallback when unavailable/failed.
  const aiAnalysis = judgment.ok ? judgment.ai : heuristicForensicAnalysis(parsedEmail);
  const engine = judgment.ok && judgment.engine ? judgment.engine : 'forensic-heuristic-fallback';
  const fallbackReason = judgment.ok ? undefined : judgment.reason;

  // 4. Combine the independent engine scores. This is the BASE score — the
  //    on-demand VirusTotal deep scan adds points on top of it later.
  //      3 engines available:  rule*0.35 + ml*0.30 + gemini*0.35
  //      ML skipped (default): rule*0.50 +           gemini*0.50
  const geminiScore = clampScore(aiAnalysis?.fraudScore);
  const ruleScore = clampScore(ruleResult.ruleScore);
  const mlScore = mlVerdict ? clampScore(mlVerdict.score) : null;

  const scoreWeights =
    mlScore !== null
      ? { rule: 0.35, ml: 0.3 as number | null, gemini: 0.35 }
      : { rule: 0.5, ml: null as number | null, gemini: 0.5 };

  const baseFraudScore =
    mlScore !== null
      ? Math.min(100, Math.round(ruleScore * 0.35 + mlScore * 0.3 + geminiScore * 0.35))
      : Math.min(100, Math.round(ruleScore * 0.5 + geminiScore * 0.5));

  const aiClassification = aiAnalysis?.classification;
  const classification = reconcileClassification(baseFraudScore, aiClassification);

  // Plain-English summary for a non-technical reader — Gemini's if usable, else synthesised.
  const plainSummary =
    typeof aiAnalysis?.plainSummary === 'string' && aiAnalysis.plainSummary.trim().length > 20
      ? aiAnalysis.plainSummary.trim()
      : plainSummaryFallback(classification, ruleResult.triggeredRules, aiAnalysis?.redFlags || []);

  const mlModel = mlVerdict
    ? { label: mlVerdict.label, confidence: mlVerdict.confidence, score: mlVerdict.score }
    : null;
  const mlSkipped = mlScore === null;

  console.log(
    mlScore !== null
      ? `[EmailShield AI] Hybrid score => rule ${ruleScore} (x0.35) + ml ${mlScore} (x0.30, ${mlVerdict!.label} ${mlVerdict!.confidence}%) + ${engine} ${geminiScore} (x0.35) ` +
        `= ${baseFraudScore} [${classification}] | ${ruleResult.triggeredRules.length} rule(s) triggered`
      : `[EmailShield AI] Hybrid score => rule ${ruleScore} (x0.5) + ${engine} ${geminiScore} (x0.5) [ML layer skipped] ` +
        `= ${baseFraudScore} [${classification}] | ${ruleResult.triggeredRules.length} rule(s) triggered`,
  );

  return {
    ...aiAnalysis,
    classification,
    plainSummary,
    fraudScore: baseFraudScore,
    baseFraudScore,
    aiClassification,
    geminiScore,
    ruleScore,
    mlScore,
    mlModel,
    mlSkipped,
    scoreWeights,
    triggeredRules: ruleResult.triggeredRules,
    redFlags: aiAnalysis?.redFlags || [],
    suspiciousPhrases: aiAnalysis?.suspiciousPhrases || [],
    indicators: aiAnalysis?.indicators || {},
    attachments: Array.isArray(parsedEmail?.attachments)
      ? parsedEmail.attachments.map((a: any) => ({
          filename: a.filename,
          mimeType: a.mimeType,
          size: a.size,
          sha256: a.sha256 || '',
          extensionRisk: a.extensionRisk ?? null,
          riskReason: a.riskReason,
          archiveContents: a.archiveContents,
        }))
      : [],
    deepScan: null,
    domainIntel,
    analyzedAt: new Date().toISOString(),
    engine,
    fallbackReason,
    originTrace,
    analysisScope: opts.bodyOnly ? 'body-and-sender' : 'full',
  };
}

/**
 * Re-derives `fraudScore` + `classification` from the base score plus any
 * VirusTotal deep-scan points. Called after each deep-scan item completes.
 */
function applyDeepScan(analysis: any): void {
  const items: DeepScanItemResult[] = analysis.deepScan?.items || [];
  let added = 0;
  for (const it of items) {
    const flagged = (it.malicious || 0) + (it.suspicious || 0) >= 3;
    if (!flagged) continue;
    added += it.kind === 'file' ? 30 : 25;
  }
  const base = typeof analysis.baseFraudScore === 'number' ? analysis.baseFraudScore : analysis.fraudScore;
  analysis.fraudScore = Math.min(100, base + added);
  analysis.classification = reconcileClassification(analysis.fraudScore, analysis.aiClassification);
  if (analysis.deepScan) analysis.deepScan.addedPoints = added;
}

/** Removes transient attachment bytes before a value is serialized to a client. */
function stripAttachmentContent<T>(value: T): T {
  const walk = (v: any) => {
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      if (v instanceof Uint8Array || Buffer.isBuffer(v)) return undefined;
      const out: any = {};
      for (const [k, val] of Object.entries(v)) {
        if (k === 'content') continue;
        out[k] = walk(val);
      }
      return out;
    }
    return v;
  };
  return walk(value);
}

/**
 * In-memory case store for the Chrome-extension -> web-app handoff.
 * Keyed by a short case ID; capped at MAX_CASES with oldest-first eviction
 * (Map preserves insertion order, so the first key is the oldest).
 */
const MAX_CASES = 50;
const caseStore = new Map<string, { caseId: string; parsedEmail: any; analysis: any; createdAt: string }>();

function makeCaseId(): string {
  return 'EMS-' + Math.random().toString(16).slice(2, 8).toUpperCase();
}

function storeCase(parsedEmail: any, analysis: any): string {
  let caseId = makeCaseId();
  while (caseStore.has(caseId)) caseId = makeCaseId();
  if (analysis && typeof analysis === 'object') analysis.caseId = caseId;
  caseStore.set(caseId, { caseId, parsedEmail, analysis, createdAt: new Date().toISOString() });
  while (caseStore.size > MAX_CASES) {
    const oldest = caseStore.keys().next().value;
    if (oldest === undefined) break;
    caseStore.delete(oldest);
  }
  return caseId;
}

/**
 * Traffic-light band for a rule-only score (no Gemini). Deliberately conservative:
 * a single missing/failed auth signal (+15) stays green, two nudge to amber, a
 * brand-lookalike + urgency combo (or an outright auth failure set) goes red.
 */
function riskBand(score: number): 'green' | 'amber' | 'red' {
  if (score >= 50) return 'red';
  if (score >= 20) return 'amber';
  return 'green';
}

/** Minimal ParsedEmail shell for running rule checks on Gmail list metadata. */
function partialParsedFromMetadata(fromHeader: string, subject: string): any {
  const a = parseAddress(fromHeader || '');
  return {
    from: { raw: fromHeader || '', displayName: a.displayName, address: a.address, domain: a.domain },
    to: { raw: '', address: '' },
    subject: subject || '',
    date: '',
    returnPath: '',
    replyTo: '',
    messageId: '',
    receivedHops: [],
    authResults: {},
    bodyText: '',
    bodyHtml: undefined,
    extractedLinks: [],
    rawHeaders: {},
    rawSource: '',
  };
}

/** Maps a thrown Gmail/auth error onto an HTTP response the client can act on. */
function respondGmailError(err: any, res: express.Response): void {
  if (err instanceof AuthExpiredError || err?.code === 'auth-expired') {
    res.status(401).json({ error: err.message || 'Please sign in again.', code: 'auth-expired' });
    return;
  }
  console.error('[EmailShield AI] Gmail error:', err?.message || err);
  const rateLimited = err?.status === 429 || err?.status === 403;
  res.status(rateLimited ? 429 : 502).json({
    error: rateLimited
      ? 'Gmail API rate limit reached — wait a few seconds and try again.'
      : err?.message || 'Gmail request failed.',
    code: 'gmail-error',
  });
}

/** Express middleware: attach the signed-in session or 401. */
function requireSession(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const session = getSession(parseCookie(req.headers.cookie, SESSION_COOKIE));
  if (!session) {
    res.status(401).json({ error: 'Not signed in.', code: 'auth-required' });
    return;
  }
  (req as any).session = session;
  next();
}

async function startServer() {
  // API Endpoints
  app.post('/api/analyze-email', async (req, res) => {
    try {
      const { parsedEmail, bodyOnly } = req.body;
      if (!parsedEmail) {
        return res.status(400).json({ error: 'Missing parsedEmail payload' });
      }
      // The browser already ran parseRawEml + hashAndClassifyAttachments, so
      // parsedEmail.attachments carries metadata + SHA-256 (never the bytes).

      const analysis = await analyzeEmailWithGemini(parsedEmail, { bodyOnly: Boolean(bodyOnly) });
      const caseId = storeCase(parsedEmail, analysis);
      return res.json(stripAttachmentContent({ ...analysis, caseId }));
    } catch (err: any) {
      console.error('/api/analyze-email error:', err);
      return res.status(500).json({ error: err?.message || 'Forensic analysis failed' });
    }
  });

  // Retrieve a stored analysis by case ID (Gmail Quick Scan -> "View Full Analysis").
  app.get('/api/analysis/:caseId', (req, res) => {
    const entry = caseStore.get(req.params.caseId);
    if (!entry) {
      return res.status(404).json({ error: 'Analysis not found — the case ID is unknown or has been evicted from the cache.' });
    }
    return res.json(
      stripAttachmentContent({
        caseId: entry.caseId,
        parsedEmail: entry.parsedEmail,
        analysis: entry.analysis,
        createdAt: entry.createdAt,
      }),
    );
  });

  // ------------------------------------------------------------------------
  // VirusTotal deep scan — on demand, one item per request, keyed by case ID.
  // ------------------------------------------------------------------------
  const deepScanKeyOf = (r: DeepScanItemResult) => (r.kind === 'url' ? `u:${r.url}` : `f:${r.sha256}`);

  function mergeDeepScanResult(analysis: any, result: DeepScanItemResult): void {
    const ds: DeepScanState = analysis.deepScan || { ranAt: new Date().toISOString(), items: [], addedPoints: 0 };
    ds.items = ds.items.filter((r) => deepScanKeyOf(r) !== deepScanKeyOf(result));
    ds.items.push(result);
    ds.ranAt = new Date().toISOString();
    analysis.deepScan = ds;
    applyDeepScan(analysis);
  }

  app.post('/api/deep-scan/:caseId/scan-item', async (req, res) => {
    const entry = caseStore.get(req.params.caseId);
    if (!entry) {
      return res.status(404).json({ error: 'Case not found — re-run the analysis before a deep scan.', code: 'case-not-found' });
    }
    const item = req.body?.item;
    if (!item || (item.kind !== 'url' && item.kind !== 'file')) {
      return res.status(400).json({ error: 'Missing or invalid scan item.' });
    }

    try {
      let result: DeepScanItemResult;
      if (item.kind === 'url') {
        if (!item.url) return res.status(400).json({ error: 'Missing url.' });
        result = await vtLookupUrl(String(item.url), {
          displayText: item.displayText,
          mismatched: Boolean(item.mismatched),
          appearsCount: Number(item.appearsCount) || undefined,
        });
      } else {
        if (!item.sha256) return res.status(400).json({ error: 'Missing sha256.' });
        result = await vtLookupFile(String(item.sha256), String(item.filename || 'attachment'));
      }

      mergeDeepScanResult(entry.analysis, result);
      console.log(
        `[EmailShield AI] Deep scan ${req.params.caseId} => ${item.kind} "${item.kind === 'url' ? item.url : item.filename}" ` +
          `[${result.status}] ${result.malicious}/${result.total} malicious | +${entry.analysis.deepScan.addedPoints} pts => ${entry.analysis.fraudScore}`,
      );

      return res.json(stripAttachmentContent({ result, analysis: entry.analysis, caseId: entry.caseId }));
    } catch (err: any) {
      console.error('/api/deep-scan error:', err?.message || err);
      return res.status(502).json({ error: err?.message || 'Deep scan failed.', code: 'deepscan-error' });
    }
  });

  // Re-poll an in-flight VT URL analysis (used by "Check again" and the client's
  // polling loop). Does NOT resubmit — just checks the existing analysis id.
  app.post('/api/deep-scan/:caseId/poll-item', async (req, res) => {
    const entry = caseStore.get(req.params.caseId);
    if (!entry) {
      return res.status(404).json({ error: 'Case not found.', code: 'case-not-found' });
    }
    const { analysisId, url, displayText, mismatched, appearsCount } = req.body || {};
    if (!url) return res.status(400).json({ error: 'Missing url.' });

    try {
      const result = await vtPollUrlAnalysis(String(analysisId || ''), String(url), {
        displayText,
        mismatched: Boolean(mismatched),
        appearsCount: Number(appearsCount) || undefined,
      });
      mergeDeepScanResult(entry.analysis, result);
      console.log(
        `[EmailShield AI] Deep scan poll ${req.params.caseId} => "${url}" [${result.status}]` +
          (result.status === 'done' ? ` ${result.malicious}/${result.total} malicious => ${entry.analysis.fraudScore}` : ''),
      );
      return res.json(stripAttachmentContent({ result, analysis: entry.analysis, caseId: entry.caseId }));
    } catch (err: any) {
      console.error('/api/deep-scan poll error:', err?.message || err);
      return res.status(502).json({ error: err?.message || 'Deep scan poll failed.', code: 'deepscan-error' });
    }
  });

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', service: 'EmailShield AI' });
  });

  // ------------------------------------------------------------------------
  // Google OAuth 2.0 (Gmail sign-in)
  // ------------------------------------------------------------------------
  app.get('/auth/google', (_req, res) => {
    if (!googleOAuthConfigured()) {
      return res.status(500).send('Google OAuth is not configured (missing GOOGLE_CLIENT_ID / SECRET / REDIRECT_URI).');
    }
    const { url, state } = buildAuthUrl();
    res.cookie(OAUTH_STATE_COOKIE, state, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 10 * 60 * 1000,
      path: '/',
    });
    res.redirect(url);
  });

  app.get('/auth/callback', async (req, res) => {
    const code = String(req.query.code || '');
    const state = String(req.query.state || '');
    const cookieState = parseCookie(req.headers.cookie, OAUTH_STATE_COOKIE);
    res.clearCookie(OAUTH_STATE_COOKIE, { path: '/' });

    if (req.query.error) {
      return res.redirect('/?auth_error=' + encodeURIComponent(String(req.query.error)));
    }
    if (!code || !state || state !== cookieState || !consumeState(state)) {
      return res.redirect('/?auth_error=state_mismatch');
    }
    try {
      const session = await exchangeCodeForSession(code);
      res.cookie(SESSION_COOKIE, session.id, {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000,
        path: '/',
      });
      res.redirect('/?signed_in=1');
    } catch (err: any) {
      console.error('[EmailShield AI] /auth/callback:', err?.message || err);
      res.redirect('/?auth_error=' + encodeURIComponent((err?.message || 'exchange_failed').slice(0, 120)));
    }
  });

  app.post('/auth/logout', (req, res) => {
    destroySession(parseCookie(req.headers.cookie, SESSION_COOKIE));
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.json({ ok: true });
  });

  app.get('/api/me', (req, res) => {
    // Gmail (OAuth) session takes precedence and behaves exactly as before.
    const session = getSession(parseCookie(req.headers.cookie, SESSION_COOKIE));
    if (session) {
      return res.json({ email: session.email, provider: 'gmail', oauthConfigured: true });
    }
    // Otherwise, an IMAP session (Outlook / Yahoo / custom) if one is connected.
    const imap = getImapSession(parseCookie(req.headers.cookie, IMAP_SESSION_COOKIE));
    if (imap) {
      return res.json({ email: imap.email, provider: 'imap', imapHost: imap.host });
    }
    return res.status(401).json({ error: 'Not signed in.', code: 'auth-required', oauthConfigured: googleOAuthConfigured() });
  });

  // ------------------------------------------------------------------------
  // Gmail inbox + message endpoints (rule-based only — NO Gemini here)
  // ------------------------------------------------------------------------

  // Last 20 inbox messages with a rule-based risk badge computed from metadata.
  app.get('/api/gmail/inbox', requireSession, async (req, res) => {
    const session: Session = (req as any).session;
    try {
      const ids = await listInboxMessageIds(session, 20);
      const settled = await Promise.allSettled(ids.map((id) => getMessageMetadata(session, id)));

      const messages: any[] = [];
      let failures = 0;
      for (const r of settled) {
        if (r.status !== 'fulfilled') {
          failures++;
          // An auth failure in the batch means the whole session is dead.
          if ((r.reason as any)?.code === 'auth-expired') throw r.reason;
          continue;
        }
        const m = r.value;
        const a = parseAddress(m.from || '');
        const partial = partialParsedFromMetadata(m.from, m.subject);
        // Metadata only -> skip the header-dependent rules (auth, missing Received).
        const { ruleScore, triggeredRules } = runRuleChecks(partial, undefined, { skipHeaderRules: true });
        messages.push({
          id: m.id,
          from: { name: a.displayName || a.address || '(unknown)', address: a.address, domain: a.domain },
          subject: m.subject || '(no subject)',
          date: m.date,
          snippet: m.snippet,
          ruleScore,
          riskBand: riskBand(ruleScore),
          ruleCount: triggeredRules.length,
          ruleTitles: triggeredRules.map((t) => t.rule),
        });
      }

      res.json({ email: session.email, count: messages.length, partialFailures: failures, messages });
    } catch (err) {
      respondGmailError(err, res);
    }
  });

  // One message: full raw fetch -> parse -> rule checks with real headers. NO Gemini.
  app.get('/api/gmail/message/:id', requireSession, async (req, res) => {
    const session: Session = (req as any).session;
    try {
      const raw = await getMessageRaw(session, req.params.id);
      const parsed = parseRawEml(raw);
      // Classify attachments on filename alone here (fast, no attachment fetch).
      await hashAndClassifyAttachments(parsed);
      const { ruleScore, triggeredRules } = runRuleChecks(parsed, undefined, {});
      res.json(
        stripAttachmentContent({
          id: req.params.id,
          parsedEmail: {
            from: parsed.from,
            to: parsed.to,
            subject: parsed.subject,
            date: parsed.date,
            returnPath: parsed.returnPath,
            replyTo: parsed.replyTo,
            messageId: parsed.messageId,
            bodyText: parsed.bodyText,
            bodyHtml: parsed.bodyHtml,
            extractedLinks: parsed.extractedLinks,
            attachments: parsed.attachments,
            authResults: parsed.authResults,
            receivedHopCount: parsed.receivedHops.length,
          },
          ruleScore,
          triggeredRules,
          riskBand: riskBand(ruleScore),
        }),
      );
    } catch (err) {
      respondGmailError(err, res);
    }
  });

  // Advanced Scan: the ONLY Gmail path that calls Gemini. Full existing pipeline.
  app.post('/api/gmail/message/:id/advanced-scan', requireSession, async (req, res) => {
    const session: Session = (req as any).session;
    try {
      const raw = await getMessageRaw(session, req.params.id);
      const parsed = parseRawEml(raw);

      // Attachment bytes: pull them via the Gmail API (messages.attachments.get)
      // so Gmail-sourced mail supports the same hash-based deep scan as .eml uploads.
      try {
        const apiAttachments = await getMessageAttachments(session, req.params.id);
        if (apiAttachments.length) parsed.attachments = apiAttachments as any;
      } catch (e: any) {
        console.warn('[EmailShield AI] Gmail attachment fetch failed:', e?.message || e);
      }
      await hashAndClassifyAttachments(parsed);

      const analysis = await analyzeEmailWithGemini(parsed); // rules + Gemini + origin trace + reputation
      const caseId = storeCase(parsed, analysis);
      res.json(stripAttachmentContent({ ...analysis, caseId, parsedEmail: parsed }));
    } catch (err) {
      respondGmailError(err, res);
    }
  });

  // ------------------------------------------------------------------------
  // IMAP mailbox (Outlook / Yahoo / custom) — a SEPARATE login path that feeds
  // the SAME shared analysis pipeline. Nothing in the Gmail integration above
  // is touched; these routes only differ in how the raw message is fetched.
  // ------------------------------------------------------------------------

  function requireImapSession(req: express.Request, res: express.Response, next: express.NextFunction): void {
    const s = getImapSession(parseCookie(req.headers.cookie, IMAP_SESSION_COOKIE));
    if (!s) {
      res.status(401).json({ error: 'Your IMAP session has ended — please connect again.', code: 'auth-required' });
      return;
    }
    (req as any).imap = s;
    next();
  }

  function respondImapError(err: any, res: express.Response): void {
    if (err instanceof ImapAuthError || err?.code === 'imap-auth') {
      res.status(401).json({ error: err.message || 'Invalid email or app password.', code: 'imap-auth' });
      return;
    }
    if (err instanceof ImapConnError || err?.code === 'imap-conn') {
      res.status(502).json({ error: err.message || 'Could not connect to the mail server.', code: 'imap-conn' });
      return;
    }
    console.error('[EmailShield AI] IMAP error:', err?.message || err);
    res.status(502).json({ error: 'The mail server request failed — please try again.', code: 'imap-error' });
  }

  app.post('/api/imap/connect', async (req, res) => {
    try {
      const { email, password, host, port } = req.body || {};
      const session = await createImapSession({
        email: String(email || ''),
        password: String(password || ''),
        host: String(host || ''),
        port: Number(port) || 993,
      });
      res.cookie(IMAP_SESSION_COOKIE, session.id, {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000,
        path: '/',
      });
      console.log(`[EmailShield AI] IMAP session opened for ${session.email} @ ${session.host}:${session.port}`);
      res.json({ email: session.email, provider: 'imap', imapHost: session.host });
    } catch (err) {
      respondImapError(err, res);
    }
  });

  app.post('/api/imap/logout', (req, res) => {
    destroyImapSession(parseCookie(req.headers.cookie, IMAP_SESSION_COOKIE));
    res.clearCookie(IMAP_SESSION_COOKIE, { path: '/' });
    res.json({ ok: true });
  });

  // Inbox — headers only, rule-based badge from metadata. NO Gemini.
  app.get('/api/imap/inbox', requireImapSession, async (req, res) => {
    const s: ImapSession = (req as any).imap;
    try {
      const rows = await listImapInbox(s, 20);
      const messages = rows.map((m) => {
        const a = parseAddress(m.from || '');
        const partial = partialParsedFromMetadata(m.from, m.subject);
        const { ruleScore, triggeredRules } = runRuleChecks(partial, undefined, { skipHeaderRules: true });
        return {
          id: m.uid,
          from: { name: a.displayName || a.address || '(unknown)', address: a.address, domain: a.domain },
          subject: m.subject || '(no subject)',
          date: m.date,
          snippet: '',
          ruleScore,
          riskBand: riskBand(ruleScore),
          ruleCount: triggeredRules.length,
          ruleTitles: triggeredRules.map((t) => t.rule),
        };
      });
      res.json({ email: s.email, count: messages.length, partialFailures: 0, messages });
    } catch (err) {
      respondImapError(err, res);
    }
  });

  // One message: raw RFC822 -> shared parse + rule checks with real headers. NO Gemini.
  app.get('/api/imap/message/:uid', requireImapSession, async (req, res) => {
    const s: ImapSession = (req as any).imap;
    try {
      const raw = await getImapMessageRaw(s, req.params.uid);
      const parsed = parseRawEml(raw);
      await hashAndClassifyAttachments(parsed);
      const { ruleScore, triggeredRules } = runRuleChecks(parsed, undefined, {});
      res.json(
        stripAttachmentContent({
          id: req.params.uid,
          parsedEmail: {
            from: parsed.from,
            to: parsed.to,
            subject: parsed.subject,
            date: parsed.date,
            returnPath: parsed.returnPath,
            replyTo: parsed.replyTo,
            messageId: parsed.messageId,
            bodyText: parsed.bodyText,
            bodyHtml: parsed.bodyHtml,
            extractedLinks: parsed.extractedLinks,
            attachments: parsed.attachments,
            authResults: parsed.authResults,
            receivedHopCount: parsed.receivedHops.length,
          },
          ruleScore,
          triggeredRules,
          riskBand: riskBand(ruleScore),
        }),
      );
    } catch (err) {
      respondImapError(err, res);
    }
  });

  // Advanced Scan — the ONLY IMAP path that calls Gemini. Shared full pipeline
  // (rules + ML + Gemini + origin trace + threat intel), identical to .eml/Gmail.
  app.post('/api/imap/message/:uid/advanced-scan', requireImapSession, async (req, res) => {
    const s: ImapSession = (req as any).imap;
    try {
      const raw = await getImapMessageRaw(s, req.params.uid);
      const parsed = parseRawEml(raw); // the raw source carries the full MIME incl. attachments
      await hashAndClassifyAttachments(parsed);
      const analysis = await analyzeEmailWithGemini(parsed);
      const caseId = storeCase(parsed, analysis);
      res.json(stripAttachmentContent({ ...analysis, caseId, parsedEmail: parsed }));
    } catch (err) {
      respondImapError(err, res);
    }
  });

  // Vite middleware in dev mode, static files in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`EmailShield AI server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
