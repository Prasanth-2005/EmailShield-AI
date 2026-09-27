import type { ParsedEmail, ThreatAnalysisResult, TriggeredRule, ExtractedLink, AuthResults } from '../types';

export type RiskBand = 'green' | 'amber' | 'red';

export interface InboxMessage {
  id: string;
  from: { name: string; address: string; domain: string };
  subject: string;
  date: string;
  snippet: string;
  ruleScore: number;
  riskBand: RiskBand;
  ruleCount: number;
  ruleTitles: string[];
}

export interface InboxResponse {
  email: string;
  count: number;
  partialFailures: number;
  messages: InboxMessage[];
}

export interface MessageDetail {
  id: string;
  parsedEmail: {
    from: ParsedEmail['from'];
    to: ParsedEmail['to'];
    subject: string;
    date: string;
    returnPath: string;
    replyTo: string;
    messageId: string;
    bodyText: string;
    bodyHtml?: string;
    extractedLinks: ExtractedLink[];
    authResults: AuthResults;
    receivedHopCount: number;
  };
  ruleScore: number;
  triggeredRules: TriggeredRule[];
  riskBand: RiskBand;
}

/** Advanced-scan response: the full threat analysis plus the parsed email. */
export type AdvancedScanResult = ThreatAnalysisResult & { caseId: string; parsedEmail: ParsedEmail };

/** Thrown when the server reports the Google session is gone (401 auth-expired/required). */
export class GmailAuthError extends Error {
  constructor(message = 'Your Google session has ended — please sign in again.') {
    super(message);
    this.name = 'GmailAuthError';
  }
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: 'same-origin', ...init });
  let body: any = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON */
  }
  if (res.status === 401) {
    throw new GmailAuthError(body?.error || 'Please sign in again.');
  }
  if (!res.ok) {
    throw new Error(body?.error || `Request failed (HTTP ${res.status})`);
  }
  return body as T;
}

export const SIGN_IN_URL = '/auth/google';

/** Returns the signed-in user, or null if not authenticated. */
export async function fetchMe(): Promise<{ email: string } | null> {
  try {
    return await api<{ email: string }>('/api/me');
  } catch (err) {
    if (err instanceof GmailAuthError) return null;
    throw err;
  }
}

export const fetchInbox = () => api<InboxResponse>('/api/gmail/inbox');

export const fetchMessage = (id: string) => api<MessageDetail>(`/api/gmail/message/${encodeURIComponent(id)}`);

export const runAdvancedScan = (id: string) =>
  api<AdvancedScanResult>(`/api/gmail/message/${encodeURIComponent(id)}/advanced-scan`, { method: 'POST' });

export const signOut = () => api<{ ok: boolean }>('/auth/logout', { method: 'POST' });
