/**
 * Provider-neutral mailbox client. The inbox UI talks to this so the SAME
 * components work for both the Gmail OAuth path (`/api/gmail/*`) and the IMAP
 * path for Outlook / Yahoo / custom servers (`/api/imap/*`).
 *
 * The types and the 401 error class are re-used from `gmailService.ts` (which is
 * left completely unchanged) so nothing downstream has to care which provider
 * connected the mailbox.
 */
import { GmailAuthError } from './gmailService';
import type { InboxResponse, MessageDetail, AdvancedScanResult } from './gmailService';

export type { InboxMessage, InboxResponse, MessageDetail, AdvancedScanResult, RiskBand } from './gmailService';
export { GmailAuthError as MailboxAuthError } from './gmailService';

export type MailProvider = 'gmail' | 'imap';

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: 'same-origin', ...init });
  let body: any = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON */
  }
  if (res.status === 401) {
    throw new GmailAuthError(body?.error || 'Please connect again.');
  }
  if (!res.ok) {
    throw new Error(body?.error || `Request failed (HTTP ${res.status})`);
  }
  return body as T;
}

const base = (p: MailProvider) => (p === 'imap' ? '/api/imap' : '/api/gmail');

/** Signed-in mailbox identity, or null when nothing is connected. */
export async function fetchMe(): Promise<{ email: string; provider: MailProvider } | null> {
  try {
    const r = await api<{ email: string; provider?: string }>('/api/me');
    return { email: r.email, provider: r.provider === 'imap' ? 'imap' : 'gmail' };
  } catch (err) {
    if (err instanceof GmailAuthError) return null;
    throw err;
  }
}

export const fetchInbox = (provider: MailProvider) => api<InboxResponse>(`${base(provider)}/inbox`);

export const fetchMessage = (provider: MailProvider, id: string) =>
  api<MessageDetail>(`${base(provider)}/message/${encodeURIComponent(id)}`);

export const runAdvancedScan = (provider: MailProvider, id: string) =>
  api<AdvancedScanResult>(`${base(provider)}/message/${encodeURIComponent(id)}/advanced-scan`, { method: 'POST' });

export const signOutMailbox = (provider: MailProvider) =>
  api<{ ok: boolean }>(provider === 'imap' ? '/api/imap/logout' : '/auth/logout', { method: 'POST' });

// --- IMAP connect --------------------------------------------------------

export interface ImapConnectInput {
  email: string;
  password: string;
  host: string;
  port: number;
}

export interface ImapConnectFailure extends Error {
  /** 'imap-auth' = bad credentials, 'imap-conn' = server unreachable. */
  code?: 'imap-auth' | 'imap-conn' | 'imap-error';
}

/**
 * Verify IMAP credentials and open a server-side session. The password is sent
 * once, used to authenticate, and kept only in server memory tied to the session
 * cookie — it is never stored in the browser.
 */
export async function imapConnect(input: ImapConnectInput): Promise<{ email: string }> {
  const res = await fetch('/api/imap/connect', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  let body: any = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON */
  }
  if (!res.ok) {
    const err = new Error(body?.error || `Could not connect (HTTP ${res.status})`) as ImapConnectFailure;
    err.code = body?.code;
    throw err;
  }
  return { email: String(body?.email || input.email) };
}
