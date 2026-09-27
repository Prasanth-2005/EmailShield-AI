/**
 * Google OAuth 2.0 + Gmail read-only API — server side only.
 *
 * Tokens live in an in-memory session store keyed by an opaque session id that
 * is handed to the browser as an HttpOnly cookie. The browser never sees an
 * access or refresh token.
 */
import crypto from 'node:crypto';

const GMAIL_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';
const AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const GMAIL_BASE = 'https://gmail.googleapis.com/gmail/v1/users/me';

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_SESSIONS = 100;
const STATE_TTL_MS = 10 * 60 * 1000;

export const SESSION_COOKIE = 'emailshield_session';
export const OAUTH_STATE_COOKIE = 'emailshield_oauth_state';

export class AuthExpiredError extends Error {
  code = 'auth-expired' as const;
  constructor(message = 'Your Google session has expired — please sign in again.') {
    super(message);
    this.name = 'AuthExpiredError';
  }
}

export class GmailApiError extends Error {
  code = 'gmail-error' as const;
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'GmailApiError';
    this.status = status;
  }
}

interface TokenSet {
  access_token: string;
  refresh_token?: string;
  expiry: number; // ms epoch
  scope: string;
}

export interface Session {
  id: string;
  email: string;
  tokens: TokenSet;
  createdAt: number;
  lastSeen: number;
}

const SESSIONS = new Map<string, Session>();
const OAUTH_STATES = new Map<string, number>();

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required environment variable: ${name}`);
  return v;
}

export function googleOAuthConfigured(): boolean {
  return Boolean(
    process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REDIRECT_URI,
  );
}

function randomId(bytes = 16): string {
  return crypto.randomBytes(bytes).toString('hex');
}

/** Parse a single cookie value out of a raw Cookie header. */
export function parseCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return undefined;
}

// --- OAuth ------------------------------------------------------------------

export function buildAuthUrl(): { url: string; state: string } {
  const state = randomId(12);
  OAUTH_STATES.set(state, Date.now());
  pruneStates();
  const params = new URLSearchParams({
    client_id: env('GOOGLE_CLIENT_ID'),
    redirect_uri: env('GOOGLE_REDIRECT_URI'),
    response_type: 'code',
    scope: GMAIL_SCOPE,
    access_type: 'offline',
    include_granted_scopes: 'true',
    prompt: 'consent',
    state,
  });
  return { url: `${AUTH_ENDPOINT}?${params.toString()}`, state };
}

export function consumeState(state: string): boolean {
  const ts = OAUTH_STATES.get(state);
  OAUTH_STATES.delete(state);
  return Boolean(ts) && Date.now() - (ts as number) < STATE_TTL_MS;
}

function pruneStates(): void {
  const now = Date.now();
  for (const [k, ts] of OAUTH_STATES) {
    if (now - ts > STATE_TTL_MS) OAUTH_STATES.delete(k);
  }
}

function pruneSessions(): void {
  const now = Date.now();
  for (const [k, s] of SESSIONS) {
    if (now - s.createdAt > SESSION_TTL_MS) SESSIONS.delete(k);
  }
  while (SESSIONS.size > MAX_SESSIONS) {
    const oldest = SESSIONS.keys().next().value;
    if (oldest === undefined) break;
    SESSIONS.delete(oldest);
  }
}

/** Exchange an authorization code for tokens and create a session. */
export async function exchangeCodeForSession(code: string): Promise<Session> {
  const body = new URLSearchParams({
    code,
    client_id: env('GOOGLE_CLIENT_ID'),
    client_secret: env('GOOGLE_CLIENT_SECRET'),
    redirect_uri: env('GOOGLE_REDIRECT_URI'),
    grant_type: 'authorization_code',
  });
  const res = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new GmailApiError(`OAuth token exchange failed (${res.status}): ${text.slice(0, 200)}`, res.status);
  }
  const data: any = await res.json();
  const tokens: TokenSet = {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expiry: Date.now() + (Number(data.expires_in) || 3600) * 1000,
    scope: data.scope || GMAIL_SCOPE,
  };

  // The user's own email address is available under gmail.readonly.
  const profile = await gmailApi(tokens, '/profile');
  const email = profile.emailAddress || 'unknown';

  const session: Session = {
    id: randomId(16),
    email,
    tokens,
    createdAt: Date.now(),
    lastSeen: Date.now(),
  };
  SESSIONS.set(session.id, session);
  pruneSessions();
  return session;
}

export function getSession(sessionId: string | undefined): Session | null {
  if (!sessionId) return null;
  const s = SESSIONS.get(sessionId);
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_TTL_MS) {
    SESSIONS.delete(sessionId);
    return null;
  }
  s.lastSeen = Date.now();
  return s;
}

export function destroySession(sessionId: string | undefined): void {
  if (sessionId) SESSIONS.delete(sessionId);
}

// --- Gmail REST -----------------------------------------------------------

async function refreshIfNeeded(tokens: TokenSet): Promise<void> {
  if (Date.now() < tokens.expiry - 60_000) return;
  if (!tokens.refresh_token) {
    throw new AuthExpiredError('Google session expired and no refresh token is available — please sign in again.');
  }
  const body = new URLSearchParams({
    client_id: env('GOOGLE_CLIENT_ID'),
    client_secret: env('GOOGLE_CLIENT_SECRET'),
    refresh_token: tokens.refresh_token,
    grant_type: 'refresh_token',
  });
  const res = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    throw new AuthExpiredError('Could not refresh the Google access token — please sign in again.');
  }
  const data: any = await res.json();
  tokens.access_token = data.access_token;
  tokens.expiry = Date.now() + (Number(data.expires_in) || 3600) * 1000;
  if (data.refresh_token) tokens.refresh_token = data.refresh_token;
}

async function gmailApi(
  tokens: TokenSet,
  path: string,
  params?: Record<string, string | string[]>,
): Promise<any> {
  await refreshIfNeeded(tokens);

  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (Array.isArray(v)) v.forEach((x) => qs.append(k, x));
    else qs.append(k, v);
  }
  const url = `${GMAIL_BASE}${path}${qs.toString() ? `?${qs.toString()}` : ''}`;

  const res = await fetch(url, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  if (res.status === 401) {
    throw new AuthExpiredError('Google rejected the session — please sign in again.');
  }
  if (res.status === 429 || res.status === 403) {
    throw new GmailApiError('Gmail API rate limit or quota reached — wait a moment and retry.', res.status);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new GmailApiError(`Gmail API error ${res.status}: ${text.slice(0, 200)}`, res.status);
  }
  return res.json();
}

/** Newest N inbox message ids. */
export async function listInboxMessageIds(session: Session, max = 20): Promise<string[]> {
  const data = await gmailApi(session.tokens, '/messages', {
    maxResults: String(max),
    labelIds: 'INBOX',
  });
  return ((data.messages as any[]) || []).map((m) => m.id as string);
}

export interface GmailMetadata {
  id: string;
  from: string;
  subject: string;
  date: string;
  snippet: string;
}

/** Cheap metadata-only fetch: From / Subject / Date headers + snippet. No body. */
export async function getMessageMetadata(session: Session, id: string): Promise<GmailMetadata> {
  const data = await gmailApi(session.tokens, `/messages/${id}`, {
    format: 'metadata',
    metadataHeaders: ['From', 'Subject', 'Date'],
  });
  const headers: any[] = data.payload?.headers || [];
  const h = (name: string) =>
    headers.find((x) => (x.name || '').toLowerCase() === name.toLowerCase())?.value || '';
  return {
    id,
    from: h('From'),
    subject: h('Subject'),
    date: h('Date'),
    snippet: data.snippet || '',
  };
}

/** Full raw RFC 822 message, base64url-decoded to a UTF-8 string. */
export async function getMessageRaw(session: Session, id: string): Promise<string> {
  const data = await gmailApi(session.tokens, `/messages/${id}`, { format: 'raw' });
  const raw = data.raw as string | undefined;
  if (!raw) throw new GmailApiError('Gmail returned no raw content for this message.');
  return Buffer.from(raw.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

interface FetchedAttachment {
  filename: string;
  mimeType: string;
  size: number;
  sha256: string;
  extensionRisk: null;
  content: Uint8Array;
}

/**
 * Attachment bytes for one message, via `messages.get(format=full)` +
 * `messages.attachments.get`. Returned shape matches `EmailAttachment`
 * (pre-hash); the caller runs `hashAndClassifyAttachments`.
 */
export async function getMessageAttachments(session: Session, id: string): Promise<FetchedAttachment[]> {
  const msg = await gmailApi(session.tokens, `/messages/${id}`, { format: 'full' });

  const parts: any[] = [];
  const walk = (p: any) => {
    if (!p) return;
    if (Array.isArray(p.parts)) p.parts.forEach(walk);
    if (p.filename && p.body?.attachmentId) parts.push(p);
  };
  walk(msg.payload);

  const out: FetchedAttachment[] = [];
  for (const p of parts.slice(0, 15)) {
    try {
      const att = await gmailApi(session.tokens, `/messages/${id}/attachments/${p.body.attachmentId}`);
      const b64 = String(att.data || '').replace(/-/g, '+').replace(/_/g, '/');
      const bytes = new Uint8Array(Buffer.from(b64, 'base64'));
      out.push({
        filename: p.filename,
        mimeType: (p.mimeType || 'application/octet-stream').toLowerCase(),
        size: bytes.length,
        sha256: '',
        extensionRisk: null,
        content: bytes,
      });
    } catch {
      out.push({
        filename: p.filename,
        mimeType: (p.mimeType || 'application/octet-stream').toLowerCase(),
        size: Number(p.body?.size) || 0,
        sha256: '',
        extensionRisk: null,
        content: new Uint8Array(0),
      });
    }
  }
  return out;
}
