/**
 * IMAP mailbox access for Outlook / Yahoo / custom servers — server side only.
 *
 * This is a SEPARATE login path from the Gmail OAuth flow (`gmail.ts`) and does
 * not touch it. The user's app password is held only in an in-memory session
 * keyed by an opaque HttpOnly cookie — the same pattern as the Gmail token
 * store — and is never written to disk or returned to the browser.
 *
 * A fresh IMAP connection is opened per request (connect → work → logout)
 * rather than held open, so a dropped socket can never wedge a session.
 */
import crypto from 'node:crypto';
import { ImapFlow, AuthenticationFailure, type ImapFlowOptions } from 'imapflow';

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_SESSIONS = 100;
const CONNECT_TIMEOUT_MS = 15_000;

export const IMAP_SESSION_COOKIE = 'emailshield_imap_session';

export class ImapAuthError extends Error {
  code = 'imap-auth' as const;
  constructor(message = 'Invalid email or app password.') {
    super(message);
    this.name = 'ImapAuthError';
  }
}

export class ImapConnError extends Error {
  code = 'imap-conn' as const;
  constructor(message = 'Could not connect to the mail server.') {
    super(message);
    this.name = 'ImapConnError';
  }
}

interface ImapCreds {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
}

export interface ImapSession {
  id: string;
  email: string;
  host: string;
  port: number;
  secure: boolean;
  /** App password — in memory only, never serialized out. */
  pass: string;
  createdAt: number;
  lastSeen: number;
}

const IMAP_SESSIONS = new Map<string, ImapSession>();

function randomId(bytes = 16): string {
  return crypto.randomBytes(bytes).toString('hex');
}

function pruneSessions(): void {
  const now = Date.now();
  for (const [k, s] of IMAP_SESSIONS) {
    if (now - s.createdAt > SESSION_TTL_MS) IMAP_SESSIONS.delete(k);
  }
  while (IMAP_SESSIONS.size > MAX_SESSIONS) {
    const oldest = IMAP_SESSIONS.keys().next().value;
    if (oldest === undefined) break;
    IMAP_SESSIONS.delete(oldest);
  }
}

/** Classify a raw connection error as "bad credentials" vs "server unreachable". */
function classifyError(err: any): ImapAuthError | ImapConnError {
  const msg = String(err?.message || err || '');
  const code = String(err?.code || err?.responseText || '');
  const authFlagged =
    err instanceof AuthenticationFailure ||
    err?.authenticationFailed === true ||
    err?.serverResponseCode === 'AUTHENTICATIONFAILED' ||
    err?.code === 'AUTHENTICATIONFAILED' ||
    /AUTHENTICATIONFAILED|auth(entication)?\s*fail|invalid credential|LOGIN failed|username and password|\[AUTH/i.test(
      msg + ' ' + code,
    );
  if (authFlagged) {
    return new ImapAuthError(
      'Invalid email or app password. For Outlook and Yahoo, make sure you are using an App Password, not your regular account password.',
    );
  }
  if (
    /ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ETIMEDOUT|ECONNRESET|EHOSTUNREACH|EPIPE|CONNECT_TIMEOUT|greeting|timed?\s*out|certificate|self-signed|altnames|wrong version number/i.test(
      msg + ' ' + code,
    )
  ) {
    return new ImapConnError('Could not connect to the mail server — check the server address and port and try again.');
  }
  // Unknown — treat as a connection problem so we never leak internals.
  return new ImapConnError('Could not connect to the mail server — check the server address and try again.');
}

function clientOptions(creds: ImapCreds, extra: Partial<ImapFlowOptions> = {}): ImapFlowOptions {
  return {
    host: creds.host,
    port: creds.port,
    secure: creds.secure,
    auth: { user: creds.user, pass: creds.pass },
    logger: false,
    emitLogs: false,
    // Fail fast rather than hang the request.
    greetingTimeout: CONNECT_TIMEOUT_MS,
    connectionTimeout: CONNECT_TIMEOUT_MS,
    socketTimeout: 60_000,
    tls: { rejectUnauthorized: true },
    ...extra,
  };
}

/** Open a connection, run `fn`, always tear the connection down. */
async function withClient<T>(creds: ImapCreds, fn: (client: ImapFlow) => Promise<T>): Promise<T> {
  const client = new ImapFlow(clientOptions(creds));
  try {
    await client.connect();
  } catch (err) {
    try {
      client.close();
    } catch {
      /* ignore */
    }
    throw classifyError(err);
  }
  try {
    return await fn(client);
  } finally {
    try {
      await client.logout();
    } catch {
      try {
        client.close();
      } catch {
        /* ignore */
      }
    }
  }
}

/**
 * Verify the credentials by opening a real connection (authenticate only), then
 * store an in-memory session. Throws {@link ImapAuthError} / {@link ImapConnError}.
 */
export async function createImapSession(input: {
  email: string;
  password: string;
  host: string;
  port: number;
}): Promise<ImapSession> {
  const email = String(input.email || '').trim();
  const host = String(input.host || '')
    .trim()
    .toLowerCase();
  const port = Number(input.port) || 993;
  const password = String(input.password || '');
  const secure = port === 993;

  if (!email || !host || !password) {
    throw new ImapAuthError('Email, app password and server host are all required.');
  }

  const creds: ImapCreds = { host, port, secure, user: email, pass: password };
  const isMicrosoft = /(^|\.)(outlook|office365|hotmail|live)\./i.test(host) || host === 'outlook.office365.com';

  // `verifyOnly` connects, authenticates, then logs straight back out.
  const probe = new ImapFlow(clientOptions(creds, { verifyOnly: true }));
  try {
    await probe.connect();
  } catch (err) {
    try {
      probe.close();
    } catch {
      /* ignore */
    }
    const classified = classifyError(err);
    // Microsoft permanently disabled Basic Auth (app passwords) for Outlook /
    // Office 365 IMAP — the server advertises LOGINDISABLED and only AUTH=XOAUTH2.
    // No password, app password or otherwise, can work; only OAuth 2.0.
    if (classified instanceof ImapAuthError && isMicrosoft) {
      throw new ImapAuthError(
        'Outlook / Microsoft 365 no longer allows IMAP sign-in with a password or app password — ' +
          'Microsoft disabled Basic Authentication for these mailboxes and now requires OAuth. ' +
          'Use a provider that still supports app passwords (Yahoo, iCloud, GMX, Zoho, or most college / custom mail servers).',
      );
    }
    throw classified;
  }

  const session: ImapSession = {
    id: randomId(16),
    email,
    host,
    port,
    secure,
    pass: password,
    createdAt: Date.now(),
    lastSeen: Date.now(),
  };
  IMAP_SESSIONS.set(session.id, session);
  pruneSessions();
  return session;
}

export function getImapSession(sessionId: string | undefined): ImapSession | null {
  if (!sessionId) return null;
  const s = IMAP_SESSIONS.get(sessionId);
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_TTL_MS) {
    IMAP_SESSIONS.delete(sessionId);
    return null;
  }
  s.lastSeen = Date.now();
  return s;
}

export function destroyImapSession(sessionId: string | undefined): void {
  if (sessionId) IMAP_SESSIONS.delete(sessionId);
}

function credsOf(s: ImapSession): ImapCreds {
  return { host: s.host, port: s.port, secure: s.secure, user: s.email, pass: s.pass };
}

export interface ImapHeaderRow {
  /** Per-mailbox UID used to fetch the message later. */
  uid: string;
  from: string;
  subject: string;
  date: string;
}

/** Newest `max` INBOX messages, headers only (From / Subject / Date). */
export async function listImapInbox(session: ImapSession, max = 20): Promise<ImapHeaderRow[]> {
  return withClient(credsOf(session), async (client) => {
    const lock = await client.getMailboxLock('INBOX');
    try {
      const total = client.mailbox ? client.mailbox.exists : 0;
      if (!total) return [];
      const start = Math.max(1, total - max + 1);

      const rows: ImapHeaderRow[] = [];
      for await (const msg of client.fetch(`${start}:*`, { envelope: true, internalDate: true })) {
        const env = msg.envelope;
        const fromAddr = env?.from?.[0];
        const fromStr = fromAddr
          ? fromAddr.name
            ? `${fromAddr.name} <${fromAddr.address || ''}>`
            : fromAddr.address || ''
          : '';
        const rawDate = env?.date || msg.internalDate;
        rows.push({
          uid: String(msg.uid),
          from: fromStr,
          subject: env?.subject || '',
          date: rawDate ? new Date(rawDate).toISOString() : '',
        });
      }
      rows.reverse(); // newest first
      return rows;
    } finally {
      lock.release();
    }
  });
}

/** Full RFC822 source for one message, by UID. */
export async function getImapMessageRaw(session: ImapSession, uid: string): Promise<string> {
  return withClient(credsOf(session), async (client) => {
    const lock = await client.getMailboxLock('INBOX');
    try {
      const msg = await client.fetchOne(String(uid), { source: true }, { uid: true });
      const src = msg && msg.source;
      if (!src) throw new ImapConnError('The mail server returned no content for this message.');
      return Buffer.isBuffer(src) ? src.toString('utf8') : String(src);
    } finally {
      lock.release();
    }
  });
}
