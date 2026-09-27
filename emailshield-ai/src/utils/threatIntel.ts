import type { DeepScanFileResult, DeepScanUrlResult, DomainIntelEntry, DomainIntelReport, IpReputation } from '../types';
import { isPrivateOrReservedIp } from './ipUtils';

/**
 * External threat-intelligence clients (server side only).
 *  - AbuseIPDB   — IP reputation, run automatically for every public relay IP.
 *  - VirusTotal  — URL / file (hash-only) lookups, run on demand.
 *
 * All lookups are cached in memory by key and degrade gracefully: a rate limit,
 * timeout or API error returns a `status: 'unavailable'` result rather than
 * throwing, so a failed feed never breaks the analysis or the panels.
 */

const TIMEOUT_MS = 8000;
const env = (k: string) => (typeof process !== 'undefined' ? process.env?.[k] : undefined);

function withTimeout(url: string, init: RequestInit): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  return fetch(url, { ...init, signal: ctrl.signal }).finally(() => clearTimeout(t));
}

// ==========================================================================
// AbuseIPDB
// ==========================================================================

/** AbuseIPDB numeric category id -> name (https://www.abuseipdb.com/categories). */
const ABUSE_CATEGORIES: Record<number, string> = {
  1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
  5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
  9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
  13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
  17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
  21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted',
};

const ipRepCache = new Map<string, IpReputation>();

/** AbuseIPDB reputation for one IP. Cached; never throws. */
export async function checkIpReputation(ip: string): Promise<IpReputation> {
  const cached = ipRepCache.get(ip);
  if (cached) return cached;

  const base = (): IpReputation => ({
    ip,
    status: 'unavailable',
    abuseConfidenceScore: 0,
    totalReports: 0,
    categories: [],
  });

  if (isPrivateOrReservedIp(ip)) {
    const r: IpReputation = { ...base(), status: 'clean', message: 'Private / reserved address' };
    ipRepCache.set(ip, r);
    return r;
  }

  const key = env('ABUSEIPDB_API_KEY');
  if (!key) {
    const r: IpReputation = { ...base(), message: 'ABUSEIPDB_API_KEY not configured' };
    ipRepCache.set(ip, r);
    return r;
  }

  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const res = await withTimeout(url, { headers: { Key: key, Accept: 'application/json' } });

    if (res.status === 429) {
      return finalize({ ...base(), message: 'AbuseIPDB rate limit reached' });
    }
    if (!res.ok) {
      return finalize({ ...base(), message: `AbuseIPDB HTTP ${res.status}` });
    }

    const body: any = await res.json();
    const d = body?.data || {};
    const catIds: number[] = [];
    for (const rep of Array.isArray(d.reports) ? d.reports : []) {
      for (const c of Array.isArray(rep.categories) ? rep.categories : []) {
        if (!catIds.includes(c)) catIds.push(c);
      }
    }
    const score = Number(d.abuseConfidenceScore) || 0;
    const reports = Number(d.totalReports) || 0;
    const r: IpReputation = {
      ip,
      status: score > 0 || reports > 0 ? 'flagged' : 'clean',
      abuseConfidenceScore: score,
      totalReports: reports,
      categories: catIds.map((id) => ABUSE_CATEGORIES[id]).filter(Boolean),
      countryCode: d.countryCode || undefined,
      isTor: Boolean(d.isTor),
      isWhitelisted: Boolean(d.isWhitelisted),
      lastReportedAt: d.lastReportedAt || undefined,
    };
    return finalize(r);
  } catch (err: any) {
    return finalize({ ...base(), message: err?.name === 'AbortError' ? 'AbuseIPDB timed out' : 'AbuseIPDB request failed' });
  }

  function finalize(r: IpReputation): IpReputation {
    ipRepCache.set(ip, r);
    return r;
  }
}

// ==========================================================================
// VirusTotal (v3)
// ==========================================================================

const VT_BASE = 'https://www.virustotal.com/api/v3';
const VT_MIN_INTERVAL_MS = Number(env('VT_MIN_INTERVAL_MS')) || 16000; // ~4 req/min free tier
let vtLastCall = 0;

const vtUrlCache = new Map<string, DeepScanUrlResult>();
const vtFileCache = new Map<string, DeepScanFileResult>();

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Space out live VT calls to respect the free-tier limit. Cached hits skip this. */
async function vtRateGate(): Promise<void> {
  const wait = vtLastCall + VT_MIN_INTERVAL_MS - Date.now();
  if (wait > 0) await sleep(wait);
  vtLastCall = Date.now();
}

function statsFrom(attrs: any): { malicious: number; suspicious: number; harmless: number; undetected: number; total: number } {
  const s = attrs?.last_analysis_stats || attrs?.stats || {};
  const malicious = Number(s.malicious) || 0;
  const suspicious = Number(s.suspicious) || 0;
  const harmless = Number(s.harmless) || 0;
  const undetected = Number(s.undetected) || 0;
  const timeout = Number(s.timeout) || 0;
  return { malicious, suspicious, harmless, undetected, total: malicious + suspicious + harmless + undetected + timeout };
}

function vtUrlId(url: string): string {
  // URL-safe base64 without padding — the VT v3 URL identifier.
  if (typeof Buffer !== 'undefined') return Buffer.from(url).toString('base64url');
  return btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export interface VtUrlMeta {
  displayText?: string;
  mismatched?: boolean;
  appearsCount?: number;
}

function urlStub(url: string, meta: VtUrlMeta | undefined, status: DeepScanUrlResult['status'], message?: string): DeepScanUrlResult {
  return {
    kind: 'url',
    url,
    displayText: meta?.displayText,
    mismatched: meta?.mismatched,
    appearsCount: meta?.appearsCount,
    status,
    message,
    malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0,
  };
}

/**
 * First VirusTotal lookup for a URL. If the URL is already known, returns a
 * completed result. If it is unknown, submits it and returns `pending` with the
 * `analysisId` — the caller then polls with {@link vtPollUrlAnalysis} rather than
 * this function blocking for the ~30-60 s VT takes on a fresh URL.
 */
export async function vtLookupUrl(url: string, meta?: VtUrlMeta): Promise<DeepScanUrlResult> {
  const cached = vtUrlCache.get(url);
  if (cached) {
    return { ...cached, displayText: meta?.displayText ?? cached.displayText, mismatched: meta?.mismatched ?? cached.mismatched, appearsCount: meta?.appearsCount ?? cached.appearsCount };
  }

  const key = env('VIRUSTOTAL_API_KEY');
  if (!key) return urlStub(url, meta, 'unavailable', 'VIRUSTOTAL_API_KEY not configured');
  const headers = { 'x-apikey': key, Accept: 'application/json' };

  try {
    await vtRateGate();
    const res = await withTimeout(`${VT_BASE}/urls/${vtUrlId(url)}`, { headers });

    if (res.status === 429) return urlStub(url, meta, 'unavailable', 'VirusTotal rate limit reached');

    if (res.status === 404) {
      // Unknown URL — submit it for analysis; the caller polls the returned id.
      await vtRateGate();
      const submit = await withTimeout(`${VT_BASE}/urls`, {
        method: 'POST',
        headers: { ...headers, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ url }).toString(),
      });
      if (submit.status === 429) return urlStub(url, meta, 'unavailable', 'VirusTotal rate limit reached');
      if (!submit.ok) return urlStub(url, meta, 'unavailable', `VirusTotal HTTP ${submit.status}`);
      const analysisId = (await submit.json())?.data?.id;
      const pending = urlStub(url, meta, 'pending', 'VirusTotal is analysing this URL for the first time');
      pending.analysisId = analysisId || undefined;
      return pending;
    }

    if (!res.ok) return urlStub(url, meta, 'unavailable', `VirusTotal HTTP ${res.status}`);

    const attrs = (await res.json())?.data?.attributes;
    const done: DeepScanUrlResult = { ...urlStub(url, meta, 'done'), ...statsFrom(attrs) };
    vtUrlCache.set(url, done);
    return done;
  } catch (err: any) {
    return urlStub(url, meta, 'unavailable', err?.name === 'AbortError' ? 'VirusTotal timed out' : 'VirusTotal request failed');
  }
}

/**
 * Re-polls an in-flight VT URL analysis. Returns a completed result, or keeps it
 * `pending` (with the same `analysisId`) so the caller can try again. Uses a
 * lighter rate gate than a full lookup — polls are cheap and the caller paces them.
 */
export async function vtPollUrlAnalysis(analysisId: string, url: string, meta?: VtUrlMeta): Promise<DeepScanUrlResult> {
  const cached = vtUrlCache.get(url);
  if (cached) return { ...cached, displayText: meta?.displayText ?? cached.displayText, mismatched: meta?.mismatched ?? cached.mismatched, appearsCount: meta?.appearsCount ?? cached.appearsCount };

  const keepPending = (message?: string): DeepScanUrlResult => {
    const p = urlStub(url, meta, 'pending', message || 'VirusTotal is still analysing this URL');
    p.analysisId = analysisId;
    return p;
  };

  const key = env('VIRUSTOTAL_API_KEY');
  if (!key) return urlStub(url, meta, 'unavailable', 'VIRUSTOTAL_API_KEY not configured');
  if (!analysisId) return keepPending('No analysis id — re-run the scan for this URL');

  try {
    // Light gate — polls are cheap and the client already spaces them ~5 s apart.
    const gap = vtLastCall + 1000 - Date.now();
    if (gap > 0) await sleep(gap);
    const poll = await withTimeout(`${VT_BASE}/analyses/${encodeURIComponent(analysisId)}`, {
      headers: { 'x-apikey': key, Accept: 'application/json' },
    });
    vtLastCall = Date.now();
    if (poll.status === 429) return keepPending('VirusTotal rate limit — will retry');
    if (!poll.ok) return keepPending(`VirusTotal HTTP ${poll.status}`);
    const pd = (await poll.json())?.data?.attributes;
    if (pd?.status === 'completed') {
      const done: DeepScanUrlResult = { ...urlStub(url, meta, 'done'), ...statsFrom(pd) };
      vtUrlCache.set(url, done);
      return done;
    }
    return keepPending();
  } catch (err: any) {
    return keepPending(err?.name === 'AbortError' ? 'VirusTotal timed out' : 'VirusTotal request failed');
  }
}

export async function vtLookupFile(sha256: string, filename: string): Promise<DeepScanFileResult> {
  const cached = vtFileCache.get(sha256);
  if (cached) return { ...cached, filename };

  const stub = (status: DeepScanFileResult['status'], message?: string): DeepScanFileResult => ({
    kind: 'file',
    filename,
    sha256,
    status,
    message,
    malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0,
  });

  const key = env('VIRUSTOTAL_API_KEY');
  if (!key) return stub('unavailable', 'VIRUSTOTAL_API_KEY not configured');
  if (!/^[a-f0-9]{64}$/i.test(sha256)) return stub('unavailable', 'attachment hash unavailable');

  try {
    await vtRateGate();
    const res = await withTimeout(`${VT_BASE}/files/${sha256.toLowerCase()}`, {
      headers: { 'x-apikey': key, Accept: 'application/json' },
    });

    if (res.status === 429) return stub('unavailable', 'VirusTotal rate limit reached');
    if (res.status === 404) {
      const r = stub('unknown', 'No prior threat record');
      vtFileCache.set(sha256, r);
      return r;
    }
    if (!res.ok) return stub('unavailable', `VirusTotal HTTP ${res.status}`);

    const attrs = (await res.json())?.data?.attributes;
    const r: DeepScanFileResult = { ...stub('done'), ...statsFrom(attrs) };
    vtFileCache.set(sha256, r);
    return r;
  } catch (err: any) {
    return stub('unavailable', err?.name === 'AbortError' ? 'VirusTotal timed out' : 'VirusTotal request failed');
  }
}

// ==========================================================================
// RDAP — domain registration intelligence (free, no API key; replaced WHOIS)
// ==========================================================================

/** Registry suffixes that take three labels to reach the registrable domain. */
const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'ac.in', 'gov.in',
  'co.nz', 'com.br', 'com.sg', 'co.za', 'co.jp', 'or.jp', 'com.cn', 'net.cn',
]);

/** Reduce any host / address / URL to its registrable domain, lower-cased. */
export function registrableDomain(input: string): string {
  let d = (input || '').trim().toLowerCase();
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // scheme
  d = d.replace(/^[^@/]*@/, ''); // userinfo / local-part
  d = d.split(/[/:?#\s<>]/)[0]; // path / port / query / stray brackets
  d = d.replace(/^\.+|\.+$/g, '');
  const parts = d.split('.').filter(Boolean);
  if (parts.length <= 2) return d;
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

export interface DomainIntel {
  domain: string;
  status: 'ok' | 'not-found' | 'unavailable';
  registeredAt?: string;
  updatedAt?: string;
  expiresAt?: string;
  registrar?: string;
  ageDays?: number;
  message?: string;
}

const domainIntelCache = new Map<string, DomainIntel>();

function rdapDate(events: any[], action: string): string | undefined {
  const e = (Array.isArray(events) ? events : []).find(
    (x) => String(x?.eventAction || '').toLowerCase() === action,
  );
  if (!e?.eventDate) return undefined;
  const d = new Date(e.eventDate);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

function rdapRegistrar(entities: any[]): string | undefined {
  let name: string | undefined;
  const walk = (arr: any[]): void => {
    for (const ent of Array.isArray(arr) ? arr : []) {
      const roles = (ent?.roles || []).map((r: any) => String(r).toLowerCase());
      if (!name && roles.includes('registrar')) {
        const vcard = ent?.vcardArray?.[1];
        if (Array.isArray(vcard)) {
          const fn = vcard.find((f: any) => Array.isArray(f) && f[0] === 'fn');
          if (fn?.[3]) name = String(fn[3]).trim();
        }
        if (!name && Array.isArray(ent?.publicIds) && ent.publicIds[0]?.identifier) {
          name = `IANA registrar #${ent.publicIds[0].identifier}`;
        }
      }
      if (ent?.entities) walk(ent.entities);
    }
  };
  walk(entities);
  return name;
}

/**
 * RDAP registration data for one domain. Cached by domain; never throws. Some
 * ccTLD registries (e.g. parts of `.in`) do not serve RDAP through the rdap.org
 * bootstrap — those degrade to `status: 'unavailable'` rather than erroring.
 */
export async function checkDomainIntel(rawDomain: string): Promise<DomainIntel> {
  const domain = registrableDomain(rawDomain);
  if (!domain || !domain.includes('.')) {
    return { domain: rawDomain || '(none)', status: 'unavailable', message: 'Not a lookupable domain' };
  }

  const cached = domainIntelCache.get(domain);
  if (cached) return cached;

  const finalize = (r: DomainIntel): DomainIntel => {
    domainIntelCache.set(domain, r);
    return r;
  };
  const unavailable = (message: string) => finalize({ domain, status: 'unavailable', message });
  const notFound = () => finalize({ domain, status: 'not-found', message: 'No RDAP registration record found' });

  try {
    const res = await withTimeout(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      // Several RDAP servers (incl. some Verisign endpoints reached via the
      // rdap.org bootstrap) reject requests with the default Node user-agent.
      headers: {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'EmailShieldAI/1.0 (email forensic analysis; +https://localhost)',
      },
    });

    if (res.status === 404) return notFound();
    if (res.status === 429) return unavailable('RDAP rate limit reached');
    if (!res.ok) return unavailable(`RDAP HTTP ${res.status}`);

    let body: any;
    try {
      body = await res.json();
    } catch {
      return unavailable('RDAP returned a non-JSON response');
    }
    if (body?.errorCode) {
      return Number(body.errorCode) === 404 ? notFound() : unavailable(`RDAP error ${body.errorCode}`);
    }

    const events: any[] = Array.isArray(body?.events) ? body.events : [];
    const registeredAt = rdapDate(events, 'registration');
    const updatedAt = rdapDate(events, 'last changed') || rdapDate(events, 'last update of rdap database');
    const expiresAt = rdapDate(events, 'expiration');
    const registrar = rdapRegistrar(body?.entities);

    if (!registeredAt && !updatedAt && !expiresAt && !registrar) {
      return unavailable('RDAP record carried no registration data');
    }

    const ageDays = registeredAt
      ? Math.max(0, Math.floor((Date.now() - new Date(registeredAt).getTime()) / 86_400_000))
      : undefined;

    return finalize({ domain, status: 'ok', registeredAt, updatedAt, expiresAt, registrar, ageDays });
  } catch (err: any) {
    return unavailable(err?.name === 'AbortError' ? 'RDAP lookup timed out' : 'RDAP lookup failed');
  }
}

/**
 * Runs {@link checkDomainIntel} for the From domain, the Return-Path domain and
 * up to two domains behind deceptive (display-text ≠ href) links, in parallel.
 * The From / Return-Path ages feed a rule check; link domains are informational.
 */
export async function buildDomainIntelReport(parsedEmail: any): Promise<DomainIntelReport> {
  const roleFor = new Map<string, DomainIntelEntry['role']>();
  const add = (raw: string, role: DomainIntelEntry['role']) => {
    const d = registrableDomain(raw);
    if (d && d.includes('.') && !roleFor.has(d)) roleFor.set(d, role);
  };

  add(parsedEmail?.from?.domain || parsedEmail?.from?.address || '', 'from');

  const rp = String(parsedEmail?.returnPath || '');
  if (rp.includes('@')) add(rp, 'return-path');
  else if (rp.includes('.')) add(rp, 'return-path');

  const links = Array.isArray(parsedEmail?.extractedLinks) ? parsedEmail.extractedLinks : [];
  let linkDomains = 0;
  for (const l of links) {
    if (linkDomains >= 2) break;
    if (!l?.isMismatched) continue;
    const host = registrableDomain(String(l.href || ''));
    if (host && host.includes('.') && !roleFor.has(host)) {
      roleFor.set(host, 'deceptive-link');
      linkDomains += 1;
    }
  }

  const pairs = [...roleFor.entries()];
  if (pairs.length === 0) return { entries: [] };

  const entries: DomainIntelEntry[] = await Promise.all(
    pairs.map(async ([domain, role]): Promise<DomainIntelEntry> => {
      const intel = await checkDomainIntel(domain);
      return { ...intel, domain: intel.domain, role };
    }),
  );

  let sendingMinAgeDays: number | undefined;
  let sendingYoungestDomain: string | undefined;
  for (const e of entries) {
    if ((e.role === 'from' || e.role === 'return-path') && typeof e.ageDays === 'number') {
      if (sendingMinAgeDays === undefined || e.ageDays < sendingMinAgeDays) {
        sendingMinAgeDays = e.ageDays;
        sendingYoungestDomain = e.domain;
      }
    }
  }

  return { entries, sendingMinAgeDays, sendingYoungestDomain };
}
