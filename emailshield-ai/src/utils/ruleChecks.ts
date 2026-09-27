import type { GeoLocation, ParsedEmail } from '../types';

/**
 * A single deterministic rule that fired while inspecting an email.
 */
export interface TriggeredRule {
  id: string;
  rule: string;
  description: string;
  points: number;
  category:
    | 'Authentication'
    | 'Domain Alignment'
    | 'Brand Lookalike'
    | 'Social Engineering'
    | 'Deceptive Link'
    | 'Routing Anomaly'
    | 'Origin Geolocation'
    | 'Threat Intelligence'
    | 'Domain Intelligence'
    | 'Attachment';
}

/**
 * Optional geolocation context for the originating hop, supplied by the caller
 * after the async ip-api.com lookup has completed.
 */
export interface GeoRuleContext {
  originGeo: GeoLocation | null;
  originCountryCode: string | null;
  /** Highest AbuseIPDB confidence score across all relay-chain IPs. */
  maxAbuseScore?: number;
  /** The relay IP carrying that score (for the rule description). */
  abuseFlaggedIp?: string | null;
  /** Age in days of the youngest From / Return-Path domain (RDAP). */
  domainMinAgeDays?: number;
  /** Which sending domain carries that age (for the rule description). */
  domainAgeDomain?: string | null;
}

export interface RuleCheckOptions {
  /**
   * Skip the rules that depend on raw headers (SPF/DKIM/DMARC evaluation and the
   * "no Received headers" routing check). Used by the Gmail Quick Scan flow,
   * where only the rendered body and sender are available.
   */
  skipHeaderRules?: boolean;
}

/** Country each defended brand is expected to originate mail from. */
const BRAND_EXPECTED_COUNTRY: Record<string, string> = {
  paypal: 'US',
  amazon: 'US',
  microsoft: 'US',
  google: 'US',
  apple: 'US',
  chase: 'US',
  hdfc: 'IN',
  sbi: 'IN',
  icici: 'IN',
};

export interface RuleCheckResult {
  /** Deterministic rule-based score, 0 - 100 (sum of triggered rule points, capped). */
  ruleScore: number;
  triggeredRules: TriggeredRule[];
}

/** Brands we defend against lookalike / typosquat sender domains. */
const COMMON_BRANDS = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'chase', 'hdfc', 'sbi', 'icici'];

/**
 * Registrable domains that legitimately belong to the brands above. A sender on
 * one of these is never flagged as a lookalike.
 */
const BRAND_LEGIT_DOMAINS = new Set([
  'paypal.com',
  'amazon.com',
  'amazon.in',
  'amazon.co.uk',
  'microsoft.com',
  'office.com',
  'office365.com',
  'live.com',
  'outlook.com',
  'google.com',
  'gmail.com',
  'googlemail.com',
  'apple.com',
  'icloud.com',
  'chase.com',
  'hdfcbank.com',
  'sbi.co.in',
  'onlinesbi.sbi',
  'sbicard.com',
  'icicibank.com',
]);

/** Body / subject phrases that indicate urgency or social-engineering pressure. */
const SOCIAL_ENGINEERING_KEYWORDS = [
  'verify your account',
  'urgent action required',
  'suspended',
  'click immediately',
  'confirm your password',
  'limited time',
];

/** Classic Levenshtein edit distance. */
function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  let prev = new Array<number>(n + 1);
  let curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

/** Normalised string similarity in [0, 1] (1 = identical). */
function similarity(a: string, b: string): number {
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1;
  return 1 - levenshtein(a, b) / maxLen;
}

/** Fold common homoglyph / leet substitutions so "paypa1" -> "paypal". */
function deLeet(s: string): string {
  return s
    .toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/\$/g, 's')
    .replace(/rn/g, 'm');
}

const MULTI_PART_TLDS = new Set(['co.uk', 'com.au', 'co.in', 'org.uk', 'net.in', 'co.nz', 'com.br', 'co.jp']);

/** Extract the registrable label, e.g. "mail.paypal.com" -> "paypal", "x.co.uk" -> "x". */
function registrableLabel(domain: string): string {
  const parts = domain.toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 1) return parts[0] || '';
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) return parts[parts.length - 3];
  return parts[parts.length - 2];
}

/** True when two domains share the same organisational (last-two-label) domain. */
function domainsAligned(a: string, b: string): boolean {
  const norm = (x: string) => x.replace(/^www\./, '').toLowerCase().trim();
  const x = norm(a);
  const y = norm(b);
  if (!x || !y) return true;
  if (x === y) return true;
  return x.split('.').slice(-2).join('.') === y.split('.').slice(-2).join('.');
}

/** Detects a link whose visible URL text points to a different domain than its href. */
function isDisplayHrefMismatch(link: { text?: string; href?: string }): boolean {
  const text = (link.text || '').trim();
  const href = (link.href || '').trim();
  if (!text || !href) return false;

  const textUrl = text.match(/https?:\/\/([^/\s]+)/i);
  const hrefUrl = href.match(/https?:\/\/([^/\s]+)/i);
  if (!textUrl || !hrefUrl) return false;

  const t = textUrl[1].replace(/^www\./, '').toLowerCase();
  const h = hrefUrl[1].replace(/^www\./, '').toLowerCase();
  return !h.endsWith(t) && !t.endsWith(h);
}

/**
 * Checks whether a sender domain is a lookalike / typosquat of a common brand:
 * very similar to a brand name but not one of that brand's real domains.
 */
function detectBrandLookalike(domain: string): { brand: string; reason: string } | null {
  if (!domain) return null;
  const d = domain.toLowerCase();
  if (BRAND_LEGIT_DOMAINS.has(d)) return null;

  const label = registrableLabel(d);
  if (!label || label.length < 3) return null;

  const normLabel = deLeet(label);
  const tokens = label.split(/[^a-z0-9]+/i).filter(Boolean).map(deLeet);
  const candidates = Array.from(new Set([normLabel, ...tokens]));

  for (const brand of COMMON_BRANDS) {
    const isShortBrand = brand.length <= 4; // sbi, hdfc — fuzzy matching too noisy

    for (const cand of candidates) {
      if (!cand) continue;

      if (cand === brand) {
        // Brand name appears verbatim. If it IS the whole label ("amazon.de"),
        // treat as a benign ccTLD variant; if it is only part of a longer label
        // ("paypal-secure"), that is a classic impersonation pattern.
        if (label.toLowerCase() === brand) continue;
        return {
          brand,
          reason: `Sender domain "${domain}" places the brand name "${brand}" inside a larger label ("${label}") instead of using the official ${brand} domain.`,
        };
      }

      if (!isShortBrand) {
        const dist = levenshtein(cand, brand);
        if (dist > 0 && dist <= 2 && similarity(cand, brand) >= 0.72) {
          return {
            brand,
            reason: `Sender domain label "${label}" is a near-identical lookalike of "${brand}" (edit distance ${dist}).`,
          };
        }
        if (cand.includes(brand) && cand !== brand) {
          return {
            brand,
            reason: `Sender domain "${domain}" contains "${brand}" as part of a longer deceptive label.`,
          };
        }
      }
    }
  }
  return null;
}

/**
 * Runs the deterministic rule-based checks over a parsed email and returns a
 * score out of 100 plus the list of rules that fired. This score is designed to
 * be blended 50/50 with the AI judgment so verdicts stay explainable and stable.
 */
export function runRuleChecks(
  emailData: ParsedEmail,
  geo?: GeoRuleContext,
  opts: RuleCheckOptions = {},
): RuleCheckResult {
  const triggeredRules: TriggeredRule[] = [];

  const auth = emailData.authResults || {};
  const from = emailData.from || ({ domain: '', address: '', displayName: '', raw: '' } as ParsedEmail['from']);
  const fromDomain = (from.domain || '').toLowerCase();
  const fromName = (from.displayName || '').toLowerCase();
  const bodyText = (emailData.bodyText || '').toLowerCase();
  const subject = (emailData.subject || '').toLowerCase();
  const hops = emailData.receivedHops || [];
  const links = emailData.extractedLinks || [];

  // 1. SPF / DKIM / DMARC — fail OR missing: +15 each  (skipped for body-only scans)
  const authChecks: Array<{ name: 'SPF' | 'DKIM' | 'DMARC'; status?: string }> = opts.skipHeaderRules ? [] : [
    { name: 'SPF', status: auth.spf?.status },
    { name: 'DKIM', status: auth.dkim?.status },
    { name: 'DMARC', status: auth.dmarc?.status },
  ];
  for (const { name, status } of authChecks) {
    const s = (status || '').toLowerCase();
    const failed = s === 'fail' || s === 'softfail' || s === 'permerror' || s === 'temperror';
    const missing = !s || s === 'none' || s === 'neutral';
    if (failed || missing) {
      triggeredRules.push({
        id: `rule-auth-${name.toLowerCase()}`,
        rule: `${name} ${failed ? `failed (${s})` : 'missing / not evaluated'}`,
        description: failed
          ? `${name} authentication returned "${s}", meaning the sending server is not authorised for this domain or the message was altered in transit.`
          : `No conclusive ${name} result was present in the headers, so this aspect of sender authenticity is unverified.`,
        points: 15,
        category: 'Authentication',
      });
    }
  }

  // 2. Return-Path domain does not match From domain: +15
  const returnPathRaw = (emailData.returnPath || '').toLowerCase();
  const returnPathDomain = returnPathRaw.includes('@')
    ? returnPathRaw.split('@').pop()!.replace(/[<>\s]/g, '')
    : '';
  if (returnPathDomain && fromDomain && !domainsAligned(returnPathDomain, fromDomain)) {
    triggeredRules.push({
      id: 'rule-returnpath-mismatch',
      rule: 'Return-Path domain does not match From domain',
      description: `Bounce (Return-Path) domain "${returnPathDomain}" is not aligned with the From domain "${fromDomain}", a common indicator of spoofing or a relay hijack.`,
      points: 15,
      category: 'Domain Alignment',
    });
  }

  // 3. Sender domain is a lookalike of a common brand: +20
  const lookalike = detectBrandLookalike(fromDomain);
  if (lookalike) {
    triggeredRules.push({
      id: 'rule-brand-lookalike',
      rule: `Brand lookalike sender domain (${lookalike.brand})`,
      description: lookalike.reason,
      points: 20,
      category: 'Brand Lookalike',
    });
  }

  // 4. Urgency / social-engineering keywords: +10 each, capped at +30
  const matched = SOCIAL_ENGINEERING_KEYWORDS.filter((kw) => bodyText.includes(kw) || subject.includes(kw));
  if (matched.length > 0) {
    triggeredRules.push({
      id: 'rule-social-engineering',
      rule: `Urgency / social-engineering language (${matched.length} phrase${matched.length > 1 ? 's' : ''})`,
      description: `Body or subject contains coercive phrasing: ${matched.map((k) => `"${k}"`).join(', ')}. Scored +10 each, capped at +30.`,
      points: Math.min(matched.length * 10, 30),
      category: 'Social Engineering',
    });
  }

  // 5. Any link whose displayed text does not match the actual href: +20
  const mismatchedLink = links.find((l) => l && (l.isMismatched || isDisplayHrefMismatch(l)));
  if (mismatchedLink) {
    triggeredRules.push({
      id: 'rule-link-mismatch',
      rule: 'Hyperlink display text does not match its destination',
      description:
        mismatchedLink.mismatchReason ||
        `A link displays "${mismatchedLink.text}" but actually points to "${mismatchedLink.href}".`,
      points: 20,
      category: 'Deceptive Link',
    });
  }

  // 6. More than 6 Received hops, or no Received headers at all: +10
  //    (the "none at all" case is skipped for body-only scans — headers are simply
  //    not available there, so their absence is not evidence of anything)
  if (hops.length === 0 && !opts.skipHeaderRules) {
    triggeredRules.push({
      id: 'rule-no-received',
      rule: 'No Received headers present',
      description:
        'The message carries no "Received:" routing headers, which is abnormal for legitimately delivered mail and typical of directly injected spam or phishing.',
      points: 10,
      category: 'Routing Anomaly',
    });
  } else if (hops.length > 6) {
    triggeredRules.push({
      id: 'rule-excessive-hops',
      rule: `Excessive relay hops (${hops.length})`,
      description: `The message passed through ${hops.length} relays (more than 6), which can indicate laundering through open relays, forwarders, or a botnet.`,
      points: 10,
      category: 'Routing Anomaly',
    });
  }

  // 7. Originating IP sits in a hosting / proxy / VPN / TOR range: +15
  const originGeo = geo?.originGeo || null;
  if (originGeo && originGeo.status === 'success' && (originGeo.proxy || originGeo.hosting)) {
    const kinds = [originGeo.proxy ? 'anonymising proxy / VPN / TOR' : '', originGeo.hosting ? 'datacentre / hosting provider' : '']
      .filter(Boolean)
      .join(' and ');
    triggeredRules.push({
      id: 'rule-origin-infra',
      rule: 'Originating IP is anonymised or datacentre-hosted',
      description: `The earliest reliable sending IP (${originGeo.ip}${originGeo.isp ? `, ${originGeo.isp}` : ''}) is flagged by ip-api.com as ${kinds}. Legitimate transactional mail from a real organisation rarely originates from such infrastructure.`,
      points: 15,
      category: 'Origin Geolocation',
    });
  }

  // 8. Originating country differs from the claimed sender brand's home country: +10
  const claimedBrand = COMMON_BRANDS.find(
    (b) => fromName.includes(b) || subject.includes(b) || registrableLabel(fromDomain).includes(b),
  );
  const originCc = geo?.originCountryCode || (originGeo && originGeo.status === 'success' ? originGeo.countryCode : null) || null;
  if (claimedBrand && originCc) {
    const expected = BRAND_EXPECTED_COUNTRY[claimedBrand];
    if (expected && originCc.toUpperCase() !== expected) {
      triggeredRules.push({
        id: 'rule-origin-country-mismatch',
        rule: `Origin country (${originCc}) does not match ${claimedBrand} (${expected})`,
        description: `The message claims association with "${claimedBrand}" but the earliest reliable sending IP geolocates to ${originGeo?.country || originCc}, not ${claimedBrand}'s expected sending region (${expected}).`,
        points: 10,
        category: 'Origin Geolocation',
      });
    }
  }

  // 9. Any relay-chain IP flagged for prior abuse (AbuseIPDB confidence > 50): +20
  const maxAbuse = geo?.maxAbuseScore ?? 0;
  if (maxAbuse > 50) {
    triggeredRules.push({
      id: 'rule-ip-abuse',
      rule: 'IP flagged for prior abuse reports',
      description:
        `A relay-chain IP${geo?.abuseFlaggedIp ? ` (${geo.abuseFlaggedIp})` : ''} has an AbuseIPDB abuse-confidence ` +
        `score of ${maxAbuse}%, meaning it has been reported by other operators for spam, phishing or attack traffic.`,
      points: 20,
      category: 'Threat Intelligence',
    });
  }

  // 11. Sending domain registration age (RDAP). A failed / absent lookup adds
  //     nothing — only a confirmed young age scores.
  const domainAge = geo?.domainMinAgeDays;
  const ageDomain = geo?.domainAgeDomain ? ` "${geo.domainAgeDomain}"` : '';
  if (typeof domainAge === 'number' && domainAge < 30) {
    triggeredRules.push({
      id: 'rule-domain-newly-registered',
      rule: 'Newly registered sender domain',
      description:
        `The sending domain${ageDomain} was registered only ${domainAge} day${domainAge === 1 ? '' : 's'} ago. ` +
        'Domains used in phishing and fraud campaigns are very frequently days-to-weeks old.',
      points: 25,
      category: 'Domain Intelligence',
    });
  } else if (typeof domainAge === 'number' && domainAge < 90) {
    triggeredRules.push({
      id: 'rule-domain-recently-registered',
      rule: 'Recently registered sender domain',
      description:
        `The sending domain${ageDomain} was registered ${domainAge} days ago (under 90 days). ` +
        'Newly created domains carry an elevated risk of abuse.',
      points: 15,
      category: 'Domain Intelligence',
    });
  }

  // 10. Attachment static analysis (metadata only — no API call).
  const attachments = emailData.attachments || [];
  attachments.forEach((att, i) => {
    const tag = (att.sha256 || String(i)).slice(0, 8);
    if (att.extensionRisk === 'high') {
      triggeredRules.push({
        id: `rule-att-high-${tag}`,
        rule: `High-risk attachment: ${att.filename}`,
        description: att.riskReason || `"${att.filename}" is an executable or script attachment.`,
        points: 25,
        category: 'Attachment',
      });
    } else if (att.extensionRisk === 'macro') {
      triggeredRules.push({
        id: `rule-att-macro-${tag}`,
        rule: `Macro-enabled document: ${att.filename}`,
        description: att.riskReason || `"${att.filename}" is a macro-enabled Office document and can execute code on open.`,
        points: 15,
        category: 'Attachment',
      });
    } else if (att.extensionRisk === 'archive-exe') {
      triggeredRules.push({
        id: `rule-att-archive-${tag}`,
        rule: `Archive contains an executable: ${att.filename}`,
        description: att.riskReason || `The archive "${att.filename}" bundles an executable file.`,
        points: 15,
        category: 'Attachment',
      });
    }
  });

  const rawScore = triggeredRules.reduce((sum, r) => sum + r.points, 0);
  return { ruleScore: Math.min(100, rawScore), triggeredRules };
}
