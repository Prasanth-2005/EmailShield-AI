import { AuthResults, ExtractedLink, ParsedEmail, ReceivedHop } from '../types';
import { extractAttachments } from './attachments';

/**
 * Decodes MIME encoded-words (=?charset?encoding?encoded_text?=)
 */
export function decodeMimeWords(str: string): string {
  if (!str) return '';
  return str.replace(/=\?([^?]+)\?([BQbq])\?([^?]*)\?=/gi, (_match, _charset, encoding, encodedText) => {
    try {
      if (encoding.toUpperCase() === 'B') {
        return atob(encodedText);
      } else if (encoding.toUpperCase() === 'Q') {
        const decoded = encodedText
          .replace(/_/g, ' ')
          .replace(/=([0-9A-Fa-f]{2})/g, (_m: string, hex: string) => String.fromCharCode(parseInt(hex, 16)));
        return decodeURIComponent(escape(decoded));
      }
    } catch {
      return encodedText;
    }
    return encodedText;
  });
}

/**
 * Decodes Quoted-Printable content
 */
export function decodeQuotedPrintable(input: string): string {
  if (!input) return '';
  // Remove soft line breaks: =\r\n or =\n
  const cleanSoftBreaks = input.replace(/=\r?\n/g, '');
  // Replace =XX hex bytes
  return cleanSoftBreaks.replace(/=([0-9A-Fa-f]{2})/g, (_match, hex) => {
    try {
      return String.fromCharCode(parseInt(hex, 16));
    } catch {
      return _match;
    }
  });
}

/**
 * Extracts address and display name from "Name <user@domain.com>" or "user@domain.com"
 */
export function parseAddress(raw: string): { displayName: string; address: string; domain: string } {
  if (!raw) return { displayName: '', address: '', domain: '' };

  const cleaned = decodeMimeWords(raw.trim());
  const angleMatch = cleaned.match(/^(.*?)\s*<([^>]+)>/);

  if (angleMatch) {
    const displayName = angleMatch[1].replace(/^["']|["']$/g, '').trim();
    const address = angleMatch[2].trim().toLowerCase();
    const domain = address.split('@')[1] || '';
    return { displayName: displayName || address, address, domain };
  }

  const emailMatch = cleaned.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  if (emailMatch) {
    const address = emailMatch[1].toLowerCase();
    const domain = address.split('@')[1] || '';
    return { displayName: address, address, domain };
  }

  return { displayName: cleaned, address: cleaned, domain: '' };
}

/**
 * Parses individual Received headers into structured Hop data
 */
export function parseReceivedHop(rawHop: string, hopNumber: number): ReceivedHop {
  const unfolded = rawHop.replace(/\s+/g, ' ').trim();

  // Extract from
  const fromMatch = unfolded.match(/from\s+([^\s;]+(?:\s*\([^)]+\))?)/i);
  const fromServer = fromMatch ? fromMatch[1].trim() : 'Unknown sender host';

  // Extract by
  const byMatch = unfolded.match(/by\s+([^\s;]+)/i);
  const byServer = byMatch ? byMatch[1].trim() : 'Unknown relay host';

  // Extract IP
  const ipMatch = unfolded.match(/\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]/);
  const ipAddress = ipMatch ? ipMatch[1] : undefined;

  // Extract protocol
  const withMatch = unfolded.match(/with\s+([^\s;]+)/i);
  const withProtocol = withMatch ? withMatch[1].trim() : undefined;

  // Extract for recipient
  const forMatch = unfolded.match(/for\s+<([^>]+)>/i) || unfolded.match(/for\s+([^\s;]+)/i);
  const forRecipient = forMatch ? forMatch[1].trim() : undefined;

  // Extract TLS info
  const tlsMatch = unfolded.match(/(TLSv[0-9.]+|version=[^\s;]+|cipher=[^\s;]+|using\s+TLS[^\s;]*)/i);
  const tls = tlsMatch ? tlsMatch[0].trim() : undefined;

  // Extract timestamp at end after ';'
  const semiIndex = unfolded.lastIndexOf(';');
  let timestamp = undefined;
  if (semiIndex !== -1) {
    timestamp = unfolded.substring(semiIndex + 1).trim();
  }

  return {
    hopNumber,
    fromServer,
    byServer,
    withProtocol,
    forRecipient,
    timestamp,
    ipAddress,
    tls,
    rawHop: unfolded,
  };
}

/**
 * Parses SPF, DKIM, DMARC from Authentication-Results and Received-SPF headers
 */
export function parseAuthenticationHeaders(headers: Record<string, string | string[]>): AuthResults {
  const authResults: AuthResults = {};

  const getHeaderStr = (name: string): string => {
    const val = headers[name.toLowerCase()];
    if (!val) return '';
    return Array.isArray(val) ? val.join(' \n ') : val;
  };

  const authHeader = getHeaderStr('authentication-results');
  const spfHeader = getHeaderStr('received-spf');
  const dkimHeader = getHeaderStr('dkim-signature');

  authResults.rawAuthHeader = authHeader || spfHeader || undefined;

  // Parse SPF
  if (spfHeader) {
    const lowerSpf = spfHeader.toLowerCase();
    if (lowerSpf.startsWith('pass')) authResults.spf = { status: 'pass', details: spfHeader };
    else if (lowerSpf.startsWith('fail')) authResults.spf = { status: 'fail', details: spfHeader };
    else if (lowerSpf.startsWith('softfail')) authResults.spf = { status: 'softfail', details: spfHeader };
    else if (lowerSpf.startsWith('neutral')) authResults.spf = { status: 'neutral', details: spfHeader };
    else if (lowerSpf.startsWith('none')) authResults.spf = { status: 'none', details: spfHeader };
  } else if (authHeader) {
    const spfMatch = authHeader.match(/spf=([a-z]+)(?:\s+\(([^)]+)\))?/i);
    if (spfMatch) {
      const status = spfMatch[1].toLowerCase() as AuthResults['spf']['status'];
      authResults.spf = {
        status,
        details: spfMatch[2] || spfMatch[0],
      };
    }
  }

  // Parse DKIM
  if (authHeader) {
    const dkimMatch = authHeader.match(/dkim=([a-z]+)(?:\s+\(([^)]+)\))?/i);
    if (dkimMatch) {
      const status = dkimMatch[1].toLowerCase() as AuthResults['dkim']['status'];
      const domainMatch = authHeader.match(/header\.[id]=@?([a-zA-Z0-9.-]+)/i);
      authResults.dkim = {
        status,
        domain: domainMatch ? domainMatch[1] : undefined,
        details: dkimMatch[2] || dkimMatch[0],
      };
    }
  } else if (dkimHeader) {
    const dMatch = dkimHeader.match(/d=([a-zA-Z0-9.-]+)/i);
    authResults.dkim = {
      status: 'pass',
      domain: dMatch ? dMatch[1] : undefined,
      details: 'DKIM-Signature header present',
    };
  }

  // Parse DMARC
  if (authHeader) {
    const dmarcMatch = authHeader.match(/dmarc=([a-z]+)(?:\s+\(([^)]+)\))?/i);
    if (dmarcMatch) {
      const status = dmarcMatch[1].toLowerCase() as AuthResults['dmarc']['status'];
      const actionMatch = authHeader.match(/action=([a-zA-Z]+)/i) || authHeader.match(/p=([a-zA-Z]+)/i);
      authResults.dmarc = {
        status,
        policy: actionMatch ? actionMatch[1] : undefined,
        details: dmarcMatch[2] || dmarcMatch[0],
      };
    }
  }

  return authResults;
}

/**
 * Extracts links from HTML and plaintext, checking for text-vs-target mismatches
 */
export function extractAndCheckLinks(html: string, text: string): ExtractedLink[] {
  const links: ExtractedLink[] = [];
  const seen = new Set<string>();

  // 1. Extract from HTML anchor tags
  const anchorRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']*)["'][^>]*>(.*?)<\/a>/gis;
  let match;
  while ((match = anchorRegex.exec(html)) !== null) {
    const href = match[1].trim();
    const innerText = match[2].replace(/<[^>]*>/g, '').trim();

    if (!href || href.startsWith('#') || href.startsWith('mailto:')) continue;

    const key = `${href}|${innerText}`;
    if (seen.has(key)) continue;
    seen.add(key);

    let isMismatched = false;
    let mismatchReason = undefined;

    // Check if innerText looks like a URL but points to a different domain
    const textUrlMatch = innerText.match(/https?:\/\/([^\/\s]+)/i);
    const hrefUrlMatch = href.match(/https?:\/\/([^\/\s]+)/i);

    if (textUrlMatch && hrefUrlMatch) {
      const textDomain = textUrlMatch[1].toLowerCase();
      const hrefDomain = hrefUrlMatch[1].toLowerCase();

      // Normalize common subdomains
      const cleanTextDomain = textDomain.replace(/^www\./, '');
      const cleanHrefDomain = hrefDomain.replace(/^www\./, '');

      if (!cleanHrefDomain.endsWith(cleanTextDomain) && !cleanTextDomain.endsWith(cleanHrefDomain)) {
        isMismatched = true;
        mismatchReason = `Link text displays "${textDomain}" but actually points to malicious destination "${hrefDomain}"`;
      }
    }

    links.push({
      text: innerText || href,
      href,
      isMismatched,
      mismatchReason,
    });
  }

  // 2. Extract plain text URLs
  const urlRegex = /(https?:\/\/[^\s<>"']+)/gi;
  let textMatch;
  while ((textMatch = urlRegex.exec(text)) !== null) {
    // Trim trailing sentence punctuation the greedy match pulls in ("...paypal).")
    const href = textMatch[1].trim().replace(/[.,;:!?)\]}'"]+$/, '');
    if (!href) continue;
    const key = `${href}|${href}`;
    if (!seen.has(key)) {
      seen.add(key);
      links.push({
        text: href,
        href,
        isMismatched: false,
      });
    }
  }

  return links;
}

/**
 * Decodes a base64 payload to a UTF-8 string (falls back to latin1 on error).
 * Works in both the browser and Node.
 */
function decodeBase64ToString(b64: string): string {
  const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '');
  if (!clean) return '';
  const bin = atob(clean);
  try {
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    return bin;
  }
}

/** Applies a MIME part's Content-Transfer-Encoding. */
function decodeTransferEncoding(body: string, cte: string): string {
  const enc = (cte || '').toLowerCase();
  if (enc.includes('quoted-printable')) return decodeQuotedPrintable(body);
  if (enc.includes('base64')) {
    try {
      return decodeBase64ToString(body);
    } catch {
      return body;
    }
  }
  return body;
}

/** Minimal HTML entity decoder for the common named + numeric entities. */
export function decodeHtmlEntities(input: string): string {
  if (!input) return '';
  return input
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;|&apos;/gi, "'")
    .replace(/&mdash;/gi, '—')
    .replace(/&ndash;/gi, '–')
    .replace(/&hellip;/gi, '…')
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, h) => {
      try { return String.fromCodePoint(parseInt(h, 16)); } catch { return _m; }
    })
    .replace(/&#(\d+);/g, (_m, d) => {
      try { return String.fromCodePoint(Number(d)); } catch { return _m; }
    });
}

/**
 * Converts an HTML email body to readable plain text for keyword analysis and
 * display. Anchor destinations are preserved as "text (href)" when the visible
 * text differs from the href, so link-based signals still reach the rule engine
 * and the AI even when the message has no text/plain part.
 */
export function htmlBodyToText(html: string): string {
  if (!html) return '';
  let s = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(style|script|head|title)[\s\S]*?<\/\1>/gi, '');

  s = s.replace(/<a\b[^>]*?href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, (_m, href, inner) => {
    const text = String(inner).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    const h = String(href).trim();
    if (!h || /^(mailto:|tel:|#|javascript:)/i.test(h)) return text || h;
    if (!text || text === h) return h;
    return `${text} (${h})`;
  });

  s = s
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|li|tr|h[1-6]|table|blockquote|section|article)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ');

  s = decodeHtmlEntities(s);

  return s
    .replace(/[ \t\f\v]+/g, ' ')
    .replace(/ *\n */g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

interface MimeBodyParts {
  text: string;
  html: string;
}

/**
 * Recursively walks a MIME node collecting the richest text/plain and text/html
 * bodies. Handles arbitrarily nested multipart/* containers (mixed > alternative
 * > related, ...), which the previous single-level boundary split missed and
 * which caused HTML-only mail to reach the analysis pipeline with an empty body.
 */
function collectMimeBodies(headerBlock: string, body: string, out: MimeBodyParts, depth = 0): void {
  if (depth > 15) return;
  const headers = headerBlock.replace(/\n[ \t]+/g, ' '); // unfold continuation lines
  const ctMatch = headers.match(/content-type:\s*([^\s;]+)/i);
  const contentType = (ctMatch ? ctMatch[1] : 'text/plain').toLowerCase();
  const cteMatch = headers.match(/content-transfer-encoding:\s*([^\s;]+)/i);
  const cte = cteMatch ? cteMatch[1] : '';
  const dispMatch = headers.match(/content-disposition:\s*([^\s;]+)/i);
  const disposition = (dispMatch ? dispMatch[1] : '').toLowerCase();

  if (contentType.startsWith('multipart/')) {
    const bMatch = headers.match(/boundary=(?:"([^"]+)"|'([^']+)'|([^\s;]+))/i);
    const boundary = bMatch ? bMatch[1] || bMatch[2] || bMatch[3] : '';
    if (!boundary) return;
    const esc = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const segments = body.split(new RegExp(`\\n?--${esc}(?:--)?[ \\t]*(?:\\n|$)`));
    for (const seg of segments) {
      const sp = seg.indexOf('\n\n');
      if (sp === -1) continue;
      const segHeaders = seg.slice(0, sp);
      // Skip the multipart preamble / epilogue (free text, not a real part).
      if (!/^[A-Za-z][A-Za-z-]*:/.test(segHeaders.trimStart())) continue;
      collectMimeBodies(segHeaders, seg.slice(sp + 2), out, depth + 1);
    }
    return;
  }

  if (disposition === 'attachment') return;
  const isHtml = contentType.startsWith('text/html');
  const isPlain = contentType.startsWith('text/plain');
  if (!isHtml && !isPlain) return;

  const decoded = decodeTransferEncoding(body.trim(), cte);
  if (isHtml) {
    if (decoded.length > out.html.length) out.html = decoded;
  } else if (decoded.length > out.text.length) {
    out.text = decoded;
  }
}

/**
 * Main parser function to parse raw .eml text into structured ParsedEmail
 */
export function parseRawEml(rawEml: string): ParsedEmail {
  if (!rawEml || typeof rawEml !== 'string') {
    throw new Error('No raw email content provided');
  }

  // Normalize line endings
  const normalized = rawEml.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  // Split headers and body at the first blank line
  const splitIndex = normalized.indexOf('\n\n');
  let headerSection = '';
  let bodySection = '';

  if (splitIndex !== -1) {
    headerSection = normalized.substring(0, splitIndex);
    bodySection = normalized.substring(splitIndex + 2);
  } else {
    headerSection = normalized;
    bodySection = '';
  }

  // Parse headers by unfolding continuation lines
  const headerLines = headerSection.split('\n');
  const unfoldedHeaders: string[] = [];

  for (const line of headerLines) {
    if ((line.startsWith(' ') || line.startsWith('\t')) && unfoldedHeaders.length > 0) {
      unfoldedHeaders[unfoldedHeaders.length - 1] += ' ' + line.trim();
    } else if (line.trim().length > 0) {
      unfoldedHeaders.push(line);
    }
  }

  const rawHeaders: Record<string, string | string[]> = {};
  const receivedRawList: string[] = [];

  for (const h of unfoldedHeaders) {
    const colonIdx = h.indexOf(':');
    if (colonIdx === -1) continue;

    const key = h.substring(0, colonIdx).trim().toLowerCase();
    const value = h.substring(colonIdx + 1).trim();

    if (key === 'received') {
      receivedRawList.push(value);
    }

    if (rawHeaders[key]) {
      if (Array.isArray(rawHeaders[key])) {
        (rawHeaders[key] as string[]).push(value);
      } else {
        rawHeaders[key] = [rawHeaders[key] as string, value];
      }
    } else {
      rawHeaders[key] = value;
    }
  }

  const getFirstHeader = (key: string): string => {
    const val = rawHeaders[key.toLowerCase()];
    if (!val) return '';
    return Array.isArray(val) ? val[0] : val;
  };

  // Parse basic headers
  const fromRaw = getFirstHeader('from');
  const from = parseAddress(fromRaw);

  const toRaw = getFirstHeader('to');
  const toAddress = parseAddress(toRaw).address || toRaw;

  const subject = decodeMimeWords(getFirstHeader('subject')) || '(No Subject)';
  const date = getFirstHeader('date') || '';
  const returnPath = getFirstHeader('return-path').replace(/^<|>$/g, '') || '';
  const replyTo = getFirstHeader('reply-to').replace(/^<|>$/g, '') || '';
  const messageId = getFirstHeader('message-id').replace(/^<|>$/g, '') || '';

  // Process Received header chain:
  // In email headers, the newest hop is added to the top.
  // We reverse them so Hop 1 is the sender/originating server, progressing to the final recipient server.
  const receivedHops: ReceivedHop[] = [];
  const hopsChronological = [...receivedRawList].reverse();

  hopsChronological.forEach((rawHop, idx) => {
    receivedHops.push(parseReceivedHop(rawHop, idx + 1));
  });

  // Parse Authentication headers (SPF, DKIM, DMARC)
  const authResults = parseAuthenticationHeaders(rawHeaders);

  // Extract body: recursively walk the MIME tree (handles arbitrarily nested
  // multipart/*) collecting the best text/plain and text/html parts.
  const mimeBodies: MimeBodyParts = { text: '', html: '' };
  collectMimeBodies(unfoldedHeaders.join('\n'), bodySection, mimeBodies);

  let bodyHtml = mimeBodies.html;
  let bodyText = mimeBodies.text;

  // No usable text/plain part (HTML-only mail): derive readable text from the
  // HTML part so the rule-based keyword checks and the AI engine still receive
  // body content and link context rather than scoring on headers alone.
  const plainIsUsable = bodyText.replace(/\s+/g, ' ').trim().length >= 24;
  if (!plainIsUsable && bodyHtml.trim()) {
    const derived = htmlBodyToText(bodyHtml);
    if (derived.length > bodyText.trim().length) bodyText = derived;
  }

  // Extract links
  const extractedLinks = extractAndCheckLinks(bodyHtml, bodyText);

  // Extract attachments (metadata + transient bytes for hashing — see
  // hashAndClassifyAttachments, which the caller runs next).
  const attachments = extractAttachments(rawEml);

  return {
    from: {
      raw: fromRaw,
      displayName: from.displayName,
      address: from.address,
      domain: from.domain,
    },
    to: {
      raw: toRaw,
      address: toAddress,
    },
    subject,
    date,
    returnPath,
    replyTo,
    messageId,
    receivedHops,
    authResults,
    bodyText: bodyText.trim(),
    bodyHtml: bodyHtml.trim() || undefined,
    extractedLinks,
    attachments,
    rawHeaders,
    rawSource: rawEml,
  };
}
