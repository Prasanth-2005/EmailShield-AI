import type { EmailAttachment, ParsedEmail } from '../types';

/**
 * Attachment extraction, hashing and static risk classification.
 *
 * Runs in both the browser (`.eml` upload) and Node (Gmail Advanced Scan) — it
 * only uses APIs available in both (Web Crypto `crypto.subtle`, `TextDecoder`,
 * `DataView`, and a cross-platform base64 decoder).
 *
 * `content` bytes are used only to compute the SHA-256 and peek inside `.zip`
 * archives, then dropped — file bytes never leave the machine.
 */

const HIGH_RISK_EXT = new Set([
  'exe', 'scr', 'js', 'jse', 'vbs', 'vbe', 'bat', 'cmd', 'com', 'pif', 'jar',
  'hta', 'msi', 'msp', 'ps1', 'wsf', 'wsh', 'lnk', 'reg', 'cpl', 'gadget',
]);
const MACRO_EXT = new Set(['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'xlam', 'ppam']);
const ARCHIVE_EXT = new Set(['zip', 'rar', '7z']);
const BENIGN_LOOKING_EXT = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png', 'gif',
  'txt', 'htm', 'html', 'csv', 'rtf', 'zip', 'mp3', 'mp4', 'mov', 'invoice', 'receipt',
]);

function extOf(filename: string): string {
  const parts = filename.toLowerCase().trim().split('.');
  return parts.length > 1 ? parts[parts.length - 1] : '';
}

/** Cross-platform base64 (or base64url) -> bytes. */
export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/[^A-Za-z0-9+/=_-]/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(clean, 'base64'));
  const bin = atob(clean.replace(/=+$/, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
  return out;
}

/** Quoted-printable -> bytes. */
function quotedPrintableToBytes(text: string): Uint8Array {
  const cleaned = text.replace(/=\r?\n/g, '');
  const bytes: number[] = [];
  for (let i = 0; i < cleaned.length; i++) {
    const c = cleaned[i];
    if (c === '=' && /[0-9A-Fa-f]{2}/.test(cleaned.slice(i + 1, i + 3))) {
      bytes.push(parseInt(cleaned.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(c.charCodeAt(0) & 0xff);
    }
  }
  return Uint8Array.from(bytes);
}

function decodePartBody(body: string, cte: string): Uint8Array {
  const enc = (cte || '').toLowerCase().trim();
  if (enc === 'base64') return base64ToBytes(body);
  if (enc === 'quoted-printable') return quotedPrintableToBytes(body);
  const out = new Uint8Array(body.length);
  for (let i = 0; i < body.length; i++) out[i] = body.charCodeAt(i) & 0xff;
  return out;
}

function headerValue(headerBlock: string, name: string): string {
  // headerBlock lines already unfolded on '\n'
  const re = new RegExp(`^${name}\\s*:\\s*(.*)$`, 'im');
  const m = headerBlock.match(re);
  return m ? m[1].trim() : '';
}

function paramValue(headerLine: string, param: string): string {
  const m =
    headerLine.match(new RegExp(`${param}\\s*=\\s*"([^"]*)"`, 'i')) ||
    headerLine.match(new RegExp(`${param}\\s*=\\s*([^;\\s]+)`, 'i'));
  return m ? m[1].trim() : '';
}

interface RawPart {
  filename: string;
  mimeType: string;
  bytes: Uint8Array;
}

/** Recursively walk a MIME tree, collecting parts that look like attachments. */
function walkMime(headerBlock: string, body: string, out: RawPart[], depth: number): void {
  if (depth > 12) return;
  const ct = headerValue(headerBlock, 'content-type');
  const cd = headerValue(headerBlock, 'content-disposition');
  const cte = headerValue(headerBlock, 'content-transfer-encoding');
  const mime = (ct.split(';')[0] || '').trim().toLowerCase();

  if (mime.startsWith('multipart/')) {
    const boundary = paramValue(ct, 'boundary');
    if (!boundary) return;
    const marker = `--${boundary}`;
    const segments = body.split(marker);
    for (const seg of segments) {
      const trimmed = seg.replace(/^\r?\n/, '');
      if (!trimmed || trimmed.startsWith('--')) continue; // closing marker / preamble
      const sepIdx = trimmed.search(/\r?\n\r?\n/);
      if (sepIdx === -1) continue;
      const partHeaders = trimmed.slice(0, sepIdx).replace(/\r\n[ \t]+/g, ' ').replace(/\n[ \t]+/g, ' ');
      const partBody = trimmed.slice(trimmed.indexOf('\n', sepIdx) + 1).replace(/\r?\n$/, '');
      walkMime(partHeaders, partBody, out, depth + 1);
    }
    return;
  }

  // Leaf part — is it an attachment?
  const filename =
    paramValue(cd, 'filename') || paramValue(ct, 'name') || '';
  const isAttachment = /attachment/i.test(cd) || (!!filename && !mime.startsWith('multipart/'));
  const isInlineImageOnly = /inline/i.test(cd) && !filename;
  if (!isAttachment || isInlineImageOnly) return;

  try {
    const bytes = decodePartBody(body, cte);
    out.push({
      filename: filename || 'unnamed',
      mimeType: mime || 'application/octet-stream',
      bytes,
    });
  } catch {
    /* skip undecodable part */
  }
}

/** Extract raw attachment parts from a full RFC 822 message. Never throws. */
export function extractAttachments(rawEml: string): EmailAttachment[] {
  try {
    if (!rawEml || typeof rawEml !== 'string') return [];
    const normalized = rawEml.replace(/\r\n/g, '\n');
    const sepIdx = normalized.indexOf('\n\n');
    if (sepIdx === -1) return [];
    const headerBlock = normalized.slice(0, sepIdx).replace(/\n[ \t]+/g, ' ');
    const body = normalized.slice(sepIdx + 2);

    const parts: RawPart[] = [];
    walkMime(headerBlock, body, parts, 0);

    return parts.map((p) => ({
      filename: p.filename,
      mimeType: p.mimeType,
      size: p.bytes.length,
      sha256: '',
      extensionRisk: null,
      content: p.bytes,
    }));
  } catch {
    return [];
  }
}

// --- ZIP central-directory listing (no decompression) ----------------------

function listZipEntries(bytes: Uint8Array): string[] | null {
  try {
    const EOCD = 0x06054b50;
    const CDH = 0x02014b50;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let eocd = -1;
    const minStart = Math.max(0, bytes.length - 22 - 65536);
    for (let i = bytes.length - 22; i >= minStart; i--) {
      if (dv.getUint32(i, true) === EOCD) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) return null;
    const total = dv.getUint16(eocd + 10, true);
    let off = dv.getUint32(eocd + 16, true);
    const names: string[] = [];
    const dec = new TextDecoder('utf-8', { fatal: false });
    for (let n = 0; n < total && off + 46 <= bytes.length; n++) {
      if (dv.getUint32(off, true) !== CDH) break;
      const nameLen = dv.getUint16(off + 28, true);
      const extraLen = dv.getUint16(off + 30, true);
      const commentLen = dv.getUint16(off + 32, true);
      names.push(dec.decode(bytes.subarray(off + 46, off + 46 + nameLen)));
      off += 46 + nameLen + extraLen + commentLen;
    }
    return names;
  } catch {
    return null;
  }
}

function classify(
  filename: string,
  archiveNames: string[] | null,
): { risk: EmailAttachment['extensionRisk']; reason?: string } {
  const lower = filename.toLowerCase().trim();
  const segs = lower.split('.');
  const ext = segs.length > 1 ? segs[segs.length - 1] : '';

  if (segs.length >= 3) {
    const prev = segs[segs.length - 2];
    if (BENIGN_LOOKING_EXT.has(prev) && HIGH_RISK_EXT.has(ext)) {
      return { risk: 'high', reason: `Double extension ".${prev}.${ext}" — an executable disguised as a document.` };
    }
  }
  if (HIGH_RISK_EXT.has(ext)) {
    return { risk: 'high', reason: `High-risk executable / script extension ".${ext}".` };
  }
  if (MACRO_EXT.has(ext)) {
    return { risk: 'macro', reason: `Macro-enabled Office document (".${ext}") — can run code on open.` };
  }
  if (ARCHIVE_EXT.has(ext) && archiveNames) {
    const bad = archiveNames.filter((n) => HIGH_RISK_EXT.has(extOf(n)));
    if (bad.length) {
      return { risk: 'archive-exe', reason: `Archive contains an executable: ${bad.slice(0, 4).join(', ')}.` };
    }
  }
  return { risk: null };
}

/** Web Crypto SHA-256 (available in browsers and Node 20+). */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const view = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength ? bytes : bytes.slice();
  const digest = await crypto.subtle.digest('SHA-256', view);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Fills in `sha256` + `extensionRisk` (+ `archiveContents`) for every attachment
 * on a parsed email, then drops the raw `content` bytes. Idempotent, never throws.
 */
export async function hashAndClassifyAttachments(parsed: Pick<ParsedEmail, 'attachments'>): Promise<void> {
  const list = parsed.attachments || [];
  for (const att of list) {
    try {
      const bytes = att.content;
      if (bytes && bytes.length) {
        att.sha256 = att.sha256 || (await sha256Hex(bytes));
        let archiveNames: string[] | null = null;
        if (ARCHIVE_EXT.has(extOf(att.filename)) && extOf(att.filename) === 'zip') {
          archiveNames = listZipEntries(bytes);
          if (archiveNames) att.archiveContents = archiveNames;
        }
        const c = classify(att.filename, archiveNames);
        att.extensionRisk = c.risk;
        att.riskReason = c.reason;
      } else {
        // Metadata-only (bytes unavailable) — still classify on the name.
        const c = classify(att.filename, att.archiveContents || null);
        att.extensionRisk = c.risk;
        att.riskReason = c.reason;
      }
    } catch {
      /* leave this attachment unclassified */
    } finally {
      delete att.content;
    }
  }
}
