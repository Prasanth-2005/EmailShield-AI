import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { ParsedEmail, ThreatAnalysisResult } from '../types';

/**
 * Client-side forensic report export (jsPDF + autotable).
 * Text-only, printable A4 layout - no external assets, no images.
 */

/** Short, reasonably unique case identifier, e.g. "ESA-LXF9A2-7Q4K". */
export function generateCaseId(now: Date = new Date()): string {
  const t = now.getTime().toString(36).toUpperCase().slice(-6);
  const r = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `ESA-${t}-${r}`;
}

interface ActionBand {
  band: string;
  guidance: string;
  rgb: [number, number, number];
}

function recommendedAction(score: number): ActionBand {
  if (score > 70) {
    return {
      band: 'BLOCK SENDER & ESCALATE',
      guidance:
        'High-confidence malicious indicators. Block the sending address and originating domain/IP at the gateway, ' +
        'purge any delivered copies from user mailboxes, and escalate to the security incident response team. ' +
        'If any recipient interacted with links or attachments, initiate credential-reset and endpoint-review procedures.',
      rgb: [176, 32, 32],
    };
  }
  if (score >= 40) {
    return {
      band: 'QUARANTINE & REVIEW',
      guidance:
        'Several suspicious signals are present but the verdict is not conclusive. Move the message to quarantine, ' +
        'have an analyst review the headers, links and body in context, and confirm with the purported sender through ' +
        'a known-good channel before releasing or discarding.',
      rgb: [176, 120, 16],
    };
  }
  return {
    band: 'NO ACTION REQUIRED',
    guidance:
      'No significant threat indicators were detected. The message authenticates correctly and its content, links and ' +
      'routing appear consistent with a legitimate sender. Retain this report for reference; no containment action is needed.',
    rgb: [24, 128, 72],
  };
}

const PAGE = { w: 595.28, h: 841.89 };
const MARGIN = 48;
const CONTENT_W = PAGE.w - MARGIN * 2;
const SLATE: [number, number, number] = [30, 41, 59];
const LIGHT: [number, number, number] = [241, 245, 249];

function fmt(v: string | undefined | null): string {
  const s = (v ?? '').toString().trim();
  return s.length ? s : '-';
}

function authStatus(a?: { status?: string; details?: string }): string {
  if (!a || !a.status) return 'MISSING / not evaluated';
  return a.details ? `${a.status.toUpperCase()} - ${a.details}` : a.status.toUpperCase();
}

export interface ReportResult {
  caseId: string;
  fileName: string;
}

/**
 * Builds the report PDF and returns the jsPDF document plus its metadata.
 * Does not trigger a download - see {@link generateForensicReport}.
 */
export function buildForensicReportDoc(
  email: ParsedEmail,
  analysis: ThreatAnalysisResult,
  opts: { sourceFileName?: string; caseId?: string } = {},
): { doc: jsPDF; caseId: string; fileName: string } {
  const now = new Date();
  const caseId = opts.caseId ?? generateCaseId(now);
  const bodyOnly = analysis.analysisScope === 'body-and-sender';
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });

  let y = MARGIN;

  // ---- Header -----------------------------------------------------------
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(17);
  doc.setTextColor(...SLATE);
  doc.text('EmailShield AI - Forensic Analysis Report', MARGIN, y);
  y += 20;

  doc.setDrawColor(...SLATE);
  doc.setLineWidth(1);
  doc.line(MARGIN, y, PAGE.w - MARGIN, y);
  y += 16;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(71, 85, 105);
  doc.text(`Case ID:  ${caseId}`, MARGIN, y);
  doc.text(`Generated:  ${now.toLocaleString()}`, PAGE.w - MARGIN, y, { align: 'right' });
  y += 13;
  doc.text(`Source file:  ${fmt(opts.sourceFileName) || 'raw-email-stream.eml'}`, MARGIN, y);
  doc.text(`AI engine:  ${fmt(analysis.engine)}`, PAGE.w - MARGIN, y, { align: 'right' });
  y += 13;
  doc.text(
    `Analysis scope:  ${bodyOnly ? 'BODY & SENDER ONLY (Gmail Quick Scan — no raw headers)' : 'Full (raw .eml — headers, auth, routing)'}`,
    MARGIN,
    y,
  );
  y += 10;

  // ---- Layout helpers -------------------------------------------------
  const PAGE_BOTTOM = PAGE.h - MARGIN - 24; // keep clear of the footer

  const ensureSpace = (needed: number) => {
    if (y + needed > PAGE_BOTTOM) {
      doc.addPage();
      y = MARGIN;
    }
  };

  const section = (title: string, reserve = 84) => {
    y += 24;
    ensureSpace(reserve);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11.5);
    doc.setTextColor(...SLATE);
    doc.text(title, MARGIN, y);
    y += 6;
  };

  const paragraph = (text: string, size = 9, style: 'normal' | 'italic' = 'normal') => {
    doc.setFont('helvetica', style);
    doc.setFontSize(size);
    doc.setTextColor(15, 23, 42);
    const lines = doc.splitTextToSize(text, CONTENT_W);
    ensureSpace(lines.length * (size + 3) + 6);
    doc.text(lines, MARGIN, y + size);
    y += lines.length * (size + 3) + 6;
  };

  const baseTable = (opts2: Parameters<typeof autoTable>[1]) => {
    autoTable(doc, {
      startY: y + 6,
      margin: { left: MARGIN, right: MARGIN, bottom: MARGIN + 26 },
      styles: { font: 'helvetica', fontSize: 9, cellPadding: 5, overflow: 'linebreak', textColor: [15, 23, 42] },
      headStyles: { fillColor: SLATE, textColor: [255, 255, 255], fontStyle: 'bold', fontSize: 9 },
      alternateRowStyles: { fillColor: LIGHT },
      tableWidth: CONTENT_W,
      ...opts2,
    });
    const finalY = (doc as any).lastAutoTable?.finalY;
    if (typeof finalY === 'number') y = finalY;
  };

  // ---- Verdict summary ------------------------------------------------
  const action = recommendedAction(analysis.fraudScore);
  section('1.  Verdict Summary');
  const dsPoints = analysis.deepScan?.addedPoints ?? 0;
  const baseScore = typeof analysis.baseFraudScore === 'number' ? analysis.baseFraudScore : analysis.fraudScore;
  const mlOn = analysis.mlModel != null && analysis.mlScore != null;
  const wts = analysis.scoreWeights ?? { rule: mlOn ? 0.35 : 0.5, ml: mlOn ? 0.3 : null, gemini: mlOn ? 0.35 : 0.5 };
  const composition =
    (mlOn
      ? `Rule engine ${analysis.ruleScore} x ${wts.rule}  +  ML model ${analysis.mlScore} x ${wts.ml}  +  AI ${analysis.geminiScore} x ${wts.gemini}`
      : `Rule engine ${analysis.ruleScore} x ${wts.rule}  +  AI ${analysis.geminiScore} x ${wts.gemini}  (ML layer skipped - service offline)`) +
    (dsPoints > 0 ? `  = ${baseScore}  +  Deep Scan ${dsPoints}  = ${analysis.fraudScore}` : '');
  baseTable({
    body: [
      ['Classification', fmt(analysis.classification)],
      ['Final fraud score', `${analysis.fraudScore} / 100${dsPoints > 0 ? '  (updated after Threat Intelligence deep scan)' : ''}`],
      ['In plain terms', fmt(analysis.plainSummary)],
      ['Score composition', composition],
      [
        'ML model verdict',
        mlOn
          ? `${String(analysis.mlModel!.label).toUpperCase()} (${analysis.mlModel!.confidence}% confidence) - bert-finetuned-phishing`
          : 'Skipped - local ML service was not reachable',
      ],
      ['AI confidence', `${fmt(String(analysis.confidence))}%`],
      ['Analyst recommendation', action.band],
    ],
    columnStyles: { 0: { cellWidth: 150, fontStyle: 'bold', fillColor: LIGHT }, 1: { cellWidth: CONTENT_W - 150 } },
    didParseCell: (data) => {
      if (data.section === 'body' && data.row.index === 0 && data.column.index === 1) {
        data.cell.styles.textColor = action.rgb;
        data.cell.styles.fontStyle = 'bold';
      }
    },
  });

  // ---- Email metadata ----------------------------------------------------
  section('2.  Email Metadata');
  baseTable({
    head: [['Field', 'Value']],
    body: [
      ['From (address)', fmt(email.from?.address)],
      ['Display name', fmt(email.from?.displayName)],
      ['To', fmt(email.to?.address || email.to?.raw)],
      ['Subject', fmt(email.subject)],
      ['Date', fmt(email.date)],
      ['Message-ID', fmt(email.messageId)],
      ['Return-Path', fmt(email.returnPath)],
      ['Reply-To', fmt(email.replyTo)],
    ],
    columnStyles: { 0: { cellWidth: 130, fontStyle: 'bold' }, 1: { cellWidth: CONTENT_W - 130 } },
  });

  // ---- Authentication --------------------------------------------------
  section('3.  Authentication Results');
  if (bodyOnly) {
    baseTable({
      body: [
        [
          'Not available — this analysis came from the Gmail Quick Scan extension, which does not expose the ' +
            'Authentication-Results header. SPF, DKIM and DMARC were not evaluated. Upload the original .eml file ' +
            'for sender authentication forensics.',
        ],
      ],
    });
  } else {
    baseTable({
      head: [['Mechanism', 'Result']],
      body: [
        ['SPF', authStatus(email.authResults?.spf)],
        ['DKIM', authStatus(email.authResults?.dkim)],
        ['DMARC', authStatus(email.authResults?.dmarc)],
      ],
      columnStyles: { 0: { cellWidth: 90, fontStyle: 'bold' }, 1: { cellWidth: CONTENT_W - 90 } },
    });
  }

  // ---- Rule-based findings -------------------------------------------
  section('4.  Rule-Based Findings');
  const rules = analysis.triggeredRules || [];
  if (rules.length === 0) {
    baseTable({ body: [['No deterministic rules were triggered for this message.']] });
  } else {
    baseTable({
      head: [['Rule', 'Category', 'Description', 'Pts']],
      body: [
        ...rules.map((r) => [fmt(r.rule), fmt(r.category), fmt(r.description), `+${r.points}`]),
        ['', '', 'Rule sub-score (sum, capped at 100)', String(analysis.ruleScore)],
      ],
      columnStyles: {
        0: { cellWidth: 120, fontStyle: 'bold' },
        1: { cellWidth: 80 },
        2: { cellWidth: CONTENT_W - 120 - 80 - 34 },
        3: { cellWidth: 34, halign: 'right' },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.row.index === rules.length) {
          data.cell.styles.fontStyle = 'bold';
          data.cell.styles.fillColor = LIGHT;
        }
      },
    });
  }

  // ---- AI analysis ---------------------------------------------------
  section(`5.  AI Analysis  (${fmt(analysis.engine)})`);
  y += 8;
  paragraph(fmt(analysis.explanation), 9, 'italic');

  const flags = analysis.redFlags || [];
  if (flags.length === 0) {
    baseTable({ body: [['No AI-detected flags were returned for this message.']] });
  } else {
    baseTable({
      head: [['Severity', 'Category', 'Flag', 'Detail']],
      body: flags.map((f) => [fmt(f.severity).toUpperCase(), fmt(f.category), fmt(f.title), fmt(f.description)]),
      columnStyles: {
        0: { cellWidth: 58, fontStyle: 'bold' },
        1: { cellWidth: 92 },
        2: { cellWidth: 120 },
        3: { cellWidth: CONTENT_W - 58 - 92 - 120 },
      },
    });
  }

  // ---- Origin trace ------------------------------------------------
  section('6.  Origin Trace');
  const trace = analysis.originTrace;
  if (bodyOnly) {
    baseTable({
      body: [
        [
          'Not available — the Gmail Quick Scan extension cannot read Received headers, so the relay path, ' +
            'originating IP and geolocation could not be traced. Upload the original .eml file for origin tracing.',
        ],
      ],
    });
  } else if (!trace || trace.hops.length === 0) {
    baseTable({ body: [[fmt(trace?.note) || 'No Received routing headers were available to trace.']] });
  } else {
    const originIdx = trace.hops.findIndex((h) => h.isProbableOrigin);
    baseTable({
      head: [['Hop', 'IP', 'City', 'Country', 'ISP / Org', 'Origin']],
      body: trace.hops.map((h, i) => [
        String(i + 1),
        fmt(h.ip),
        h.geo?.status === 'success' ? fmt(h.geo.city) : h.isPublic ? 'unavailable' : 'private hop',
        h.geo?.status === 'success' ? fmt(h.geo.country) : '-',
        h.geo?.status === 'success' ? fmt(h.geo.isp || h.geo.org) : '-',
        h.isProbableOrigin ? 'PROBABLE ORIGIN' : h.flags.length ? h.flags.join(', ').toUpperCase() : '',
      ]),
      columnStyles: {
        0: { cellWidth: 30, halign: 'right' },
        1: { cellWidth: 96 },
        2: { cellWidth: 82 },
        3: { cellWidth: 78 },
        4: { cellWidth: CONTENT_W - 30 - 96 - 82 - 78 - 96 },
        5: { cellWidth: 96, fontStyle: 'bold' },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.row.index === originIdx) {
          data.cell.styles.fillColor = [254, 226, 226];
          if (data.column.index === 5) data.cell.styles.textColor = [176, 32, 32];
        }
      },
    });
    if (trace.originGeo?.status === 'success') {
      y += 8;
      const note = `Probable origin: ${trace.originIp} - ${fmt(trace.originGeo.city)}, ${fmt(trace.originGeo.country)} (${fmt(
        trace.originGeo.isp,
      )})${trace.originGeo.proxy ? '  · flagged proxy/VPN' : ''}${trace.originGeo.hosting ? '  · flagged datacentre/hosting' : ''}.`;
      paragraph(note, 8.5);
    }
  }

  // ---- Threat intelligence findings ------------------------------
  section('7.  Threat Intelligence Findings');

  // 7a. AbuseIPDB per hop
  y += 6;
  paragraph('AbuseIPDB — relay-chain IP reputation:', 9, 'italic');
  const repHops = (trace?.hops || []).filter((h) => h.isPublic && h.ip);
  if (repHops.length === 0) {
    baseTable({ body: [['No public relay-chain IPs to check.']] });
  } else {
    baseTable({
      head: [['Hop', 'IP', 'Reputation', 'Reports', 'Categories']],
      body: repHops.map((h, i) => {
        const rep = h.reputation;
        const status = !rep
          ? '-'
          : rep.status === 'unavailable'
          ? `Check unavailable (${rep.message || 'error'})`
          : rep.status === 'clean'
          ? 'Clean'
          : `Flagged — abuse confidence ${rep.abuseConfidenceScore}%`;
        return [
          String(i + 1),
          fmt(h.ip),
          status,
          rep ? String(rep.totalReports) : '-',
          rep && rep.categories.length ? rep.categories.join(', ') : '-',
        ];
      }),
      columnStyles: {
        0: { cellWidth: 28, halign: 'right' },
        1: { cellWidth: 96 },
        2: { cellWidth: 150 },
        3: { cellWidth: 44, halign: 'right' },
        4: { cellWidth: CONTENT_W - 28 - 96 - 150 - 44 },
      },
    });
  }

  // 7b. Domain registration intelligence (RDAP)
  y += 10;
  paragraph('Domain registration intelligence (RDAP):', 9, 'italic');
  const domainEntries = analysis.domainIntel?.entries || [];
  if (domainEntries.length === 0) {
    baseTable({ body: [['No sender / return-path / link domains were available to look up.']] });
  } else {
    baseTable({
      head: [['Domain', 'Role', 'Registered', 'Age (days)', 'Expires', 'Registrar']],
      body: domainEntries.map((e) => {
        const reg =
          e.status !== 'ok'
            ? 'Registration data unavailable'
            : e.registeredAt
            ? new Date(e.registeredAt).toISOString().slice(0, 10)
            : '-';
        return [
          fmt(e.domain),
          e.role.replace('-', ' '),
          reg,
          typeof e.ageDays === 'number' ? String(e.ageDays) : '-',
          e.status === 'ok' && e.expiresAt ? new Date(e.expiresAt).toISOString().slice(0, 10) : '-',
          e.status === 'ok' ? fmt(e.registrar) : '-',
        ];
      }),
      columnStyles: {
        0: { cellWidth: 120, fontStyle: 'bold' },
        1: { cellWidth: 74 },
        2: { cellWidth: 74 },
        3: { cellWidth: 56, halign: 'right' },
        4: { cellWidth: 74 },
        5: { cellWidth: CONTENT_W - 120 - 74 - 74 - 56 - 74 },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 3) {
          const e = domainEntries[data.row.index];
          if (e && typeof e.ageDays === 'number' && e.ageDays < 30) {
            data.cell.styles.textColor = [176, 32, 32];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
  }

  // 7c. Attachment analysis
  const atts = analysis.attachments || email.attachments || [];
  y += 10;
  paragraph('Attachment static analysis (SHA-256 + extension risk):', 9, 'italic');
  if (atts.length === 0) {
    baseTable({ body: [['This message has no attachments.']] });
  } else {
    baseTable({
      head: [['Filename', 'Type', 'Size', 'Risk', 'SHA-256']],
      body: atts.map((a) => [
        fmt(a.filename),
        fmt(a.mimeType),
        `${a.size} B`,
        a.extensionRisk ? `${a.extensionRisk.toUpperCase()}${a.riskReason ? ` — ${a.riskReason}` : ''}` : 'none',
        a.sha256 || '(hash unavailable)',
      ]),
      columnStyles: {
        0: { cellWidth: 110, fontStyle: 'bold' },
        1: { cellWidth: 96 },
        2: { cellWidth: 40, halign: 'right' },
        3: { cellWidth: 120 },
        4: { cellWidth: CONTENT_W - 110 - 96 - 40 - 120, fontSize: 6.5 },
      },
    });
  }

  // 7d. VirusTotal deep scan
  y += 10;
  paragraph('VirusTotal deep scan (on demand):', 9, 'italic');
  const ds = analysis.deepScan;
  if (!ds || ds.items.length === 0) {
    baseTable({ body: [['Threat intelligence deep scan not performed.']] });
  } else {
    baseTable({
      head: [['Item', 'Type', 'Detection', 'SHA-256 / note']],
      body: ds.items.map((it) => {
        const ratio =
          it.status === 'done'
            ? `${it.malicious}/${it.total} malicious${it.suspicious ? ` (+${it.suspicious} suspicious)` : ''}`
            : it.status === 'unknown'
            ? 'No prior threat record (SHA-256 hash lookup only; file not uploaded)'
            : it.status === 'pending'
            ? 'Scan pending'
            : it.message || 'Scan unavailable';
        const item =
          it.kind === 'url'
            ? `${it.url}${(it.appearsCount || 0) > 1 ? `  (appears ${it.appearsCount}x)` : ''}`
            : it.filename;
        return [
          item,
          it.kind.toUpperCase(),
          ratio,
          it.kind === 'file' ? it.sha256 : it.mismatched ? 'display text != destination' : '-',
        ];
      }),
      columnStyles: {
        0: { cellWidth: 150 },
        1: { cellWidth: 36 },
        2: { cellWidth: 130 },
        3: { cellWidth: CONTENT_W - 150 - 36 - 130, fontSize: 6.5 },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 2) {
          const it = ds.items[data.row.index];
          if (it && it.status === 'done' && it.malicious + it.suspicious >= 3) {
            data.cell.styles.textColor = [176, 32, 32];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    if (ds.addedPoints > 0) {
      y += 6;
      paragraph(
        `Deep scan raised the fraud score by ${ds.addedPoints} points (${baseScore} -> ${analysis.fraudScore}).`,
        8.5,
      );
    }
    if (ds.items.some((it) => it.kind === 'file' && it.status === 'unknown')) {
      y += 4;
      paragraph(
        '"No prior threat record" means the file\'s SHA-256 hash was checked against VirusTotal and not found. ' +
          'Attachments are never uploaded to third parties, so unique or personal documents will not have a prior ' +
          'record. This is a privacy design choice, not an indication of malware.',
        8,
        'italic',
      );
    }
  }

  // ---- Recommended action ------------------------------------------
  section('8.  Recommended Action', 150);
  y += 10;
  ensureSpace(28 + 60);
  doc.setFillColor(action.rgb[0], action.rgb[1], action.rgb[2]);
  doc.rect(MARGIN, y, CONTENT_W, 20, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(255, 255, 255);
  doc.text(`${action.band}   (score ${analysis.fraudScore}/100)`, MARGIN + 8, y + 13.5);
  y += 30;
  paragraph(action.guidance, 9);

  // ---- Footer on every page --------------------------------------
  const pageCount = doc.getNumberOfPages();
  for (let p = 1; p <= pageCount; p++) {
    doc.setPage(p);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.5);
    doc.line(MARGIN, PAGE.h - 30, PAGE.w - MARGIN, PAGE.h - 30);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(120, 130, 145);
    doc.text('Generated by EmailShield AI - for investigative reference', MARGIN, PAGE.h - 18);
    doc.text(`${caseId}   ·   Page ${p} of ${pageCount}`, PAGE.w - MARGIN, PAGE.h - 18, { align: 'right' });
  }

  const dateStr = now.toISOString().slice(0, 10);
  const fileName = `EmailShield-Report-${caseId}-${dateStr}.pdf`;
  return { doc, caseId, fileName };
}

/** Builds the report and triggers a browser download. */
export function generateForensicReport(
  email: ParsedEmail,
  analysis: ThreatAnalysisResult,
  opts: { sourceFileName?: string; caseId?: string } = {},
): ReportResult {
  const { doc, caseId, fileName } = buildForensicReportDoc(email, analysis, opts);
  doc.save(fileName);
  return { caseId, fileName };
}
